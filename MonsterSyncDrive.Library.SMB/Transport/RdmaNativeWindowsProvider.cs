/*
 * MIT License
 *
 * Copyright (c) 2025 - 2026 MonsterSyncDrive.Com
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */
using System.Buffers;
using System.Collections.Concurrent;
using System.ComponentModel;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Threading.Channels;
using MonsterSyncDrive.SMB.Transport;

namespace MonsterSyncDrive.SMB;

/// <summary>已安装的 Windows NetworkDirect v2 目录条目。</summary>
/// <param name="Id">已安装的提供程序标识符。</param>
/// <param name="Name">提供程序在目录中的显示名称。</param>
/// <param name="AddressFamily">本条目支持的地址族。</param>
/// <param name="LibraryPath">原生提供程序 DLL 的绝对路径。</param>
public sealed record SmbNetworkDirectProviderInfo(Guid Id, string Name, AddressFamily AddressFamily, string LibraryPath);

/// <summary>使用兼容 AOT 的原生 COM 调用的内置 Windows NetworkDirect v2 RDMA 提供程序。</summary>
/// <remarks>
/// 需要 Windows、64 位进程、RDMA 网卡及其已安装的 NDv2 提供程序。本实现使用
/// 真实适配器、队列对和连接管理器；不会通过 TCP 或 UDP 发送 SMB 负载。UDP 套接字
/// 仅用于查询 Windows 路由，以确定能够到达所选目标的本地 IP。
/// </remarks>
public sealed class SmbNetworkDirectProvider : ISmbRdmaProvider
{
    /// <summary>当前操作系统和进程是否支持本后端接口；不代表已经安装可用网卡。</summary>
    public static bool IsSupported => OperatingSystem.IsWindows() && IntPtr.Size == 8;
    /// <summary>可选地将原生发现限制为指定的已安装提供程序。</summary>
    public Guid? PreferredProviderId { get; init; }

    /// <summary>返回已安装的 NDv2 提供程序，不打开设备，也不连接对端。</summary>
    public static IReadOnlyList<SmbNetworkDirectProviderInfo> GetAvailableProviders()
    {
        CheckPlatform();
        using var winsock = new RdmaNativeWinsockLease();
        return RdmaNativeNetworkDirect.Enumerate().Select(p => new SmbNetworkDirectProviderInfo(p.Id, p.Name, (AddressFamily)p.Family, p.Path)).ToArray();
    }

    /// <summary>打开选定原生适配器，并建立可靠连接的 RDMA 队列对。</summary>
    public async ValueTask<ISmbRdmaEndpoint> ConnectAsync(SmbRdmaConnectOptions options, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(options);
        CheckPlatform();
        ArgumentException.ThrowIfNullOrWhiteSpace(options.Host);
        ArgumentOutOfRangeException.ThrowIfLessThan(options.Port, 1);
        ArgumentOutOfRangeException.ThrowIfGreaterThan(options.Port, 65535);
        cancellationToken.ThrowIfCancellationRequested();
        var providers = GetAvailableProviders().Where(p => PreferredProviderId is null || p.Id == PreferredProviderId).ToArray();
        if (providers.Length == 0)
            throw new PlatformNotSupportedException("No matching Windows NetworkDirect v2 provider is installed. SMB Direct requires an RDMA NIC and its NDv2 driver.");
        var addresses = IPAddress.TryParse(options.Host.Trim('[', ']'), out var literal) ? [literal]
            : await Dns.GetHostAddressesAsync(options.Host, cancellationToken).ConfigureAwait(false);
        var failures = new List<Exception>();
        foreach (var address in addresses)
        {
            if (address.AddressFamily is not (AddressFamily.InterNetwork or AddressFamily.InterNetworkV6)) continue;
            if (options.LocalEndPoint is { } configured && configured.AddressFamily != address.AddressFamily) continue;
            var remote = new IPEndPoint(address, options.Port);
            var local = SourceAddress(remote, options.LocalEndPoint);
            foreach (var provider in providers.Where(p => p.AddressFamily == address.AddressFamily))
            {
                try { return await RdmaNativeWindowsEndpoint.OpenAsync(provider, local, remote, options, cancellationToken).ConfigureAwait(false); }
                catch (Exception ex) when (ex is IOException or Win32Exception or SocketException or DllNotFoundException or BadImageFormatException)
                { failures.Add(ex); }
            }
        }
        throw new IOException("No installed NetworkDirect provider could establish the requested RDMA connection.", new AggregateException(failures));
    }

    /// <summary>仅查询本地路由；连接 UDP 套接字不会发送 SMB 数据包。</summary>
    private static IPEndPoint SourceAddress(IPEndPoint remote, IPEndPoint? configured)
    {
        if (configured is not null && !configured.Address.Equals(IPAddress.Any) && !configured.Address.Equals(IPAddress.IPv6Any))
            return new(configured.Address, configured.Port);
        using var route = new Socket(remote.AddressFamily, SocketType.Dgram, ProtocolType.Udp);
        route.Connect(remote);
        var selected = (IPEndPoint)route.LocalEndPoint!;
        return new(selected.Address, configured?.Port ?? 0);
    }

    /// <summary>保护全部 Windows DLL 调用入口，并约束到已定义的 64 位 ND2 布局。</summary>
    private static void CheckPlatform()
    {
        if (!IsSupported)
            throw new PlatformNotSupportedException("The built-in NetworkDirect v2 backend requires 64-bit Windows. Other platforms can supply a native ISmbRdmaProvider.");
    }
}

/// <summary>独立于托管套接字，平衡原生 WSAStartup 和 WSACleanup 引用。</summary>
internal sealed class RdmaNativeWinsockLease : IDisposable
{
    /// <summary>确保清理只执行一次。</summary>
    private int disposed;
    /// <summary>通过不依赖特定布局宽度的临时 WSADATA 存储初始化 Winsock 2.2。</summary>
    internal RdmaNativeWinsockLease()
    {
        var data = RdmaNativeNetworkDirect.AllocateWsaData();
        try
        {
            var status = RdmaNativeNetworkDirect.WsaStartup(0x202, data);
            if (status != 0) throw new Win32Exception(status, "Could not initialize Winsock for NetworkDirect.");
        }
        finally { RdmaNativeNetworkDirect.FreeWsaData(data); }
    }
    /// <summary>全部依赖对象销毁后，释放本次初始化。</summary>
    public void Dispose() { if (Interlocked.Exchange(ref disposed, 1) == 0) _ = RdmaNativeNetworkDirect.WsaCleanup(); }
}

/// <summary>可靠连接的 NDv2 端点、完成结果分发器及已注册缓冲区所有者。</summary>
internal sealed class RdmaNativeWindowsEndpoint : ISmbRdmaEndpoint
{
    /// <summary>串行保护 COM 调用与队列对、完成队列销毁之间的访问。</summary>
    private readonly object nativeGate = new();
    /// <summary>只要仍有原生接口存在，就持有提供程序 DLL。</summary>
    private nint module;
    /// <summary>拥有已打开的适配器引用。</summary>
    private nint adapter;
    /// <summary>拥有共享完成队列引用。</summary>
    private nint completionQueue;
    /// <summary>拥有可靠连接的队列对引用。</summary>
    private nint queuePair;
    /// <summary>拥有连接管理器引用。</summary>
    private nint connector;
    /// <summary>拥有适配器的异步文件句柄。</summary>
    private nint file;
    /// <summary>维持原生 Winsock 和提供程序支持的初始化状态。</summary>
    private readonly RdmaNativeWinsockLease winsock = new();
    /// <summary>拥有的句柄释放前，取消原生注册和初始化操作。</summary>
    private readonly CancellationTokenSource abortSignal = new();
    /// <summary>将发起方工作限制在协商得到的硬件队列深度内。</summary>
    private SemaphoreSlim initiatorSlots = new(1, 1);
    /// <summary>将原生请求标识映射到托管完成状态。</summary>
    private readonly ConcurrentDictionary<nint, Work> pending = new();
    /// <summary>保留每个固定区域，直到注销或队列对销毁完成访问栅栏。</summary>
    private readonly ConcurrentDictionary<Region, byte> regions = new();
    /// <summary>排队复制后的接收负载，由已投递接收计数限制容量。</summary>
    private readonly Channel<SmbRdmaReceive> receives = Channel.CreateUnbounded<SmbRdmaReceive>(new UnboundedChannelOptions { SingleWriter = true });
    /// <summary>被中止的队列对已没有未完成工作请求时完成。</summary>
    private readonly TaskCompletionSource drained = new(TaskCreationOptions.RunContinuationsAsynchronously);
    /// <summary>运行原生完成结果分发器。</summary>
    private Task poller = Task.CompletedTask;
    /// <summary>分配不透明标识；不将托管对象地址传入原生接口。</summary>
    private long sequence;
    /// <summary>统计已投递或已排队、但尚未由 ReceiveAsync 返回的接收。</summary>
    private int receiveOutstanding;
    /// <summary>队列对开始清空后，阻止新工作进入。</summary>
    private int aborted;
    /// <summary>确保端点释放只执行一次。</summary>
    private int disposed;
    /// <summary>串行建立唯一的异步释放任务，防止并发调用方越过尚未结束的设备栅栏。</summary>
    private readonly object disposalGate = new();
    /// <summary>所有调用方共同等待的原生资源清理任务。</summary>
    private Task? disposalTask;
    /// <summary>保留首次原生失败。</summary>
    private Exception? failure;
    /// <summary>IND2Adapter.Query 返回的硬件限制。</summary>
    private RdmaNativeNetworkDirect.AdapterInfo limits;
    /// <summary>分配缓冲区时采用的接收最大字节数。</summary>
    private int receiveSize;

    /// <summary>已绑定的本地 RDMA 套接字地址。</summary>
    public EndPoint? LocalEndPoint { get; private set; }
    /// <summary>选定的远程 RDMA 套接字地址。</summary>
    public EndPoint? RemoteEndPoint { get; private set; }
    /// <summary>提供程序接受的 SEND 工作请求最大字节数。</summary>
    public int MaximumSendSize { get; private set; }
    /// <summary>提供程序接受的 RECEIVE 工作请求最大字节数。</summary>
    public int MaximumReceiveSize => receiveSize;
    /// <summary>接收信用的公布数量绝不超过由设备资源支持的容量。</summary>
    public ushort MaximumReceiveQueueDepth { get; private set; }
    /// <summary>只有连接协商了入站 RDMA 读取资源，才允许服务端读取本地注册数据。</summary>
    public bool SupportsRemoteRead => limits.MaximumInboundReadLimit > 0;
    /// <summary>可靠连接的 ND2 队列对允许注册远程写入区域。</summary>
    public bool SupportsRemoteWrite => true;

    /// <summary>异步设备初始化前，先创建原生资源所有者。</summary>
    private RdmaNativeWindowsEndpoint() { }

    /// <summary>打开提供程序、适配器、完成队列、队列对和连接器，并完成 RDMA 连接管理握手。</summary>
    internal static async Task<RdmaNativeWindowsEndpoint> OpenAsync(SmbNetworkDirectProviderInfo provider, IPEndPoint local,
        IPEndPoint remote, SmbRdmaConnectOptions options, CancellationToken cancellationToken)
    {
        var result = new RdmaNativeWindowsEndpoint();
        try
        {
            result.module = NativeLibrary.Load(provider.LibraryPath);
            var providerPointer = RdmaNativeNetworkDirect.GetProvider(result.module, provider.Id);
            try
            {
                RdmaNativeNetworkDirect.Check(RdmaNativeNetworkDirect.Resolve(providerPointer, Sockaddr(local), out var adapterId), "IND2Provider.ResolveAddress");
                result.adapter = RdmaNativeNetworkDirect.OpenAdapter(providerPointer, adapterId);
            }
            finally { RdmaNativeNetworkDirect.Release(providerPointer); }
            result.limits = RdmaNativeNetworkDirect.Query(result.adapter);
            if (result.limits.MaximumReceiveSge == 0 || result.limits.MaximumInitiatorSge == 0 || result.limits.MaximumReceiveQueueDepth == 0 ||
                result.limits.MaximumInitiatorQueueDepth == 0 || result.limits.MaximumCompletionQueueDepth < 2 || result.limits.MaximumTransferLength < 128 || result.limits.MaximumRegistrationSize == 0)
                throw new IOException("The ND2 adapter lacks the queues or memory capabilities needed by SMB Direct.");
            result.MaximumReceiveQueueDepth = (ushort)Math.Min(options.MaximumReceiveCredits, Math.Min(ushort.MaxValue, Math.Min(result.limits.MaximumReceiveQueueDepth, result.limits.MaximumCompletionQueueDepth / 2)));
            var initiatorDepth = Math.Min(128u, Math.Min(result.limits.MaximumInitiatorQueueDepth, result.limits.MaximumCompletionQueueDepth - result.MaximumReceiveQueueDepth));
            result.initiatorSlots.Dispose(); result.initiatorSlots = new((int)initiatorDepth, (int)initiatorDepth);
            var maximumBuffer = Math.Min(result.limits.MaximumTransferLength, (ulong)result.limits.MaximumRegistrationSize);
            result.MaximumSendSize = (int)Math.Min((ulong)options.PreferredSendSize, maximumBuffer);
            result.receiveSize = (int)Math.Min((ulong)options.MaximumReceiveSize, maximumBuffer);
            if (result.MaximumSendSize < 128 || result.receiveSize < 128) throw new IOException("The ND2 device cannot register an MS-SMBD minimum buffer.");
            result.file = RdmaNativeNetworkDirect.CreateFile(result.adapter);
            result.completionQueue = RdmaNativeNetworkDirect.CreateCq(result.adapter, result.file, result.MaximumReceiveQueueDepth + initiatorDepth);
            result.queuePair = RdmaNativeNetworkDirect.CreateQp(result.adapter, result.completionQueue, result.MaximumReceiveQueueDepth, initiatorDepth);
            result.connector = RdmaNativeNetworkDirect.CreateObject(result.adapter, result.file, RdmaNativeNetworkDirect.ConnectorId, 12);
            RdmaNativeNetworkDirect.Bind(result.connector, Sockaddr(local));
            await RdmaNativeOperation.RunAsync(result.connector, overlapped => RdmaNativeNetworkDirect.Connect(result.connector, result.queuePair, Sockaddr(remote),
                Math.Min(1u, result.limits.MaximumInboundReadLimit), Math.Min(1u, result.limits.MaximumOutboundReadLimit), overlapped), cancellationToken).ConfigureAwait(false);
            await RdmaNativeOperation.RunAsync(result.connector, overlapped => RdmaNativeNetworkDirect.CompleteConnect(result.connector, overlapped), cancellationToken).ConfigureAwait(false);
            result.LocalEndPoint = ParseSockaddr(RdmaNativeNetworkDirect.Address(result.connector, false));
            result.RemoteEndPoint = ParseSockaddr(RdmaNativeNetworkDirect.Address(result.connector, true));
            result.poller = Task.Run(result.PollAsync);
            return result;
        }
        catch { await result.DisposeAsync().ConfigureAwait(false); throw; }
    }

    /// <summary>投递真实的已注册 RECEIVE 工作请求，不超过硬件队列容量。</summary>
    public async ValueTask<int> PostReceivesAsync(int count, int bufferSize, CancellationToken cancellationToken = default)
    {
        if (count < 0 || bufferSize < 1 || bufferSize > MaximumReceiveSize) throw new ArgumentOutOfRangeException(nameof(count));
        ThrowIfClosed();
        var posted = 0;
        for (; posted < count; posted++)
        {
            lock (nativeGate)
            {
                ThrowIfClosed();
                if (receiveOutstanding >= MaximumReceiveQueueDepth) break;
                receiveOutstanding++;
            }
            Region? region = null;
            try
            {
                region = await Region.CreateAsync(this, new byte[bufferSize], 1, cancellationToken).ConfigureAwait(false);
                var work = new Work(NextCookie(), region, true);
                lock (nativeGate)
                {
                    ThrowIfClosed(); pending.TryAdd(work.Cookie, work);
                    var status = RdmaNativeNetworkDirect.Post(queuePair, work.Cookie, region.ScatterGather, true);
                    if (status < 0) { pending.TryRemove(work.Cookie, out _); RdmaNativeNetworkDirect.Check(status, "IND2QueuePair.Receive"); }
                }
            }
            catch
            {
                Interlocked.Decrement(ref receiveOutstanding);
                if (region is not null) await region.DisposeAsync().ConfigureAwait(false);
                throw;
            }
        }
        return posted;
    }

    /// <summary>提交原生 SEND，并保持其已注册内存固定，直到完成。</summary>
    public async ValueTask SendAsync(ReadOnlyMemory<byte> message, uint? invalidateRemoteToken = null, CancellationToken cancellationToken = default)
    {
        ThrowIfClosed();
        cancellationToken.ThrowIfCancellationRequested();
        if (message.IsEmpty || message.Length > MaximumSendSize) throw new ArgumentOutOfRangeException(nameof(message));
        // ND2 基础队列对接口没有 SEND_WITH_INVALIDATE 入口。MS-SMBD 明确允许忽略
        // 这一可选令牌；注册对象释放仍是确认远程访问结束的权威栅栏。
        await using var region = await Region.CreateAsync(this, message.ToArray(), 0, cancellationToken).ConfigureAwait(false);
        await SubmitAsync(region, null, false, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>返回一个已复制的完成结果，不向外暴露提供程序注册的接收缓冲区。</summary>
    public async ValueTask<SmbRdmaReceive> ReceiveAsync(CancellationToken cancellationToken = default)
    {
        try
        {
            var result = await receives.Reader.ReadAsync(cancellationToken).ConfigureAwait(false);
            Interlocked.Decrement(ref receiveOutstanding);
            return result;
        }
        catch (ChannelClosedException) { ThrowIfClosed(); throw new IOException("The native RDMA receive queue closed."); }
    }

    /// <summary>根据设备长度限制注册一个或多个片段，仅授予请求的远程权限。</summary>
    public async ValueTask<SmbRdmaMemoryRegistration> RegisterMemoryAsync(Memory<byte> buffer, SmbRdmaMemoryAccess access, CancellationToken cancellationToken = default)
    {
        ThrowIfClosed();
        cancellationToken.ThrowIfCancellationRequested();
        if (buffer.IsEmpty || access == 0 || (access & ~(SmbRdmaMemoryAccess.RemoteRead | SmbRdmaMemoryAccess.RemoteWrite)) != 0)
            throw new ArgumentException("Invalid RDMA buffer or access mask.");
        if ((access & SmbRdmaMemoryAccess.RemoteRead) != 0 && !SupportsRemoteRead)
            throw new NotSupportedException("The ND2 connection has no inbound RDMA read resources.");
        var segments = new List<Region>();
        uint flags = (access & SmbRdmaMemoryAccess.RemoteRead) != 0 ? 2u : 0;
        if ((access & SmbRdmaMemoryAccess.RemoteWrite) != 0) flags |= 5;
        try
        {
            for (var offset = 0; offset < buffer.Length;)
            {
                var length = (int)Math.Min((ulong)(buffer.Length - offset), (ulong)limits.MaximumRegistrationSize);
                segments.Add(await Region.CreateAsync(this, buffer.Slice(offset, length), flags, cancellationToken).ConfigureAwait(false));
                offset += length;
            }
            return new Registration(segments.ToArray());
        }
        catch { foreach (var segment in segments) await segment.DisposeAsync().ConfigureAwait(false); throw; }
    }

    /// <summary>向已固定的本地读取目标区域发出原生 RDMA READ。</summary>
    public async ValueTask ReadAsync(Memory<byte> destination, SmbRdmaBufferDescriptor source, CancellationToken cancellationToken = default)
    {
        ThrowIfClosed();
        cancellationToken.ThrowIfCancellationRequested();
        if (limits.MaximumReadSge == 0 || limits.MaximumOutboundReadLimit == 0) throw new NotSupportedException("The ND2 adapter does not support outbound RDMA reads.");
        ValidateDirect(destination.Length, source);
        for (var offset = 0; offset < destination.Length;)
        {
            var count = (int)Math.Min((ulong)(destination.Length - offset), Math.Min(limits.MaximumTransferLength, (ulong)limits.MaximumRegistrationSize));
            await using var region = await Region.CreateAsync(this, destination.Slice(offset, count), 1 | 8, cancellationToken).ConfigureAwait(false);
            await SubmitAsync(region, source with { Offset = source.Offset + (uint)offset, Length = (uint)count }, false, cancellationToken).ConfigureAwait(false);
            offset += count;
        }
    }

    /// <summary>从已固定、已注册的源缓冲区发出原生 RDMA WRITE。</summary>
    public async ValueTask WriteAsync(ReadOnlyMemory<byte> source, SmbRdmaBufferDescriptor destination, CancellationToken cancellationToken = default)
    {
        ThrowIfClosed(); cancellationToken.ThrowIfCancellationRequested(); ValidateDirect(source.Length, destination);
        for (var offset = 0; offset < source.Length;)
        {
            var count = (int)Math.Min((ulong)(source.Length - offset), Math.Min(limits.MaximumTransferLength, (ulong)limits.MaximumRegistrationSize));
            await using var region = await Region.CreateAsync(this, source.Slice(offset, count).ToArray(), 0, cancellationToken).ConfigureAwait(false);
            await SubmitAsync(region, destination with { Offset = destination.Offset + (uint)offset, Length = (uint)count }, true, cancellationToken).ConfigureAwait(false);
            offset += count;
        }
    }

    /// <summary>投递工作前校验描述符范围；超出硬件限制的请求由调用处分段。</summary>
    private void ValidateDirect(int length, SmbRdmaBufferDescriptor descriptor)
    {
        if (length <= 0 || length != descriptor.Length || descriptor.Offset > ulong.MaxValue - descriptor.Length)
            throw new ArgumentOutOfRangeException(nameof(length));
    }

    /// <summary>投递发起方请求；即使调用方取消，也先收取其完成结果。</summary>
    private async Task SubmitAsync(Region region, SmbRdmaBufferDescriptor? remote, bool write, CancellationToken cancellationToken)
    {
        await initiatorSlots.WaitAsync(cancellationToken).ConfigureAwait(false);
        var work = new Work(NextCookie(), region, false);
        try
        {
            lock (nativeGate)
            {
                ThrowIfClosed(); pending.TryAdd(work.Cookie, work);
                var status = remote is { } descriptor ? RdmaNativeNetworkDirect.PostDirect(queuePair, work.Cookie, region.ScatterGather, descriptor, write)
                    : RdmaNativeNetworkDirect.Post(queuePair, work.Cookie, region.ScatterGather, false);
                if (status < 0) { pending.TryRemove(work.Cookie, out _); RdmaNativeNetworkDirect.Check(status, "IND2QueuePair initiator request"); }
            }
            try { await work.Completion.Task.WaitAsync(cancellationToken).ConfigureAwait(false); }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                Abort();
                // 清空完成结果是允许 Region.Dispose 解除内存固定的栅栏。
                try { await work.Completion.Task.ConfigureAwait(false); } catch (IOException) { }
                throw;
            }
        }
        finally { initiatorSlots.Release(); }
    }

    /// <summary>分发真实完成队列结果，并注销已经完成的接收缓冲区。</summary>
    private async Task PollAsync()
    {
        var batch = new RdmaNativeNetworkDirect.Result[32];
        try
        {
            while (true)
            {
                uint count;
                lock (nativeGate) count = completionQueue == 0 ? 0 : RdmaNativeNetworkDirect.Results(completionQueue, batch);
                if (count > batch.Length) throw new IOException("The ND2 provider overran a completion-result array.");
                for (var i = 0; i < count; i++)
                {
                    var result = batch[i];
                    if (!pending.TryRemove(result.RequestContext, out var work)) throw new IOException("An ND2 completion has an unknown request cookie.");
                    if (work.Receive)
                    {
                        try
                        {
                            if (result.Status < 0)
                            {
                                Interlocked.Decrement(ref receiveOutstanding);
                                if (Volatile.Read(ref aborted) == 0) RdmaNativeNetworkDirect.Check(result.Status, "ND2 receive completion");
                            }
                            else
                            {
                                if (result.BytesTransferred > work.Region.Buffer.Length) throw new IOException("The ND2 provider returned an oversized receive.");
                                var copy = work.Region.Buffer.Slice(0, (int)result.BytesTransferred).ToArray();
                                if (!receives.Writer.TryWrite(new(copy))) Interlocked.Decrement(ref receiveOutstanding);
                            }
                        }
                        finally { await work.Region.DisposeAsync().ConfigureAwait(false); }
                    }
                    else
                    {
                        if (result.Status < 0) work.Completion.TrySetException(new IOException($"ND2 work completion failed: 0x{(uint)result.Status:X8}."));
                        else work.Completion.TrySetResult();
                    }
                }
                if (Volatile.Read(ref aborted) != 0 && pending.IsEmpty) { drained.TrySetResult(); return; }
                if (count == 0) await Task.Delay(1).ConfigureAwait(false);
            }
        }
        catch (Exception ex)
        {
            Abort(ex);
            // 完成结果流失败时，先销毁队列对，再释放任何未完成缓冲区。
            lock (nativeGate) { RdmaNativeNetworkDirect.Release(queuePair); queuePair = 0; }
            foreach (var item in pending)
                if (pending.TryRemove(item.Key, out var work)) work.Completion.TrySetException(ex);
            drained.TrySetResult();
        }
    }

    /// <summary>在指针可表示的范围内分配原生请求标识。</summary>
    private nint NextCookie() => checked((nint)Interlocked.Increment(ref sequence));
    /// <summary>提供显式中止，并保留原生缓冲区，直到完成队列收取结束。</summary>
    public void Abort() => Abort(new IOException("The native RDMA endpoint was aborted."));
    /// <summary>恰好清空一次队列对，并用原始失败原因唤醒上层接收。</summary>
    private void Abort(Exception error)
    {
        Interlocked.CompareExchange(ref failure, error, null);
        if (Interlocked.Exchange(ref aborted, 1) != 0) return;
        abortSignal.Cancel();
        receives.Writer.TryComplete(error);
        lock (nativeGate)
        {
            if (queuePair != 0)
            {
                try { RdmaNativeNetworkDirect.Flush(queuePair); }
                catch (IOException)
                {
                    RdmaNativeNetworkDirect.Release(queuePair); queuePair = 0;
                    foreach (var item in pending)
                        if (pending.TryRemove(item.Key, out var work)) work.Completion.TrySetException(error);
                }
            }
            if (pending.IsEmpty) drained.TrySetResult();
        }
    }
    /// <summary>开始取消、失败或释放后，阻止新工作进入。</summary>
    private void ThrowIfClosed()
    {
        if (Volatile.Read(ref aborted) != 0 || Volatile.Read(ref disposed) != 0)
            throw new IOException("The native RDMA endpoint is closed.", failure);
    }

    /// <summary>先清空并收取完成结果，再释放队列对、内存、COM 引用、DLL 和 Winsock。</summary>
    public ValueTask DisposeAsync()
    {
        lock (disposalGate) return new(disposalTask ??= DisposeCoreAsync());
    }

    /// <summary>等待队列对清空、注册内存注销和原生引用销毁后，才完成共享释放任务。</summary>
    private async Task DisposeCoreAsync()
    {
        Volatile.Write(ref disposed, 1);
        Abort(new ObjectDisposedException(nameof(RdmaNativeWindowsEndpoint)));
        await drained.Task.ConfigureAwait(false);
        await poller.ConfigureAwait(false);
        lock (nativeGate) { RdmaNativeNetworkDirect.Release(queuePair); queuePair = 0; }
        foreach (var region in regions.Keys) await region.ReleaseAfterFenceAsync().ConfigureAwait(false);
        lock (nativeGate)
        {
            RdmaNativeNetworkDirect.Release(connector); connector = 0;
            RdmaNativeNetworkDirect.Release(completionQueue); completionQueue = 0;
            if (file != 0) { _ = RdmaNativeNetworkDirect.CloseHandle(file); file = 0; }
            RdmaNativeNetworkDirect.Release(adapter); adapter = 0;
            if (module != 0) { NativeLibrary.Free(module); module = 0; }
        }
        winsock.Dispose();
    }

    /// <summary>复制 BCL 端点序列化器生成的 Windows sockaddr 字节。</summary>
    private static byte[] Sockaddr(IPEndPoint address)
    {
        var serialized = address.Serialize(); var bytes = new byte[serialized.Size];
        for (var i = 0; i < bytes.Length; i++) bytes[i] = serialized[i];
        return bytes;
    }
    /// <summary>将原生 AF_INET 或 AF_INET6 地址转换为端点值。</summary>
    private static IPEndPoint ParseSockaddr(byte[] bytes)
    {
        var family = (AddressFamily)(bytes[0] | (bytes[1] << 8));
        if (family is not (AddressFamily.InterNetwork or AddressFamily.InterNetworkV6)) throw new IOException("Unsupported native RDMA address family.");
        var address = new SocketAddress(family, bytes.Length);
        for (var i = 0; i < bytes.Length; i++) address[i] = bytes[i];
        return (IPEndPoint)new IPEndPoint(family == AddressFamily.InterNetwork ? IPAddress.Any : IPAddress.IPv6Any, 0).Create(address);
    }

    /// <summary>拥有操作标识、对应接收区域以及完成状态。</summary>
    private sealed class Work
    {
        /// <summary>原生完成队列返回的不透明值。</summary>
        internal readonly nint Cookie;
        /// <summary>必须在完成前保持注册的内存。</summary>
        internal readonly Region Region;
        /// <summary>为真时，完成处理拥有并负责释放对应接收区域。</summary>
        internal readonly bool Receive;
        /// <summary>硬件完成栅栏生效后，才完成发起方任务。</summary>
        internal readonly TaskCompletionSource Completion = new(TaskCreationOptions.RunContinuationsAsynchronously);
        /// <summary>投递到队列对前先创建工作状态。</summary>
        internal Work(nint cookie, Region region, bool receive) { Cookie = cookie; Region = region; Receive = receive; }
    }

    /// <summary>已固定的原生内存区域，失败时延迟解除固定以保护内存安全。</summary>
    private sealed class Region : IAsyncDisposable
    {
        /// <summary>端点保持适配器和提供程序 DLL 有效。</summary>
        private readonly RdmaNativeWindowsEndpoint owner;
        /// <summary>串行保护注销与队列对销毁后的强制清理。</summary>
        private readonly object gate = new();
        /// <summary>拥有原生内存区域接口。</summary>
        private nint pointer;
        /// <summary>防止已注册的托管缓冲区被移动。</summary>
        private MemoryHandle pin;
        /// <summary>唯一的异步注销任务。</summary>
        private Task? disposal;
        /// <summary>记录注册是否成功完成。</summary>
        private bool registered;
        /// <summary>等待初始化栅栏，防止端点释放正在注册的原生对象。</summary>
        private readonly TaskCompletionSource initialized = new(TaskCreationOptions.RunContinuationsAsynchronously);
        /// <summary>注册对象代表的托管内存范围。</summary>
        internal Memory<byte> Buffer { get; }
        /// <summary>原生本地散布与聚集元素。</summary>
        internal RdmaNativeNetworkDirect.Sge ScatterGather { get; private set; }
        /// <summary>包含远程提供程序令牌、可向对端公布的描述符。</summary>
        internal SmbRdmaBufferDescriptor Descriptor { get; private set; }
        /// <summary>尝试原生注册前，先固定托管缓冲区。</summary>
        private Region(RdmaNativeWindowsEndpoint owner, Memory<byte> buffer) { this.owner = owner; Buffer = buffer; pin = buffer.Pin(); }

        /// <summary>创建、注册并跟踪内存区域；取消时释放已创建的部分资源。</summary>
        internal static async Task<Region> CreateAsync(RdmaNativeWindowsEndpoint owner, Memory<byte> buffer, uint flags, CancellationToken cancellationToken)
        {
            var region = new Region(owner, buffer);
            using var linked = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, owner.abortSignal.Token);
            try
            {
                lock (owner.nativeGate)
                {
                    owner.ThrowIfClosed();
                    owner.regions.TryAdd(region, 0);
                    region.pointer = RdmaNativeNetworkDirect.CreateObject(owner.adapter, owner.file, RdmaNativeNetworkDirect.MemoryRegionId, 7);
                }
                var address = RdmaNativeNetworkDirect.PinnedPointer(region.pin);
                await RdmaNativeOperation.RunAsync(region.pointer, overlapped => RdmaNativeNetworkDirect.Register(region.pointer, address, (nuint)buffer.Length, flags, overlapped), linked.Token).ConfigureAwait(false);
                region.registered = true;
                region.ScatterGather = new() { Buffer = address, Length = (uint)buffer.Length, Token = RdmaNativeNetworkDirect.Token(region.pointer, false) };
                region.Descriptor = new(unchecked((ulong)address), RdmaNativeNetworkDirect.Token(region.pointer, true), (uint)buffer.Length);
                lock (owner.nativeGate) owner.ThrowIfClosed();
                return region;
            }
            catch { region.initialized.TrySetResult(); await region.DisposeAsync().ConfigureAwait(false); throw; }
            finally { region.initialized.TrySetResult(); }
        }

        /// <summary>只开始一次注销；提供程序报告栅栏失败时，内存继续保持固定。</summary>
        public ValueTask DisposeAsync()
        {
            lock (gate) return new(disposal ??= DisposeCoreAsync());
        }
        /// <summary>注销成功后才解除固定；原生操作失败时延迟解除固定。</summary>
        private async Task DisposeCoreAsync()
        {
            await initialized.Task.ConfigureAwait(false);
            if (pointer == 0) { pin.Dispose(); owner.regions.TryRemove(this, out _); return; }
            if (registered)
            {
                try { await RdmaNativeOperation.RunAsync(pointer, overlapped => RdmaNativeNetworkDirect.Deregister(pointer, overlapped), CancellationToken.None).ConfigureAwait(false); }
                catch (Exception ex) { owner.Abort(ex); owner.regions.TryAdd(this, 0); throw; }
            }
            Release();
        }
        /// <summary>队列对销毁后，即使注销曾失败，也释放延迟保留的区域。</summary>
        internal async Task ReleaseAfterFenceAsync()
        {
            try { await DisposeAsync().ConfigureAwait(false); }
            catch (Exception) { lock (gate) Release(); }
        }
        /// <summary>只有调用方确认栅栏已生效后，才释放原生状态并解除固定。</summary>
        private void Release()
        {
            var value = Interlocked.Exchange(ref pointer, 0);
            if (value != 0) RdmaNativeNetworkDirect.Release(value);
            pin.Dispose(); owner.regions.TryRemove(this, out _);
        }
    }

    /// <summary>拥有可由对端访问的注册片段。</summary>
    private sealed class Registration : SmbRdmaMemoryRegistration
    {
        /// <summary>保留原生片段，直到释放过程完成远程访问栅栏。</summary>
        private Region[]? segments;
        /// <summary>向对端公布的不可变描述符。</summary>
        private readonly IReadOnlyList<SmbRdmaBufferDescriptor> descriptors;
        /// <summary>全部片段注册成功后，再复制所有描述符。</summary>
        internal Registration(Region[] segments) { this.segments = segments; descriptors = Array.AsReadOnly(segments.Select(s => s.Descriptor).ToArray()); }
        /// <summary>按缓冲区顺序排列的远程可访问片段。</summary>
        public override IReadOnlyList<SmbRdmaBufferDescriptor> Descriptors => descriptors;
        /// <summary>注销每个片段；某个片段失败后仍继续清理其他片段。</summary>
        public override async ValueTask DisposeAsync()
        {
            var values = Interlocked.Exchange(ref segments, null); if (values is null) return;
            List<Exception>? errors = null;
            foreach (var region in values)
                try { await region.DisposeAsync().ConfigureAwait(false); } catch (Exception ex) { (errors ??= []).Add(ex); }
            if (errors is not null) throw new AggregateException("RDMA buffer deregistration failed.", errors);
        }
    }
}

/// <summary>持有 OVERLAPPED 内存及其事件，直到收取原生完成或取消结果。</summary>
internal static class RdmaNativeOperation
{
    /// <summary>执行一次 ND2 异步操作；取消期间不提前释放其存储。</summary>
    internal static async Task RunAsync(nint nativeObject, Func<nint, int> start, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var @event = RdmaNativeNetworkDirect.CreateEvent(0, 0, 0, 0);
        if (@event == 0) throw new Win32Exception(Marshal.GetLastPInvokeError(), "Could not allocate an ND2 completion event.");
        var overlapped = RdmaNativeNetworkDirect.AllocateOverlapped(@event);
        try
        {
            var status = start(overlapped);
            if (status != RdmaNativeNetworkDirect.Pending) { RdmaNativeNetworkDirect.Check(status, "ND2 overlapped operation"); return; }
            try
            {
                while (true)
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    status = RdmaNativeNetworkDirect.OverlappedResult(nativeObject, overlapped, false);
                    if (status is not (RdmaNativeNetworkDirect.Pending or RdmaNativeNetworkDirect.Incomplete)) break;
                    await Task.Delay(1, cancellationToken).ConfigureAwait(false);
                }
                RdmaNativeNetworkDirect.Check(status, "ND2 overlapped completion");
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                RdmaNativeNetworkDirect.Cancel(nativeObject);
                // 取消不会转移 OVERLAPPED 的所有权。通过工作线程收取完成结果，确保
                // 原生代码之后不能访问已释放的事件、OVERLAPPED 或已解除固定的注册数据。
                _ = await Task.Run(() => RdmaNativeNetworkDirect.OverlappedResult(nativeObject, overlapped, true), CancellationToken.None).ConfigureAwait(false);
                throw;
            }
        }
        finally { RdmaNativeNetworkDirect.FreeOverlapped(overlapped); _ = RdmaNativeNetworkDirect.CloseHandle(@event); }
    }
}