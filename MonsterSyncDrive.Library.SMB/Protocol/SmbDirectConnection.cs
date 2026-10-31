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
using MonsterSyncDrive.Library.SMB.Transport;
using System.Net;
using System.Threading.Channels;

namespace MonsterSyncDrive.Library.SMB.Protocol;

/// <summary>通过 MS-SMBD 接收并重组的上层消息。</summary>
/// <param name="Data">一条重组消息的独立字节；仅独立失效事件允许为空。</param>
/// <param name="InvalidatedToken">接收本条消息时失效的可选本地令牌。</param>
public sealed record SmbDirectMessage(ReadOnlyMemory<byte> Data, uint? InvalidatedToken);

/// <summary>
/// 通过提供程序的可靠 RDMA 队列对传输 MS-SMBD 1.0 消息。本类拥有
/// 端点，并负责协商、已投递接收的信用流控、分片和保活。
/// </summary>
public sealed class SmbDirectConnection : IAsyncDisposable
{
    /// <summary>拥有可靠的原生 RDMA 队列对。</summary>
    private readonly ISmbRdmaEndpoint endpoint;
    /// <summary>经过校验的不可变限制与空闲策略。</summary>
    private readonly SmbDirectOptions options;
    /// <summary>连接失败或释放后取消后台工作。</summary>
    private readonly CancellationTokenSource lifetime = new();
    /// <summary>防止不同上层消息的分片相互交错。</summary>
    private readonly SemaphoreSlim messageWriter = new(1, 1);
    /// <summary>串行发送 SEND 请求，包括信用和保活消息。</summary>
    private readonly SemaphoreSlim wireWriter = new(1, 1);
    /// <summary>串行补充原生接收，并维护队列容量计数。</summary>
    private readonly SemaphoreSlim posting = new(1, 1);
    /// <summary>保护发送信用、接收信用和已投递接收计数。</summary>
    private readonly object stateGate = new();
    /// <summary>将应用背压队列限制为八条完整消息。</summary>
    private readonly Channel<SmbDirectMessage> messages = Channel.CreateBounded<SmbDirectMessage>(new BoundedChannelOptions(8)
    {
        SingleReader = false,
        SingleWriter = true,
        FullMode = BoundedChannelFullMode.Wait
    });
    /// <summary>授予信用或投递接收改变可用资源时，唤醒延迟发送。</summary>
    private TaskCompletionSource creditChanged = Signal();
    /// <summary>运行唯一的原生接收及完成结果消费者。</summary>
    private readonly Task receiveTask;
    /// <summary>运行可选的空闲探测策略。</summary>
    private readonly Task keepaliveTask;
    /// <summary>独立于接收循环，跟踪已排队的信用或保活响应。</summary>
    private Task controlTask = Task.CompletedTask;
    /// <summary>统计已投递或已完成、但本循环尚未消费的原生接收缓冲区。</summary>
    private int postedReceives;
    /// <summary>统计已经向对端公布、尚未消耗的已投递接收。</summary>
    private int receiveCredits;
    /// <summary>统计对端当前允许的 SEND 工作请求数量。</summary>
    private int sendCredits;
    /// <summary>对端最近一次请求的接收信用总数。</summary>
    private int peerCreditTarget;
    /// <summary>合并立即发送控制消息的请求。</summary>
    private int controlRequested;
    /// <summary>防止多个控制消息工作任务并行运行。</summary>
    private int controlRunning;
    /// <summary>最近收到有效消息的单调时间戳。</summary>
    private long lastReceive = Environment.TickCount64;
    /// <summary>探测发送的单调时间戳；没有未完成探测时为零。</summary>
    private long probeStarted;
    /// <summary>为后续操作保留首次失败原因。</summary>
    private Exception? failure;
    /// <summary>确保异步释放只执行一次。</summary>
    private int disposed;
    /// <summary>保护异步释放任务的创建，确保所有并发调用者都等待同一个硬件栅栏。</summary>
    private readonly object disposeGate = new();
    /// <summary>共享的完整释放任务；非空不代表设备清理已经完成。</summary>
    private Task? disposal;

    /// <summary>原生提供程序实际选定的本地 RDMA 端点。</summary>
    public EndPoint? LocalEndPoint => endpoint.LocalEndPoint;
    /// <summary>原生提供程序实际选定的远程 RDMA 端点。</summary>
    public EndPoint? RemoteEndPoint => endpoint.RemoteEndPoint;
    /// <summary>DATA_TRANSFER 帧的最大字节数，包含 20 或 24 字节的消息头。</summary>
    public int MaximumSendSize
    {
        get;
    }
    /// <summary>单个传入 DATA_TRANSFER 帧允许的最大字节数。</summary>
    public int MaximumReceiveSize
    {
        get;
    }
    /// <summary>与对端协商的完整上层消息最大长度。</summary>
    public int MaximumFragmentedSendSize
    {
        get;
    }
    /// <summary>本地公布的上层消息重组最大长度。</summary>
    public int MaximumFragmentedReceiveSize
    {
        get;
    }
    /// <summary>协商得到的逻辑 RDMA 读写最大长度；零表示禁用直接放置。</summary>
    public int MaximumReadWriteSize
    {
        get;
    }
    /// <summary>是否允许自动直接放置；还必须由 SMB 会话和文件操作检查签名、加密与长度边界。</summary>
    public bool DirectPlacementEnabled => options.EnableDirectPlacement && MaximumReadWriteSize > 0;
    /// <summary>只有大于该字节数的数据块才进入自动内存注册路径。</summary>
    public int DirectPlacementThreshold => options.DirectPlacementThreshold;
    /// <summary>底层设备是否允许对端读取本地注册缓冲区。</summary>
    public bool SupportsRemoteRead => endpoint.SupportsRemoteRead;
    /// <summary>底层设备是否允许对端写入本地注册缓冲区。</summary>
    public bool SupportsRemoteWrite => endpoint.SupportsRemoteWrite;
    /// <summary>消息连接是否仍可执行操作。</summary>
    public bool IsConnected => Volatile.Read(ref failure) is null && Volatile.Read(ref disposed) == 0;

    /// <summary>只有原生接收和协商都成功后才创建已建立连接状态。</summary>
    private SmbDirectConnection(ISmbRdmaEndpoint endpoint, SmbDirectOptions options, SmbDirectNegotiation peer, int posted)
    {
        this.endpoint = endpoint;
        this.options = options;
        postedReceives = posted;
        sendCredits = peer.CreditsGranted;
        peerCreditTarget = peer.CreditsRequested;
        MaximumSendSize = Math.Min(options.PreferredSendSize, Math.Min(peer.MaximumReceiveSize, endpoint.MaximumSendSize));
        MaximumReceiveSize = Math.Max(128, Math.Min(options.MaximumReceiveSize, peer.PreferredSendSize));
        MaximumFragmentedSendSize = peer.MaximumFragmentedSize;
        MaximumFragmentedReceiveSize = options.MaximumFragmentedReceiveSize;
        MaximumReadWriteSize = Math.Min(options.MaximumReadWriteSize, peer.MaximumReadWriteSize);
        receiveTask = ReceiveLoopAsync();
        keepaliveTask = KeepaliveLoopAsync();
    }

    /// <summary>连接 RDMA 端点，并执行 MS-SMBD 协商交换。</summary>
    public static async Task<SmbDirectConnection> ConnectAsync(string host, int port, SmbDirectOptions options,
        int maximumMessageSize = 8 * 1024 * 1024, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(host);
        ArgumentOutOfRangeException.ThrowIfLessThan(port, 1);
        ArgumentOutOfRangeException.ThrowIfGreaterThan(port, 65535);
        ArgumentNullException.ThrowIfNull(options);
        options = options.Validate();
        if (maximumMessageSize < 131072)
            throw new ArgumentOutOfRangeException(nameof(maximumMessageSize), "MS-SMBD requires at least 128 KiB fragmented receive capacity.");
        options = options with
        {
            MaximumFragmentedReceiveSize = Math.Min(options.MaximumFragmentedReceiveSize, maximumMessageSize)
        };
        ISmbRdmaProvider provider = options.Provider ?? (SmbNetworkDirectProvider.IsSupported ? new SmbNetworkDirectProvider() : throw new PlatformNotSupportedException(
            "The built-in SMB Direct provider requires 64-bit Windows. Configure a native ISmbRdmaProvider for this platform; TCP fallback is not performed."));
        ISmbRdmaEndpoint? endpoint = await provider.ConnectAsync(new(host, port, options.LocalEndPoint, options.PreferredSendSize,
            options.MaximumReceiveSize, options.MaximumReceiveCredits), cancellationToken).ConfigureAwait(false);
        if (endpoint is null)
            throw new SmbProtocolException("The RDMA provider returned no endpoint.");
        SmbDirectConnection? connection = null;
        try
        {
            if (endpoint.MaximumReceiveQueueDepth == 0 || endpoint.MaximumSendSize < 128 || endpoint.MaximumReceiveSize < 128)
                throw new SmbProtocolException("The RDMA provider cannot satisfy MS-SMBD minimum limits.");
            options = options with
            {
                PreferredSendSize = Math.Min(options.PreferredSendSize, endpoint.MaximumSendSize),
                MaximumReceiveSize = Math.Min(options.MaximumReceiveSize, endpoint.MaximumReceiveSize),
                MaximumReceiveCredits = Math.Min(options.MaximumReceiveCredits, endpoint.MaximumReceiveQueueDepth)
            };
            int posted = await endpoint.PostReceivesAsync(options.MaximumReceiveCredits, options.MaximumReceiveSize, cancellationToken).ConfigureAwait(false);
            if (posted <= 0 || posted > options.MaximumReceiveCredits)
                throw new SmbProtocolException("The RDMA provider did not post valid negotiation receives.");
            await endpoint.SendAsync(SmbDirectWire.NegotiateRequest(options), cancellationToken: cancellationToken).ConfigureAwait(false);
            SmbDirectNegotiation peer;
            using (SmbRdmaReceive response = await endpoint.ReceiveAsync(cancellationToken).ConfigureAwait(false))
                peer = SmbDirectWire.NegotiateResponse(response.Data.Span, options);
            posted--;
            ushort desired = Math.Min(peer.CreditsRequested, options.MaximumReceiveCredits);
            int additional = await endpoint.PostReceivesAsync(Math.Max(0, desired - posted), options.MaximumReceiveSize, cancellationToken).ConfigureAwait(false);
            if (additional < 0 || additional > Math.Max(0, desired - posted))
                throw new SmbProtocolException("The RDMA provider overposted negotiation receives.");
            posted += additional;
            if (posted == 0)
                throw new SmbProtocolException("No RDMA receive remains after negotiation.");
            connection = new SmbDirectConnection(endpoint, options, peer, posted);
            // 发起方必须先公布已投递接收，再发送普通上层流量。
            await connection.SendFragmentAsync(ReadOnlyMemory<byte>.Empty, 0, null, false, cancellationToken).ConfigureAwait(false);
            return connection;
        }
        catch
        {
            if (connection is not null)
                await connection.DisposeAsync().ConfigureAwait(false);
            else
            {
                endpoint.Abort();
                await endpoint.DisposeAsync().ConfigureAwait(false);
            }
            throw;
        }
    }

    /// <summary>发送一条完整上层消息，并保持分片顺序。</summary>
    public async ValueTask SendAsync(ReadOnlyMemory<byte> message, uint? invalidateRemoteToken = null, CancellationToken cancellationToken = default)
    {
        ThrowIfClosed();
        if (message.Length > MaximumFragmentedSendSize)
            throw new ArgumentOutOfRangeException(nameof(message));
        using var linked = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, lifetime.Token);
        await messageWriter.WaitAsync(linked.Token).ConfigureAwait(false);
        bool sent = false;
        try
        {
            if (message.IsEmpty)
            {
                await SendFragmentAsync(message, 0, invalidateRemoteToken, false, linked.Token).ConfigureAwait(false);
                return;
            }
            int offset = 0;
            while (offset < message.Length)
            {
                int count = Math.Min(MaximumSendSize - SmbDirectWire.PayloadOffset, message.Length - offset);
                await SendFragmentAsync(message.Slice(offset, count), (uint)(message.Length - offset - count),
                    offset + count == message.Length ? invalidateRemoteToken : null, false, linked.Token).ConfigureAwait(false);
                sent = true;
                offset += count;
            }
        }
        catch (Exception ex)
        {
            if (sent)
                Abort(ex);
            throw;
        }
        finally
        {
            _ = messageWriter.Release();
        }
    }

    /// <summary>接收一条完整消息或失效事件，不向上层暴露原生接收缓冲区租约。</summary>
    /// <param name="cancellationToken">取消当前调用方的等待，不丢弃连接中已经排队的消息。</param>
    /// <returns>独立持有的重组字节，以及可选的已失效内存令牌。</returns>
    public async ValueTask<SmbDirectMessage> ReceiveAsync(CancellationToken cancellationToken = default)
    {
        ThrowIfClosed();
        try
        {
            return await messages.Reader.ReadAsync(cancellationToken).ConfigureAwait(false);
        }
        catch (ChannelClosedException)
        {
            ThrowIfClosed();
            throw new IOException("The SMB Direct receive queue was closed.");
        }
    }

    /// <summary>注册内存，并校验提供程序返回的片段是否按序覆盖完整缓冲区。</summary>
    public async ValueTask<SmbRdmaMemoryRegistration> RegisterBufferAsync(Memory<byte> buffer, SmbRdmaMemoryAccess access,
        CancellationToken cancellationToken = default)
    {
        ThrowIfClosed();
        if (buffer.IsEmpty)
            throw new ArgumentException("A registered buffer cannot be empty.", nameof(buffer));
        if (access == 0 || (access & ~(SmbRdmaMemoryAccess.RemoteRead | SmbRdmaMemoryAccess.RemoteWrite)) != 0)
            throw new ArgumentOutOfRangeException(nameof(access));
        using var linked = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, lifetime.Token);
        SmbRdmaMemoryRegistration? registration = await endpoint.RegisterMemoryAsync(buffer, access, linked.Token).ConfigureAwait(false);
        if (registration is null)
            throw new SmbProtocolException("The RDMA provider returned no memory registration.");
        try
        {
            SmbRdmaBufferDescriptor[] descriptors = registration.Descriptors.ToArray();
            _ = SmbRdmaBufferDescriptor.Encode(descriptors);
            return descriptors.Sum(descriptor => descriptor.Length) != buffer.Length
                ? throw new SmbProtocolException("An RDMA registration does not cover the complete buffer.")
                : (SmbRdmaMemoryRegistration)new Registration(registration, descriptors);
        }
        catch
        {
            await registration.DisposeAsync().ConfigureAwait(false);
            throw;
        }
    }

    /// <summary>读取远程逻辑缓冲区范围，在描述符和协商长度边界处分段。</summary>
    /// <param name="destination">本地目标内存，保持有效直到全部设备读取完成。</param>
    /// <param name="descriptors">从上层协议消息收到的远程缓冲区片段。</param>
    /// <param name="remoteOffset">跨全部远程片段计算的逻辑偏移。</param>
    /// <param name="cancellationToken">取消正在执行的原生操作，并等待其访问栅栏生效。</param>
    public async ValueTask ReadRemoteAsync(Memory<byte> destination, IReadOnlyList<SmbRdmaBufferDescriptor> descriptors,
        long remoteOffset = 0, CancellationToken cancellationToken = default)
    {
        ThrowIfClosed();
        cancellationToken.ThrowIfCancellationRequested();
        if (!destination.IsEmpty && MaximumReadWriteSize == 0)
            throw new NotSupportedException("The peer did not negotiate RDMA direct placement.");
        IReadOnlyList<SmbRdmaBufferDescriptor> selected = SmbRdmaBufferDescriptor.Slice(descriptors, remoteOffset, destination.Length);
        using var linked = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, lifetime.Token);
        int position = 0;
        try
        {
            foreach (SmbRdmaBufferDescriptor descriptor in selected)
                for (uint offset = 0; offset < descriptor.Length;)
                {
                    int count = (int)Math.Min((uint)MaximumReadWriteSize, descriptor.Length - offset);
                    await endpoint.ReadAsync(destination.Slice(position, count), descriptor with
                    {
                        Offset = descriptor.Offset + offset,
                        Length = (uint)count
                    }, linked.Token).ConfigureAwait(false);
                    position += count;
                    offset += (uint)count;
                }
        }
        catch (Exception ex)
        {
            Abort(ex);
            throw;
        }
    }

    /// <summary>写入远程逻辑缓冲区范围，在描述符和协商长度边界处分段。</summary>
    /// <param name="source">本地源字节。</param>
    /// <param name="descriptors">从上层协议消息收到的远程目标片段。</param>
    /// <param name="remoteOffset">跨全部远程片段计算的逻辑偏移。</param>
    /// <param name="cancellationToken">取消正在执行的原生操作，并等待其访问栅栏生效。</param>
    public async ValueTask WriteRemoteAsync(ReadOnlyMemory<byte> source, IReadOnlyList<SmbRdmaBufferDescriptor> descriptors,
        long remoteOffset = 0, CancellationToken cancellationToken = default)
    {
        ThrowIfClosed();
        cancellationToken.ThrowIfCancellationRequested();
        if (!source.IsEmpty && MaximumReadWriteSize == 0)
            throw new NotSupportedException("The peer did not negotiate RDMA direct placement.");
        IReadOnlyList<SmbRdmaBufferDescriptor> selected = SmbRdmaBufferDescriptor.Slice(descriptors, remoteOffset, source.Length);
        using var linked = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, lifetime.Token);
        int position = 0;
        try
        {
            foreach (SmbRdmaBufferDescriptor descriptor in selected)
                for (uint offset = 0; offset < descriptor.Length;)
                {
                    int count = (int)Math.Min((uint)MaximumReadWriteSize, descriptor.Length - offset);
                    await endpoint.WriteAsync(source.Slice(position, count), descriptor with
                    {
                        Offset = descriptor.Offset + offset,
                        Length = (uint)count
                    }, linked.Token).ConfigureAwait(false);
                    position += count;
                    offset += (uint)count;
                }
        }
        catch (Exception ex)
        {
            Abort(ex);
            throw;
        }
    }

    /// <summary>先投递设备接收，再允许公布对应信用。</summary>
    /// <param name="force">额外保留一个接收，允许使用最后一个 SEND 信用。</param>
    /// <param name="cancellationToken">取消原生接收分配。</param>
    private async ValueTask ReplenishAsync(bool force, CancellationToken cancellationToken)
    {
        await posting.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            int count;
            lock (stateGate)
            {
                int target = Math.Min(peerCreditTarget, options.MaximumReceiveCredits);
                if (force && target <= receiveCredits)
                    target = Math.Min(options.MaximumReceiveCredits, receiveCredits + 1);
                count = Math.Max(0, target - postedReceives);
            }
            if (count == 0)
                return;
            int added = await endpoint.PostReceivesAsync(count, MaximumReceiveSize, cancellationToken).ConfigureAwait(false);
            if (added < 0 || added > count)
                throw new SmbProtocolException("The RDMA provider returned an invalid posted receive count.");
            lock (stateGate)
            {
                postedReceives += added;
                WakeSenders();
            }
        }
        finally
        {
            _ = posting.Release();
        }
    }

    /// <summary>先保留信用再获取发送锁，避免信用回复与接收互相等待。</summary>
    /// <remarks>资源已经保留后若发生取消，将中止连接，避免复用不确定的信用状态。</remarks>
    private async ValueTask SendFragmentAsync(ReadOnlyMemory<byte> payload, uint remaining, uint? invalidate,
        bool responseRequested, CancellationToken cancellationToken)
    {
        ushort grant;
        while (true)
        {
            ThrowIfClosed();
            bool force;
            lock (stateGate)
                force = sendCredits <= 1;
            await ReplenishAsync(force, cancellationToken).ConfigureAwait(false);
            Task wait;
            lock (stateGate)
            {
                grant = (ushort)Math.Min(ushort.MaxValue - receiveCredits, postedReceives - receiveCredits);
                if (sendCredits > 1 || (sendCredits == 1 && grant > 0))
                {
                    sendCredits--;
                    receiveCredits += grant;
                    break;
                }
                wait = creditChanged.Task;
            }
            await wait.WaitAsync(cancellationToken).ConfigureAwait(false);
        }
        try
        {
            await wireWriter.WaitAsync(cancellationToken).ConfigureAwait(false);
            try
            {
                if (responseRequested)
                    _ = Interlocked.Exchange(ref probeStarted, Environment.TickCount64);
                await endpoint.SendAsync(SmbDirectWire.Data(payload.Span, remaining, options.SendCreditTarget, grant, responseRequested),
                    invalidate, cancellationToken).ConfigureAwait(false);
            }
            finally
            {
                _ = wireWriter.Release();
            }
        }
        catch (Exception ex)
        {
            Abort(ex);
            throw;
        }
    }

    /// <summary>校验帧和信用，保持分片顺序，并合并控制响应。</summary>
    private async Task ReceiveLoopAsync()
    {
        using var assembly = new MemoryStream();
        uint expectedRemaining = 0;
        uint? invalidated = null;
        try
        {
            while (!lifetime.IsCancellationRequested)
            {
                using SmbRdmaReceive received = await endpoint.ReceiveAsync(lifetime.Token).ConfigureAwait(false);
                SmbDirectData data = SmbDirectWire.ParseData(received.Data, MaximumReceiveSize, MaximumFragmentedReceiveSize);
                bool hadProbe = Interlocked.Exchange(ref probeStarted, 0) != 0;
                _ = Interlocked.Exchange(ref lastReceive, Environment.TickCount64);
                lock (stateGate)
                {
                    if (receiveCredits <= 0 || postedReceives <= 0)
                        throw new SmbProtocolException("The peer exceeded granted SMB Direct receive credits.");
                    receiveCredits--;
                    postedReceives--;
                    if (sendCredits > ushort.MaxValue - data.CreditsGranted)
                        throw new SmbProtocolException("SMB Direct credits overflowed.");
                    sendCredits += data.CreditsGranted;
                    peerCreditTarget = data.CreditsRequested;
                    WakeSenders();
                }
                await ReplenishAsync(false, lifetime.Token).ConfigureAwait(false);
                if (data.ResponseRequested && !hadProbe)
                    RequestControl();
                // 批量授予可选信用，避免对空信用消息无限相互响应。
                lock (stateGate)
                    if (!data.Payload.IsEmpty && receiveCredits <= Math.Max(1, Math.Min(peerCreditTarget, options.MaximumReceiveCredits) / 2) && postedReceives > receiveCredits)
                        RequestControl();
                if (received.InvalidatedToken is { } token)
                    invalidated = token;
                if (data.Payload.IsEmpty)
                {
                    if (received.InvalidatedToken is not null && assembly.Length == 0)
                    {
                        await messages.Writer.WriteAsync(new(ReadOnlyMemory<byte>.Empty, invalidated), lifetime.Token).ConfigureAwait(false);
                        invalidated = null;
                    }
                    continue;
                }
                if (assembly.Length == 0)
                {
                    expectedRemaining = data.RemainingLength;
                    if (data.Payload.Length + expectedRemaining > MaximumFragmentedReceiveSize)
                        throw new SmbProtocolException("An SMB Direct fragmented message is oversized.");
                }
                else
                {
                    if (data.Payload.Length > expectedRemaining || expectedRemaining - data.Payload.Length != data.RemainingLength)
                        throw new SmbProtocolException("An SMB Direct fragment sequence is inconsistent.");
                    expectedRemaining = data.RemainingLength;
                }
                assembly.Write(data.Payload.Span);
                if (assembly.Length > MaximumFragmentedReceiveSize)
                    throw new SmbProtocolException("An SMB Direct message exceeded its reassembly limit.");
                if (data.RemainingLength == 0)
                {
                    await messages.Writer.WriteAsync(new(assembly.ToArray(), invalidated), lifetime.Token).ConfigureAwait(false);
                    assembly.SetLength(0);
                    assembly.Position = 0;
                    invalidated = null;
                }
            }
        }
        catch (OperationCanceledException) when (lifetime.IsCancellationRequested) { }
        catch (Exception ex)
        {
            Abort(ex);
        }
    }

    /// <summary>排队信用或保活响应，避免接收消费者因等待发送信用而阻塞。</summary>
    private void RequestControl()
    {
        Volatile.Write(ref controlRequested, 1);
        if (Interlocked.CompareExchange(ref controlRunning, 1, 0) == 0)
            controlTask = SendControlLoopAsync();
    }

    /// <summary>发送合并后的空控制帧，同时允许接收循环继续收集信用。</summary>
    private async Task SendControlLoopAsync()
    {
        try
        {
            while (Interlocked.Exchange(ref controlRequested, 0) != 0)
                await SendFragmentAsync(ReadOnlyMemory<byte>.Empty, 0, null, false, lifetime.Token).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (lifetime.IsCancellationRequested) { }
        catch (Exception ex)
        {
            Abort(ex);
        }
        finally
        {
            Volatile.Write(ref controlRunning, 0);
            if (Volatile.Read(ref controlRequested) != 0 && !lifetime.IsCancellationRequested)
                RequestControl();
        }
    }

    /// <summary>探测空闲对端，只有实际发出的探测超时后才中止连接。</summary>
    private async Task KeepaliveLoopAsync()
    {
        if (options.KeepaliveInterval == Timeout.InfiniteTimeSpan)
            return;
        using var timer = new PeriodicTimer(TimeSpan.FromMilliseconds(Math.Max(1, Math.Min(options.KeepaliveInterval.TotalMilliseconds, options.KeepaliveTimeout.TotalMilliseconds))));
        try
        {
            while (await timer.WaitForNextTickAsync(lifetime.Token).ConfigureAwait(false))
            {
                long now = Environment.TickCount64;
                long probe = Volatile.Read(ref probeStarted);
                if (probe != 0)
                {
                    if (now - probe >= options.KeepaliveTimeout.TotalMilliseconds)
                        throw new TimeoutException("The SMB Direct peer did not answer a keepalive.");
                }
                else if (now - Volatile.Read(ref lastReceive) >= options.KeepaliveInterval.TotalMilliseconds)
                    await SendFragmentAsync(ReadOnlyMemory<byte>.Empty, 0, null, true, lifetime.Token).ConfigureAwait(false);
            }
        }
        catch (OperationCanceledException) when (lifetime.IsCancellationRequested) { }
        catch (Exception ex)
        {
            Abort(ex);
        }
    }

    /// <summary>创建可安全异步调度延续任务的资源变化信号。</summary>
    private static TaskCompletionSource Signal()
    {
        return new(TaskCreationOptions.RunContinuationsAsynchronously);
    }

    /// <summary>持有 stateGate 时替换信号，并唤醒全部等待发送。</summary>
    private void WakeSenders()
    {
        TaskCompletionSource signal = creditChanged;
        creditChanged = Signal();
        _ = signal.TrySetResult();
    }
    /// <summary>拒绝后续操作时保留连接的原始错误。</summary>
    private void ThrowIfClosed()
    {
        ObjectDisposedException.ThrowIf(Volatile.Read(ref disposed) != 0, this);
        if (Volatile.Read(ref failure) is { } error)
            throw new IOException("The SMB Direct connection is closed.", error);
    }

    /// <summary>终止原生流量、唤醒等待方，并保留内存直到提供程序清理完成访问栅栏。</summary>
    public void Abort()
    {
        Abort(new IOException("The SMB Direct connection was aborted."));
    }

    /// <summary>记录首次失败，并终止未完成的传输工作。</summary>
    private void Abort(Exception error)
    {
        if (Interlocked.CompareExchange(ref failure, error, null) is not null)
            return;
        lifetime.Cancel();
        endpoint.Abort();
        _ = messages.Writer.TryComplete(error);
        lock (stateGate)
            WakeSenders();
    }

    /// <summary>先停止后台工作，再异步释放拥有的 RDMA 提供程序端点。</summary>
    public ValueTask DisposeAsync()
    {
        lock (disposeGate)
            return new(disposal ??= DisposeCoreAsync());
    }

    /// <summary>执行唯一的停止及清理流程；并发释放方通过共享任务等待设备访问完全结束。</summary>
    private async Task DisposeCoreAsync()
    {
        Volatile.Write(ref disposed, 1);
        Abort(new ObjectDisposedException(nameof(SmbDirectConnection)));
        await Task.WhenAll(receiveTask, keepaliveTask, controlTask).ConfigureAwait(false);
        await endpoint.DisposeAsync().ConfigureAwait(false);
    }

    /// <summary>拥有提供程序注册对象，同时向外提供不可变描述符快照。</summary>
    /// <param name="inner">原生注册租约。</param>
    /// <param name="descriptors">经过校验、完整覆盖已注册缓冲区的片段。</param>
    private sealed class Registration(SmbRdmaMemoryRegistration inner, SmbRdmaBufferDescriptor[] descriptors) : SmbRdmaMemoryRegistration
    {
        /// <summary>提供程序注册对象，首次释放时原子替换为空。</summary>
        private SmbRdmaMemoryRegistration? registration = inner;
        /// <summary>防止调用方修改已经公布的片段地址或令牌。</summary>
        private readonly IReadOnlyList<SmbRdmaBufferDescriptor> snapshot = Array.AsReadOnly(descriptors);
        /// <summary>经过校验的不可变远程访问片段列表。</summary>
        public override IReadOnlyList<SmbRdmaBufferDescriptor> Descriptors => snapshot;
        /// <summary>恰好释放一次提供程序注册对象，以完成远程访问栅栏。</summary>
        public override ValueTask DisposeAsync()
        {
            return Interlocked.Exchange(ref registration, null)?.DisposeAsync() ?? ValueTask.CompletedTask;
        }
    }
}