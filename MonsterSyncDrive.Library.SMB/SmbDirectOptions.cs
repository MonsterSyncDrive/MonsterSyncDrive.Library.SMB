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
using System.Net;

namespace MonsterSyncDrive.SMB;

/// <summary>MS-SMBD 传输限制，以及连接所使用的 RDMA 设备提供程序。</summary>
/// <remarks>
/// 当 Provider 为空且系统受支持时，使用内置的 Windows NetworkDirect v2 后端。
/// 其他系统可提供使用真实 RDMA 设备的提供程序。本库不会
/// 将 TCP 套接字冒充 RDMA 提供程序。
/// </remarks>
public sealed record SmbDirectOptions
{
    /// <summary>覆盖原生提供程序；为空时在 64 位 Windows 上选用内置 NetworkDirect 后端。</summary>
    public ISmbRdmaProvider? Provider { get; init; }
    /// <summary>可选的本地 RDMA 网卡 IP 和端口；通配地址通过操作系统路由选择。</summary>
    public IPEndPoint? LocalEndPoint { get; init; }
    /// <summary>向对端请求的 SEND 信用总数，包括已经持有的信用。</summary>
    public ushort SendCreditTarget { get; init; } = 128;
    /// <summary>向对端公布的、由硬件接收资源支持的信用上限。</summary>
    public ushort MaximumReceiveCredits { get; init; } = 128;
    /// <summary>请求的单条 MS-SMBD SEND 消息最大字节数，包含消息头。</summary>
    public int PreferredSendSize { get; init; } = 65536;
    /// <summary>单个已投递接收缓冲区可接收的最大字节数。</summary>
    public int MaximumReceiveSize { get; init; } = 65536;
    /// <summary>上层消息重组后的最大字节数；MS-SMBD 至少要求 128 KiB。</summary>
    public int MaximumFragmentedReceiveSize { get; init; } = 8 * 1024 * 1024;
    /// <summary>逻辑直接放置请求的最大长度，还须受对端协商结果约束。</summary>
    public int MaximumReadWriteSize { get; init; } = 8 * 1024 * 1024;
    /// <summary>是否允许文件读写自动使用直接放置；签名、加密及共享安全策略仍有更高优先级。</summary>
    public bool EnableDirectPlacement { get; init; } = true;
    /// <summary>直接放置的长度阈值；仅大于该值的数据块尝试注册内存，零表示所有非空数据块。</summary>
    public int DirectPlacementThreshold { get; init; } = 16 * 1024;
    /// <summary>空闲多长时间后探测对端；InfiniteTimeSpan 表示关闭定期探测。</summary>
    public TimeSpan KeepaliveInterval { get; init; } = TimeSpan.FromSeconds(120);
    /// <summary>空闲探测实际发出后，等待响应的最长时间。</summary>
    public TimeSpan KeepaliveTimeout { get; init; } = TimeSpan.FromSeconds(30);

    /// <summary>校验协议边界、定时器范围，并复制可变的本地端点配置。</summary>
    /// <returns>经过校验的选项快照。</returns>
    internal SmbDirectOptions Validate()
    {
        if (SendCreditTarget == 0 || MaximumReceiveCredits == 0)
            throw new ArgumentOutOfRangeException(nameof(SendCreditTarget), "SMB Direct requires nonzero credit limits.");
        if (PreferredSendSize < 128 || MaximumReceiveSize < 128 || MaximumFragmentedReceiveSize < 131072 || MaximumReadWriteSize <= 0)
            throw new ArgumentOutOfRangeException(nameof(PreferredSendSize), "Invalid SMB Direct transfer limits.");
        ArgumentOutOfRangeException.ThrowIfNegative(DirectPlacementThreshold);
        if (KeepaliveInterval != Timeout.InfiniteTimeSpan && (KeepaliveInterval <= TimeSpan.Zero || KeepaliveInterval.TotalMilliseconds > uint.MaxValue - 1))
            throw new ArgumentOutOfRangeException(nameof(KeepaliveInterval));
        if (KeepaliveTimeout <= TimeSpan.Zero || KeepaliveTimeout.TotalMilliseconds > uint.MaxValue - 1)
            throw new ArgumentOutOfRangeException(nameof(KeepaliveTimeout));
        return this with { LocalEndPoint = LocalEndPoint is null ? null : new IPEndPoint(LocalEndPoint.Address, LocalEndPoint.Port) };
    }
}

/// <summary>开始 MS-SMBD 握手前传递给原生 RDMA 提供程序的设置。</summary>
/// <param name="Host">选定的服务器名称或数字 IP 地址。</param>
/// <param name="Port">服务器的 RDMA 连接管理器端口，通常为 5445。</param>
/// <param name="LocalEndPoint">可选的源 RDMA 网卡 IP 和源端口。</param>
/// <param name="PreferredSendSize">请求的 SEND 最大字节数。</param>
/// <param name="MaximumReceiveSize">请求的 RECEIVE 最大字节数。</param>
/// <param name="MaximumReceiveCredits">请求的接收队列容量。</param>
public sealed record SmbRdmaConnectOptions(string Host, int Port, IPEndPoint? LocalEndPoint,
    int PreferredSendSize, int MaximumReceiveSize, ushort MaximumReceiveCredits);

/// <summary>创建可靠连接的 RDMA SEND/RECEIVE 端点。</summary>
/// <remarks>
/// 实现应使用 NetworkDirect、verbs 或等效的设备接口；流式套接字
/// 不能作为合规实现。为支持 AOT，提供程序调用不得依赖反射或动态代码。
/// </remarks>
public interface ISmbRdmaProvider
{
    /// <summary>连接可靠的 RDMA 端点；不负责 SMB 会话认证。</summary>
    /// <param name="options">目标、源端点绑定以及队列大小建议。</param>
    /// <param name="cancellationToken">取消连接建立，并等待原生初始化操作结束。</param>
    /// <returns>由调用方拥有、已准备好进行 MS-SMBD 协商的端点。</returns>
    ValueTask<ISmbRdmaEndpoint> ConnectAsync(SmbRdmaConnectOptions options, CancellationToken cancellationToken = default);
}

/// <summary>可靠连接的 RDMA 队列对及其已注册内存操作。</summary>
public interface ISmbRdmaEndpoint : IAsyncDisposable
{
    /// <summary>实际绑定的 RDMA 源地址。</summary>
    EndPoint? LocalEndPoint { get; }
    /// <summary>实际连接的 RDMA 目标地址。</summary>
    EndPoint? RemoteEndPoint { get; }
    /// <summary>单条 SEND 工作请求的最大字节数。</summary>
    int MaximumSendSize { get; }
    /// <summary>单条 RECEIVE 工作请求的最大字节数。</summary>
    int MaximumReceiveSize { get; }
    /// <summary>由设备资源支持的未完成或已排队接收数量。</summary>
    ushort MaximumReceiveQueueDepth { get; }
    /// <summary>是否允许对端读取本地注册区域；仅支持消息传输的提供程序应返回假。</summary>
    bool SupportsRemoteRead => true;
    /// <summary>是否允许对端写入本地注册区域；仅支持消息传输的提供程序应返回假。</summary>
    bool SupportsRemoteWrite => true;

    /// <summary>
    /// 投递至多 <paramref name="count"/> 个新的接收请求，每个缓冲区至少为 <paramref name="bufferSize"/>
    /// 字节。返回实际投递数量。每次完成的 ReceiveAsync 恰好消耗
    /// 一个已投递接收。缓冲区在完成或 Abort 前持续有效。
    /// </summary>
    ValueTask<int> PostReceivesAsync(int count, int bufferSize, CancellationToken cancellationToken = default);

    /// <summary>等待 RDMA SEND 以及可选的 SEND_WITH_INVALIDATE 完成后返回。</summary>
    ValueTask SendAsync(ReadOnlyMemory<byte> message, uint? invalidateRemoteToken = null, CancellationToken cancellationToken = default);

    /// <summary>返回一次 SEND 接收完成结果，以及保护对应接收缓冲区的租约。</summary>
    ValueTask<SmbRdmaReceive> ReceiveAsync(CancellationToken cancellationToken = default);

    /// <summary>注册并固定内存，直到返回的注册对象被释放。</summary>
    ValueTask<SmbRdmaMemoryRegistration> RegisterMemoryAsync(Memory<byte> buffer, SmbRdmaMemoryAccess access, CancellationToken cancellationToken = default);

    /// <summary>设备 RDMA READ 完成后才返回结果或报告取消。</summary>
    /// <param name="destination">本地读取目标内存，在完成前保持有效。</param>
    /// <param name="source">对端源地址、导向令牌和字节数。</param>
    /// <param name="cancellationToken">取消未完成的设备访问，并等待访问栅栏生效。</param>
    ValueTask ReadAsync(Memory<byte> destination, SmbRdmaBufferDescriptor source, CancellationToken cancellationToken = default);
    /// <summary>设备 RDMA WRITE 完成后才返回结果或报告取消。</summary>
    /// <param name="source">本地源数据。</param>
    /// <param name="destination">对端目标地址、导向令牌和字节数。</param>
    /// <param name="cancellationToken">取消未完成的设备访问，并等待访问栅栏生效。</param>
    ValueTask WriteAsync(ReadOnlyMemory<byte> source, SmbRdmaBufferDescriptor destination, CancellationToken cancellationToken = default);

    /// <summary>终止队列对，使未完成工作失败，并阻止后续远程内存访问。</summary>
    void Abort();
}

/// <summary>已注册本地 RDMA 内存区域授予对端的访问权限。</summary>
[Flags]
public enum SmbRdmaMemoryAccess
{
    /// <summary>允许对端读取已注册的本地字节。</summary>
    RemoteRead = 1,
    /// <summary>允许对端写入已注册的本地字节。</summary>
    RemoteWrite = 2
}

/// <summary>一次 RDMA 接收完成；释放对象时将接收缓冲区归还提供程序。</summary>
public sealed class SmbRdmaReceive : IDisposable
{
    /// <summary>持有提供程序的接收缓冲区租约，直到使用方释放。</summary>
    private IDisposable? lease;
    /// <summary>在本次完成租约生命周期内有效的字节。</summary>
    public ReadOnlyMemory<byte> Data { get; }
    /// <summary>对端 SEND 操作失效的可选本地导向令牌。</summary>
    public uint? InvalidatedToken { get; }
    /// <summary>创建完成结果，并保留提供程序缓冲区的租约。</summary>
    /// <param name="data">一条完整的 RDMA SEND 负载。</param>
    /// <param name="invalidatedToken">原生失效完成结果报告的令牌。</param>
    /// <param name="bufferLease">由 Dispose 恰好释放一次的租约。</param>
    public SmbRdmaReceive(ReadOnlyMemory<byte> data, uint? invalidatedToken = null, IDisposable? bufferLease = null)
    {
        Data = data; InvalidatedToken = invalidatedToken; lease = bufferLease;
    }
    /// <summary>恰好释放一次原生接收缓冲区。</summary>
    public void Dispose() => Interlocked.Exchange(ref lease, null)?.Dispose();
}

/// <summary>提供程序拥有的注册对象；释放时必须等待远程操作结束并注销内存。</summary>
public abstract class SmbRdmaMemoryRegistration : IAsyncDisposable
{
    /// <summary>按逻辑缓冲区顺序排列的已注册远程访问片段。</summary>
    public abstract IReadOnlyList<SmbRdmaBufferDescriptor> Descriptors { get; }
    /// <summary>等待远程操作结束并注销内存后返回。</summary>
    public abstract ValueTask DisposeAsync();
}