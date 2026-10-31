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
using System.Net.Sockets;

namespace MonsterSyncDrive.SMB.Transport;

/// <summary>在统一的连接截止时间内建立所选 SMB 传输。</summary>
internal static class SmbTransportFactory
{
    /// <summary>创建已经完成 TLS 或 NetBIOS 会话建立的消息传输对象。</summary>
    /// <param name="host">用于 DNS 解析和证书检查的逻辑 SMB 身份。</param>
    /// <param name="port">已经确定的显式端口或该传输的标准端口。</param>
    /// <param name="options">传输方式和端点配置。</param>
    /// <param name="maximumPacketSize">允许从对端接收的最大完整消息大小。</param>
    /// <param name="connectTimeout">覆盖全部地址尝试、握手和重定向的截止时间。</param>
    /// <param name="cancellationToken">调用方取消令牌。</param>
    /// <returns>由调用方持有且可以开始传输 SMB NEGOTIATE 的传输对象。</returns>
    /// <exception cref="TimeoutException">整个连接过程的截止时间已到。</exception>
    internal static async Task<ISmbMessageTransport> ConnectAsync(string host, int port, SmbTransportOptions options, int maximumPacketSize,
        TimeSpan connectTimeout, CancellationToken cancellationToken)
    {
        options = options.Validate(host);
        if (port is < 1 or > 65535) throw new ArgumentOutOfRangeException(nameof(port));
        if (maximumPacketSize is < 64 or > 0xFFFFFF) throw new ArgumentOutOfRangeException(nameof(maximumPacketSize));
        using var timeout = new CancellationTokenSource();
        if (connectTimeout != Timeout.InfiniteTimeSpan) timeout.CancelAfter(connectTimeout);
        using var linked = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, timeout.Token);
        try
        {
            return options.Kind switch
            {
                SmbTransportKind.DirectTcp => WrapTcp(await SmbEndpointConnector.ConnectTcpAsync(host, port, options, linked.Token).ConfigureAwait(false), options.Kind, maximumPacketSize),
                SmbTransportKind.NetBios => await ConnectNetBiosAsync(host, port, options, maximumPacketSize, linked.Token).ConfigureAwait(false),
                SmbTransportKind.Quic => await SmbQuicTransport.ConnectAsync(host, port, options, maximumPacketSize, linked.Token).ConfigureAwait(false),
                SmbTransportKind.Rdma => await ConnectRdmaAsync(host, port, options, maximumPacketSize, linked.Token).ConfigureAwait(false),
                _ => throw new ArgumentOutOfRangeException(nameof(options))
            };
        }
        catch (OperationCanceledException) when (timeout.IsCancellationRequested && !cancellationToken.IsCancellationRequested)
        { throw new TimeoutException("The SMB transport connection timed out."); }
    }

    /// <summary>将已连接 TCP 套接字的所有权转移至带分帧和生命周期管理的消息传输对象。</summary>
    /// <param name="tcp">已连接的 TCP 套接字，其所有权在此转移。</param>
    /// <param name="kind">Direct TCP，或已经建立的 NetBIOS 会话。</param>
    /// <param name="maximum">配置的消息大小上限。</param>
    /// <returns>封装后的消息传输对象。</returns>
    private static ISmbMessageTransport WrapTcp(TcpClient tcp, SmbTransportKind kind, int maximum) =>
        new SmbStreamMessageTransport(tcp.GetStream(), kind, maximum, tcp.Client.LocalEndPoint, tcp.Client.RemoteEndPoint,
            () => SmbSocketTrafficClass.Dispose(tcp), () => { SmbSocketTrafficClass.Dispose(tcp); return ValueTask.CompletedTask; });

    /// <summary>仅跟随调用方明确允许、未超出次数限制且未形成循环的 RFC 1002 会话重定向。</summary>
    /// <param name="host">原始逻辑主机名称，在重定向过程中保持不变。</param>
    /// <param name="port">原始会话服务端口。</param>
    /// <param name="options">名称、端点筛选条件及重定向授权策略。</param>
    /// <param name="maximum">配置的消息大小上限，另受 NetBIOS 的 17 位长度限制。</param>
    /// <param name="cancellationToken">全部重定向和握手共用的截止时间。</param>
    /// <returns>收到会话成功响应后建立的带分帧传输对象。</returns>
    private static async Task<ISmbMessageTransport> ConnectNetBiosAsync(string host, int port, SmbTransportOptions options, int maximum, CancellationToken cancellationToken)
    {
        var visited = new HashSet<IPEndPoint>();
        for (var count = 0; ; count++)
        {
            var tcp = await SmbEndpointConnector.ConnectTcpAsync(host, port, options, cancellationToken).ConfigureAwait(false);
            try
            {
                if (tcp.Client.RemoteEndPoint is IPEndPoint remote && !visited.Add(remote)) throw new SmbProtocolException("NetBIOS session retarget loop.");
                var target = await NetBiosSession.RequestAsync(tcp.GetStream(), options.NetBios, cancellationToken).ConfigureAwait(false);
                if (target is null) return WrapTcp(tcp, SmbTransportKind.NetBios, maximum);
                // 重定向只提供新的网络端点，不会改变 SMB 或 TLS 身份。
                // 连接服务器提供的端点之前，先执行调用方策略。
                if (!options.NetBios.AllowRetarget || count >= options.NetBios.MaximumRetargets || options.NetBios.RetargetPolicy?.Invoke(target) == false)
                    throw new SmbProtocolException("The NetBIOS retarget was disallowed or exceeded its limit.");
                SmbSocketTrafficClass.Dispose(tcp);
                options = options with { RemoteAddress = target.Address };
                port = target.Port;
            }
            catch { SmbSocketTrafficClass.Dispose(tcp); throw; }
        }
    }

    /// <summary>将源端点和目标地址覆盖配置传递给实际的 SMB Direct RDMA 提供程序。</summary>
    /// <param name="host">逻辑主机名称，或仅向网络提供程序传入的地址覆盖值。</param>
    /// <param name="port">RDMA 连接管理端口。</param>
    /// <param name="options">提供程序和端点配置。</param>
    /// <param name="maximum">分片重组后的 SMB 消息大小上限。</param>
    /// <param name="cancellationToken">整个连接过程的截止时间。</param>
    /// <returns>RDMA 消息传输对象。</returns>
    private static async Task<ISmbMessageTransport> ConnectRdmaAsync(string host, int port, SmbTransportOptions options, int maximum, CancellationToken cancellationToken)
    {
        if (options.Dscp is not null) throw new PlatformNotSupportedException("RDMA fabric traffic class must be configured by the selected RDMA provider.");
        var endpointOptions = options;
        if (options.LocalAddress is null && options.LocalPort == 0 && options.Rdma.LocalEndPoint is { } source)
            endpointOptions = options with { LocalAddress = source.Address };
        var addresses = await SmbEndpointConnector.ResolveAsync(host, endpointOptions, cancellationToken).ConfigureAwait(false);
        var errors = new List<Exception>();
        foreach (var address in addresses)
        {
            var rdma = options.Rdma;
            if (options.LocalAddress is not null || options.LocalPort != 0)
                rdma = rdma with { LocalEndPoint = new IPEndPoint(options.LocalAddress ?? (address.AddressFamily == AddressFamily.InterNetworkV6 ? IPAddress.IPv6Any : IPAddress.Any), options.LocalPort) };
            try
            {
                // 连接管理器的尝试采用顺序执行，因为提供程序可能占用固定的
                // 本地端点或稀缺的 QP 资源。提供程序收到的是具体网络地址，
                // 而客户端独立保留的 Host 始终代表 SMB 身份。
                return await SmbDirectTransport.ConnectAsync(address.ToString(), port, rdma, maximum, cancellationToken).ConfigureAwait(false);
            }
            catch (IOException error) when (error is not SmbProtocolException) { errors.Add(error); }
            catch (SocketException error) { errors.Add(error); }
        }
        if (errors.Count == 1) throw errors[0];
        throw new IOException("No resolved SMB RDMA endpoint could be reached.", new AggregateException(errors));
    }
}