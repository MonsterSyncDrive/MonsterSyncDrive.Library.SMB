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
using System.Net.Quic;
using System.Net.Security;
using System.Security.Authentication;

namespace MonsterSyncDrive.Library.SMB.Transport;

/// <summary>建立单条 SMB QUIC 双向流，采用经过身份验证的 TLS 1.3 和 ALPN smb。</summary>
internal static class SmbQuicTransport
{
    /// <summary>获取 IANA 为 SMB over QUIC 分配的 ALPN 字节序列。</summary>
    internal static SslApplicationProtocol ApplicationProtocol => new("smb");

    /// <summary>对可用 QUIC 端点进行连接竞速，同时为所有地址保留逻辑证书身份。</summary>
    /// <param name="host">逻辑 SMB 主机名称，默认用作 TLS 证书名称。</param>
    /// <param name="port">远端 UDP 端口。</param>
    /// <param name="options">已经验证的端点和证书选项。</param>
    /// <param name="maximum">采用长度前缀的 SMB 消息所允许的最大长度。</param>
    /// <param name="cancellationToken">覆盖整个连接过程的截止时间。</param>
    /// <returns>同时持有 QUIC 连接及唯一出站流的消息传输对象。</returns>
    /// <exception cref="PlatformNotSupportedException">QUIC 不可用，或调用方请求了不支持的逐连接 DSCP 配置。</exception>
    internal static async Task<ISmbMessageTransport> ConnectAsync(string host, int port, SmbTransportOptions options, int maximum, CancellationToken cancellationToken)
    {
        if (!(OperatingSystem.IsWindows() || OperatingSystem.IsLinux() || OperatingSystem.IsMacOS()) || !QuicConnection.IsSupported)
            throw new PlatformNotSupportedException("SMB over QUIC requires a supported System.Net.Quic platform and the Microsoft MsQuic runtime.");
        if (options.Dscp is not null)
            throw new PlatformNotSupportedException("System.Net.Quic does not expose per-connection DSCP configuration.");
        IPAddress[] addresses = await SmbEndpointConnector.ResolveAsync(host, options, cancellationToken).ConfigureAwait(false);
        using CancellationTokenSource race = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        if (options.LocalPort != 0)
        {
            List<Exception> sequentialErrors = new();
            foreach (IPAddress address in addresses)
            {
                try
                {
                    return await AttemptAsync(address, host, port, options, maximum, TimeSpan.Zero, cancellationToken).ConfigureAwait(false);
                }
                catch (Exception ex) when (ex is QuicException or AuthenticationException or System.Net.Sockets.SocketException)
                {
                    sequentialErrors.Add(ex);
                }
            }
            if (sequentialErrors.Count == 1)
                throw sequentialErrors[0];
            throw new IOException("No resolved SMB QUIC endpoint could be reached.", new AggregateException(sequentialErrors));
        }
        List<Task<ISmbMessageTransport>> tasks = addresses.Select((a, i) => AttemptAsync(a, host, port, options, maximum,
            options.AddressRaceDelay * i, race.Token)).ToList();
        List<Exception> errors = new();
        try
        {
            while (tasks.Count > 0)
            {
                Task<ISmbMessageTransport> completed = await Task.WhenAny(tasks).ConfigureAwait(false);
                _ = tasks.Remove(completed);
                try
                {
                    return await completed.ConfigureAwait(false);
                }
                catch (Exception ex) when (ex is QuicException or AuthenticationException or System.Net.Sockets.SocketException)
                {
                    errors.Add(ex);
                }
            }
            if (errors.Count == 1)
                throw errors[0];
            throw new IOException("No resolved SMB QUIC endpoint could be reached.", new AggregateException(errors));
        }
        finally
        {
            await race.CancelAsync().ConfigureAwait(false);
            foreach (Task<ISmbMessageTransport>? task in tasks)
            {
                try
                {
                    await (await task.ConfigureAwait(false)).DisposeAsync().ConfigureAwait(false);
                }
                catch (Exception ex) when (ex is OperationCanceledException or QuicException or AuthenticationException or System.Net.Sockets.SocketException or IOException) { }
            }
        }
    }

    /// <summary>对一条 QUIC 连接进行身份认证，并打开唯一由客户端发起的双向流。</summary>
    /// <param name="address">具体网络地址；该值不会替换证书名称。</param>
    /// <param name="host">逻辑证书身份，仅在显式设置 ServerName 时被覆盖。</param>
    /// <param name="port">远端 UDP 端口。</param>
    /// <param name="options">源端点绑定、证书信任和连接存活策略。</param>
    /// <param name="maximum">消息分帧长度上限。</param>
    /// <param name="delay">用于错开地址竞速尝试的延迟。</param>
    /// <param name="cancellationToken">用于取消延迟、TLS 握手和流创建的令牌。</param>
    /// <returns>已经建立连接的消息传输对象。</returns>
    private static async Task<ISmbMessageTransport> AttemptAsync(IPAddress address, string host, int port, SmbTransportOptions options, int maximum,
        TimeSpan delay, CancellationToken cancellationToken)
    {
        if (!(OperatingSystem.IsWindows() || OperatingSystem.IsLinux() || OperatingSystem.IsMacOS()) || !QuicConnection.IsSupported)
            throw new PlatformNotSupportedException("QUIC is unavailable.");
        if (delay > TimeSpan.Zero)
            await Task.Delay(delay, cancellationToken).ConfigureAwait(false);
        // 默认不安装放宽证书验证的回调；目标地址覆盖设置与
        // TargetHost 分别管理，因此为多通道选择 IP 地址时，不会
        // 悄然改变应用原本要验证的服务器证书身份。
        SslClientAuthenticationOptions tls = new()
        {
            TargetHost = options.Quic.ServerName ?? host.Trim('[', ']'),
            ApplicationProtocols = [ApplicationProtocol],
            EnabledSslProtocols = SslProtocols.Tls13,
            ClientCertificates = options.Quic.ClientCertificates,
            RemoteCertificateValidationCallback = options.Quic.RemoteCertificateValidationCallback,
            CertificateChainPolicy = options.Quic.CertificateChainPolicy,
            CertificateRevocationCheckMode = options.Quic.CertificateRevocationCheckMode,
            AllowRenegotiation = false
        };
        QuicConnection connection = await QuicConnection.ConnectAsync(new QuicClientConnectionOptions
        {
            RemoteEndPoint = new IPEndPoint(address, port),
            LocalEndPoint = options.LocalAddress is not null || options.LocalPort != 0
                ? new IPEndPoint(options.LocalAddress ?? (address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6 ? IPAddress.IPv6Any : IPAddress.Any), options.LocalPort) : null,
            ClientAuthenticationOptions = tls,
            DefaultCloseErrorCode = 0,
            DefaultStreamErrorCode = 0,
            // SMB 仅使用一条由客户端发起的流；通过 QUIC 的流数量限制拒绝对端新建的其他流，
            // 避免意外创建另一个 SMB 消息接收者。
            MaxInboundBidirectionalStreams = 0,
            MaxInboundUnidirectionalStreams = 0,
            IdleTimeout = options.Quic.IdleTimeout,
            KeepAliveInterval = options.Quic.KeepAliveInterval
        }, cancellationToken).ConfigureAwait(false);
        try
        {
            QuicStream stream = await connection.OpenOutboundStreamAsync(QuicStreamType.Bidirectional, cancellationToken).ConfigureAwait(false);
            var closeGate = new object();
            Task? close = null;
            // 先释放字节流，再释放持有它的 QUIC 连接。
            async Task CloseAsync()
            {
                if (!(OperatingSystem.IsWindows() || OperatingSystem.IsLinux() || OperatingSystem.IsMacOS()))
                    return;
                try
                {
                    await stream.DisposeAsync().ConfigureAwait(false);
                }
                catch (QuicException) { }
                finally
                {
                    await connection.DisposeAsync().ConfigureAwait(false);
                }
            }
            // 在重复调用之间共享同一次异步释放操作。
            ValueTask DisposeOwner()
            {
                lock (closeGate)
                {
                    close ??= CloseAsync();
                    return new ValueTask(close);
                }
            }
            // 中断字节流的两个方向，防止挂起的分帧读取一直阻塞。
            void AbortOwner()
            {
                if (!(OperatingSystem.IsWindows() || OperatingSystem.IsLinux() || OperatingSystem.IsMacOS()))
                    return;
                try
                {
                    stream.Abort(QuicAbortDirection.Both, 0);
                }
                catch (ObjectDisposedException) { }
            }
            return new SmbStreamMessageTransport(stream, SmbTransportKind.Quic, maximum, connection.LocalEndPoint, connection.RemoteEndPoint, AbortOwner, DisposeOwner);
        }
        catch
        {
            await connection.DisposeAsync().ConfigureAwait(false);
            throw;
        }
    }
}