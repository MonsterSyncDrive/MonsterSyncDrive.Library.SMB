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

/// <summary>解析逻辑主机名称，并在显式地址族和源地址绑定约束下连接具体端点。</summary>
internal static class SmbEndpointConnector
{
    /// <summary>解析并交错排列可用目标地址，逻辑主机身份仍由上层保留。</summary>
    /// <param name="host">DNS 名称，或带方括号、不带方括号的 IP 地址字面量。</param>
    /// <param name="options">已经验证的远端覆盖地址、本地绑定和地址族优先设置。</param>
    /// <param name="cancellationToken">用于取消 DNS 查询的令牌。</param>
    /// <returns>为连接竞速排列的不同地址，最多返回 128 个。</returns>
    /// <exception cref="SocketException">没有地址同时满足请求的地址族和本地绑定要求。</exception>
    internal static async Task<IPAddress[]> ResolveAsync(string host, SmbTransportOptions options, CancellationToken cancellationToken)
    {
        if (host.StartsWith('[') && host.EndsWith(']')) host = host[1..^1];
        var addresses = options.RemoteAddress is { } explicitAddress ? [explicitAddress]
            : IPAddress.TryParse(host, out var literal) ? [literal]
            : await Dns.GetHostAddressesAsync(host, cancellationToken).ConfigureAwait(false);
        var family = options.Kind == SmbTransportKind.NetBios ? AddressFamily.InterNetwork
            : options.AddressFamily switch { SmbAddressFamilyPreference.IPv4Only => AddressFamily.InterNetwork, SmbAddressFamilyPreference.IPv6Only => AddressFamily.InterNetworkV6, _ => AddressFamily.Unspecified };
        addresses = addresses.Where(a => a.AddressFamily is AddressFamily.InterNetwork or AddressFamily.InterNetworkV6)
            .Where(a => family == AddressFamily.Unspecified || a.AddressFamily == family)
            .Where(a => options.LocalAddress is null || options.LocalAddress.AddressFamily == a.AddressFamily)
            .Distinct().Take(128).ToArray();
        if (addresses.Length == 0) throw new SocketException((int)SocketError.AddressFamilyNotSupported);
        var preferV6 = options.AddressFamily == SmbAddressFamilyPreference.PreferIPv6 ||
            (options.AddressFamily != SmbAddressFamilyPreference.PreferIPv4 && addresses[0].AddressFamily == AddressFamily.InterNetworkV6);
        // 交错排列两种地址族，避免将全部优先地址族的地址排在另一地址族之前。
        // 不可达的 IPv6 路由不应导致第一次 IPv4 尝试排在全部 AAAA 记录之后。
        var first = new Queue<IPAddress>(addresses.Where(a => (a.AddressFamily == AddressFamily.InterNetworkV6) == preferV6));
        var second = new Queue<IPAddress>(addresses.Where(a => (a.AddressFamily == AddressFamily.InterNetworkV6) != preferV6));
        var ordered = new List<IPAddress>(addresses.Length);
        while (first.Count + second.Count > 0)
        {
            if (first.TryDequeue(out var a)) ordered.Add(a);
            if (second.TryDequeue(out var b)) ordered.Add(b);
        }
        return ordered.ToArray();
    }

    /// <summary>建立 TCP 连接，取消竞速失败者，并释放所有未被选中的成功连接。</summary>
    /// <param name="host">逻辑目标名称；存在远端覆盖地址时不对该名称执行解析。</param>
    /// <param name="port">目标 TCP 端口。</param>
    /// <param name="options">已经验证的端点、连接竞速和流量类别设置。</param>
    /// <param name="cancellationToken">覆盖整个连接过程的截止时间及调用方取消令牌。</param>
    /// <returns>竞速成功且由调用方持有的已连接套接字。</returns>
    internal static async Task<TcpClient> ConnectTcpAsync(string host, int port, SmbTransportOptions options, CancellationToken cancellationToken)
    {
        var addresses = await ResolveAsync(host, options, cancellationToken).ConfigureAwait(false);
        using var race = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        var errors = new List<Exception>();
        // 固定的本地 TCP 端口不能同时绑定到多个竞速连接尝试。
        if (options.LocalPort != 0)
        {
            foreach (var address in addresses)
            {
                try { return await AttemptAsync(address, port, options, TimeSpan.Zero, cancellationToken).ConfigureAwait(false); }
                catch (Exception ex) when (ex is SocketException or IOException) { errors.Add(ex); }
            }
            throw Failure(errors);
        }
        var tasks = addresses.Select((a, i) => AttemptAsync(a, port, options, options.AddressRaceDelay * i, race.Token)).ToList();
        try
        {
            while (tasks.Count > 0)
            {
                var completed = await Task.WhenAny(tasks).ConfigureAwait(false);
                tasks.Remove(completed);
                try { return await completed.ConfigureAwait(false); }
                catch (Exception ex) when (ex is SocketException or IOException) { errors.Add(ex); }
            }
            throw Failure(errors);
        }
        finally
        {
            await race.CancelAsync().ConfigureAwait(false);
            foreach (var task in tasks)
            {
                try { SmbSocketTrafficClass.Dispose(await task.ConfigureAwait(false)); }
                catch (Exception ex) when (ex is OperationCanceledException or SocketException or IOException or PlatformNotSupportedException or System.ComponentModel.Win32Exception) { }
            }
        }
    }

    /// <summary>创建指定地址族的套接字，按需绑定源端点，建立连接并应用请求的 QoS。</summary>
    /// <param name="address">具体的目标地址。</param>
    /// <param name="port">目标端口。</param>
    /// <param name="options">源地址绑定及 DSCP 配置。</param>
    /// <param name="delay">创建套接字之前用于错开各次尝试的延迟。</param>
    /// <param name="cancellationToken">用于取消延迟和连接操作的令牌。</param>
    /// <returns>已连接的套接字；任何失败都会释放本次尝试创建的套接字。</returns>
    private static async Task<TcpClient> AttemptAsync(IPAddress address, int port, SmbTransportOptions options, TimeSpan delay, CancellationToken cancellationToken)
    {
        if (delay > TimeSpan.Zero) await Task.Delay(delay, cancellationToken).ConfigureAwait(false);
        var tcp = new TcpClient(address.AddressFamily) { NoDelay = true };
        try
        {
            if (options.LocalAddress is not null || options.LocalPort != 0)
                tcp.Client.Bind(new IPEndPoint(options.LocalAddress ?? (address.AddressFamily == AddressFamily.InterNetworkV6 ? IPAddress.IPv6Any : IPAddress.Any), options.LocalPort));
            await tcp.ConnectAsync(address, port, cancellationToken).ConfigureAwait(false);
            if (options.Dscp is { } dscp) SmbSocketTrafficClass.Apply(tcp.Client, dscp);
            return tcp;
        }
        catch { tcp.Dispose(); throw; }
    }

    /// <summary>单个端点失败时保留原始错误，多个地址失败时保留全部尝试的错误。</summary>
    /// <param name="errors">按观察到的完成顺序记录的端点错误。</param>
    /// <returns>需要向调用方传播的异常。</returns>
    private static Exception Failure(List<Exception> errors) => errors.Count == 1 ? errors[0] : new IOException("No resolved SMB endpoint could be reached.", new AggregateException(errors));
}