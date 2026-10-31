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

namespace MonsterSyncDrive.Library.SMB;

/// <summary>为新发起的请求选择存活传输通道的策略。</summary>
public enum SmbChannelSelectionPolicy
{
    /// <summary>选择当前等待响应请求数最少的通道；并列时轮转分配。</summary>
    LeastOutstanding,
    /// <summary>在当前仍连接的通道间轮转，不按请求数调整。</summary>
    RoundRobin
}

/// <summary>需显式启用的 SMB3 通道绑定选项；通道失败后不会盲目重放既有请求。</summary>
public sealed record SmbMultichannelOptions
{
    /// <summary>是否提供 SMB3 多通道能力并允许绑定附加连接；默认关闭。</summary>
    public bool Enabled
    {
        get; init;
    }
    /// <summary>是否在首次登录后查询服务器接口并自动绑定更多通道；凭据不会持久保存在客户端中。</summary>
    public bool AutoConnect
    {
        get; init;
    }
    /// <summary>会话最多同时使用的通道数，包含主通道；范围 1 至 64，默认 4。</summary>
    public int MaximumChannels { get; init; } = 4;
    /// <summary>为新请求选择通道的策略，不改变已经发送的请求所在的通道。</summary>
    public SmbChannelSelectionPolicy SelectionPolicy { get; init; } = SmbChannelSelectionPolicy.LeastOutstanding;

    /// <summary>验证限制和自动发现开关之间的约束，并创建独立选项快照。</summary>
    /// <returns>验证后的不可变选项副本。</returns>
    /// <exception cref="ArgumentException">通道数、策略或自动发现配置无效。</exception>
    internal SmbMultichannelOptions Validate()
    {
        return MaximumChannels is < 1 or > 64 || !Enum.IsDefined(SelectionPolicy)
            ? throw new ArgumentException("Invalid SMB multichannel limits or selection policy.")
            : AutoConnect && !Enabled
            ? throw new ArgumentException("Automatic channel discovery requires multichannel to be enabled.")
            : (this with
            {
            });
    }
}

/// <summary>NETWORK_INTERFACE_INFO 中由服务器声明的网络接口能力。</summary>
[Flags]
public enum SmbNetworkInterfaceCapabilities : uint
{
    /// <summary>服务器未声明 RSS 或 RDMA 能力。</summary>
    None = 0,
    /// <summary>服务器声明接口支持接收端扩展，允许为此接口建立多个通道。</summary>
    RssCapable = 1,
    /// <summary>服务器声明接口支持 RDMA；实际连接还需要本机可用的 RDMA 提供程序。</summary>
    RdmaCapable = 2
}

/// <summary>服务器声明的网络接口；附加连接仍须通过绑定来验证同一服务器身份。</summary>
/// <param name="InterfaceIndex">服务器端接口索引，不能作为本地 IPv6 区域索引使用。</param>
/// <param name="Capabilities">服务器返回的 RSS 和 RDMA 能力位。</param>
/// <param name="LinkSpeed">服务器声明的接口速率，单位 bit/s。</param>
/// <param name="Address">IPv4 或 IPv6 地址；协议保留的端口、流信息和区域索引均已忽略。</param>
public sealed record SmbNetworkInterfaceInfo(uint InterfaceIndex, SmbNetworkInterfaceCapabilities Capabilities,
    ulong LinkSpeed, IPAddress Address);

/// <summary>属于同一认证 SMB 会话的传输通道状态快照。</summary>
/// <param name="Id">本客户端中的通道标识，主通道为零。</param>
/// <param name="Host">连接目标的地址覆盖值或主机名。</param>
/// <param name="Port">连接使用的配置端口。</param>
/// <param name="IsPrimary">是否为最初建立会话的通道。</param>
/// <param name="IsConnected">获取快照时该连接是否仍可使用。</param>
/// <param name="OutstandingRequests">获取快照时等待服务端响应的请求数。</param>
public sealed record SmbChannelInfo(int Id, string Host, int Port, bool IsPrimary, bool IsConnected, int OutstandingRequests);