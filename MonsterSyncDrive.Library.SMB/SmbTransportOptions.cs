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
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;

namespace MonsterSyncDrive.Library.SMB;

/// <summary>标识用于承载完整 SMB 协议消息的传输方式。</summary>
public enum SmbTransportKind
{
    /// <summary>采用四字节长度前缀的 Direct TCP 传输，默认端口为 445。</summary>
    DirectTcp,
    /// <summary>采用 RFC 1002 定义的 IPv4 会话服务，默认端口为 139。</summary>
    NetBios,
    /// <summary>采用 TLS 1.3、ALPN smb 和单条双向流的 QUIC 传输，默认端口为 443。</summary>
    Quic,
    /// <summary>通过真实 RDMA 提供程序实现 SMB Direct，默认端口为 5445。</summary>
    Rdma
}

/// <summary>在保留逻辑 SMB 服务器名称的前提下筛选并排序解析所得的地址。</summary>
public enum SmbAddressFamilyPreference
{
    /// <summary>使用两种地址族，并按解析器最初的优先顺序交错尝试。</summary>
    Any,
    /// <summary>仅使用 IPv4 地址。</summary>
    IPv4Only,
    /// <summary>仅使用 IPv6 地址。</summary>
    IPv6Only,
    /// <summary>并行竞速尝试两种地址族，首先尝试 IPv4 地址。</summary>
    PreferIPv4,
    /// <summary>并行竞速尝试两种地址族，首先尝试 IPv6 地址。</summary>
    PreferIPv6
}

/// <summary>配置网络端点和传输方式；Host 始终保留为逻辑 SMB 服务器身份。</summary>
public sealed record SmbTransportOptions
{
    /// <summary>获取所选的网络传输方式，默认为 Direct TCP。</summary>
    public SmbTransportKind Kind
    {
        get; init;
    }
    /// <summary>获取可选的目标地址覆盖值；该值不会改变 SMB 服务器身份或 TLS 名称。</summary>
    public IPAddress? RemoteAddress
    {
        get; init;
    }
    /// <summary>获取可选的本地接口地址，仅尝试与其地址族匹配的目标地址。</summary>
    public IPAddress? LocalAddress
    {
        get; init;
    }
    /// <summary>获取源端口；零表示由操作系统分配临时端口。</summary>
    public int LocalPort
    {
        get; init;
    }
    /// <summary>获取 DNS 结果的地址族筛选条件及优先顺序。</summary>
    public SmbAddressFamilyPreference AddressFamily
    {
        get; init;
    }
    /// <summary>获取相互重叠的连接尝试之间的延迟；指定固定源端口时改为顺序尝试。</summary>
    public TimeSpan AddressRaceDelay { get; init; } = TimeSpan.FromMilliseconds(250);
    /// <summary>获取请求的 DSCP 值，范围为 0 至 63；传输方式或平台不支持时明确报错。</summary>
    public int? Dscp
    {
        get; init;
    }
    /// <summary>获取 RFC 1002 主叫名、被叫名及重定向策略。</summary>
    public SmbNetBiosOptions NetBios { get; init; } = new();
    /// <summary>获取 SMB over QUIC 的证书、身份和连接存活检测设置。</summary>
    public SmbQuicOptions Quic { get; init; } = new();
    /// <summary>获取 SMB Direct 设备提供程序及协商传输上限。</summary>
    public SmbDirectOptions Rdma { get; init; } = new();

    /// <summary>获取所选传输方式的标准端口，仅在调用方未显式指定端口时使用。</summary>
    internal int DefaultPort => Kind switch { SmbTransportKind.NetBios => 139, SmbTransportKind.Quic => 443, SmbTransportKind.Rdma => 5445, _ => 445 };

    /// <summary>验证设置，并为可变地址、证书策略和嵌套选项创建快照。</summary>
    /// <param name="host">逻辑 SMB 主机名称，保留用于身份认证和证书名称验证。</param>
    /// <returns>由连接持有的配置快照。</returns>
    /// <exception cref="ArgumentException">枚举值、名称或传输方式与地址族的组合无效。</exception>
    /// <exception cref="ArgumentOutOfRangeException">端口、DSCP 值或重试延迟超出支持范围。</exception>
    internal SmbTransportOptions Validate(string host)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(host);
        if (!Enum.IsDefined(Kind) || !Enum.IsDefined(AddressFamily))
            throw new ArgumentException("Unknown SMB transport or address family.");
        if (LocalPort is < 0 or > 65535)
            throw new ArgumentOutOfRangeException(nameof(LocalPort));
        if (Dscp is < 0 or > 63)
            throw new ArgumentOutOfRangeException(nameof(Dscp));
        if (AddressRaceDelay < TimeSpan.Zero || AddressRaceDelay > TimeSpan.FromMinutes(1))
            throw new ArgumentOutOfRangeException(nameof(AddressRaceDelay));
        ArgumentNullException.ThrowIfNull(NetBios);
        ArgumentNullException.ThrowIfNull(Quic);
        ArgumentNullException.ThrowIfNull(Rdma);
        return Kind == SmbTransportKind.NetBios && (AddressFamily == SmbAddressFamilyPreference.IPv6Only || RemoteAddress?.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6 || LocalAddress?.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6)
            ? throw new ArgumentException("RFC 1002 NetBIOS Session Service requires IPv4.")
            : (this with
            {
                RemoteAddress = Copy(RemoteAddress),
                LocalAddress = Copy(LocalAddress),
                NetBios = NetBios.Validate(),
                Quic = Quic.Validate(),
                Rdma = Rdma.Validate()
            });
    }

    /// <summary>复制地址及其可变的 IPv6 作用域标识符，使副本由连接独立持有。</summary>
    /// <param name="address">需要创建快照的地址，也可以为 null。</param>
    /// <returns>独立的地址实例；输入为 null 时返回 null。</returns>
    private static IPAddress? Copy(IPAddress? address)
    {
        return address is null ? null : IPAddress.Parse(address.ToString());
    }
}

/// <summary>配置 RFC 1002 会话名称、DNS 风格作用域和有次数限制的服务器重定向。</summary>
public sealed record SmbNetBiosOptions
{
    /// <summary>获取服务器的 NetBIOS 基础名称；默认通配名称可被 SMB 服务器识别。</summary>
    public string CalledName { get; init; } = "*SMBSERVER";
    /// <summary>获取服务器名称的第十六个字节；0x20 表示文件服务器服务。</summary>
    public byte CalledNameSuffix { get; init; } = 0x20;
    /// <summary>获取可选的完整 16 字节服务器名称，覆盖 CalledName 及其服务后缀。</summary>
    public ReadOnlyMemory<byte>? CalledNameBytes
    {
        get; init;
    }
    /// <summary>获取会话请求中发送的客户端 NetBIOS 基础名称。</summary>
    public string CallingName { get; init; } = "MONSTERSYNC";
    /// <summary>获取客户端名称的第十六个字节；零表示工作站服务。</summary>
    public byte CallingNameSuffix
    {
        get; init;
    }
    /// <summary>获取可选的完整 16 字节客户端名称，覆盖 CallingName 及其服务后缀。</summary>
    public ReadOnlyMemory<byte>? CallingNameBytes
    {
        get; init;
    }
    /// <summary>获取追加在两个第一级编码名称之后的可选 DNS 标签作用域。</summary>
    public string Scope { get; init; } = "";
    /// <summary>获取是否跟随服务器请求的重定向；调用方明确允许之前始终禁用。</summary>
    public bool AllowRetarget
    {
        get; init;
    }
    /// <summary>获取原始连接之外最多允许建立的重定向连接数。</summary>
    public int MaximumRetargets { get; init; } = 3;
    /// <summary>获取对服务器请求的 IPv4 重定向施加的可选附加限制。</summary>
    public Func<IPEndPoint, bool>? RetargetPolicy
    {
        get; init;
    }

    /// <summary>验证编码名称，并为可选原始字节创建快照，防止连接建立后被外部修改。</summary>
    /// <returns>独立的选项快照。</returns>
    internal SmbNetBiosOptions Validate()
    {
        _ = CalledNameBytes is { } called ? NetBiosSession.EncodeName(called.Span, Scope) : NetBiosSession.EncodeName(CalledName, CalledNameSuffix, Scope);
        _ = CallingNameBytes is { } calling ? NetBiosSession.EncodeName(calling.Span, Scope) : NetBiosSession.EncodeName(CallingName, CallingNameSuffix, Scope);
        return MaximumRetargets is < 0 or > 16
            ? throw new ArgumentOutOfRangeException(nameof(MaximumRetargets))
            : (this with
            {
                CalledNameBytes = CalledNameBytes is { } rawCalled ? new ReadOnlyMemory<byte>(rawCalled.ToArray()) : (ReadOnlyMemory<byte>?)null,
                CallingNameBytes = CallingNameBytes is { } rawCalling ? new ReadOnlyMemory<byte>(rawCalling.ToArray()) : (ReadOnlyMemory<byte>?)null
            });
    }
}

/// <summary>配置单条 SMB over QUIC 双向流的 TLS 设置，ALPN 为 smb。</summary>
public sealed record SmbQuicOptions
{
    /// <summary>获取 TLS 证书名称；即使配置了 RemoteAddress，默认仍使用逻辑 SMB Host。</summary>
    public string? ServerName
    {
        get; init;
    }
    /// <summary>获取可选的客户端证书；要求双向 TLS 认证时，证书应包含私钥。</summary>
    /// <remarks>集合会创建快照；证书实例仍由调用方持有，必须在连接建立期间保持有效。</remarks>
    public X509CertificateCollection? ClientCertificates
    {
        get; init;
    }
    /// <summary>获取显式提供的证书验证回调；null 表示保留平台信任和主机名检查。</summary>
    public RemoteCertificateValidationCallback? RemoteCertificateValidationCallback
    {
        get; init;
    }
    /// <summary>获取可选的自定义证书链策略，例如应用专用信任存储。</summary>
    public X509ChainPolicy? CertificateChainPolicy
    {
        get; init;
    }
    /// <summary>获取未指定自定义证书链策略时使用的平台吊销检查模式。</summary>
    public X509RevocationMode CertificateRevocationCheckMode { get; init; } = X509RevocationMode.Online;
    /// <summary>获取连接空闲超时；无限值表示不施加应用层的空闲截止时间。</summary>
    public TimeSpan IdleTimeout { get; init; } = Timeout.InfiniteTimeSpan;
    /// <summary>获取 QUIC 保活间隔；零表示禁用传输层的周期保活。</summary>
    public TimeSpan KeepAliveInterval { get; init; } = TimeSpan.FromSeconds(30);

    /// <summary>验证 TLS 设置，并为证书集合和证书链策略创建快照。</summary>
    /// <returns>由连接持有的配置快照。</returns>
    internal SmbQuicOptions Validate()
    {
        if (ServerName is not null && (string.IsNullOrWhiteSpace(ServerName) || ServerName.IndexOfAny(['\0', '/', '\\']) >= 0))
            throw new ArgumentException("Invalid TLS server name.");
        if (!Enum.IsDefined(CertificateRevocationCheckMode))
            throw new ArgumentException("Invalid certificate revocation mode.");
        return IdleTimeout != Timeout.InfiniteTimeSpan && IdleTimeout < TimeSpan.Zero
            ? throw new ArgumentOutOfRangeException(nameof(IdleTimeout))
            : KeepAliveInterval < TimeSpan.Zero || KeepAliveInterval > TimeSpan.FromDays(1)
            ? throw new ArgumentOutOfRangeException(nameof(KeepAliveInterval))
            : (this with
            {
                ClientCertificates = ClientCertificates is null ? null : new X509CertificateCollection(ClientCertificates),
                CertificateChainPolicy = CertificateChainPolicy?.Clone()
            });
    }
}

/// <summary>保留在 SMB 协商开始之前返回的 RFC 1002 会话拒绝原因。</summary>
public sealed class SmbNetBiosException : IOException
{
    /// <summary>获取服务器返回的单字节拒绝原因，包括当前无法识别的将来扩展值。</summary>
    public byte ErrorCode
    {
        get;
    }
    /// <summary>创建异常，并保留服务器返回的会话拒绝状态码。</summary>
    /// <param name="code">未经修改的 RFC 1002 错误字节。</param>
    internal SmbNetBiosException(byte code) : base($"NetBIOS session rejected: 0x{code:X2} ({Describe(code)}).")
    {
        ErrorCode = code;
    }

    /// <summary>将标准拒绝原因映射为诊断文本，同时保留对未知值的描述。</summary>
    /// <param name="code">未经修改的拒绝原因。</param>
    /// <returns>简短的诊断说明。</returns>
    private static string Describe(byte code)
    {
        return code switch
        {
            0x80 => "not listening on called name",
            0x81 => "not listening for calling name",
            0x82 => "called name not present",
            0x83 => "insufficient resources",
            0x8F => "unspecified error",
            _ => "unknown rejection"
        };
    }
}