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
using System.Security.Cryptography;

namespace MonsterSyncDrive.SMB;


/// <summary>SMB2/3 线上协议版本号；数值直接写入 NEGOTIATE 的 dialect 数组。</summary>
public enum SmbDialect : ushort
{

    /// <summary>SMB 2.0.2；不使用多 credit 和 SMB3 加密。</summary>
    Smb202 = 0x0202,

    /// <summary>SMB 2.1；可协商 Large MTU。</summary>
    Smb210 = 0x0210,

    /// <summary>SMB 3.0；支持 AES-CCM 和会话绑定等能力。</summary>
    Smb300 = 0x0300,

    /// <summary>SMB 3.0.2 协议版本。</summary>
    Smb302 = 0x0302,

    /// <summary>SMB 3.1.1；支持预认证完整性、算法上下文和可选网络压缩。</summary>
    Smb311 = 0x0311
}


/// <summary>请求和响应签名策略；服务器要求签名时不能以客户端配置绕过。</summary>
public enum SmbSigningMode
{
    /// <summary>对认证后的消息启用签名，同时遵守服务器必须签名的要求。</summary>
    Enabled,
    /// <summary>要求签名；不接受无法提供消息完整性的会话。</summary>
    Required,
    /// <summary>关闭常规 SMB 签名；服务器要求签名时连接失败。</summary>
    Disabled
}

/// <summary>SMB 消息加密策略，与 QUIC 的 TLS 传输加密分别处理。</summary>
public enum SmbEncryptionPolicy
{
    /// <summary>双方和当前传输支持 SMB 加密时启用，否则仍遵守签名策略。</summary>
    WhenAvailable,
    /// <summary>必须使用 SMB3 消息加密；无法满足时拒绝连接。</summary>
    Required,
    /// <summary>不启用 SMB 消息加密；强制加密共享会被拒绝。</summary>
    Disabled
}

/// <summary>MS-SMB2 定义的 SMB 3.1.1 加密算法标识。</summary>
public enum SmbEncryptionCipher : ushort
{
    /// <summary>128 位密钥 AES-CCM。</summary>
    Aes128Ccm = 1,
    /// <summary>128 位密钥 AES-GCM。</summary>
    Aes128Gcm = 2,
    /// <summary>256 位密钥 AES-CCM。</summary>
    Aes256Ccm = 3,
    /// <summary>256 位密钥 AES-GCM。</summary>
    Aes256Gcm = 4
}

/// <summary>SMB 消息签名算法；实际算法由协商结果决定。</summary>
public enum SmbSigningAlgorithm : ushort
{
    /// <summary>HMAC-SHA256，线上签名使用摘要的前 16 字节。</summary>
    HmacSha256,
    /// <summary>AES-CMAC；SMB 3.0/3.0.2 的固定签名算法。</summary>
    AesCmac,
    /// <summary>AES-GMAC；以消息号和消息方向构造 nonce。</summary>
    AesGmac
}

/// <summary>连接配置快照；建立套接字之前验证并复制可变集合和嵌套选项。</summary>
public sealed record SmbClientOptions
{

    /// <summary>逻辑 SMB 服务器名或 IP；用于身份和共享路径，可与 Transport.RemoteAddress 的实际连接地址分离。</summary>
    public required string Host { get; init; }

    /// <summary>显式端口覆盖；null 时根据传输类型选择标准端口，避免切换传输后仍沿用 TCP 445。</summary>
    private readonly int? port;
    /// <summary>未显式指定时按传输选择标准端口：TCP 445、NetBIOS 139、QUIC 443、RDMA 5445。</summary>
    public int Port { get => port ?? (Transport?.DefaultPort ?? 445); init => port = value; }

    /// <summary>地址选择、本地绑定、NetBIOS、QUIC 和 RDMA 的独立配置。</summary>
    public SmbTransportOptions Transport { get; init; } = new();

    /// <summary>同一认证会话的多通道发现、数量和调度配置。</summary>
    public SmbMultichannelOptions Multichannel { get; init; } = new();

    /// <summary>SMB 3.1.1 网络压缩配置；只有双方实际协商成功才生效。</summary>
    public SmbCompressionOptions Compression { get; init; } = new();

    /// <summary>同一客户端所有通道共享的文件数据限速和请求调度配置。</summary>
    public SmbQosOptions Qos { get; init; } = new();

    /// <summary>允许协商的最低协议版本；还需满足所选传输的协议限制。</summary>
    public SmbDialect MinimumDialect { get; init; } = SmbDialect.Smb210;

    /// <summary>允许协商的最高协议版本；可与最低值相等来固定版本。</summary>
    public SmbDialect MaximumDialect { get; init; } = SmbDialect.Smb311;

    /// <summary>消息签名策略，默认必须签名。</summary>
    public SmbSigningMode Signing { get; init; } = SmbSigningMode.Required;

    /// <summary>SMB 消息加密策略，默认在可用时启用。</summary>
    public SmbEncryptionPolicy Encryption { get; init; } = SmbEncryptionPolicy.WhenAvailable;
    /// <summary>SMB 3.1.1 加密套件的协商顺序；为空时采用当前平台支持的默认列表。</summary>
    public IReadOnlyList<SmbEncryptionCipher>? EncryptionCiphers { get; init; }
    /// <summary>SMB 3.1.1 签名算法的协商顺序；更早版本采用协议规定的固定算法。</summary>
    public IReadOnlyList<SmbSigningAlgorithm>? SigningAlgorithms { get; init; }

    /// <summary>显式允许服务器返回来宾或匿名会话；仍不能绕过强制签名及加密要求。</summary>
    public bool AllowGuest { get; init; }

    /// <summary>建立底层传输及连接阶段的时间限制；可使用无限超时。</summary>
    public TimeSpan ConnectTimeout { get; init; } = TimeSpan.FromSeconds(15);

    /// <summary>普通请求的响应超时；通知和等待式锁由取消令牌控制。</summary>
    public TimeSpan OperationTimeout { get; init; } = TimeSpan.FromSeconds(60);
    /// <summary>未可信网络消息的字节上限，包含 SMB 加密变换头，独立于服务器声明尺寸。</summary>
    public int MaximumPacketSize { get; init; } = 8 * 1024 * 1024;

    /// <summary>应用传输缓冲上限；实际请求还受协商尺寸、credit 和传输帧限制。</summary>
    public int TransferBufferSize { get; init; } = 1024 * 1024;

    /// <summary>本客户端的稳定连接标识；绑定通道沿用此值，不得为空。</summary>
    public Guid ClientGuid { get; init; } = Guid.NewGuid();


    /// <summary>在建立连接前验证配置并复制可变列表和嵌套选项，避免调用方并发修改协商内容。</summary>
    internal SmbClientOptions Validate()
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(Host);
        if (Host.IndexOfAny(['\\', '/', '\0']) >= 0)
            throw new ArgumentException("Host must be a DNS name or IP address without a path.", nameof(Host));
        ArgumentOutOfRangeException.ThrowIfLessThan(Port, 1);
        ArgumentOutOfRangeException.ThrowIfGreaterThan(Port, 65535);
        if (!Enum.IsDefined(MinimumDialect) || !Enum.IsDefined(MaximumDialect) || MinimumDialect > MaximumDialect)
            throw new ArgumentException("Invalid SMB dialect range.");
        if (!Enum.IsDefined(Signing) || !Enum.IsDefined(Encryption))
            throw new ArgumentException("Invalid security policy.");
        if (Transport?.Kind == SmbTransportKind.NetBios && Encryption == SmbEncryptionPolicy.Required)
            throw new ArgumentException("Required SMB encryption is not supported over NetBIOS Session Service. Use Direct TCP, QUIC or RDMA.");
        ValidateTimeout(ConnectTimeout, nameof(ConnectTimeout));
        ValidateTimeout(OperationTimeout, nameof(OperationTimeout));
        if (MaximumPacketSize is < 65536 + 256 or > 0xFFFFFF)
            throw new ArgumentOutOfRangeException(nameof(MaximumPacketSize));
        if (TransferBufferSize < 4096 || TransferBufferSize > MaximumPacketSize - 256)
            throw new ArgumentOutOfRangeException(nameof(TransferBufferSize));
        if (ClientGuid == Guid.Empty)
            throw new ArgumentException("ClientGuid must not be empty.", nameof(ClientGuid));
        return this with
        {
            Transport = (Transport ?? throw new ArgumentException("Transport options are required.")).Validate(Host),
            Multichannel = (Multichannel ?? throw new ArgumentException("Multichannel options are required.")).Validate(),
            Compression = (Compression ?? throw new ArgumentException("Compression options are required.")).Snapshot(),
            Qos = (Qos ?? throw new ArgumentException("QoS options are required.")).Snapshot(),
            EncryptionCiphers = Snapshot(EncryptionCiphers, nameof(EncryptionCiphers)),
            SigningAlgorithms = Snapshot(SigningAlgorithms, nameof(SigningAlgorithms))
        };
    }


    /// <summary>复制枚举算法列表，并拒绝空列表、重复值及未定义标识。</summary>
    /// <param name="values">调用者给出的算法顺序；null 表示采用默认列表。</param>
    /// <param name="name">无效配置异常中报告的参数名。</param>
    private static T[]? Snapshot<T>(IReadOnlyList<T>? values, string name) where T : struct, Enum
    {
        if (values is null)
            return null;
        var result = values.ToArray();
        if (result.Length == 0 || result.Any(value => !Enum.IsDefined(value)) || result.Distinct().Count() != result.Length)
            throw new ArgumentException("Algorithm offers must contain distinct supported identifiers.", name);
        return result;
    }


    /// <summary>校验可供取消计时器使用的正超时或无限超时。</summary>
    /// <param name="value">待校验的超时。</param>
    /// <param name="name">异常中报告的属性名。</param>
    private static void ValidateTimeout(TimeSpan value, string name)
    {
        if (value != Timeout.InfiniteTimeSpan && (value <= TimeSpan.Zero || value.TotalMilliseconds > uint.MaxValue - 1))
            throw new ArgumentOutOfRangeException(name);
    }
}

/// <summary>NTLMv2 显式或匿名凭据；诊断字符串始终排除密码。</summary>
public sealed class SmbCredential
{

    /// <summary>认证用户名；构造时可从 DOMAIN\user 中拆出域。</summary>
    public string UserName { get; }

    /// <summary>NTLM 认证域；空字符串表示未显式指定。</summary>
    public string Domain { get; }

    /// <summary>仅供 NTLM 运算读取的密码，不进入诊断字符串；调用方应控制凭据对象生命周期。</summary>
    internal string Password { get; }

    /// <summary>是否明确请求匿名身份，而非提供空用户名的普通认证。</summary>
    public bool IsAnonymous { get; }

    /// <summary>无用户名和密码的匿名凭据；服务器策略仍可能拒绝。</summary>
    public static SmbCredential Anonymous { get; } = new("", "", "", true);


    /// <summary>保存显式身份并校验名称，域未单独给出时解析 DOMAIN\user；绝不在异常文本中输出密码。</summary>
    public SmbCredential(string userName, string password, string domain = "")
        : this(userName, password, domain, false) { }


    /// <summary>保存显式身份并校验名称，域未单独给出时解析 DOMAIN\user；绝不在异常文本中输出密码。</summary>
    public SmbCredential(NetworkCredential credential)
        : this((credential ?? throw new ArgumentNullException(nameof(credential))).UserName,
            credential.Password, credential.Domain)
    { }


    /// <summary>保存显式身份并校验名称，域未单独给出时解析 DOMAIN\user；绝不在异常文本中输出密码。</summary>
    private SmbCredential(string userName, string password, string domain, bool anonymous)
    {
        ArgumentNullException.ThrowIfNull(userName);
        ArgumentNullException.ThrowIfNull(password);
        ArgumentNullException.ThrowIfNull(domain);
        if (!anonymous)
            ArgumentException.ThrowIfNullOrWhiteSpace(userName);
        if (userName.Contains('\0') || domain.Contains('\0'))
            throw new ArgumentException("Names must not contain NUL characters.");
        var separator = userName.IndexOf('\\');
        if (separator >= 0 && domain.Length == 0)
        {
            domain = userName[..separator];
            userName = userName[(separator + 1)..];
            ArgumentException.ThrowIfNullOrWhiteSpace(userName);
        }
        UserName = userName;
        Password = password;
        Domain = domain;
        IsAnonymous = anonymous;
    }


    /// <summary>返回用于诊断的域和用户名或匿名标记，不包含密码。</summary>
    public override string ToString() => IsAnonymous ? "(anonymous)" : $"{Domain}\\{UserName}";
}


/// <summary>认证完成后的服务器能力和实际协商快照；支持某协议版本不等于启用了该版本全部可选功能。</summary>
/// <param name="Dialect">实际协商的协议版本。</param>
/// <param name="ServerGuid">服务器在协商回复中给出的 GUID。</param>
/// <param name="MaxReadSize">服务器声明的最大读取数据长度，单位字节。</param>
/// <param name="MaxWriteSize">服务器声明的最大写入数据长度，单位字节。</param>
/// <param name="MaxTransactionSize">服务器声明的信息查询和控制事务上限。</param>
/// <param name="SigningRequired">服务器或本地策略是否要求签名。</param>
/// <param name="EncryptionSupported">当前平台、传输与服务器是否共同支持消息加密。</param>
/// <param name="IsGuest">服务器是否将身份映射为 Guest。</param>
/// <param name="IsAnonymous">会话是否为匿名会话。</param>
public sealed record SmbConnectionInfo(
    SmbDialect Dialect, Guid ServerGuid, int MaxReadSize, int MaxWriteSize,
    int MaxTransactionSize, bool SigningRequired, bool EncryptionSupported,
    bool IsGuest, bool IsAnonymous)
{

    /// <summary>实际协商或由该协议版本规定的签名算法。</summary>
    public SmbSigningAlgorithm SigningAlgorithm { get; init; }

    /// <summary>实际选定的 SMB 加密套件；未协商时为空。</summary>
    public SmbEncryptionCipher? EncryptionCipher { get; init; }

    /// <summary>该会话的常规请求是否使用 SMB 消息加密，不表示 QUIC TLS 状态。</summary>
    public bool IsEncrypted { get; init; }

    /// <summary>建立主会话所使用的传输种类。</summary>
    public SmbTransportKind Transport { get; init; }

    /// <summary>与服务器实际协商成功的压缩算法，未协商时为空列表。</summary>
    public IReadOnlyList<SmbCompressionAlgorithm> CompressionAlgorithms { get; init; } = [];

    /// <summary>双方是否实际协商成功链式压缩。</summary>
    public bool SupportsChainedCompression { get; init; }
}


/// <summary>srvsvc level 1 返回的共享资源信息。</summary>
/// <param name="Name">共享名，不包含服务器前缀。</param>
/// <param name="Type">STYPE 原始类型及附加标志。</param>
/// <param name="Remark">服务器提供的共享备注。</param>
public sealed record SmbShareInfo(string Name, uint Type, string Remark)
{

    /// <summary>共享基础类型是否为磁盘资源。</summary>
    public bool IsDisk => (Type & 0xFFFF) == 0;

    /// <summary>类型含隐藏标志或名称以美元符号结尾。</summary>
    public bool IsHidden => (Type & 0x80000000) != 0 || Name.EndsWith('$');
}


/// <summary>一次上传或下载的应用数据进度，不计 SMB 头和重试控制开销。</summary>
/// <param name="BytesTransferred">已完成传输的文件数据字节数。</param>
/// <param name="TotalBytes">已知总长度；不可定位的源流可能没有总长度。</param>
public sealed record SmbTransferProgress(long BytesTransferred, long? TotalBytes);