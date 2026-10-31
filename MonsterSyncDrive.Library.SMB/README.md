# MonsterSyncDrive.SMB

面向 .NET 10 的 SMB2/SMB3 客户端。使用托管协议实现，不依赖系统挂载、反射序列化或动态代码生成；库没有 NuGet 包依赖，测试使用微软 MSTest。常规 TCP、文件操作、签名、加密和编解码可跨平台使用，Native AOT 通过独立工程实际发布验证。

实现范围及尚未实现的协议能力见 [SMB 功能对照表](SMB_FEATURE_MATRIX.md)。真实服务器结果见[测试记录](../Test.MonsterSyncDrive.SMB/REAL_SERVER_TEST_RESULTS.md)。可选能力需要服务端、文件系统和当前身份共同支持，库保留明确的 NTSTATUS，不将不支持或权限拒绝当作成功。

## 工程

| 工程 | 用途 |
| --- | --- |
| MonsterSyncDrive.SMB | 客户端库，启用 AOT、裁剪和 XML 文档检查 |
| Test.MonsterSyncDrive.SMB | 密码学、编解码、真实传输回环及可选真实服务器测试 |
| Test.MonsterSyncDrive.SMB.AotSmoke | 实际发布运行的 Native AOT 验证程序 |
| MonsterSyncDrive.SMB.slnx | 只包含上述三个工程的独立解决方案 |

测试工程位于解决方案的 `200.测试工程` 文件夹内。新增功能独立实现，不依赖其他协议工程的客户端方案。

## 标准扩展

| 能力 | 当前实现与边界 |
| --- | --- |
| 地址连接 | DNS、IPv4、IPv6、地址族选择、目的地址覆盖、源地址和端口绑定 |
| NetBIOS Session Service | 名称与 scope 编码、原始 16 字节名称、正负握手、受控 retarget、keepalive、17 位长度；适用 SMB 2.0.2 至 3.0.2 |
| SMB over QUIC | SMB 3.1.1、TLS 1.3、smb ALPN、一个双向流、服务器证书验证和可选客户端证书 |
| SMB Direct | MS-SMBD 协商、credit、分片、保活、注册内存；内置 64 位 Windows NetworkDirect v2，其他系统可提供原生 RDMA 提供程序 |
| Multichannel | 同一会话的签名绑定、独立通道密钥、共享会话加密密钥、接口发现、轮转或最少待处理请求调度、失效通道处理 |
| 打开语义 | 顺序、随机、无缓冲、备份意图；冲突校验及远端逻辑扇区对齐校验 |
| 分配大小 | 请求与实际报告值、EOF、严格报告核对、仅增长接口；不将服务器接受请求等同于物理空间保证 |
| 配额 | 专用配额控制流、SID、分页与按 SID 查询、显式修改删除；卷默认值与可写控制位 |
| Oplock | None、Level II、Exclusive、Batch、主动撤销与确认、应用回调、CREATE 注册竞争处理 |
| 网络压缩 | LZNT1、LZ77、LZ77+Huffman、Pattern V1、LZ4；链式及非链式、原始尺寸限制、实际算法统计 |
| 应用 QoS | 上传下载独立限速、突发额度、跨通道并发限制、加权优先级和取消；TCP 支持可选 DSCP |
| 文件信息 | 全部 53 个标准类的用途目录；远程适用类提供类型化接口，含 11 种目录格式、EA、管道、名称、文件 ID 与扩展设置 |

多通道当前使用 AES-CMAC 或 HMAC-SHA256，明确排除 GMAC 绑定组合，避免会话签名密钥和重复连接消息号引起 nonce 重用；GMAC-only 配置会明确失败。单通道 AES-GMAC 保持支持。

SMB Direct 的内置原生后端限定于 64 位 Windows，Linux/macOS 没有随库提供 verbs 后端。真实 NIC、驱动和服务器互操作需要单独的硬件测试；受控完成提供程序测试不能代替硬件证明。签名、加密或压缩要求与直接放置不兼容时保留正常受保护的 SEND/RECEIVE 路径。

当前仍不包含 SMB1、NTLMv1、Kerberos/系统单点登录、DFS 自动转介、lease 缓存、durable/persistent handle 自动恢复、Compound、操作系统盘符挂载或完整打印/RPC 管理客户端。通道内断线不会盲目重放可能已执行的写入、重命名或删除。

## 基础连接和文件传输

```csharp
using MonsterSyncDrive.SMB;

var credential = new SmbCredential(
    "user",
    Environment.GetEnvironmentVariable("SMB_PASSWORD")
        ?? throw new InvalidOperationException("请设置 SMB_PASSWORD"),
    "DOMAIN");

var options = new SmbClientOptions
{
    Host = "files.example.com",
    MinimumDialect = SmbDialect.Smb210,
    Signing = SmbSigningMode.Required,
    Encryption = SmbEncryptionPolicy.WhenAvailable
};

await using var client = await SmbClient.ConnectAsync(options, credential);
await using var share = await client.ConnectShareAsync("documents");
await share.CreateDirectoryAsync("reports");

using var source = new MemoryStream("内容"u8.ToArray());
await share.UploadAsync("reports/result.txt", source);
using var destination = new MemoryStream();
await share.DownloadAsync("reports/result.txt", destination);

await foreach (var entry in share.EnumerateDirectoryAsync("reports", "*.txt"))
    Console.WriteLine(entry.Name);
```

同名共享复用底层 tree，并返回独立使用对象；释放一个对象只关闭其自己打开的句柄。最后一个使用对象释放时才断开 tree。释放客户端则结束整个认证会话及全部通道。

## 地址和传输

逻辑 `Host` 用于 SMB 身份和共享路径，`Transport.RemoteAddress` 用于选择实际网络目的地。源地址应与目的地址族一致。默认端口随传输选择为 TCP 445、NetBIOS 139、QUIC 443、RDMA 5445；显式设置的 `Port` 始终作为覆盖值。

```csharp
using System.Net;

var pinnedAddress = options with
{
    Transport = new SmbTransportOptions
    {
        RemoteAddress = IPAddress.Parse("192.0.2.10"),
        AddressFamily = SmbAddressFamilyPreference.PreferIPv4
    }
};

var ipv6 = options with
{
    Host = "2001:db8::10",
    Transport = new SmbTransportOptions
    {
        AddressFamily = SmbAddressFamilyPreference.IPv6Only,
        LocalAddress = IPAddress.IPv6Any
    }
};
```

NetBIOS 建立单独的 RFC 1002 会话，retarget 默认关闭，启用后还受次数、循环和目的地策略约束。Windows 不接受 NetBIOS 上的 SMB 加密变换，因此此传输使用签名，`Encryption.Required` 会在连接前失败。

```csharp
var netbios = options with
{
    MaximumDialect = SmbDialect.Smb302,
    Encryption = SmbEncryptionPolicy.Disabled,
    Transport = new SmbTransportOptions
    {
        Kind = SmbTransportKind.NetBios,
        NetBios = new SmbNetBiosOptions
        {
            CalledName = "FILESERVER",
            CallingName = "MONSTERSYNC"
        }
    }
};
```

QUIC 保持默认证书链和名称验证，不自动信任任意证书。可使用 `CertificateChainPolicy` 配置专用根，或通过 `ClientCertificates` 提供客户端证书；回调中的自定义放行由调用方负责。

```csharp
var quic = options with
{
    MinimumDialect = SmbDialect.Smb311,
    MaximumDialect = SmbDialect.Smb311,
    Transport = new SmbTransportOptions
    {
        Kind = SmbTransportKind.Quic,
        Quic = new SmbQuicOptions { ServerName = "files.example.com" }
    }
};
```

QUIC 需要当前平台的 .NET QUIC 支持与原生依赖。请求平台无法提供的 DSCP、传输或加密能力时明确失败。

## SMB Direct 与 RDMA

```csharp
var rdma = options with
{
    MinimumDialect = SmbDialect.Smb300,
    Transport = new SmbTransportOptions
    {
        Kind = SmbTransportKind.Rdma,
        Rdma = new SmbDirectOptions()
    }
};
```

Windows 下未指定 `Provider` 时自动选择内置 `SmbNetworkDirectProvider`，需要 RDMA 网卡及 NetworkDirect v2 驱动。`IsSupported` 只表达操作系统与进程 ABI 条件；`GetAvailableProviders()` 只读取已安装的驱动目录，二者都不能证明硬件数据传输成功。

其他平台可实现 `ISmbRdmaProvider` / `ISmbRdmaEndpoint` 并配置到 `SmbDirectOptions.Provider`。提供程序必须实际建立 RDMA 队列和注册内存，不能用普通 TCP 数据伪装。注册内存、取消、flush 和注销的完成时序属于内存安全边界。

标准 RDMA 直接放置路径必须将注册、描述符和 SMB 请求固定到同一个队列对，并在取消后先关闭、排空该通道再解除注册。普通消息签名、加密或网络压缩生效时采用 SEND/RECEIVE，保持已经选择的完整性和保密策略。RDMA 不协商 SMB 网络压缩。

## 多通道

```csharp
var parallel = options with
{
    Multichannel = new SmbMultichannelOptions
    {
        Enabled = true,
        AutoConnect = true,
        MaximumChannels = 4,
        SelectionPolicy = SmbChannelSelectionPolicy.LeastOutstanding
    }
};
await using var parallelClient = await SmbClient.ConnectAsync(parallel, credential);
Console.WriteLine(parallelClient.Channels.Count);
```

也可调用 `AddChannelAsync` 显式绑定地址。服务器必须声明 Multichannel；附加通道必须匹配服务器 GUID、版本、安全能力和用户身份。发现结果中的保留端口不会替换原端口，IPv6 的远端 scope 也不会当作本地接口 scope。

绑定使用原会话签名密钥，完成后切换到新通道签名密钥；加密方向密钥和 nonce 分配空间属于整个会话。通道故障后维护共享 `ChannelSequence`，新请求可选择存活通道，原有句柄继续属于同一会话；已经失败的请求不自动重放。没有替代通道时调用方需要重新建立客户端。

## 打开选项和分配大小

```csharp
var open = SmbOpenSemantics.ForWrite(
    disposition: SmbCreateDisposition.OpenIf,
    pattern: SmbAccessPattern.Sequential,
    buffering: SmbBufferingMode.Unbuffered,
    backupIntent: true);

await using var file = await share.OpenFileAsync("aligned.bin", open);
var geometry = await file.GetSectorSizeInformationAsync();
var block = new byte[checked((int)geometry.LogicalBytesPerSector)];
await file.WriteAllAsync(block, 0);

var allocation = await file.EnsureAllocationAsync(1024 * 1024);
Console.WriteLine(allocation.ReportedAllocationMeetsRequest);
```

顺序与随机提示互斥。无缓冲数据操作按远端逻辑扇区校验偏移和长度，整个 `WriteAllAsync` 在发送前检查总范围；本地托管缓冲地址不会作为普通 SMB 文件数据地址发送。扇区查询在旧服务器上可回退到卷空间几何信息。

备份意图只是协议打开选项，服务端仍决定是否授权备份/还原访问。`AllocateAsync` 可以改变分配量，缩小时可能截断 EOF；`EnsureAllocationAsync` 只申请增长。`requireReportedAllocation` 可要求服务端报告值达到请求，否则明确失败；报告值本身仍不等于所有存储实现都作出了物理预留保证。

## 用户和卷配额

用户配额使用专用控制句柄，不使用普通目录句柄：

```csharp
await using var quotas = await share.OpenQuotaControlAsync();
await foreach (var entry in quotas.EnumerateQuotasAsync(maximumEntries: 16))
    Console.WriteLine(entry.SecurityIdentifier);
```

此接口仅为固定的 `$Extend\$Quota:$Q:$INDEX_ALLOCATION` 保留索引流开放内部 CREATE 路径；普通 ADS 路径校验仍保持。`GetQuotaAsync` 和 `GetQuotasAsync` 支持按 SID 查询，`UpdateQuotaAsync` 保留未指定字段，`DeleteQuotaAsync` 显式删除。修改必须使用 `OpenQuotaControlAsync(writable: true)` 并满足服务端权限。

配额 `-1` 表示无限制，`-2` 是删除条目，不能把它作为“保持原值”。SID 按规范混合字节序编解码，不依赖 Windows-only SID 类型。Windows 的该索引流通常只在卷根共享中可达；当前共享不暴露此流时会保留打开错误。

卷默认值与控制信息通过普通卷/目录句柄的 `GetVolumeQuotaControlAsync` / `SetVolumeQuotaControlAsync` 操作。微软规范规定部分执行/重建标志在远程 SET 时由服务端忽略，API 将可写设置和服务器报告状态分开，不声称此请求能够启用服务端配额执行。

## 文件信息友好接口

`SmbFileInformationCatalog.All` 列出 53 个标准类，明确区分文件查询、目录查询、配额、LOCAL 和未指定用途。LOCAL 信息不会伪装成可通过普通网络请求完成。

| 范围 | 主要入口 |
| --- | --- |
| 基础与聚合 | GetBasicInformationAsync、GetStandardInformationAsync、GetAllInformationAsync |
| 标识与名称 | GetFileIdentityAsync、GetInternalFileIndexAsync、GetAlternateNameAsync、GetNormalizedNameAsync |
| 对齐与压缩属性 | GetAlignmentInformationAsync、GetCompressionInformationAsync、GetAttributeTagAsync |
| 模式与位置 | GetFileModeAsync、SetFileModeAsync、GetServerPositionAsync、SetServerPositionAsync |
| 扩展设置 | SetShortNameAsync、SetValidDataLengthAsync、SetDispositionAsync、RenameExtendedAsync |
| 扩展属性 | EA 查询分页接口、SetExtendedAttributesAsync |
| 管道 | Get/SetPipeInformationAsync、GetPipeLocalInformationAsync、GetPipeRemoteInformationAsync |
| 目录 | QueryDirectoryPageAsync 与 SmbDirectoryQuery，支持 11 种结果格式 |

```csharp
var basic = await file.GetBasicInformationAsync();
var identity = await file.GetFileIdentityAsync();

await using var directory = await share.OpenFileAsync("", new SmbOpenOptions
{
    Access = SmbAccessMask.ReadData | SmbAccessMask.ReadAttributes,
    CreateOptions = SmbCreateOptions.DirectoryFile
});
var page = await directory.QueryDirectoryPageAsync(new SmbDirectoryQuery
{
    Pattern = "*",
    RestartScan = true,
    InformationClass = SmbDirectoryInformationClass.IdBothDirectory
});
```

目录查询和普通 QUERY_INFO 有不同命令布局。默认页不超过一个 credit，显式大事务受服务器、Large MTU 和承载限制；最大 65535 字节 EA 值可在支持多 credit 的服务器上处理。Stream.Position 是库内游标，服务端位置字段通过独立类型化接口读写。

## Oplock 和通知

在 `SmbOpenOptions.RequestedOplockLevel` 申请 None、Level II、Exclusive 或 Batch。服务器可授予更低级别，实际值从句柄 `OplockLevel` 读取。库没有本地文件缓存，默认撤销处理直接确认；应用存在缓存时应在 `OplockBreakHandler` 中先完成刷新/作废，再返回确认级别。

接收循环只分派通知，用户处理和 ACK 不阻塞接收线程。CREATE 回复与句柄登记之间的通知会暂存，并受容量、超时和生命周期约束。关闭句柄或会话失效后等待者得到相应结果。

主动 OPLOCK_BREAK 没有对应请求，客户端 WhenAvailable 主动加密请求的偏好不代表服务器主动通知必须加密。仍分别执行本地 Required、经认证的服务器会话强制加密、以及关联共享的强制加密条件；CREATE 暂存流程也保留实际加密状态。按 MS-SMB2 规定对全 1 消息号的主动通知跳过普通签名流程，普通响应的强制签名校验保持不变。

目录 `NotifyChangesAsync` 提供单次变化批次、子树、过滤、取消和需要重扫标志。调用方需要再次订阅；它不承诺持久事件队列或断线补偿扫描。

## 网络压缩与实际统计

```csharp
var compressed = options with
{
    Compression = new SmbCompressionOptions
    {
        Enabled = true,
        Algorithms = [SmbCompressionAlgorithm.Lz77Huffman, SmbCompressionAlgorithm.Lz4],
        AllowChained = true
    }
};
await using var compressedClient = await SmbClient.ConnectAsync(compressed, credential);
Console.WriteLine(compressedClient.ConnectionInfo.CompressionAlgorithms.Count);
Console.WriteLine(compressedClient.CompressionStatistics.CompressedMessagesReceived);
```

发送顺序为签名、压缩、加密；接收先解密和解压，再校验普通 SMB 消息。磁盘 READ 在合格通道上设置请求压缩标志。未协商算法、无效链、尺寸溢出和解压炸弹会被拒绝。

启用配置不代表服务器实际使用压缩。`ConnectionInfo.CompressionAlgorithms` 返回协商结果，`CompressionStatistics` 返回实际压缩消息、前后字节数和非空数据使用过的算法集合；只读当前通道集合的统计，不将未压缩回退算成压缩成功。网络压缩与 NTFS 文件系统压缩分别处理。

## 应用限速和 QoS

```csharp
var limited = options with
{
    Qos = new SmbQosOptions
    {
        UploadBytesPerSecond = 8 * 1024 * 1024,
        DownloadBytesPerSecond = 16 * 1024 * 1024,
        MaximumConcurrentRequests = 8,
        BurstBytes = 65536
    }
};
using (SmbQosScope.Begin(SmbRequestPriority.High))
{
    // 在该异步调用链中建立的请求使用较高优先级。
}
```

文件字节预算按实际确认的写入和交付的读取统计，不将短写按原请求量虚计；通知、锁等待及必要控制流不会占满普通调度槽。高、普通、低、后台按加权轮转分配，取消排队不会泄漏并发槽。多通道共享同一限速器，不会让每个通道分别获得完整速率。

`Transport.Dscp` 可请求 TCP 流的 DSCP；Windows 使用 QoS2，Linux/macOS 使用本机 traffic class。平台、权限或传输不能提供时明确失败；网络设备是否执行该优先级由网络配置决定。QUIC 的 .NET API 不开放对应底层套接字控制。

## 安全和错误边界

默认必须签名；支持 HMAC-SHA256、AES-CMAC、AES-GMAC 和四种 AES-CCM/GCM 密码套件。SMB 3.1.1 维护 SHA-512 预认证完整性，SMB 3.0/3.0.2 进行安全协商验证。NTLM/SPNEGO 支持额外机制列表 MIC 轮次。

AES-CCM 取决于平台实际能力。密码不进入凭据诊断字符串；`SmbException.Status` 保留原始 NTSTATUS，`ErrorData` 保留载荷，`IsNotFound` 只识别明确的不存在状态。权限错误不会被 ExistsAsync 吞掉。

取消已完整发出的请求会发送 SMB CANCEL，并继续处理服务端最终回复；半帧、签名错误、解密认证失败、非法标识或超时可能终止受影响通道。RDMA 注册内存需要额外完成栅栏，不能在远端仍可能访问时提前解除注册。递归删除只操作明确路径，不主动遍历目录重解析点。

## 构建和测试

```powershell
dotnet build MonsterSyncDrive.SMB.slnx -c Release

# 回归包括真实本机 TCP、IPv6、NetBIOS、QUIC 和受控 RDMA 完成提供程序。
dotnet run --project Test.MonsterSyncDrive.SMB -c Release -- --filter 'TestCategory!=Integration' --no-progress

# 测试目录的 global.json 已启用 Microsoft.Testing.Platform。
Push-Location Test.MonsterSyncDrive.SMB
dotnet test --project Test.MonsterSyncDrive.SMB.csproj -c Release --no-progress
Pop-Location

dotnet publish Test.MonsterSyncDrive.SMB.AotSmoke -c Release -r win-x64 --self-contained
& ./Test.MonsterSyncDrive.SMB.AotSmoke/bin/Release/net10.0/win-x64/publish/Test.MonsterSyncDrive.SMB.AotSmoke.exe
```

AOT 场景实际运行五种协议、可用密码套件、共享枚举、文件流、服务器复制、锁，以及压缩和类型化信息/最大 EA。NetworkDirect 驱动目录读取只作为平台检查，不能算作网卡数据传输验证。Linux/macOS 需在对应系统和原生工具链上发布；CI 配置分别使用 `linux-x64`、`osx-arm64` 和 `win-x64`，配置存在不代表本次已实跑所有系统。

真实服务端测试从环境变量读取凭据，所有普通文件写入限定在指定父目录中新建的随机子目录，完成后验证清理。用户配额只读测试不修改任何用户条目或卷默认值。

| 环境变量 | 含义 |
| --- | --- |
| MONSTERSYNC_SMB_TEST_HOST | 服务器名 |
| MONSTERSYNC_SMB_TEST_SHARE | 目标共享 |
| MONSTERSYNC_SMB_TEST_DIRECTORY | 已存在的测试父目录，可为空 |
| MONSTERSYNC_SMB_TEST_USERNAME | 用户名 |
| MONSTERSYNC_SMB_TEST_PASSWORD | 仅进程环境中的密码 |
| MONSTERSYNC_SMB_TEST_DOMAIN | 域，可省略 |
| MONSTERSYNC_SMB_TEST_PORT | 覆盖 TCP 端口，可省略 |

```powershell
dotnet run --project Test.MonsterSyncDrive.SMB -c Release -- --filter 'TestCategory=Integration&TestCategory!=RdmaHardware' --no-progress
& ./Test.MonsterSyncDrive.SMB.AotSmoke/bin/Release/net10.0/win-x64/publish/Test.MonsterSyncDrive.SMB.AotSmoke.exe --real-server
```

RDMA 硬件测试单独配置 `MONSTERSYNC_SMB_RDMA_HOST`，可选 `MONSTERSYNC_SMB_RDMA_PORT` 和 `MONSTERSYNC_SMB_RDMA_LOCAL_ADDRESS`。没有硬件端点、服务端不声明多通道或压缩、以及可选信息类不可用时明确记为未验证，不当作功能通过。结果写入测试输出的 `TestResults/real-server-*.jsonl`，不包含密码。

## 注释和许可证

所有库源码包含完整 [MIT 许可](LICENSE)，版权声明沿用仓库原文。类型、字段、属性、构造函数、方法和枚举成员具有中文 XML 文档，协议偏移、密码学、状态转换、并发、取消和原生资源边界有中文说明。MIT 许可保留法律原文。

库生成 XML 文档，并将文档缺失等编译警告作为错误；不再屏蔽 CS1591。代码变更后应再次检查私有声明、记录参数和原生结构字段的说明。

## 协议依据

- [MS-SMB2](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/)：SMB2/3 协商、会话、文件命令及扩展。
- [MS-SMBD](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smbd/)：SMB Direct。
- [MS-FSCC](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/)：信息类、配额和 FSCTL。
- [MS-FSA](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fsa/)：文件系统语义和配额控制流。
- [MS-XCA](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-xca/)：LZNT1、XPRESS、Huffman 等编解码。
- [MS-NLMP](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/)：NTLMv2 和 MIC。
- [MS-SRVS](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-srvs/)：共享枚举。
- [RFC 1002](https://www.rfc-editor.org/rfc/rfc1002)：NetBIOS Session Service。

