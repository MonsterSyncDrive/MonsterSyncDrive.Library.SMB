# SMB 功能与现有实现对照

核对日期：2026-10-26。对象：当前工作区中的 MonsterSyncDrive.Library.SMB、Test.MonsterSyncDrive.SMB 和 Native AOT 验证工程。

当前库具备 SMB2/3 文件访问与安全能力，并补齐本轮要求的传输、打开语义、分配、配额、传统 oplock、压缩、QoS 和类型化文件信息扩展。19个核心命令均有处理路径；Kerberos、DFS、lease、durable等其他可选能力仍按下表区分。命令数量不等于整体功能完成率。

范围包括现代 SMB2/3、SMB1 历史兼容项、微软公开文件系统控制接口、SMB3 POSIX 扩展及常见配套服务。主表按功能族整理；附录列出规范中现有的命令、创建上下文、控制码和信息类。SMB 允许厂商私有 FSCTL 与 RPC 扩展，因此不存在能够穷尽所有厂商功能的固定清单。协议允许的可选操作也不保证每个服务器或文件系统都支持。[MS-SMB2 消息分类和核心命令](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/6eaf6e75-9c23-4eda-be99-c9223c60b181)、[MS-FSCC 远程 FSCTL 列表](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/4dc02779-9d95-43f8-bba4-8d4ce4961458)。

## 状态和实测口径

| 状态 | 含义 |
| --- | --- |
| 已实现 | 存在对应 API 或内部协议处理。是否通过实机另看验证列；不能据此推定全部服务器、参数和平台均已通过。 |
| 部分实现 | 有部分流程或基础设施，但所列能力仍有明确缺口。 |
| 仅原始接口 | 只有 QUERY_INFO、SET_INFO 或 IOCTL 传输入口，缺少该功能的模型、流程和专项验证，不计为功能完成。 |
| 未实现 | 当前源码没有该能力的完整请求和状态处理。 |
| 外部功能 | 主要由服务器、操作系统或上层应用提供，不能直接算作本客户端库的待实现协议功能。 |

主表共 130 个功能族：已实现 73 项；未实现 41 项；部分实现 6 项；仅原始接口 5 项；外部功能 5 项。附录是主表的技术细分，存在交叉，不与主表数量相加，也不换算为完成百分比。

“实机覆盖”表示至少一个相关正向场景经过 `\\Imas\无版本控制\SMB测试` 的真实服务器测试，不代表所有变体全部验证。“回归覆盖”包括受控 TCP 回环服务端、密码学向量及错误场景测试。“实机受限”保留未验证结论，不计为通过。

本轮已新增并执行受控网络、编解码和类型化接口测试，并重跑真实服务器扩展用例。最终数量及 Windows Native AOT 实际发布/运行结果统一记录于[测试报告](../Test.MonsterSyncDrive.SMB/REAL_SERVER_TEST_RESULTS.md)。Imas 未声明多通道、未协商网络压缩，部分目录类和 EA 明确不可用；这些结果单独标为未验证。硬件 RDMA 与 Linux/macOS 的执行状态也单独记录。

## 现有代码入口

| 范围 | 代码 |
| --- | --- |
| 协商、认证、共享和会话 | [SmbClient.cs](SmbClient.cs)、[SmbOptions.cs](SmbOptions.cs) |
| 目录、文件和传输便利 API | [SmbShare.cs](SmbShare.cs)、[SmbFileStream.cs](SmbFileStream.cs) |
| 句柄、信息查询、锁和通知 | [SmbFileHandle.cs](SmbFileHandle.cs)、[SmbTypes.cs](SmbTypes.cs) |
| 复制、数据流、稀疏和重解析点 | [SmbFileHandle.Controls.cs](SmbFileHandle.Controls.cs) |
| 网络和消息校验 | [SmbConnection.cs](Protocol/SmbConnection.cs)、[Wire.cs](Protocol/Wire.cs) |
| 身份认证与加密 | [Security](Security/NtlmV2.cs)、[Spnego.cs](Security/Spnego.cs)、[SmbCryptography.cs](Security/SmbCryptography.cs) |
| 共享 RPC | [ShareEnumeration.cs](Protocol/ShareEnumeration.cs) |
| 工程与验证 | [库工程](MonsterSyncDrive.Library.SMB.csproj)、[测试工程](../Test.MonsterSyncDrive.SMB/Test.MonsterSyncDrive.SMB.csproj)、[AOT 工程](../Test.MonsterSyncDrive.SMB.AotSmoke/Test.MonsterSyncDrive.SMB.AotSmoke.csproj) |

## 协议协商和传输

功能依据：[微软 SMB 功能总览](https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-feature-descriptions)、[MS-SMB2 消息分类和核心命令](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/6eaf6e75-9c23-4eda-be99-c9223c60b181)。实现状态以当前源码为准。

| SMB 能力或相关功能 | 实现状态 | 验证范围 | 当前代码入口 | 边界和缺口 |
| --- | --- | --- | --- | --- |
| SMB 2.0.2、2.1、3.0、3.0.2、3.1.1 | 已实现 | 实机覆盖 | SmbClient.EstablishSessionAsync；SmbDialect | 五个版本均有真实文件往返；协商版本不能代表实现了该版本全部可选功能。 |
| 限制最小和最大协议版本 | 已实现 | 实机覆盖 | SmbClientOptions.MinimumDialect / MaximumDialect | 可固定单一版本。 |
| Direct TCP 连接和自定义 TCP 端口 | 已实现 | 实机默认端口；回环动态端口 | SmbConnection.ConnectAsync；Options.Port | 默认 445；TCP 接口支持指定端口。 |
| 主机名和 IP 地址连接 | 已实现 | IPv4/IPv6/绑定回环通过；Imas 主机名通过 | SmbEndpointConnector；SmbTransportOptions | 支持地址族、远端 IP 覆盖和源地址/端口；逻辑服务器身份单独保留。 |
| NetBIOS Session Service 传输 | 已实现 | 四个允许版本的完整网络回环通过 | NetBiosSession；SmbStreamMessageTransport | 握手、拒绝码、scope、原始名称、retarget、17 位帧长；不支持 SMB3.1.1 或 Windows NetBIOS 消息加密。 |
| SMB over QUIC | 已实现 | 实际 TLS1.3 QUIC 文件回环通过 | SmbQuicTransport；SmbQuicOptions | smb ALPN、一个双向流、证书链和名称验证、可选客户端证书；Imas 未提供 QUIC 测试端点。 |
| SMB Direct 和 RDMA | 已实现 | 协议/ABI/受控提供程序通过；网卡未验证 | SmbDirectConnection；SmbNetworkDirectProvider；SmbFileHandle.Rdma.cs | MS-SMBD、原生 Windows ND2、条件式 READ/WRITE 直接放置；Linux/macOS 原生后端需注入；没有实际 NIC 互操作证明。 |
| SMB Multichannel | 已实现 | 多连接回环通过；Imas 未声明支持 | SmbClient.Multichannel.cs | 同一会话绑定、发现、调度、失败序号；支持 CMAC/HMAC，排除 GMAC 绑定组合。 |
| SMB1 和 CIFS 旧协议 | 未实现 | — | SmbDialect 仅含 SMB2/3 | 当前范围有意不支持；不作为现代 SMB 功能补齐的优先项。 |
| 传输帧大小和协商能力边界检查 | 已实现 | 回归覆盖 | MaximumPacketSize；Wire.ValidateHeader；ParseContexts | 拒绝畸形帧、重复或错误的协商上下文和未提供的算法。 |

## 认证和通信安全

功能依据：[微软 SMB 安全增强](https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-security-hardening)、[微软 SMB 功能总览](https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-feature-descriptions)、[MS-SMB2 消息分类和核心命令](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/6eaf6e75-9c23-4eda-be99-c9223c60b181)。实现状态以当前源码为准。

| SMB 能力或相关功能 | 实现状态 | 验证范围 | 当前代码入口 | 边界和缺口 |
| --- | --- | --- | --- | --- |
| 用户名、密码和域凭据 | 已实现 | 普通账号实机覆盖 | SmbCredential | 可传 DOMAIN\user；没有 AD 域和跨域环境的专项实测。 |
| NTLMv2 | 已实现 | 实机覆盖 | Security/NtlmV2.cs | 使用托管 NTLMv2；不支持 NTLMv1。 |
| SPNEGO 和 NTLM MIC | 已实现 | 实机及回归覆盖 | Security/Spnego.cs；NtlmV2.cs | 包含服务器额外要求机制列表 MIC 的认证轮次。 |
| Kerberos 认证 | 未实现 | — | 认证机制只有 NTLM OID | 没有 Kerberos GSSAPI / SSPI / NegotiateAuthentication 适配。 |
| 系统单点登录和票据缓存 | 未实现 | — | ConnectAsync 需要显式 SmbCredential | 没有集成当前登录身份或票据缓存。 |
| Kerberos 委派与 TLS 通道绑定 | 未实现 | — | 无 Kerberos 委派或 TLS 通道绑定实现 | SMB3 Multichannel 的会话绑定另已实现；此处指认证机制的委派与 TLS CBT。 |
| 匿名和来宾会话 | 已实现 | 未实机验证 | SmbCredential.Anonymous；AllowGuest | 显式开放，并受签名、加密策略约束；没有真实匿名或来宾成功用例。 |
| 阻止 NTLM 并强制 Kerberos | 未实现 | — | 无可替代 NTLM 的认证机制 | 当前不能连接仅允许 Kerberos 的目标。 |
| HMAC-SHA256、AES-CMAC、AES-GMAC 签名 | 已实现 | 实机覆盖 | SmbCryptography；SigningAlgorithms | 三个算法均有强制协商的实机用例；默认要求签名。 |
| 签名完整性验证和篡改拒绝 | 已实现 | 回归覆盖 | SmbCryptography.Verify；ReceiveLoopAsync | 篡改拒绝主要在回环中验证；签名正常路径经过实机。 |
| AES-128/256-CCM 和 AES-128/256-GCM 加密 | 已实现 | 实机覆盖 | SmbCryptography；EncryptionCiphers | 四种密码套件均实机强制协商；平台需提供相应 AES 能力。 |
| 连接和共享的强制加密要求 | 已实现 | 连接策略实机覆盖；共享要求分支未单独实测 | EncryptionPolicy；ConnectNewTreeAsync | 已实现共享 EncryptionRequired 检查；不把未加密能力视为安全降级许可。 |
| SMB 3.1.1 SHA-512 预认证完整性 | 已实现 | 实机及回归覆盖 | PreauthHash；EstablishSessionAsync | 覆盖额外认证轮次及中间回复。 |
| SMB 3.0 和 3.0.2 安全协商验证 | 已实现 | 实机连接路径及回归覆盖 | ValidateNegotiateAsync | 验证协商参数；按协议处理签名的 NotSupported 回复。 |
| 算法列表和优先顺序配置 | 已实现 | 实机覆盖 | EncryptionCiphers；SigningAlgorithms | 适用于 SMB 3.1.1；较早版本使用协议规定的算法。 |
| 同一会话重新认证和身份切换 | 未实现 | — | 只有初次 EstablishSessionAsync | 初次认证的多轮交换不等于会话重新认证。 |
| 同一 TCP 连接承载多个用户会话 | 未实现 | — | SmbConnection 仅维护一个 SessionId 和认证状态 | 可以另建 SmbClient，但没有单连接多会话复用。 |

## 共享和命名空间

功能依据：[MS-SMB2 消息分类和核心命令](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/6eaf6e75-9c23-4eda-be99-c9223c60b181)、[MS-SRVS 共享枚举](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-srvs/c4a98e7b-d416-439c-97bd-4d9f52f8ba52)、[MS-DFSC DFS 转介](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dfsc/7186a5d0-5482-4b1d-b23d-211363b8cde2)。实现状态以当前源码为准。

| SMB 能力或相关功能 | 实现状态 | 验证范围 | 当前代码入口 | 边界和缺口 |
| --- | --- | --- | --- | --- |
| 连接和断开磁盘共享、IPC 共享 | 已实现 | 实机覆盖 | ConnectShareAsync；ReleaseShareAsync | 每次返回独立的共享使用对象。 |
| 枚举服务器共享 | 已实现 | 实机覆盖 | ListSharesAsync；ShareEnumeration.cs | 实现 srvsvc NetrShareEnum level 1、RPC 分片与续页。 |
| 隐藏共享和共享类型识别 | 已实现 | 枚举实机覆盖 | SmbShareInfo.IsHidden / IsDisk；SmbShare.ShareType | 提供名称、类型、备注等信息。 |
| 共享能力、加密标志和最大访问权限 | 已实现 | 真实连接中读取 | SmbShare.Flags / Capabilities / MaximumAccess | 读取服务端返回值；不是共享管理或权限计算器。 |
| 同名共享复用和生命周期管理 | 已实现 | 实机覆盖 | TreeState.References；treeGate | 本地引用计数，与 SMB lease 缓存机制无关。 |
| DFS 根和链接转介 | 未实现 | — | 无 MS-DFSC 客户端 | 识别 PathNotCovered 错误不等于解析和跟随转介。 |
| DFS 转介缓存、目标选择和故障切换 | 未实现 | — | 无 DFS 缓存和目标选择逻辑 | 直接连接已知的最终服务器和共享仍可使用。 |
| 自动处理服务器共享重定向 | 未实现 | — | 错误载荷保留但不自动重定向 | 没有集群重定向和新目标的自动重连流程。 |
| 创建、删除、配置共享 | 未实现 | — | srvsvc 仅实现枚举 | 需要额外 MS-SRVS 管理调用及服务端权限。 |

## 文件和数据传输

功能依据：[MS-SMB2 消息分类和核心命令](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/6eaf6e75-9c23-4eda-be99-c9223c60b181)、[MS-FSCC 文件信息类](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/4718fc40-e539-4014-8e33-b675af74e3e1)、[MS-SMB2 服务器端复制](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/eaa129d1-fca4-46b1-8ccd-b91f3e1d2d80)。实现状态以当前源码为准。

| SMB 能力或相关功能 | 实现状态 | 验证范围 | 当前代码入口 | 边界和缺口 |
| --- | --- | --- | --- | --- |
| 创建、打开、覆盖和 OpenIf 等处置方式 | 已实现 | 实机覆盖 | OpenFileAsync；SmbCreateDisposition | 六种基础处置方式均可表达；Stream 暴露常用 FileMode。 |
| 顺序、随机、无缓冲和备份意图打开选项 | 已实现 | 回归及 Imas 文件用例通过 | SmbOpenSemantics；ValidateUnbufferedIoAsync | 验证互斥和远端扇区对齐；备份意图仍需要服务端授权。 |
| 读写和处理短读、短写、EOF | 已实现 | 实机及回归覆盖 | ReadAsync；WriteAsync；WriteAllAsync | 普通文件单次数据块最多 64 KiB。 |
| 64 位偏移和随机访问 | 已实现 | 实机随机偏移覆盖 | SmbFileHandle 的 long offset | 没有超过 4 GiB 文件和极大偏移的专项实机验证。 |
| 顺序追加 | 已实现 | 实机覆盖 | OpenStreamAsync(FileMode.Append) | 从打开时的文件末尾开始；不提供跨连接原子追加保证。 |
| 跨连接原子追加 | 未实现 | — | Stream 使用固定位置写入 | 需要专门的服务器追加语义及并发验证。 |
| 截断、扩展和 EOF 设置 | 已实现 | 实机覆盖 | SetLengthAsync；SmbFileStream.SetLength | 已测试零填充扩展、截断和 EOF。 |
| 刷新和 WriteThrough 写入 | 已实现 | Flush 实机覆盖；WriteThrough 未专项实测 | FlushAsync；WriteAsync(writeThrough)；CreateOptions.WriteThrough | API 可请求直写；实际持久化保证取决于服务端和存储。 |
| 共享读、写、删除和独占打开 | 已实现 | 实机覆盖 | SmbShareAccess；SmbOpenOptions | 真实共享冲突用例通过。 |
| 共享锁、独占锁、解锁和等待式字节锁 | 已实现 | 实机覆盖 | LockAsync；SmbLockFlags | 真实冲突、解锁、等待取消已覆盖。 |
| 删除文件和 DeleteOnClose | 已实现 | 实机覆盖 | DeleteFileAsync；SetDeletePendingAsync；DeleteOnClose | 能够保留服务端的删除、共享与权限错误。 |
| 重命名、移动和覆盖目标 | 已实现 | 实机覆盖 | MoveAsync；RenameAsync | 没有跨服务器原子移动。 |
| 创建硬链接 | 已实现 | 实机覆盖 | CreateHardLinkAsync | 真实删除原名称后，通过硬链接读取数据成功。 |
| 同步和异步 Stream、Seek、Position | 已实现 | 实机覆盖 | SmbFileStream | 同一流的游标操作串行化；外部长度变化需 RefreshLengthAsync。 |
| 上传、下载和传输进度 | 已实现 | 实机覆盖 | UploadAsync；DownloadAsync；SmbTransferProgress | 支持取消；中止可能留下部分文件。 |
| 客户端文件复制 | 已实现 | 实机覆盖 | CopyFileAsync | 当前复制数据内容，不是完整复制 ACL、时间、ADS 和稀疏布局。 |
| 服务器端 COPYCHUNK 数据复制 | 已实现 | 实机覆盖 | CopyToOnServerAsync | 使用 resume key 和 COPYCHUNK_WRITE；仅同一客户端会话，带块大小限制调整。 |
| 按二进制 FileId 打开 | 未实现 | — | OpenFileAsync 明确拒绝 OpenByFileId | 类型化查询文件 ID 已实现，按 ID 打开是另一种 CREATE 工作流。 |
| 应用级断点续传、自动重试和原子上传 | 未实现 | — | 无持久续传记录、临时提交或自动重试 | 调用方可以利用偏移接口自行构建；当前库没有完整封装。 |

## 目录和变更通知

功能依据：[MS-SMB2 消息分类和核心命令](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/6eaf6e75-9c23-4eda-be99-c9223c60b181)、[MS-FSCC 文件信息类](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/4718fc40-e539-4014-8e33-b675af74e3e1)。实现状态以当前源码为准。

| SMB 能力或相关功能 | 实现状态 | 验证范围 | 当前代码入口 | 边界和缺口 |
| --- | --- | --- | --- | --- |
| 创建目录和递归创建 | 已实现 | 实机覆盖 | CreateDirectoryAsync | 可选择只创建单级。 |
| 目录枚举、通配符和分页 | 已实现 | 实机覆盖 | EnumerateDirectoryAsync | 使用 FileDirectoryInformation；实机测试 320 个长名称条目。 |
| 递归遍历和自动过滤的便利 API | 未实现 | — | 现有枚举针对单一目录 | 调用方可组合实现，但库中没有递归枚举器。 |
| 其他目录信息类和稳定 FileId 枚举 | 已实现 | 11类回归通过；Imas 6类通过、5类不支持 | QueryDirectoryPageAsync；SmbDirectoryQuery | 提供 64/128 位 ID、短名、EA 大小、reparse tag 等类型化字段。 |
| 目录重命名和子树保留 | 已实现 | 实机覆盖 | MoveAsync；RenameAsync | 真实子目录和文件内容保留用例通过。 |
| 非空目录删除和递归删除 | 已实现 | 实机覆盖 | DeleteDirectoryAsync | 递归删除不主动遍历目录重解析点。 |
| 目录变更通知、子树、过滤和取消 | 已实现 | 实机覆盖 | NotifyChangesAsync | 可返回变更批次和 RequiresRescan；调用方需重新发起通知。 |
| 持续监听、自动重订阅和断线后补偿扫描 | 未实现 | — | 仅单次 CHANGE_NOTIFY 请求 | 没有持久 watcher 或断线后的事件补偿。 |

## 元数据和访问控制

功能依据：[MS-FSCC 文件信息类](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/4718fc40-e539-4014-8e33-b675af74e3e1)、[MS-FSCC 文件系统信息类](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/ee12042a-9352-46e3-9f67-c094b75fe6c3)。实现状态以当前源码为准。

| SMB 能力或相关功能 | 实现状态 | 验证范围 | 当前代码入口 | 边界和缺口 |
| --- | --- | --- | --- | --- |
| 文件属性、四类时间、大小和文件索引 | 已实现 | 实机覆盖 | GetInfoAsync；SetBasicInfoAsync | 聚合查询 FileAllInformation；设置 FileBasicInformation。 |
| 卷名称、序列号和文件系统能力 | 已实现 | 实机覆盖 | GetVolumeInfoAsync；GetFileSystemAttributesAsync | 返回服务器所声明的信息。 |
| 总空间、可用空间和调用者可用量 | 已实现 | 实机覆盖 | GetSpaceAsync；SmbFileSystemSpace | 返回值由服务器配额和存储配置决定。 |
| 文件分配大小 | 已实现 | 分配请求和 EOF 实机通过 | GetAllocationInfoAsync；AllocateAsync；EnsureAllocationAsync | 区分请求与实际报告量；可严格要求报告量达到目标，物理预留仍取决于服务端。 |
| 读取 Owner、Group 和 DACL | 已实现 | 实机覆盖 | GetSecurityDescriptorAsync | 返回 self-relative 描述符字节。 |
| 写入 DACL | 已实现 | 实机覆盖 | SetSecurityDescriptorAsync | 实机以原 DACL 回写验证；不代表所有 ACL 变体均已测试。 |
| 修改 Owner、Group、SACL 和安全标签 | 已实现 | 未实机验证 | SmbSecurityInformation；SetSecurityDescriptorAsync | 提供原始描述符传输；需要服务端授权，未做专项实机验证。 |
| ACL、ACE、SID、SDDL 的跨平台对象模型 | 未实现 | — | 没有描述符解析或编辑模型 | 原始安全描述符接口不提供可读权限编辑器或账号名解析。 |
| 扩展属性 EA | 已实现 | 最大值/分页回归通过；Imas 不支持 | EA 分页 API；SetExtendedAttributesAsync | 处理最大65535字节值及多 credit；不把服务端 EAS_NOT_SUPPORTED 算通过。 |
| 用户磁盘配额和卷配额控制 | 已实现 | 回归及 Imas 专用句柄只读查询通过 | OpenQuotaControlAsync；SmbFileHandle.Quotas.cs | 用户条目使用固定配额索引流；默认只读，显式写权限；卷执行标志按规范由服务端控制。 |
| 规范化名称、短名和其他信息类 | 已实现 | 类型化与编解码回归通过 | SmbFileHandle.Information.cs；SmbFileInformationCatalog | 53类逐项分类；所有远程适用类类型化，LOCAL/未指定用途不伪装成网络支持。 |
| 创建时原子附带 ACL、EA 和预分配 | 未实现 | — | CREATE 请求未附加 Create Context | 打开后再设置已有基础接口，但原子创建上下文未实现。 |

## 数据流和高级存储操作

功能依据：[MS-FSCC 远程 FSCTL 列表](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/4dc02779-9d95-43f8-bba4-8d4ce4961458)、[MS-SMB2 IOCTL 请求和控制码](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/5c03c9d6-15de-48a2-9835-8fb37f8a79d8)、[MS-SMB2 CREATE 上下文](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/75364667-3a93-4e2c-b771-592d8d5e876d)、[MS-SMB2 历史版本枚举](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/c631e497-9a47-4537-9817-8af2a4834d03)。实现状态以当前源码为准。

| SMB 能力或相关功能 | 实现状态 | 验证范围 | 当前代码入口 | 边界和缺口 |
| --- | --- | --- | --- | --- |
| 备用数据流 ADS 读写和枚举 | 已实现 | 实机覆盖 | GetStreamsAsync；带 :stream 的路径 | 实机验证默认数据流与备用数据流独立。 |
| 稀疏文件、区间清零和已分配区间 | 已实现 | 实机覆盖 | SetSparseAsync；ZeroRangeAsync；GetAllocatedRangesAsync | 分配区间查询支持继续取页。 |
| 读取、设置和删除 Microsoft 重解析点原始数据 | 已实现 | 实机受限 | GetReparsePointAsync；SetReparsePointAsync；DeleteReparsePointAsync | 创建正向实测未通过；已验证普通文件的错误保留。 |
| 符号链接便利 API 和自动跟随 | 未实现 | — | 无 CreateSymbolicLink / 目标解析与跟随流程 | 原始 reparse API 不等于完整符号链接客户端。 |
| 目录 junction 和第三方 GUID 重解析点 | 未实现 | — | 无 junction 封装；SetReparsePointAsync 限 Microsoft tag | 现有方法不支持 REPARSE_GUID_DATA_BUFFER 的独立 GUID 头。 |
| NTFS 文件系统压缩 | 部分实现 | 类型化查询回归覆盖；设置未实机 | GetCompressionInformationAsync；IoControlAsync | 文件压缩信息查询已类型化；SET_COMPRESSION 仍是原始控制接口，与网络压缩分开。 |
| 完整性流、对象 ID、检索指针和存储区域 | 仅原始接口 | 未实机验证 | IoControlAsync | 没有结果模型和流程；见 FSCTL 明细。 |
| ODX 卸载读写和块克隆 | 仅原始接口 | 未实机验证 | IoControlAsync | 未实现 OFFLOAD_READ / WRITE、DUPLICATE_EXTENTS 的完整流程和模型。 |
| 枚举历史快照 | 仅原始接口 | 未实机验证 | IoControlAsync 可承载 SRV_ENUMERATE_SNAPSHOTS | 没有快照结果解析、缓冲重试及便利 API。 |
| 按历史时间点打开文件 | 未实现 | — | 无 TIMEWARP_TOKEN Create Context | 普通数据文件读取不等于可访问历史版本。 |
| USN 记录和变更日志相关操作 | 仅原始接口 | 未实机验证 | IoControlAsync | 仅是原始控制通道，没有远端变更日志同步流程。 |
| EFS 加密文件和完整备份恢复 | 仅原始接口 | 未实机验证 | 可传原始 SET_ENCRYPTION 等 FSCTL | 没有 EFS 密钥、备份流、RPC 和恢复流程；不能当成 EFS 功能完成。 |
| 远程快照创建和 VSS 协调 | 未实现 | — | 无 MS-FSRVP 客户端 | 属于配套远程快照协议，服务器端须提供相应服务。 |
| 共享虚拟磁盘和 SVHDX 打开上下文 | 未实现 | — | 无 SVHDX_OPEN_DEVICE_CONTEXT / MS-RSVD | 普通文件传输能力不足以声明共享虚拟磁盘协议支持。 |

## 性能和缓存

功能依据：[微软 SMB 功能总览](https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-feature-descriptions)、[MS-SMB2 Compound 请求](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/fa6687f5-99d4-4c9b-ba2e-a770310225e0)、[MS-SMB2 Lease 处理](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/24cfce29-5d80-4651-ba5f-a2661c666b41)、[MS-SMB2 CREATE 上下文](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/75364667-3a93-4e2c-b771-592d8d5e876d)。实现状态以当前源码为准。

| SMB 能力或相关功能 | 实现状态 | 验证范围 | 当前代码入口 | 边界和缺口 |
| --- | --- | --- | --- | --- |
| 同连接并发请求和乱序响应匹配 | 已实现 | 实机及回归覆盖 | SmbConnection.outstanding；MessageId | 多个请求仍复用单一 TCP 连接。 |
| credit 流控和异步 STATUS_PENDING | 已实现 | 实机及回归覆盖 | ReserveAsync；AddCredits；AsyncId | 有 charge 计算，但公开文件 IO 仍受 64 KiB 单块限制。 |
| Large MTU 和多 credit 大块数据传输 | 部分实现 | 最大 EA 多 credit 回归通过 | MaximumTransactionCapacity；credit charge | 显式大元数据事务可用；普通文件数据单块仍最多64 KiB。 |
| Compound 相关和无关操作链 | 未实现 | — | 未构造 NextCommand；Wire 拒绝非零 NextCommand | 没有将 CREATE / QUERY / READ / CLOSE 合并发送的机制。 |
| 传统 oplock 和 OPLOCK_BREAK | 已实现 | 回归及 Imas Exclusive/Batch 通过 | SmbFileHandle.Oplocks.cs；SmbOplockDispatch.cs | 完整撤销、ACK、回调和注册竞争；按规范处理主动通知保护要求，无 lease 缓存。 |
| 文件 lease v1、v2 | 未实现 | — | 无 RqLs Create Context | 没有读、写、句柄缓存租约和 lease break。 |
| 目录 lease 和目录缓存 | 未实现 | — | 无目录 lease 与元数据缓存 | 一次性分页枚举不等于目录缓存。 |
| 客户端预读、写回和缓存一致性 | 未实现 | — | 无 lease/oplock 缓存系统 | Stream 的长度快照不构成文件数据缓存。 |
| SMB 网络压缩 | 已实现 | 五算法及 native codec 交叉回归通过；Imas 未协商 | SmbCompression；SmbCompressionStatistics | 链式/非链式、READ请求标志、实际算法统计；RDMA不协商压缩，未压缩回退不计通过。 |
| BranchCache 哈希检索和内容缓存 | 未实现 | — | 无 SRV_READ_HASH 工作流或内容缓存协议 | 原始 IOCTL 传输不能代替 BranchCache 实现。 |
| 应用级带宽限制和 QoS | 已实现 | 限速/优先级/取消/字节计数回归通过 | SmbQosState；SmbQosScope；SmbSocketTrafficClass | 跨通道共享预算；TCP可选DSCP，QUIC无法提供时明确报错。 |

## 连接可靠性和高可用

功能依据：[MS-SMB2 CREATE 上下文](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/75364667-3a93-4e2c-b771-592d8d5e876d)、[微软 SMB 功能总览](https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-feature-descriptions)、[MS-SWN Witness](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-swn/56681003-0dd3-4fda-adac-121d7166e006)。实现状态以当前源码为准。

| SMB 能力或相关功能 | 实现状态 | 验证范围 | 当前代码入口 | 边界和缺口 |
| --- | --- | --- | --- | --- |
| 连接超时、操作超时和取消 | 已实现 | 实机及回归覆盖 | ConnectTimeout；OperationTimeout；CancellationToken | 等待式锁和通知使用调用方取消；不套用普通操作超时。 |
| SMB CANCEL 和异步取消标识 | 已实现 | 实机覆盖 | SendCancelAsync；AsyncId | 真实通知、等待锁和三种签名算法的 CANCEL 已覆盖。 |
| 断线使等待请求失败和手动新建连接恢复 | 已实现 | 实机覆盖 | Abort；新的 ConnectAsync | 实测中断的是客户端传输；没有服务器重启、网络设备故障或集群故障切换实测。 |
| 自动重连和透明继续文件操作 | 未实现 | — | 没有 reconnect 管理器 | 当前需调用方新建客户端；旧句柄不自动恢复。 |
| Durable Handle v1 和 v2 | 未实现 | — | 无 DHnQ / DHnC / DH2Q / DH2C | 没有持久重连句柄状态。 |
| Persistent Handle 和连续可用共享 | 未实现 | — | 无 persistent 标志及恢复流程 | 共享能力字段可读取，但不代表客户端提供连续可用性。 |
| 请求 replay 和未决操作自动恢复 | 未实现 | — | 无 REPLAY_OPERATION 自动重放流程 | 已维护通道失效的 ChannelSequence；仍不自动重试状态不明的写、删除、重命名。 |
| Resilient Handle | 未实现 | — | 无 LMR_REQUEST_RESILIENCY 工作流 | 原始 FSCTL 发出本身不能建立完整恢复语义。 |
| SMB Transparent Failover | 未实现 | — | 无 persistent / durable 恢复和故障目标处理 | 需要服务端 CA 共享及配套客户端状态。 |
| Witness 故障通知 | 未实现 | — | 无 MS-SWN 客户端 | Witness 是与 SMB 配合使用的独立协议。 |
| Scale-Out 客户端重定向和自动重平衡 | 未实现 | — | 无重定向与节点选择逻辑 | 不能据能打开 SOFS 共享就认定具备全部高级能力。 |
| ECHO 探测与自动保活策略 | 部分实现 | 手动 ECHO 实机通过 | EchoAsync | 没有定时探测、空闲策略和自动重连。 |

## 命名管道和配套服务

功能依据：[MS-SMB2 消息分类和核心命令](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/6eaf6e75-9c23-4eda-be99-c9223c60b181)、[MS-SMB2 IOCTL 请求和控制码](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/5c03c9d6-15de-48a2-9835-8fb37f8a79d8)、[MS-SRVS 共享枚举](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-srvs/c4a98e7b-d416-439c-97bd-4d9f52f8ba52)、[微软打印协议概述](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-prsod/79ee0747-9b77-4497-baab-a679fe8dbcc3)。实现状态以当前源码为准。

| SMB 能力或相关功能 | 实现状态 | 验证范围 | 当前代码入口 | 边界和缺口 |
| --- | --- | --- | --- | --- |
| IPC$ 和命名管道打开、读写、transceive | 已实现 | srvsvc 实机覆盖 | OpenFileAsync；TransceivePipeAsync | 真实覆盖 srvsvc 管道；没有通用管道服务器矩阵。 |
| 命名管道 peek、wait 和模式管理 | 部分实现 | 管道信息类回归通过 | Get/SetPipeInformationAsync；GetPipeLocal/RemoteInformationAsync | 模式已类型化；peek仍原始接口，特殊无句柄wait工作流未实现。 |
| 通用 DCE/RPC 客户端和 NDR64 | 部分实现 | 共享枚举子集实机覆盖 | ShareEnumeration.cs | 只有 srvsvc 绑定、NDR32 和 NetrShareEnum 所需子集。 |
| 服务器信息、会话、打开文件和共享管理 RPC | 未实现 | — | 无相应 MS-SRVS 方法 | ListSharesAsync 不包含这些管理功能。 |
| LSA、SAMR、注册表和服务控制 RPC | 未实现 | — | 无相关 RPC 客户端 | 这些是可借命名管道承载的独立服务协议。 |
| 完整打印共享、打印任务和队列管理 | 未实现 | — | 无打印客户端或 MS-RPRN / MS-PAR 封装 | 识别打印共享类型不足以声明打印功能完成。 |
| 远程 mailslot 和旧式浏览 | 未实现 | — | 无 MS-MAIL / 浏览协议 | 属于历史配套功能；当前不提供。 |

## 服务端能力和工程验证

功能依据：[微软 SMB 功能总览](https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-feature-descriptions)、[SMB3 POSIX 扩展规范](https://smb3posix.org/spec/latest/smb3_posix_extensions.html)。实现状态以当前源码为准。

| SMB 能力或相关功能 | 实现状态 | 验证范围 | 当前代码入口 | 边界和缺口 |
| --- | --- | --- | --- | --- |
| 跨平台的托管实现 | 已实现 | Windows网络实测；其他系统未实跑 | net10.0；平台保护；可注入RDMA接口 | 核心跨平台；QUIC受.NET平台原生支持限制，内置ND2仅64位Windows。 |
| Native AOT | 已实现 | Windows 原生验证结果见报告 | AotSmoke；CompressionSmokeScenario；FileInformationSmokeScenario | 包含压缩、最大EA、类型化信息；Linux/macOS未在当前主机实际发布运行。 |
| 不依赖第三方 NuGet 包 | 已实现 | 工程配置核对 | 库无 PackageReference；测试使用 Microsoft MSTest | 诊断脚本使用 Windows 系统 API，不属于跨平台库的运行依赖。 |
| 原始 NTSTATUS 和错误载荷 | 已实现 | 实机及回归覆盖 | SmbException.Status / ErrorData | 保持服务端错误；不提供全部扩展错误上下文的结构化解析。 |
| 结构化日志、跟踪、指标和性能计数器 | 部分实现 | QoS和压缩统计回归通过 | QosStatistics；CompressionStatistics | 已有应用计数快照，无统一 ILogger / EventSource / Meter 插桩。 |
| SMB3 POSIX 扩展 | 未实现 | — | 无 POSIX 协商和 CREATE Context | 没有 POSIX mode / UID / GID、大小写和 POSIX 删除语义模型。 |
| 共享 ABE、服务端配额、去重和存储布局 | 外部功能 | — | 由服务器或文件系统实现 | 客户端能接收过滤后的目录和配额影响后的空间值，不能将服务端实现计为本库功能。 |
| 服务端认证限速、监听端口和防火墙策略 | 外部功能 | — | 服务器和操作系统配置 | 客户端库不承担服务器角色。 |
| 集群建立、滚动升级和 Scale-Out 部署 | 外部功能 | — | 服务器集群部署 | 客户端需另行实现相应互操作能力，见高可用表。 |
| 盘符挂载、全局映射和离线文件 | 外部功能 | — | 操作系统重定向器与挂载层 | 当前返回 .NET Stream 和文件句柄，不注册操作系统文件系统。 |
| Hyper-V 和 SQL Server 应用集成 | 外部功能 | — | 应用、系统重定向器和服务端联合能力 | 本库不等同于可直接替代操作系统 SMB 重定向器。 |

## 核心命令逐项对照

依据：[MS-SMB2 消息分类和核心命令](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/6eaf6e75-9c23-4eda-be99-c9223c60b181)。代码中的 Command 枚举已覆盖 0x0000 至 0x0012。CREATE 可申请传统 oplock，但未申请 lease；此表的“基本实现”仅描述命令路径。

| 命令值 | 命令 | 状态 | 实现边界 |
| --- | --- | --- | --- |
| 0x0000 | NEGOTIATE | 基本实现 | 版本、签名、加密和预认证协商；没有压缩、POSIX 等扩展协商。 |
| 0x0001 | SESSION_SETUP | 基本实现 | NTLMv2 / SPNEGO及SMB3会话绑定；无Kerberos、TLS CBT及会话重新认证。 |
| 0x0002 | LOGOFF | 基本实现 | 客户端异步释放时注销会话。 |
| 0x0003 | TREE_CONNECT | 基本实现 | 连接共享；无 DFS 和集群转介自动处理。 |
| 0x0004 | TREE_DISCONNECT | 基本实现 | 最后一个共享引用释放时断开。 |
| 0x0005 | CREATE | 基本实现 | 文件、目录、管道基础打开；未附加 CREATE Context。 |
| 0x0006 | CLOSE | 基本实现 | 关闭远端句柄。 |
| 0x0007 | FLUSH | 基本实现 | 发出刷新请求。 |
| 0x0008 | READ | 基本实现 | 短读、EOF、偏移和异步读取；单次最多 64 KiB。 |
| 0x0009 | WRITE | 基本实现 | 短写、偏移、WriteThrough；单次最多 64 KiB。 |
| 0x000A | LOCK | 基本实现 | 共享、独占、解锁及等待取消。 |
| 0x000B | IOCTL | 基本实现 | 已有若干 FSCTL 封装；原始接口并未覆盖所有特殊无句柄形式。 |
| 0x000C | CANCEL | 基本实现 | 同步和异步请求的取消；签名和加密保护。 |
| 0x000D | ECHO | 基本实现 | 提供手动探测 API，无自动保活管理。 |
| 0x000E | QUERY_DIRECTORY | 基本实现 | 支持全部 11 种标准目录信息格式及对应类型化结果。 |
| 0x000F | CHANGE_NOTIFY | 基本实现 | 单次通知、子树、取消和重扫标志。 |
| 0x0010 | QUERY_INFO | 基本实现 | File / FileSystem / Security / Quota 原始信息请求；仅部分有模型。 |
| 0x0011 | SET_INFO | 基本实现 | 基础属性、EOF、分配、名字、链接、安全描述符及原始设置。 |
| 0x0012 | OPLOCK_BREAK | 基本实现 | 传统通知、ACK、回调、加密策略和CREATE登记竞争；无lease break。 |

## 协商上下文逐项对照

依据：[MS-SMB2 NEGOTIATE 上下文](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/15332256-522e-4a53-8cd7-0bd17678a2f7)。当前 BuildNegotiate 构造类型 1、2、5、8，并按传输和选项构造类型3；未知上下文的忽略处理不代表实现对应功能。

| 类型 | 上下文 | 状态 | 当前边界 |
| --- | --- | --- | --- |
| 0x0001 | PREAUTH_INTEGRITY_CAPABILITIES | 已实现 | SHA-512 和随机盐。 |
| 0x0002 | ENCRYPTION_CAPABILITIES | 已实现 | 四种 AES 密码套件，按平台能力提供。 |
| 0x0003 | COMPRESSION_CAPABILITIES | 已实现 | 五算法、链式支持及限制；RDMA不提供此上下文。 |
| 0x0005 | NETNAME_NEGOTIATE_CONTEXT_ID | 已实现 | 发送逻辑服务器名称。 |
| 0x0006 | TRANSPORT_CAPABILITIES | 未实现 | 无相应传输安全能力协商。 |
| 0x0007 | RDMA_TRANSFORM_CAPABILITIES | 未实现 | 无 RDMA transforms。 |
| 0x0008 | SIGNING_CAPABILITIES | 已实现 | HMAC-SHA256、AES-CMAC、AES-GMAC。 |
| 0x0100 | CONTEXTTYPE_RESERVED | 保留项不列缺口 | SMB3 POSIX 扩展另有独立规范，当前库也未实现其协商。 |

## 创建上下文逐项对照

依据：[MS-SMB2 CREATE 上下文](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/75364667-3a93-4e2c-b771-592d8d5e876d)。当前 OpenFileAsync 构造的 CREATE 请求将 CreateContextsOffset / Length 保持为零，未提供任意 CREATE Context 的公开扩展入口。下列 15 个有效标准上下文均未实现；保留项不计缺口。打开后设置 ACL、EA 或分配量不能代替创建时的原子语义。POSIX CREATE Context 另见 [SMB3 POSIX 扩展规范](https://smb3posix.org/spec/latest/smb3_posix_extensions.html)，当前同样未实现。

| 上下文 | 功能 | 状态 |
| --- | --- | --- |
| ExtA | 创建时附带 EA | 未实现 |
| SecD | 创建时附带安全描述符 | 未实现 |
| DHnQ | Durable Handle v1 请求 | 未实现 |
| DHnC | Durable Handle v1 重连 | 未实现 |
| AlSi | 创建时预分配 | 未实现 |
| MxAc | 查询文件最大访问权限 | 未实现 |
| TWrp | 历史时间点打开 | 未实现 |
| QFid | 查询磁盘标识 | 未实现 |
| RqLs v1 | 文件租约 | 未实现 |
| RqLs v2 | 文件或目录租约 | 未实现 |
| DH2Q | Durable / Persistent Handle v2 请求 | 未实现 |
| DH2C | Durable / Persistent Handle v2 重连 | 未实现 |
| APP_INSTANCE_ID | 应用实例标识 | 未实现 |
| APP_INSTANCE_VERSION | 应用实例版本 | 未实现 |
| SVHDX_OPEN_DEVICE_CONTEXT | 共享虚拟磁盘打开上下文 | 未实现 |
| RESERVED | 规范保留值，不是待实现的业务功能 | 不适用 |

## 公共远程 FSCTL 逐项对照

以下 46 个名称及控制码对应 [MS-FSCC 远程 FSCTL 列表](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/4dc02779-9d95-43f8-bba4-8d4ce4961458) 的公共列表。列表外仍可能存在产品扩展。表中的“仅原始接口”表示没有专用数据模型和流程，也没有该项专项实测，不能当成对应功能已实现。

当前 IoControlAsync 依赖一个已打开的 SmbFileHandle，输入输出受 TransactionSize 和 64 KiB 限制，并验证回复 FileId 与句柄一致。需要全 0xFF FileId、特殊树或其他无句柄请求格式的控制码不能直接套用此入口；DFS 和 PIPE_WAIT 仍需要另行实现；网络接口查询已由多通道模块构造专门请求。

| FSCTL | 控制码 | 状态 | 当前入口或缺口 |
| --- | --- | --- | --- |
| FSCTL_CREATE_OR_GET_OBJECT_ID | 0x900c0 | 仅原始接口 | IoControlAsync；无专用封装或专项验证 |
| FSCTL_DELETE_OBJECT_ID | 0x900a0 | 仅原始接口 | IoControlAsync；无专用封装或专项验证 |
| FSCTL_DELETE_REPARSE_POINT | 0x900ac | 已封装，正向未验证 | DeleteReparsePointAsync |
| FSCTL_DUPLICATE_EXTENTS_TO_FILE | 0x98344 | 仅原始接口 | IoControlAsync；无专用封装或专项验证 |
| FSCTL_DUPLICATE_EXTENTS_TO_FILE_EX | 0x983e8 | 仅原始接口 | IoControlAsync；无专用封装或专项验证 |
| FSCTL_FILESYSTEM_GET_STATISTICS | 0x90060 | 仅原始接口 | IoControlAsync；无专用封装或专项验证 |
| FSCTL_FILE_LEVEL_TRIM | 0x98208 | 仅原始接口 | IoControlAsync；无专用封装或专项验证 |
| FSCTL_FIND_FILES_BY_SID | 0x9008f | 仅原始接口 | IoControlAsync；无专用封装或专项验证 |
| FSCTL_GET_COMPRESSION | 0x9003c | 仅原始接口 | IoControlAsync；无专用封装或专项验证 |
| FSCTL_GET_INTEGRITY_INFORMATION | 0x9027c | 仅原始接口 | IoControlAsync；无专用封装或专项验证 |
| FSCTL_GET_NTFS_VOLUME_DATA | 0x90064 | 仅原始接口 | IoControlAsync；无专用封装或专项验证 |
| FSCTL_GET_REFS_VOLUME_DATA | 0x902d8 | 仅原始接口 | IoControlAsync；无专用封装或专项验证 |
| FSCTL_GET_OBJECT_ID | 0x9009c | 仅原始接口 | IoControlAsync；无专用封装或专项验证 |
| FSCTL_GET_REPARSE_POINT | 0x900a8 | 已封装，正向未验证 | GetReparsePointAsync；普通文件错误路径实机通过 |
| FSCTL_GET_RETRIEVAL_POINTER_COUNT | 0x9042b | 仅原始接口 | IoControlAsync；无专用封装或专项验证 |
| FSCTL_GET_RETRIEVAL_POINTERS | 0x90073 | 仅原始接口 | IoControlAsync；无专用封装或专项验证 |
| FSCTL_GET_RETRIEVAL_POINTERS_AND_REFCOUNT | 0x903d3 | 仅原始接口 | IoControlAsync；无专用封装或专项验证 |
| FSCTL_IS_PATHNAME_VALID | 0x9002c | 仅原始接口 | IoControlAsync；无专用封装或专项验证 |
| FSCTL_LMR_SET_LINK_TRACKING_INFORMATION | 0x1400ec | 仅原始接口 | IoControlAsync；无专用封装或专项验证 |
| FSCTL_MARK_HANDLE | 0x900fc | 仅原始接口 | IoControlAsync；无专用封装或专项验证 |
| FSCTL_OFFLOAD_READ | 0x94264 | 仅原始接口 | IoControlAsync；无专用封装或专项验证 |
| FSCTL_OFFLOAD_WRITE | 0x98268 | 仅原始接口 | IoControlAsync；无专用封装或专项验证 |
| FSCTL_PIPE_PEEK | 0x11400c | 仅原始接口 | IoControlAsync；无专用封装或专项验证 |
| FSCTL_PIPE_TRANSCEIVE | 0x11c017 | 已封装，srvsvc 实机覆盖 | TransceivePipeAsync |
| FSCTL_PIPE_WAIT | 0x110018 | 未实现特殊无句柄调用 | 现有公开接口依赖已打开的 SmbFileHandle |
| FSCTL_QUERY_ALLOCATED_RANGES | 0x940cf | 已封装，实机通过 | GetAllocatedRangesAsync |
| FSCTL_QUERY_FAT_BPB | 0x90058 | 仅原始接口 | IoControlAsync；无专用封装或专项验证 |
| FSCTL_QUERY_FILE_REGIONS | 0x90284 | 仅原始接口 | IoControlAsync；无专用封装或专项验证 |
| FSCTL_QUERY_ON_DISK_VOLUME_INFO | 0x9013c | 仅原始接口 | IoControlAsync；无专用封装或专项验证 |
| FSCTL_QUERY_SPARING_INFO | 0x90138 | 仅原始接口 | IoControlAsync；无专用封装或专项验证 |
| FSCTL_READ_FILE_USN_DATA | 0x900eb | 仅原始接口 | IoControlAsync；无专用封装或专项验证 |
| FSCTL_RECALL_FILE | 0x90117 | 仅原始接口 | IoControlAsync；无专用封装或专项验证 |
| FSCTL_REFS_STREAM_SNAPSHOT_MANAGEMENT | 0x90440 | 仅原始接口 | IoControlAsync；无专用封装或专项验证 |
| FSCTL_SET_COMPRESSION | 0x9c040 | 仅原始接口 | IoControlAsync；无专用封装或专项验证 |
| FSCTL_SET_DEFECT_MANAGEMENT | 0x98134 | 仅原始接口 | IoControlAsync；无专用封装或专项验证 |
| FSCTL_SET_ENCRYPTION | 0x900d7 | 仅原始接口 | IoControlAsync；无专用封装或专项验证 |
| FSCTL_SET_INTEGRITY_INFORMATION | 0x9c280 | 仅原始接口 | IoControlAsync；无专用封装或专项验证 |
| FSCTL_SET_INTEGRITY_INFORMATION_EX | 0x90380 | 仅原始接口 | IoControlAsync；无专用封装或专项验证 |
| FSCTL_SET_OBJECT_ID | 0x90098 | 仅原始接口 | IoControlAsync；无专用封装或专项验证 |
| FSCTL_SET_OBJECT_ID_EXTENDED | 0x900bc | 仅原始接口 | IoControlAsync；无专用封装或专项验证 |
| FSCTL_SET_REPARSE_POINT | 0x900a4 | 已封装，实机创建受限 | SetReparsePointAsync；仅 Microsoft tag |
| FSCTL_SET_SPARSE | 0x900c4 | 已封装，实机通过 | SetSparseAsync |
| FSCTL_SET_ZERO_DATA | 0x980c8 | 已封装，实机通过 | ZeroRangeAsync |
| FSCTL_SET_ZERO_ON_DEALLOCATION | 0x90194 | 仅原始接口 | IoControlAsync；无专用封装或专项验证 |
| FSCTL_SIS_COPYFILE | 0x90100 | 仅原始接口 | IoControlAsync；无专用封装或专项验证 |
| FSCTL_WRITE_USN_CLOSE_RECORD | 0x900ef | 仅原始接口 | IoControlAsync；无专用封装或专项验证 |

## SMB 专用及关联 FSCTL 逐项对照

依据：[MS-SMB2 IOCTL 请求和控制码](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/5c03c9d6-15de-48a2-9835-8fb37f8a79d8)。该规范列表 15 项与上表存在部分交叉，不重复计数。

| FSCTL | 控制码 | 状态 | 当前入口或缺口 |
| --- | --- | --- | --- |
| FSCTL_DFS_GET_REFERRALS | 0x00060194 | 未实现 | 无句柄格式、DFS 响应解析、转介处理均缺失 |
| FSCTL_PIPE_PEEK | 0x0011400c | 仅原始接口 | 无专用 peek 模型和流程 |
| FSCTL_PIPE_WAIT | 0x00110018 | 未实现 | 无句柄等待格式未实现 |
| FSCTL_PIPE_TRANSCEIVE | 0x0011c017 | 已封装，实机覆盖 | srvsvc NetrShareEnum 使用 |
| FSCTL_SRV_COPYCHUNK | 0x001440f2 | 仅原始接口 | 便利 API 使用的是 COPYCHUNK_WRITE 变体 |
| FSCTL_SRV_ENUMERATE_SNAPSHOTS | 0x00144064 | 仅原始接口 | 没有快照模型和解析 |
| FSCTL_SRV_REQUEST_RESUME_KEY | 0x00140078 | 内部实现，实机通过 | 服务器端复制获取源文件 key |
| FSCTL_SRV_READ_HASH | 0x001441bb | 仅原始接口 | 无 BranchCache 完整客户端 |
| FSCTL_SRV_COPYCHUNK_WRITE | 0x001480f2 | 已封装，实机通过 | CopyToOnServerAsync |
| FSCTL_LMR_REQUEST_RESILIENCY | 0x001401d4 | 仅原始接口 | 无 resilient handle 恢复状态机 |
| FSCTL_QUERY_NETWORK_INTERFACE_INFO | 0x001401fc | 已实现 | 全1句柄、类型化接口列表和多通道选择 |
| FSCTL_SET_REPARSE_POINT | 0x000900a4 | 已封装，实机受限 | 正向创建未验证 |
| FSCTL_DFS_GET_REFERRALS_EX | 0x000601b0 | 未实现 | 同上 |
| FSCTL_FILE_LEVEL_TRIM | 0x00098208 | 仅原始接口 | 没有专用 trim 模型和验证 |
| FSCTL_VALIDATE_NEGOTIATE_INFO | 0x00140204 | 内部实现 | SMB 3.0 / 3.0.2 的 ValidateNegotiateAsync |

## 文件信息类逐项对照

以下 53 行对应 [MS-FSCC 文件信息类](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/4718fc40-e539-4014-8e33-b675af74e3e1)。仅列原表的类，不把 LOCAL 项误算作远程客户端功能。空白用途的历史类不计为已确认的远程必需项。目录信息通过公开 QueryDirectoryPageAsync 处理，支持11种标准目录格式；普通 QueryInfoAsync 与目录命令保持区分。

| 信息类 | 编号 | 规范用途 | 当前状态 | 实现或边界 |
| --- | --- | --- | --- | --- |
| FileAccessInformation | 8 | Query | 已类型化 | GetAccessMaskAsync |
| FileAlignmentInformation | 17 | Query | 已类型化 | GetAlignmentInformationAsync |
| FileAllInformation | 18 | Query | 已类型化 | GetAllInformationAsync |
| FileAllocationInformation | 19 | Set | 已类型化 | GetAllocationInfoAsync / AllocateAsync |
| FileAlternateNameInformation | 21 | Query | 已类型化 | GetAlternateNameAsync |
| FileAttributeTagInformation | 35 | Query | 已类型化 | GetAttributeTagAsync |
| FileBasicInformation | 4 | Query, Set | 已类型化 | GetBasicInformationAsync / SetBasicInformationAsync |
| FileBothDirectoryInformation | 3 | Query | 已类型化 | QueryDirectoryPageAsync / SmbDirectoryQuery |
| FileCompressionInformation | 28 | Query | 已类型化 | GetCompressionInformationAsync |
| FileDirectoryInformation | 1 | Query | 已类型化 | QueryDirectoryPageAsync / SmbDirectoryQuery |
| FileDispositionInformation | 13 | Set | 已类型化 | SetDeletePendingAsync |
| FileDispositionInformationEx | 64 | Set | 已类型化 | SetDispositionAsync |
| FileEaInformation | 7 | Query | 已类型化 | GetExtendedAttributeSizeAsync |
| FileEndOfFileInformation | 20 | Set | 已类型化 | SetLengthAsync |
| FileFullDirectoryInformation | 2 | Query | 已类型化 | QueryDirectoryPageAsync / SmbDirectoryQuery |
| FileFullEaInformation | 15 | Query, Set | 已类型化 | EA分页 / SetExtendedAttributesAsync |
| FileHardLinkInformation | 46 | LOCAL | LOCAL，不列远程缺口 | 本地用途，不作为普通远程 QUERY_INFO 能力 |
| FileId64ExtdBothDirectoryInformation | 79 | Query | 已类型化 | QueryDirectoryPageAsync / SmbDirectoryQuery |
| FileId64ExtdDirectoryInformation | 78 | Query | 已类型化 | QueryDirectoryPageAsync / SmbDirectoryQuery |
| FileIdAllExtdBothDirectoryInformation | 81 | Query | 已类型化 | QueryDirectoryPageAsync / SmbDirectoryQuery |
| FileIdAllExtdDirectoryInformation | 80 | Query | 已类型化 | QueryDirectoryPageAsync / SmbDirectoryQuery |
| FileIdBothDirectoryInformation | 37 | Query | 已类型化 | QueryDirectoryPageAsync / SmbDirectoryQuery |
| FileIdExtdDirectoryInformation | 60 | Query | 已类型化 | QueryDirectoryPageAsync / SmbDirectoryQuery |
| FileIdFullDirectoryInformation | 38 | Query | 已类型化 | QueryDirectoryPageAsync / SmbDirectoryQuery |
| FileIdGlobalTxDirectoryInformation | 50 | LOCAL | LOCAL，不列远程缺口 | 本地用途，不作为普通远程 QUERY_INFO 能力 |
| FileIdInformation | 59 | Query | 已类型化 | GetFileIdentityAsync |
| FileInternalInformation | 6 | Query | 已类型化 | GetInternalFileIndexAsync |
| FileLinkInformation | 11 | Set | 已类型化 | CreateHardLinkAsync |
| FileMailslotQueryInformation | 26 | LOCAL | LOCAL，不列远程缺口 | 本地用途，不作为普通远程 QUERY_INFO 能力 |
| FileMailslotSetInformation | 27 | LOCAL | LOCAL，不列远程缺口 | 本地用途，不作为普通远程 QUERY_INFO 能力 |
| FileModeInformation | 16 | Query, Set | 已类型化 | GetFileModeAsync / SetFileModeAsync |
| FileMoveClusterInformation | 31 | — | 不计远程缺口 | 规范表未指定远程查询或设置用途 |
| FileNameInformation | 9 | LOCAL | LOCAL，不列远程缺口 | FileAllInformation 内嵌名称另有解析 |
| FileNamesInformation | 12 | Query | 已类型化 | QueryDirectoryPageAsync / SmbDirectoryQuery |
| FileNetworkOpenInformation | 34 | Query | 已类型化 | GetNetworkOpenInformationAsync |
| FileNormalizedNameInformation | 48 | Query | 已类型化 | GetNormalizedNameAsync |
| FileObjectIdInformation | 29 | LOCAL | LOCAL，不列远程缺口 | 本地用途，不作为普通远程 QUERY_INFO 能力 |
| FilePipeInformation | 23 | Query, Set | 已类型化 | Get/SetPipeInformationAsync |
| FilePipeLocalInformation | 24 | Query | 已类型化 | GetPipeLocalInformationAsync |
| FilePipeRemoteInformation | 25 | Query | 已类型化 | GetPipeRemoteInformationAsync |
| FilePositionInformation | 14 | Query, Set | 已类型化 | Get/SetServerPositionAsync |
| FileQuotaInformation | 32 | Query, Set | 已类型化 | OpenQuotaControlAsync + 配额专用接口 |
| FileRenameInformation | 10 | Set | 已类型化 | RenameAsync |
| FileRenameInformationEx | 65 | Set | 已类型化 | RenameExtendedAsync |
| FileReparsePointInformation | 33 | LOCAL | LOCAL，不列远程缺口 | 本地用途，不作为普通远程 QUERY_INFO 能力 |
| FileSfioReserveInformation | 44 | LOCAL | LOCAL，不列远程缺口 | 本地用途，不作为普通远程 QUERY_INFO 能力 |
| FileSfioVolumeInformation | 45 | — | 不计远程缺口 | 规范表未指定远程查询或设置用途 |
| FileShortNameInformation | 40 | Set | 已类型化 | SetShortNameAsync |
| FileStandardInformation | 5 | Query | 已类型化 | GetStandardInformationAsync |
| FileStandardLinkInformation | 54 | LOCAL | LOCAL，不列远程缺口 | 本地用途，不作为普通远程 QUERY_INFO 能力 |
| FileStreamInformation | 22 | Query | 已类型化 | GetStreamsAsync |
| FileTrackingInformation | 36 | LOCAL | LOCAL，不列远程缺口 | 本地用途，不作为普通远程 QUERY_INFO 能力 |
| FileValidDataLengthInformation | 39 | Set | 已类型化 | SetValidDataLengthAsync |

## 文件系统信息类逐项对照

以下 11 行对应 [MS-FSCC 文件系统信息类](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/ee12042a-9352-46e3-9f67-c094b75fe6c3)。库的空间便利 API 使用 FullSize 信息类；没有把本地卷操作混入 SMB 网络操作。

| 信息类 | 编号 | 规范用途 | 当前状态 | 实现或边界 |
| --- | --- | --- | --- | --- |
| FileFsVolumeInformation | 1 | Query | 已封装 | GetVolumeInfoAsync |
| FileFsLabelInformation | 2 | LOCAL | LOCAL，不列远程缺口 | 系统本地用途 |
| FileFsSizeInformation | 3 | Query | 仅原始接口 | QueryInfoAsync / SetInfoAsync，无专用模型或专项验证 |
| FileFsDeviceInformation | 4 | Query | 仅原始接口 | QueryInfoAsync / SetInfoAsync，无专用模型或专项验证 |
| FileFsAttributeInformation | 5 | Query | 已封装 | GetFileSystemAttributesAsync |
| FileFsControlInformation | 6 | Query, Set | 已类型化 | Get/SetVolumeQuotaControlAsync；服务端执行状态只读 |
| FileFsFullSizeInformation | 7 | Query | 已封装 | GetSpaceAsync |
| FileFsObjectIdInformation | 8 | Query, Set | 仅原始接口 | QueryInfoAsync / SetInfoAsync，无专用模型或专项验证 |
| FileFsDriverPathInformation | 9 | LOCAL | LOCAL，不列远程缺口 | 系统本地用途 |
| FileFsVolumeFlagsInformation | 10 | LOCAL | LOCAL，不列远程缺口 | 系统本地用途 |
| FileFsSectorSizeInformation | 11 | Query | 已类型化 | GetSectorSizeInformationAsync |

## 需要保留的测试结论

符号链接三个变体的创建请求返回 `0xC0000275 STATUS_NOT_A_REPARSE_POINT`。Windows 系统接口对照也创建失败，并查询到共享能力不包含 `FILE_SUPPORTS_REPARSE_POINTS`。这说明当前测试环境没有提供成功验证条件，但不能用此结果证明所有服务器都不支持、证明只缺账号权限，或证明库的符号链接请求已经完全正确。创建成功后的 GET / DELETE 路径仍需要支持此能力的服务端正向测试。

扩大分配大小的请求被接受，但实际额外空间预留未证实；缩小分配大小后的 EOF 和数据结果已验证。断连恢复测试验证的是旧连接失败后新建客户端可用，不能算 durable / persistent handle 自动恢复。Native AOT 在 Windows x64 已实跑；Linux / macOS 的配置不作为执行证据。

这些结论见[真实服务器报告](../Test.MonsterSyncDrive.SMB/REAL_SERVER_TEST_RESULTS.md)，不会把受限项改写成通过。

## 尚未补齐的主要能力

当前主要缺口为 Kerberos/系统单点登录、DFS与受控符号链接跟随、lease/目录缓存、durable/persistent/resilient handle自动恢复、Compound及完整配套RPC服务。多通道GMAC组合和内置Linux RDMA后端也保留明确边界。服务端和硬件环境缺少某项能力时，不用本地回环结果替代相应真实互操作证明。

## 主要官方和规范来源

- [微软 SMB 功能总览](https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-feature-descriptions)
- [MS-SMB2 消息分类和核心命令](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/6eaf6e75-9c23-4eda-be99-c9223c60b181)
- [MS-SMB2 NEGOTIATE 上下文](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/15332256-522e-4a53-8cd7-0bd17678a2f7)
- [微软 SMB 安全增强](https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-security-hardening)
- [MS-SMB2 CREATE 上下文](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/75364667-3a93-4e2c-b771-592d8d5e876d)
- [MS-FSCC 文件信息类](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/4718fc40-e539-4014-8e33-b675af74e3e1)
- [MS-FSCC 文件系统信息类](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/ee12042a-9352-46e3-9f67-c094b75fe6c3)
- [MS-FSCC 远程 FSCTL 列表](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/4dc02779-9d95-43f8-bba4-8d4ce4961458)
- [MS-SMB2 IOCTL 请求和控制码](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/5c03c9d6-15de-48a2-9835-8fb37f8a79d8)
- [MS-DFSC DFS 转介](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dfsc/7186a5d0-5482-4b1d-b23d-211363b8cde2)
- [MS-SRVS 共享枚举](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-srvs/c4a98e7b-d416-439c-97bd-4d9f52f8ba52)
- [MS-SMB2 Compound 请求](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/fa6687f5-99d4-4c9b-ba2e-a770310225e0)
- [MS-SMB2 Lease 处理](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/24cfce29-5d80-4651-ba5f-a2661c666b41)
- [MS-SMB2 服务器端复制](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/eaa129d1-fca4-46b1-8ccd-b91f3e1d2d80)
- [MS-SMB2 历史版本枚举](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/c631e497-9a47-4537-9817-8af2a4834d03)
- [MS-SWN Witness](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-swn/56681003-0dd3-4fda-adac-121d7166e006)
- [SMB3 POSIX 扩展规范](https://smb3posix.org/spec/latest/smb3_posix_extensions.html)
- [微软打印协议概述](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-prsod/79ee0747-9b77-4497-baab-a679fe8dbcc3)

