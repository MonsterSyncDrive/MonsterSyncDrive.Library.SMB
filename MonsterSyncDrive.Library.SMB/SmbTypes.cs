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
namespace MonsterSyncDrive.SMB;


/// <summary>CREATE 请求所使用的 Windows 文件访问掩码；由服务端依据安全描述符和身份授权。</summary>
[Flags]
public enum SmbAccessMask : uint
{

    /// <summary>读取文件内容或列举目录。</summary>
    ReadData = 0x1,
    /// <summary>写入文件内容或在目录中增加文件。</summary>
    WriteData = 0x2,
    /// <summary>追加文件数据或在目录中增加子目录。</summary>
    AppendData = 0x4,
    /// <summary>读取扩展属性 EA。</summary>
    ReadExtendedAttributes = 0x8,

    /// <summary>修改扩展属性 EA。</summary>
    WriteExtendedAttributes = 0x10,
    /// <summary>执行文件或遍历目录。</summary>
    Execute = 0x20,
    /// <summary>删除目录中的子项。</summary>
    DeleteChild = 0x40,

    /// <summary>读取基本属性和时间。</summary>
    ReadAttributes = 0x80,
    /// <summary>修改基本属性和时间。</summary>
    WriteAttributes = 0x100,
    /// <summary>删除或重命名对象。</summary>
    Delete = 0x10000,

    /// <summary>读取所有者、组和 DACL。</summary>
    ReadControl = 0x20000,
    /// <summary>修改 DACL；不代表具有修改所有者权限。</summary>
    WriteDac = 0x40000,
    /// <summary>设置对象所有者或组，仍受服务端特权约束。</summary>
    WriteOwner = 0x80000,

    /// <summary>请求同步访问所需的标准权限。</summary>
    Synchronize = 0x100000,
    /// <summary>访问 SACL，需要服务器相应安全特权。</summary>
    AccessSystemSecurity = 0x1000000,

    /// <summary>请求服务器计算当前身份可获得的最大访问集合。</summary>
    MaximumAllowed = 0x2000000,
    /// <summary>文件通用全部访问权限，由服务器映射。</summary>
    GenericAll = 0x10000000,

    /// <summary>文件通用执行访问权限。</summary>
    GenericExecute = 0x20000000,
    /// <summary>文件通用写访问权限。</summary>
    GenericWrite = 0x40000000,
    /// <summary>文件通用读访问权限。</summary>
    GenericRead = 0x80000000
}


/// <summary>打开句柄时允许其他句柄并行获得的访问类型，不是当前句柄自身权限。</summary>
[Flags]
public enum SmbShareAccess : uint
{
    /// <summary>不共享，阻止冲突的其他打开。</summary>
    None = 0,
    /// <summary>允许其他读取句柄。</summary>
    Read = 1,
    /// <summary>允许其他写入句柄。</summary>
    Write = 2,
    /// <summary>允许其他删除或重命名句柄。</summary>
    Delete = 4,
    /// <summary>同时允许读、写、删除共享。</summary>
    All = 7
}

/// <summary>文件存在或不存在时 CREATE 的原子处理方式。</summary>
public enum SmbCreateDisposition : uint
{
    /// <summary>存在时替换对象，不存在时创建。</summary>
    Supersede,
    /// <summary>仅打开已存在对象。</summary>
    Open,
    /// <summary>仅创建新对象，重名失败。</summary>
    Create,
    /// <summary>存在则打开，否则创建。</summary>
    OpenIf,
    /// <summary>仅覆盖已存在对象。</summary>
    Overwrite,
    /// <summary>存在则覆盖，否则创建。</summary>
    OverwriteIf
}

/// <summary>随 CREATE 透传的文件打开选项；不自动赋予服务器备份或管理权限。</summary>
[Flags]
public enum SmbCreateOptions : uint
{

    /// <summary>不指定附加打开选项。</summary>
    None = 0,
    /// <summary>目标必须是目录或按目录创建。</summary>
    DirectoryFile = 1,
    /// <summary>请求服务器按直写语义处理。</summary>
    WriteThrough = 2,
    /// <summary>声明主要顺序访问，与 RandomAccess 互斥。</summary>
    SequentialOnly = 4,

    /// <summary>请求远端无缓冲 IO；库按远端逻辑扇区校验偏移和长度。</summary>
    NoIntermediateBuffering = 8,
    /// <summary>目标必须是普通文件，不能与 DirectoryFile 同用。</summary>
    NonDirectoryFile = 0x40,
    /// <summary>声明主要随机访问，与 SequentialOnly 互斥。</summary>
    RandomAccess = 0x800,

    /// <summary>最后相关句柄关闭时按服务端语义删除。</summary>
    DeleteOnClose = 0x1000,
    /// <summary>二进制文件 ID 打开标志；路径型 OpenFileAsync 不支持此形式。</summary>
    OpenByFileId = 0x2000,
    /// <summary>声明备份意图；服务端仍决定调用身份是否具有备份或还原特权。</summary>
    OpenForBackupIntent = 0x4000,

    /// <summary>打开重解析点本身，供读取、设置、移除其原始数据。</summary>
    OpenReparsePoint = 0x200000
}


/// <summary>文件、目录或管道的不可变 CREATE 参数，访问权限与共享权限分别表达。</summary>
public sealed record SmbOpenOptions
{

    /// <summary>当前句柄请求获得的文件访问权限。</summary>
    public SmbAccessMask Access { get; init; } = SmbAccessMask.GenericRead;

    /// <summary>允许其他句柄并行访问的读、写、删除范围。</summary>
    public SmbShareAccess ShareAccess { get; init; } = SmbShareAccess.All;

    /// <summary>对象存在或不存在时的原子打开行为。</summary>
    public SmbCreateDisposition Disposition { get; init; } = SmbCreateDisposition.Open;

    /// <summary>目录、缓冲、访问模式、备份和重解析点等打开标志。</summary>
    public SmbCreateOptions CreateOptions { get; init; } = SmbCreateOptions.NonDirectoryFile;

    /// <summary>创建新对象时的文件属性；不是任意已有对象属性修改接口。</summary>
    public FileAttributes Attributes { get; init; } = FileAttributes.Normal;

    /// <summary>申请的传统 oplock 级别；默认 None，服务器可以授予较低级别。</summary>
    public SmbOplockLevel RequestedOplockLevel { get; init; } = SmbOplockLevel.None;
    /// <summary>处理撤销时先刷新或作废应用缓存，再返回希望确认的 oplock 降级级别。</summary>
    public Func<SmbOplockBreak, CancellationToken, ValueTask<SmbOplockLevel>>? OplockBreakHandler { get; init; }
}


/// <summary>FileAllInformation 的常用字段快照；FileIndex 与 SMB 句柄 ID 属于不同标识。</summary>
/// <param name="CreationTime">创建时间，未指定或协议哨兵值时为空。</param>
/// <param name="LastAccessTime">最后访问时间。</param>
/// <param name="LastWriteTime">最后写入数据的时间。</param>
/// <param name="ChangeTime">元数据变更时间。</param>
/// <param name="AllocationSize">服务器报告的已分配字节数。</param>
/// <param name="Length">文件逻辑长度 EOF，单位字节。</param>
/// <param name="Attributes">文件属性位。</param>
/// <param name="LinkCount">链接计数。</param>
/// <param name="DeletePending">是否已被标记为等待删除。</param>
/// <param name="IsDirectory">是否为目录。</param>
/// <param name="FileIndex">服务器报告的 64 位内部文件索引。</param>
/// <param name="Name">服务器返回的名称。</param>
public sealed record SmbFileInfo(
    DateTimeOffset? CreationTime, DateTimeOffset? LastAccessTime,
    DateTimeOffset? LastWriteTime, DateTimeOffset? ChangeTime,
    long AllocationSize, long Length, FileAttributes Attributes, uint LinkCount,
    bool DeletePending, bool IsDirectory, ulong FileIndex, string Name);


/// <summary>默认目录枚举的信息快照，不包含稳定的 128 位磁盘标识。</summary>
/// <param name="Name">单个目录项名称。</param>
/// <param name="Length">文件逻辑字节数。</param>
/// <param name="AllocationSize">报告的分配字节数。</param>
/// <param name="Attributes">文件属性位。</param>
/// <param name="CreationTime">创建时间。</param>
/// <param name="LastAccessTime">最后访问时间。</param>
/// <param name="LastWriteTime">最后写入时间。</param>
/// <param name="ChangeTime">元数据更改时间。</param>
/// <param name="FileIndex">目录结果中的续查索引，不能当作永久句柄。</param>
public sealed record SmbDirectoryEntry(
    string Name, long Length, long AllocationSize, FileAttributes Attributes,
    DateTimeOffset? CreationTime, DateTimeOffset? LastAccessTime,
    DateTimeOffset? LastWriteTime, DateTimeOffset? ChangeTime, uint FileIndex)
{

    /// <summary>条目是否带目录属性。</summary>
    public bool IsDirectory => (Attributes & FileAttributes.Directory) != 0;

    /// <summary>条目是否带重解析点属性，递归操作应据此控制遍历边界。</summary>
    public bool IsReparsePoint => (Attributes & FileAttributes.ReparsePoint) != 0;
}


/// <summary>服务器返回的完整空间信息，调用者可用量可能受配额约束。</summary>
/// <param name="TotalAllocationUnits">卷的总分配单元数。</param>
/// <param name="CallerAvailableAllocationUnits">当前身份可用的分配单元数。</param>
/// <param name="ActualAvailableAllocationUnits">卷实际空闲的分配单元数。</param>
/// <param name="SectorsPerAllocationUnit">每个分配单元包含的扇区数。</param>
/// <param name="BytesPerSector">每扇区字节数。</param>
public sealed record SmbFileSystemSpace(
    long TotalAllocationUnits, long CallerAvailableAllocationUnits,
    long ActualAvailableAllocationUnits, uint SectorsPerAllocationUnit, uint BytesPerSector)
{

    /// <summary>将总分配单元换算为字节，使用受检乘法拒绝溢出。</summary>
    public long TotalBytes => checked(TotalAllocationUnits * SectorsPerAllocationUnit * BytesPerSector);

    /// <summary>当前身份可用的字节数，使用受检乘法。</summary>
    public long AvailableBytes => checked(CallerAvailableAllocationUnits * SectorsPerAllocationUnit * BytesPerSector);

    /// <summary>卷实际空闲字节数，可能大于受配额限制的 AvailableBytes。</summary>
    public long FreeBytes => checked(ActualAvailableAllocationUnits * SectorsPerAllocationUnit * BytesPerSector);
}


/// <summary>FileFsVolumeInformation 的卷身份信息。</summary>
/// <param name="CreationTime">卷创建时间。</param>
/// <param name="SerialNumber">卷序列号。</param>
/// <param name="Label">卷标。</param>
/// <param name="SupportsObjects">服务器声明卷是否支持对象标识。</param>
public sealed record SmbVolumeInfo(DateTimeOffset? CreationTime, uint SerialNumber, string Label, bool SupportsObjects);

/// <summary>文件系统声明的能力，不以 NTFS 等名称字符串推断未声明的功能。</summary>
/// <param name="Attributes">FILE_FS_ATTRIBUTE_INFORMATION 能力位。</param>
/// <param name="MaximumComponentLength">单个路径组件允许的最大长度。</param>
/// <param name="FileSystemName">服务器报告的文件系统名称。</param>
public sealed record SmbFileSystemAttributes(uint Attributes, int MaximumComponentLength, string FileSystemName);


/// <summary>CHANGE_NOTIFY 的服务端过滤条件，可按位组合。</summary>
[Flags]
public enum SmbNotifyFilter : uint
{

    /// <summary>文件名称变更。</summary>
    FileName = 1,
    /// <summary>目录名称变更。</summary>
    DirectoryName = 2,
    /// <summary>属性变更。</summary>
    Attributes = 4,
    /// <summary>文件大小变更。</summary>
    Size = 8,

    /// <summary>最后写入时间变更。</summary>
    LastWrite = 0x10,
    /// <summary>最后访问时间变更。</summary>
    LastAccess = 0x20,
    /// <summary>创建时间变更。</summary>
    Creation = 0x40,

    /// <summary>EA 变更。</summary>
    ExtendedAttributes = 0x80,
    /// <summary>安全描述符变更。</summary>
    Security = 0x100,
    /// <summary>备用数据流名称变更。</summary>
    StreamName = 0x200,

    /// <summary>备用数据流大小变更。</summary>
    StreamSize = 0x400,
    /// <summary>备用数据流写入变更。</summary>
    StreamWrite = 0x800,

    /// <summary>所有本库支持的通知条件。</summary>
    All = 0xFFF
}


/// <summary>服务器通知的目录变化类型。</summary>
public enum SmbChangeAction : uint
{
    /// <summary>新增名称。</summary>
    Added = 1,
    /// <summary>移除名称。</summary>
    Removed,
    /// <summary>内容或元数据变化。</summary>
    Modified,
    /// <summary>重命名之前的名称。</summary>
    RenamedOldName,
    /// <summary>重命名之后的名称。</summary>
    RenamedNewName
}

/// <summary>一项目录变更；重命名通常由旧名、新名两项表达。</summary>
/// <param name="Action">变更操作种类。</param>
/// <param name="Name">相对于监视目录的名称。</param>
public sealed record SmbChangeNotification(SmbChangeAction Action, string Name);

/// <summary>一次 CHANGE_NOTIFY 返回的变更批次；没有持久化监听或断线补偿语义。</summary>
/// <param name="Changes">服务器返回的有序通知项。</param>
/// <param name="RequiresRescan">缓冲溢出或服务器要求重新枚举时为 true。</param>
public sealed record SmbChangeBatch(IReadOnlyList<SmbChangeNotification> Changes, bool RequiresRescan);


/// <summary>LOCK 请求的锁种类和等待策略。</summary>
[Flags]
public enum SmbLockFlags : uint
{
    /// <summary>共享读锁，具体互斥由服务器执行。</summary>
    Shared = 1,
    /// <summary>独占锁。</summary>
    Exclusive = 2,
    /// <summary>释放对应偏移和长度的已有锁。</summary>
    Unlock = 4,
    /// <summary>无法立即加锁时返回失败，不持续等待。</summary>
    FailImmediately = 0x10
}

/// <summary>一次字节范围锁或解锁操作。</summary>
/// <param name="Offset">起始字节偏移，必须非负。</param>
/// <param name="Length">范围长度，必须为正且终点不能溢出。</param>
/// <param name="Flags">共享、独占或解锁类型，以及是否立即失败。</param>
public readonly record struct SmbLockRange(long Offset, long Length, SmbLockFlags Flags);

/// <summary>QUERY_INFO 和 SET_INFO 的信息命名空间；同一数字 class 在不同类型下含义不同。</summary>
public enum SmbInfoType : byte
{
    /// <summary>文件或句柄信息。</summary>
    File = 1,
    /// <summary>卷和文件系统信息。</summary>
    FileSystem = 2,
    /// <summary>self-relative 安全描述符。</summary>
    Security = 3,
    /// <summary>用户磁盘配额专用信息格式。</summary>
    Quota = 4
}


/// <summary>查询或设置安全描述符时指定的部分及继承保护控制位。</summary>
[Flags]
public enum SmbSecurityInformation : uint
{

    /// <summary>所有者 SID。</summary>
    Owner = 1,
    /// <summary>主要组 SID。</summary>
    Group = 2,
    /// <summary>自主访问控制列表。</summary>
    Dacl = 4,
    /// <summary>系统审计访问控制列表，需要额外特权。</summary>
    Sacl = 8,
    /// <summary>完整性标签。</summary>
    Label = 0x10,

    /// <summary>资源属性。</summary>
    Attribute = 0x20,
    /// <summary>中央访问策略作用域。</summary>
    Scope = 0x40,
    /// <summary>请求备份所需的安全描述符部分。</summary>
    Backup = 0x10000,

    /// <summary>取消 SACL 继承保护。</summary>
    UnprotectedSacl = 0x10000000,
    /// <summary>取消 DACL 继承保护。</summary>
    UnprotectedDacl = 0x20000000,

    /// <summary>保护 SACL 免于继承更新。</summary>
    ProtectedSacl = 0x40000000,
    /// <summary>保护 DACL 免于继承更新。</summary>
    ProtectedDacl = 0x80000000
}


/// <summary>常见 NTSTATUS 常量；库保留未知值，不将此枚举视为全部状态的封闭集合。</summary>
public enum SmbStatus : uint
{

    /// <summary>操作成功。</summary>
    Success = 0,
    /// <summary>异步操作已接收，稍后返回最终回复。</summary>
    Pending = 0x103,
    /// <summary>通知信息不足，需要重新枚举目录。</summary>
    NotifyEnumDir = 0x10C,

    /// <summary>返回了部分数据，需要按具体命令继续读取。</summary>
    BufferOverflow = 0x80000005,
    /// <summary>目录枚举结束。</summary>
    NoMoreFiles = 0x80000006,
    /// <summary>配额等条目枚举结束。</summary>
    NoMoreEntries = 0x8000001A,

    /// <summary>通用失败。</summary>
    Unsuccessful = 0xC0000001,
    /// <summary>服务端尚未实现该操作。</summary>
    NotImplemented = 0xC0000002,

    /// <summary>句柄无效。</summary>
    InvalidHandle = 0xC0000008,
    /// <summary>参数无效。</summary>
    InvalidParameter = 0xC000000D,
    /// <summary>目标文件系统或设备不支持控制请求。</summary>
    InvalidDeviceRequest = 0xC0000010,

    /// <summary>文件不存在。</summary>
    NoSuchFile = 0xC000000F,
    /// <summary>到达逻辑文件末尾。</summary>
    EndOfFile = 0xC0000011,

    /// <summary>认证需要更多交换轮次，不等于普通 SMB ERROR 结构。</summary>
    MoreProcessingRequired = 0xC0000016,
    /// <summary>当前身份访问被拒绝。</summary>
    AccessDenied = 0xC0000022,

    /// <summary>输出缓冲区不足。</summary>
    BufferTooSmall = 0xC0000023,
    /// <summary>名称不符合服务端约束。</summary>
    ObjectNameInvalid = 0xC0000033,

    /// <summary>最终名称不存在。</summary>
    ObjectNameNotFound = 0xC0000034,
    /// <summary>仅创建新对象时发现重名。</summary>
    ObjectNameCollision = 0xC0000035,

    /// <summary>中间路径不存在。</summary>
    ObjectPathNotFound = 0xC000003A,
    /// <summary>与已有句柄的共享模式冲突。</summary>
    SharingViolation = 0xC0000043,

    /// <summary>与现有字节范围锁冲突。</summary>
    FileLockConflict = 0xC0000054,
    /// <summary>未能获得请求的锁。</summary>
    LockNotGranted = 0xC0000055,

    /// <summary>对象等待删除，不能完成该打开。</summary>
    DeletePending = 0xC0000056,
    /// <summary>当前服务端身份缺少所需特权。</summary>
    PrivilegeNotHeld = 0xC0000061,
    /// <summary>身份认证失败。</summary>
    LogonFailure = 0xC000006D,

    /// <summary>没有足够可用空间。</summary>
    DiskFull = 0xC000007F,
    /// <summary>请求要求普通文件，目标实际为目录。</summary>
    FileIsADirectory = 0xC00000BA,

    /// <summary>不支持该可选操作。</summary>
    NotSupported = 0xC00000BB,
    /// <summary>共享名不可用。</summary>
    BadNetworkName = 0xC00000CC,

    /// <summary>目录非空，不能按当前操作删除或设置。</summary>
    DirectoryNotEmpty = 0xC0000101,
    /// <summary>要求目录但目标不是目录。</summary>
    NotADirectory = 0xC0000103,

    /// <summary>服务端确认取消。</summary>
    Cancelled = 0xC0000120,
    /// <summary>句柄已关闭。</summary>
    FileClosed = 0xC0000128,

    /// <summary>会话已失效。</summary>
    UserSessionDeleted = 0xC0000203,
    /// <summary>路径需 DFS 转介或不在共享覆盖范围。</summary>
    PathNotCovered = 0xC0000257,
    /// <summary>对象不是重解析点；单独此码不能断定创建权限原因。</summary>
    NotAReparsePoint = 0xC0000275,

    /// <summary>遇到需客户端处理的符号链接，原始载荷保留在异常中。</summary>
    StopOnSymlink = 0x8000002D
}

/// <summary>服务端命令错误；保留原始 NTSTATUS 和 SMB2 错误载荷，不把权限错误转换为路径不存在。</summary>
public sealed class SmbException : IOException
{

    /// <summary>保留的原始 NTSTATUS，包括未在枚举中命名的状态值。</summary>
    public SmbStatus Status { get; }

    /// <summary>导致错误的 SMB2 命令号。</summary>
    public ushort Command { get; }

    /// <summary>服务端错误载荷的独立副本，供上层解析扩展错误。</summary>
    public ReadOnlyMemory<byte> ErrorData { get; }

    /// <summary>仅识别明确的名称或路径不存在状态，不将拒绝访问误报为不存在。</summary>
    public bool IsNotFound => Status is SmbStatus.NoSuchFile or SmbStatus.ObjectNameNotFound or SmbStatus.ObjectPathNotFound;


    /// <summary>保存命令、状态和错误载荷副本；HResult 按原始 32 位状态位模式解释。</summary>
    internal SmbException(SmbStatus status, ushort command, ReadOnlyMemory<byte> errorData)
        : base($"SMB command 0x{command:X4} failed: {status} (0x{(uint)status:X8}).")
    {
        Status = status;
        Command = command;
        ErrorData = errorData.ToArray();
        HResult = unchecked((int)status);
    }
}


/// <summary>报文格式、标识、边界或完整性不符合协议时的异常，连接通常会被终止。</summary>
public sealed class SmbProtocolException : IOException
{

    /// <summary>创建协议异常，并可保留底层解码或密码学失败作为内部异常。</summary>
    public SmbProtocolException(string message) : base(message) { }

    /// <summary>创建协议异常，并可保留底层解码或密码学失败作为内部异常。</summary>
    public SmbProtocolException(string message, Exception innerException) : base(message, innerException) { }
}


/// <summary>srvsvc 返回的 Win32 状态或 RPC fault，区别于 SMB 命令 NTSTATUS。</summary>
public sealed class SmbRpcException : IOException
{

    /// <summary>RPC 或服务方法返回的原始数值状态。</summary>
    public uint Status { get; }

    /// <summary>是否来自 RPC fault 报文，而非普通服务结果。</summary>
    public bool IsFault { get; }

    /// <summary>保存 RPC 状态及 fault 分类，诊断文本不包含凭据。</summary>
    internal SmbRpcException(uint status, bool isFault) : base($"SMB srvsvc RPC failed with status 0x{status:X8}.")
    {
        Status = status;
        IsFault = isFault;
    }
}