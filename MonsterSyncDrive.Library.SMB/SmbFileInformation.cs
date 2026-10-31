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
namespace MonsterSyncDrive.Library.SMB;

/// <summary>MS-FSCC 文件信息类编号，包含用于用途识别的本地专用类。</summary>
public enum SmbFileInformationClass : byte
{

    /// <summary>基本目录条目，包含文件名、时间、大小和属性。</summary>
    Directory = 1,
    /// <summary>在基本目录条目上增加扩展属性大小。</summary>
    FullDirectory = 2,
    /// <summary>目录条目及最长 24 字节的短文件名。</summary>
    BothDirectory = 3,
    /// <summary>查询或设置四类时间与文件属性。</summary>
    Basic = 4,
    /// <summary>分配大小、EOF、链接数、待删除与目录标志。</summary>
    Standard = 5,

    /// <summary>文件系统的 64 位内部文件索引，不是 SMB 打开句柄。</summary>
    Internal = 6,
    /// <summary>文件扩展属性的总字节数。</summary>
    Ea = 7,
    /// <summary>当前打开句柄被授予的访问掩码。</summary>
    Access = 8,
    /// <summary>仅供本地使用；远程名称可通过 All 的内嵌名称或 NormalizedName 获取。</summary>
    Name = 9,
    /// <summary>设置共享内的新名称，并选择是否替换目标。</summary>
    Rename = 10,
    /// <summary>为同一文件创建新的硬链接名称。</summary>
    Link = 11,
    /// <summary>仅返回目录条目的文件名与枚举索引。</summary>
    Names = 12,

    /// <summary>设置或撤销文件的待删除状态。</summary>
    Disposition = 13,
    /// <summary>服务器句柄游标；服务器可以返回零，普通 SMB 数据操作使用显式偏移。</summary>
    Position = 14,
    /// <summary>查询或设置具名的二进制扩展属性链。</summary>
    FullEa = 15,
    /// <summary>查询句柄打开模式，或设置规范允许更改的模式位。</summary>
    Mode = 16,
    /// <summary>底层设备要求的缓冲区对齐掩码。</summary>
    Alignment = 17,
    /// <summary>聚合基本、标准、内部索引、EA、访问、游标、模式、对齐和名称信息。</summary>
    All = 18,

    /// <summary>设置文件分配大小；物理预留效果由服务端文件系统决定。</summary>
    Allocation = 19,
    /// <summary>设置逻辑文件长度，扩展或截断 EOF。</summary>
    EndOfFile = 20,
    /// <summary>查询服务器保存的短名称，通常为 8.3 格式。</summary>
    AlternateName = 21,
    /// <summary>枚举默认数据流和命名备用数据流。</summary>
    Stream = 22,
    /// <summary>查询或设置命名管道读取与完成模式。</summary>
    Pipe = 23,

    /// <summary>查询命名管道实例、缓冲配额、可用数据和连接状态。</summary>
    PipeLocal = 24,
    /// <summary>查询管道远程收集时长与收集字节阈值。</summary>
    PipeRemote = 25,
    /// <summary>本地 mailslot 查询类，不是 SMB2 远程文件查询。</summary>
    MailslotQuery = 26,
    /// <summary>本地 mailslot 设置类，不是 SMB2 远程文件设置。</summary>
    MailslotSet = 27,

    /// <summary>查询文件系统压缩后的大小、格式与单元移位；不涉及 SMB 网络压缩。</summary>
    Compression = 28,
    /// <summary>本地对象 ID 信息类；远程对象 ID 操作使用相应 FSCTL。</summary>
    ObjectId = 29,
    /// <summary>规范表未指定远程用途的历史类，不开放为普通网络信息请求。</summary>
    MoveCluster = 31,
    /// <summary>用户磁盘配额条目；使用 Quota 信息类型而非普通 File QUERY_INFO。</summary>
    Quota = 32,
    /// <summary>本地重解析点信息类；远程原始重解析点操作使用 FSCTL。</summary>
    ReparsePoint = 33,

    /// <summary>适合网络打开操作的基本属性、分配大小和 EOF。</summary>
    NetworkOpen = 34,
    /// <summary>文件属性及重解析点标签。</summary>
    AttributeTag = 35,
    /// <summary>本地链接跟踪类，不开放为普通远程信息类。</summary>
    Tracking = 36,
    /// <summary>包含短名称和 64 位文件 ID 的目录条目。</summary>
    IdBothDirectory = 37,

    /// <summary>包含 EA 大小和 64 位文件 ID 的目录条目。</summary>
    IdFullDirectory = 38,
    /// <summary>设置已初始化数据的长度；需要服务端授予相应权限。</summary>
    ValidDataLength = 39,
    /// <summary>设置或删除文件系统保存的短名称。</summary>
    ShortName = 40,
    /// <summary>本地 SFIO 预留类，不作为远程功能提供。</summary>
    SfioReserve = 44,

    /// <summary>规范表未指定远程用途的历史 SFIO 卷类。</summary>
    SfioVolume = 45,
    /// <summary>本地硬链接枚举信息类；创建远程硬链接使用 Link 类。</summary>
    HardLink = 46,
    /// <summary>查询规范化的共享相对路径；服务器与协议版本可以不支持。</summary>
    NormalizedName = 48,
    /// <summary>本地事务目录信息类，不作为普通网络目录查询提供。</summary>
    IdGlobalTxDirectory = 50,

    /// <summary>本地标准链接信息类；远程链接计数可从 Standard 获取。</summary>
    StandardLink = 54,
    /// <summary>卷序列号及文件系统 128 位文件 ID。</summary>
    Id = 59,
    /// <summary>目录条目、EA 大小、重解析标签和 128 位文件 ID。</summary>
    IdExtdDirectory = 60,
    /// <summary>具有 POSIX、只读覆盖与关闭行为选项的扩展删除设置。</summary>
    DispositionEx = 64,

    /// <summary>具有替换、POSIX 与存储预留选项的扩展重命名设置。</summary>
    RenameEx = 65,
    /// <summary>带独立重解析标签和 64 位文件 ID 的扩展目录条目。</summary>
    Id64ExtdDirectory = 78,
    /// <summary>带短名称、重解析标签和 64 位文件 ID 的扩展目录条目。</summary>
    Id64ExtdBothDirectory = 79,

    /// <summary>同时返回 64 位与 128 位文件 ID 的扩展目录条目。</summary>
    IdAllExtdDirectory = 80,
    /// <summary>同时返回短名称、64 位及 128 位文件 ID 的扩展目录条目。</summary>
    IdAllExtdBothDirectory = 81
}


/// <summary>确定一个信息类应使用普通文件查询、目录查询、配额请求，还是仅在本地有意义。</summary>
public enum SmbInformationRoute
{
    /// <summary>使用 SMB2 File QUERY_INFO 或 SET_INFO。</summary>
    File,
    /// <summary>使用 SMB2 QUERY_DIRECTORY，不能用普通文件 QUERY_INFO 替代。</summary>
    Directory,
    /// <summary>使用 SMB2 Quota 信息类型和专门的配额结构。</summary>
    Quota,
    /// <summary>规范明确标记为 LOCAL，不作为网络客户端缺口。</summary>
    LocalOnly,
    /// <summary>规范表未指定可执行的远程查询或设置用途。</summary>
    Unspecified
}


/// <summary>一个标准信息类的名称、远程路由和可执行读写操作。</summary>
/// <param name="InformationClass">MS-FSCC 数值编号。</param>
/// <param name="SpecificationName">规范中的完整信息类名称。</param>
/// <param name="Route">请求应走的协议命令或本地用途分类。</param>
/// <param name="CanQuery">是否存在所列路由上的查询用途。</param>
/// <param name="CanSet">是否存在所列路由上的设置用途。</param>
public sealed record SmbFileInformationSupport(SmbFileInformationClass InformationClass,
    string SpecificationName, SmbInformationRoute Route, bool CanQuery, bool CanSet);

/// <summary>明确标注 MS-FSCC 2.4 表中每个信息类的远程适用范围。</summary>
public static class SmbFileInformationCatalog
{

    /// <summary>所有已分类条目的只读集合。远程用途不代表每个服务端均实现该可选信息类。</summary>
    public static IReadOnlyList<SmbFileInformationSupport> All
    {
        get;
    } = Array.AsReadOnly(new[]
    {
        File(SmbFileInformationClass.Access, "FileAccessInformation", true, false),
        File(SmbFileInformationClass.Alignment, "FileAlignmentInformation", true, false),
        File(SmbFileInformationClass.All, "FileAllInformation", true, false),
        File(SmbFileInformationClass.Allocation, "FileAllocationInformation", false, true),
        File(SmbFileInformationClass.AlternateName, "FileAlternateNameInformation", true, false),
        File(SmbFileInformationClass.AttributeTag, "FileAttributeTagInformation", true, false),
        File(SmbFileInformationClass.Basic, "FileBasicInformation", true, true),
        Directory(SmbFileInformationClass.BothDirectory, "FileBothDirectoryInformation"),
        File(SmbFileInformationClass.Compression, "FileCompressionInformation", true, false),
        Directory(SmbFileInformationClass.Directory, "FileDirectoryInformation"),
        File(SmbFileInformationClass.Disposition, "FileDispositionInformation", false, true),
        File(SmbFileInformationClass.DispositionEx, "FileDispositionInformationEx", false, true),
        File(SmbFileInformationClass.Ea, "FileEaInformation", true, false),
        File(SmbFileInformationClass.EndOfFile, "FileEndOfFileInformation", false, true),
        Directory(SmbFileInformationClass.FullDirectory, "FileFullDirectoryInformation"),
        File(SmbFileInformationClass.FullEa, "FileFullEaInformation", true, true),
        Local(SmbFileInformationClass.HardLink, "FileHardLinkInformation"),
        Directory(SmbFileInformationClass.Id64ExtdBothDirectory, "FileId64ExtdBothDirectoryInformation"),
        Directory(SmbFileInformationClass.Id64ExtdDirectory, "FileId64ExtdDirectoryInformation"),
        Directory(SmbFileInformationClass.IdAllExtdBothDirectory, "FileIdAllExtdBothDirectoryInformation"),
        Directory(SmbFileInformationClass.IdAllExtdDirectory, "FileIdAllExtdDirectoryInformation"),
        Directory(SmbFileInformationClass.IdBothDirectory, "FileIdBothDirectoryInformation"),
        Directory(SmbFileInformationClass.IdExtdDirectory, "FileIdExtdDirectoryInformation"),
        Directory(SmbFileInformationClass.IdFullDirectory, "FileIdFullDirectoryInformation"),
        Local(SmbFileInformationClass.IdGlobalTxDirectory, "FileIdGlobalTxDirectoryInformation"),
        File(SmbFileInformationClass.Id, "FileIdInformation", true, false),
        File(SmbFileInformationClass.Internal, "FileInternalInformation", true, false),
        File(SmbFileInformationClass.Link, "FileLinkInformation", false, true),
        Local(SmbFileInformationClass.MailslotQuery, "FileMailslotQueryInformation"),
        Local(SmbFileInformationClass.MailslotSet, "FileMailslotSetInformation"),
        File(SmbFileInformationClass.Mode, "FileModeInformation", true, true),
        new(SmbFileInformationClass.MoveCluster, "FileMoveClusterInformation", SmbInformationRoute.Unspecified, false, false),
        Local(SmbFileInformationClass.Name, "FileNameInformation"),
        Directory(SmbFileInformationClass.Names, "FileNamesInformation"),
        File(SmbFileInformationClass.NetworkOpen, "FileNetworkOpenInformation", true, false),
        File(SmbFileInformationClass.NormalizedName, "FileNormalizedNameInformation", true, false),
        Local(SmbFileInformationClass.ObjectId, "FileObjectIdInformation"),
        File(SmbFileInformationClass.Pipe, "FilePipeInformation", true, true),
        File(SmbFileInformationClass.PipeLocal, "FilePipeLocalInformation", true, false),
        File(SmbFileInformationClass.PipeRemote, "FilePipeRemoteInformation", true, false),
        File(SmbFileInformationClass.Position, "FilePositionInformation", true, true),
        new(SmbFileInformationClass.Quota, "FileQuotaInformation", SmbInformationRoute.Quota, true, true),
        File(SmbFileInformationClass.Rename, "FileRenameInformation", false, true),
        File(SmbFileInformationClass.RenameEx, "FileRenameInformationEx", false, true),
        Local(SmbFileInformationClass.ReparsePoint, "FileReparsePointInformation"),
        Local(SmbFileInformationClass.SfioReserve, "FileSfioReserveInformation"),
        new(SmbFileInformationClass.SfioVolume, "FileSfioVolumeInformation", SmbInformationRoute.Unspecified, false, false),
        File(SmbFileInformationClass.ShortName, "FileShortNameInformation", false, true),
        File(SmbFileInformationClass.Standard, "FileStandardInformation", true, false),
        Local(SmbFileInformationClass.StandardLink, "FileStandardLinkInformation"),
        File(SmbFileInformationClass.Stream, "FileStreamInformation", true, false),
        Local(SmbFileInformationClass.Tracking, "FileTrackingInformation"),
        File(SmbFileInformationClass.ValidDataLength, "FileValidDataLengthInformation", false, true)
    });


    /// <summary>按数值编号取得信息类用途；未定义编号抛出参数异常。</summary>
    /// <param name="informationClass">要查找的标准信息类编号。</param>
    /// <returns>包含规范名称、路由和查询/设置用途的条目。</returns>
    public static SmbFileInformationSupport Get(SmbFileInformationClass informationClass)
    {
        return All.FirstOrDefault(item => item.InformationClass == informationClass)
                ?? throw new ArgumentOutOfRangeException(nameof(informationClass));
    }


    /// <summary>建立普通 File 信息路由的目录项。</summary>
    /// <param name="value">信息类编号。</param>
    /// <param name="name">规范名称。</param>
    /// <param name="query">是否允许查询。</param>
    /// <param name="set">是否允许设置。</param>
    /// <returns>不可变的用途描述。</returns>
    private static SmbFileInformationSupport File(SmbFileInformationClass value, string name, bool query, bool set)
    {
        return new(value, name, SmbInformationRoute.File, query, set);
    }

    /// <summary>建立只支持 QUERY_DIRECTORY 的目录项。</summary>
    /// <param name="value">目录结果信息类编号。</param>
    /// <param name="name">规范名称。</param>
    /// <returns>目录查询用途描述。</returns>
    private static SmbFileInformationSupport Directory(SmbFileInformationClass value, string name)
    {
        return new(value, name, SmbInformationRoute.Directory, true, false);
    }

    /// <summary>建立规范明确标记 LOCAL 的目录项，关闭网络查询与设置标志。</summary>
    /// <param name="value">本地信息类编号。</param>
    /// <param name="name">规范名称。</param>
    /// <returns>本地用途描述。</returns>
    private static SmbFileInformationSupport Local(SmbFileInformationClass value, string name)
    {
        return new(value, name, SmbInformationRoute.LocalOnly, false, false);
    }
}


/// <summary>文件基本信息，对应 40 字节 FILE_BASIC_INFORMATION。</summary>
/// <param name="CreationTime">文件创建时间；服务器返回零时为空。</param>
/// <param name="LastAccessTime">最后访问时间；服务器返回零时为空。</param>
/// <param name="LastWriteTime">最后写入时间；服务器返回零时为空。</param>
/// <param name="ChangeTime">元数据变化时间；服务器返回零时为空。</param>
/// <param name="Attributes">服务器报告的文件属性位。</param>
public sealed record SmbBasicInformation(DateTimeOffset? CreationTime, DateTimeOffset? LastAccessTime,
    DateTimeOffset? LastWriteTime, DateTimeOffset? ChangeTime, FileAttributes Attributes);

/// <summary>文件分配、长度和链接状态，对应 FILE_STANDARD_INFORMATION。</summary>
/// <param name="AllocationSize">服务器报告的已分配字节数，不等同于逻辑长度。</param>
/// <param name="Length">逻辑文件长度，以字节计。</param>
/// <param name="LinkCount">文件系统中的硬链接计数。</param>
/// <param name="DeletePending">句柄关联对象是否处于待删除状态。</param>
/// <param name="IsDirectory">对象是否为目录。</param>
public sealed record SmbStandardInformation(long AllocationSize, long Length, uint LinkCount,
    bool DeletePending, bool IsDirectory);

/// <summary>FILE_ALL_INFORMATION 的完整聚合结果，包括旧 SmbFileInfo 没有暴露的访问、游标、模式和对齐字段。</summary>
/// <param name="Basic">四类时间与文件属性。</param>
/// <param name="Standard">分配大小、EOF 与链接状态。</param>
/// <param name="FileIndex">文件系统内部索引或目录枚举游标，具体稳定性由信息类决定。</param>
/// <param name="ExtendedAttributeSize">EA 总字节数或相应目录字段的原始值。</param>
/// <param name="Access">当前句柄的访问掩码。</param>
/// <param name="ServerPosition">服务器游标；不修改 SmbFileStream 的客户端 Position。</param>
/// <param name="Mode">服务器报告的打开模式标志。</param>
/// <param name="Alignment">设备要求的对齐掩码及字节边界。</param>
/// <param name="Name">信息类返回的名称文本。</param>
public sealed record SmbAllInformation(SmbBasicInformation Basic, SmbStandardInformation Standard,
    ulong FileIndex, uint ExtendedAttributeSize, SmbAccessMask Access, long ServerPosition,
    SmbFileMode Mode, SmbAlignmentInformation Alignment, string Name);

/// <summary>无损保存文件系统 128 位 ID 的两个 64 位段；不作 Guid 字节序转换。</summary>
/// <param name="Low">标识原始前八字节的小端无符号值。</param>
/// <param name="High">标识原始后八字节的小端无符号值。</param>
public readonly record struct SmbFileId128(ulong Low, ulong High);

/// <summary>文件所在卷与文件系统 128 位标识的组合。</summary>
/// <param name="VolumeSerialNumber">保存文件的卷的 64 位序列号。</param>
/// <param name="FileId">文件系统的 128 位标识，不是 SMB 会话句柄。</param>
public sealed record SmbFileIdentity(ulong VolumeSerialNumber, SmbFileId128 FileId);

/// <summary>文件属性与重解析点标签的组合。</summary>
/// <param name="Attributes">服务器报告的文件属性位。</param>
/// <param name="ReparseTag">重解析点标签；无对应信息时为空。</param>
public sealed record SmbFileAttributeTag(FileAttributes Attributes, uint ReparseTag);

/// <summary>服务器文件系统压缩信息，与网络传输压缩无关。</summary>
/// <param name="CompressedSize">压缩后占用的字节数。</param>
/// <param name="CompressionFormat">服务器返回的压缩格式编号；0 表示未压缩，2 通常表示 LZNT1。</param>
/// <param name="CompressionUnitShift">压缩单元大小的以 2 为底移位值。</param>
/// <param name="ChunkShift">压缩块大小的以 2 为底移位值。</param>
/// <param name="ClusterShift">文件系统簇大小的以 2 为底移位值。</param>
public sealed record SmbFileCompressionInformation(long CompressedSize, ushort CompressionFormat,
    byte CompressionUnitShift, byte ChunkShift, byte ClusterShift);

/// <summary>网络打开信息类返回的时间、属性与大小。</summary>
/// <param name="Basic">四类时间与文件属性。</param>
/// <param name="AllocationSize">服务器报告的已分配字节数，不等同于逻辑长度。</param>
/// <param name="Length">逻辑文件长度，以字节计。</param>
public sealed record SmbNetworkOpenInformation(SmbBasicInformation Basic, long AllocationSize, long Length);

/// <summary>设备缓冲区对齐要求；掩码须为规范定义的 2 的幂减一值。</summary>
/// <param name="AlignmentRequirement">对齐掩码，合法值为 0、1、3、7，依次至 511。</param>
public sealed record SmbAlignmentInformation(uint AlignmentRequirement)
{

    /// <summary>把对齐掩码转换为实际字节边界；掩码 0 对应 1 字节，无额外对齐要求。</summary>
    public uint RequiredByteAlignment => AlignmentRequirement + 1;
}


/// <summary>FILE_MODE_INFORMATION 标志。查询可包含打开时的模式；设置仅允许规范中的可变子集。</summary>
[Flags]
public enum SmbFileMode : uint
{

    /// <summary>不启用模式标志。</summary>
    None = 0,
    /// <summary>写操作要求服务端按直写语义完成。</summary>
    WriteThrough = 2,
    /// <summary>提示服务端优化顺序访问。</summary>
    SequentialOnly = 4,
    /// <summary>打开时禁止中间缓冲；不能通过 SetFileModeAsync 改变。</summary>
    NoIntermediateBuffering = 8,

    /// <summary>同步 I/O，并允许等待被警报打断；不能与 NonAlert 同时设置。</summary>
    SynchronousIoAlert = 0x10,
    /// <summary>同步 I/O 等待不受警报打断；不能与 Alert 同时设置。</summary>
    SynchronousIoNonAlert = 0x20,
    /// <summary>规范返回为零的历史模式位；关闭删除应通过打开选项或删除信息设置。</summary>
    DeleteOnClose = 0x1000
}

/// <summary>FILE_DISPOSITION_INFORMATION_EX 的删除行为位；具体权限和文件系统支持由服务器验证。</summary>
[Flags]
public enum SmbDispositionFlags : uint
{

    /// <summary>撤销待删除请求。</summary>
    None = 0,
    /// <summary>请求删除文件。</summary>
    Delete = 1,
    /// <summary>使用 POSIX 风格命名空间删除语义。</summary>
    PosixSemantics = 2,
    /// <summary>存在映像节时要求删除失败。</summary>
    ForceImageSectionCheck = 4,

    /// <summary>调整以关闭删除方式打开的句柄的删除语义。</summary>
    OnClose = 8,
    /// <summary>请求在拥有必要权限时忽略只读属性删除。</summary>
    IgnoreReadOnlyAttribute = 0x10
}

/// <summary>FILE_RENAME_INFORMATION_EX 的重命名与存储预留行为位。</summary>
[Flags]
public enum SmbRenameFlags : uint
{

    /// <summary>不替换现有目标，使用常规重命名语义。</summary>
    None = 0,
    /// <summary>允许替换同名目标。</summary>
    ReplaceIfExists = 1,
    /// <summary>替换时保留目标既有打开句柄的访问语义。</summary>
    PosixSemantics = 2,
    /// <summary>禁止从目标目录继承固定或取消固定状态。</summary>
    SuppressPinStateInheritance = 4,

    /// <summary>禁止从目标目录继承存储预留 ID。</summary>
    SuppressStorageReserveInheritance = 8,
    /// <summary>调整预留区域，防止可见可用空间增加；需要卷管理访问。</summary>
    NoIncreaseAvailableSpace = 0x10,

    /// <summary>调整预留区域，防止可见可用空间减少；需要卷管理访问。</summary>
    NoDecreaseAvailableSpace = 0x20,
    /// <summary>同时防止可见可用空间增加和减少。</summary>
    PreserveAvailableSpace = 0x30,

    /// <summary>替换时请求忽略目标的只读属性。</summary>
    IgnoreReadOnlyAttribute = 0x40,
    /// <summary>跨预留区域重命名时，强制扩大目标预留区域。</summary>
    ForceResizeTargetStorageReserve = 0x80,

    /// <summary>跨预留区域重命名时，强制缩小源预留区域。</summary>
    ForceResizeSourceStorageReserve = 0x100,
    /// <summary>同时调整源和目标存储预留区域。</summary>
    ForceResizeStorageReserve = 0x180
}


/// <summary>管道读取模式。</summary>
public enum SmbPipeReadMode : uint
{
    /// <summary>按连续字节流读取。</summary>
    ByteStream,
    /// <summary>保留管道消息边界。</summary>
    Message
}

/// <summary>管道操作完成策略。</summary>
public enum SmbPipeCompletionMode : uint
{
    /// <summary>等待连接、数据或写入完成。</summary>
    Queue,
    /// <summary>立即完成，使用非阻塞语义。</summary>
    Complete
}

/// <summary>服务器创建的命名管道类型。</summary>
public enum SmbPipeType : uint
{
    /// <summary>按字节流组织数据。</summary>
    ByteStream,
    /// <summary>按消息组织数据。</summary>
    Message
}

/// <summary>管道允许的数据流方向。</summary>
public enum SmbPipeConfiguration : uint
{
    /// <summary>仅从客户端流向服务端。</summary>
    Inbound,
    /// <summary>仅从服务端流向客户端。</summary>
    Outbound,
    /// <summary>客户端与服务端均可读写。</summary>
    FullDuplex
}

/// <summary>服务器报告的命名管道连接状态。</summary>
public enum SmbPipeState : uint
{
    /// <summary>尚未连接。</summary>
    Disconnected = 1,
    /// <summary>等待连接。</summary>
    Listening,
    /// <summary>连接已建立。</summary>
    Connected,
    /// <summary>正在关闭。</summary>
    Closing
}

/// <summary>当前句柄所处的管道端。</summary>
public enum SmbPipeEnd : uint
{
    /// <summary>客户端一端。</summary>
    Client,
    /// <summary>服务端一端。</summary>
    Server
}

/// <summary>命名管道读取模式与完成模式的友好表示。</summary>
/// <param name="ReadMode">按字节流或按消息读取管道。</param>
/// <param name="CompletionMode">管道操作等待数据或立即完成的模式。</param>
public sealed record SmbPipeInformation(SmbPipeReadMode ReadMode, SmbPipeCompletionMode CompletionMode);

/// <summary>服务器命名管道的实例数量、缓冲配额与连接状态。</summary>
/// <param name="PipeType">字节流或消息类型。</param>
/// <param name="Configuration">允许的数据流方向。</param>
/// <param name="MaximumInstances">最大允许实例数。</param>
/// <param name="CurrentInstances">当前实例数。</param>
/// <param name="InboundQuota">入站缓冲区配额字节数。</param>
/// <param name="ReadDataAvailable">当前可读字节数。</param>
/// <param name="OutboundQuota">出站缓冲区配额字节数。</param>
/// <param name="WriteQuotaAvailable">当前可写入的配额余量。</param>
/// <param name="State">连接状态。</param>
/// <param name="End">当前是客户端还是服务端一端。</param>
public sealed record SmbPipeLocalInformation(SmbPipeType PipeType, SmbPipeConfiguration Configuration,
    uint MaximumInstances, uint CurrentInstances, uint InboundQuota, uint ReadDataAvailable,
    uint OutboundQuota, uint WriteQuotaAvailable, SmbPipeState State, SmbPipeEnd End);

/// <summary>管道客户端收集数据后发送的时间和大小阈值。</summary>
/// <param name="CollectionTime">以 100 纳秒为单位的原始有符号时长。</param>
/// <param name="MaximumCollectionCount">触发发送的最大收集字节数。</param>
public sealed record SmbPipeRemoteInformation(TimeSpan CollectionTime, uint MaximumCollectionCount);

/// <summary>一个扩展属性值；向 SetExtendedAttributesAsync 传入空值将删除对应名称的 EA。</summary>
/// <param name="Name">1 至 254 个合法 ASCII 字符组成的 EA 名称。</param>
/// <param name="Value">最多 65535 字节的二进制值；设置空值会删除该 EA。</param>
/// <param name="Required">是否设置 FILE_NEED_EA，表示解释文件需要理解此 EA。</param>
public sealed record SmbExtendedAttribute(string Name, ReadOnlyMemory<byte> Value, bool Required = false);

/// <summary>一次完整解码的 EA 页及继续查询指示。</summary>
/// <param name="Entries">当前响应中完整解码的条目。</param>
/// <param name="HasMoreData">是否需要继续查询；单条 EA 模式可能需要一个空的最终页才能确定结束。</param>
public sealed record SmbExtendedAttributePage(IReadOnlyList<SmbExtendedAttribute> Entries, bool HasMoreData);

/// <summary>EA 查询选项；名称筛选与一基索引互斥，遇到截断溢出可在同一索引上受限扩容重试。</summary>
public sealed record SmbExtendedAttributeQuery
{

    /// <summary>可选 ASCII 名称筛选列表；不与 StartIndex 同时使用。</summary>
    public IReadOnlyList<string>? Names
    {
        get; init;
    }

    /// <summary>可选的一基 EA 索引；零无效。</summary>
    public uint? StartIndex
    {
        get; init;
    }

    /// <summary>没有显式索引或名称时，是否从第一个 EA 重新开始。</summary>
    public bool RestartScan { get; init; } = true;

    /// <summary>最多返回一个 EA；最后一项可能仍需额外空查询才能确认结束。</summary>
    public bool ReturnSingleEntry
    {
        get; init;
    }

    /// <summary>首次查询的最大输出字节数，默认 65536；受协商事务容量限制。</summary>
    public int BufferSize { get; init; } = 65536;

    /// <summary>截断了单个 EA 时，是否在同一索引上扩大缓冲区重试，最多至协商容量。</summary>
    public bool AllowBufferGrowth { get; init; } = true;
}


/// <summary>QUERY_DIRECTORY 允许的 11 个远程目录结果格式；不能用于普通文件 QUERY_INFO。</summary>
public enum SmbDirectoryInformationClass : byte
{

    /// <summary>基本目录条目，包含文件名、时间、大小和属性。</summary>
    Directory = 1,
    /// <summary>在基本目录条目上增加扩展属性大小。</summary>
    FullDirectory = 2,
    /// <summary>目录条目及最长 24 字节的短文件名。</summary>
    BothDirectory = 3,
    /// <summary>仅返回目录条目的文件名与枚举索引。</summary>
    Names = 12,

    /// <summary>包含短名称和 64 位文件 ID 的目录条目。</summary>
    IdBothDirectory = 37,
    /// <summary>包含 EA 大小和 64 位文件 ID 的目录条目。</summary>
    IdFullDirectory = 38,
    /// <summary>目录条目、EA 大小、重解析标签和 128 位文件 ID。</summary>
    IdExtdDirectory = 60,

    /// <summary>带独立重解析标签和 64 位文件 ID 的扩展目录条目。</summary>
    Id64ExtdDirectory = 78,
    /// <summary>带短名称、重解析标签和 64 位文件 ID 的扩展目录条目。</summary>
    Id64ExtdBothDirectory = 79,

    /// <summary>同时返回 64 位与 128 位文件 ID 的扩展目录条目。</summary>
    IdAllExtdDirectory = 80,
    /// <summary>同时返回短名称、64 位及 128 位文件 ID 的扩展目录条目。</summary>
    IdAllExtdBothDirectory = 81
}

/// <summary>统一目录条目模型；名称专用格式的元数据为空，未携带的短名、EA、标签或 ID 保持为空。</summary>
/// <param name="Name">信息类返回的名称文本。</param>
/// <param name="FileIndex">文件系统内部索引或目录枚举游标，具体稳定性由信息类决定。</param>
/// <param name="Length">逻辑文件长度，以字节计。</param>
/// <param name="AllocationSize">服务器报告的已分配字节数，不等同于逻辑长度。</param>
/// <param name="Attributes">服务器报告的文件属性位。</param>
/// <param name="CreationTime">文件创建时间；服务器返回零时为空。</param>
/// <param name="LastAccessTime">最后访问时间；服务器返回零时为空。</param>
/// <param name="LastWriteTime">最后写入时间；服务器返回零时为空。</param>
/// <param name="ChangeTime">元数据变化时间；服务器返回零时为空。</param>
/// <param name="ExtendedAttributeSize">EA 总字节数或相应目录字段的原始值。</param>
/// <param name="ReparseTag">重解析点标签；无对应信息时为空。</param>
/// <param name="ShortName">短文件名；格式不携带此字段时为空，没有短名时为空字符串。</param>
/// <param name="FileId64">格式携带的文件系统 64 位 ID，不能当成 SMB 打开句柄使用。</param>
/// <param name="FileId128">格式携带的文件系统 128 位 ID。</param>
public sealed record SmbDirectoryInformationEntry(string Name, uint FileIndex,
    long? Length, long? AllocationSize, FileAttributes? Attributes,
    DateTimeOffset? CreationTime, DateTimeOffset? LastAccessTime,
    DateTimeOffset? LastWriteTime, DateTimeOffset? ChangeTime,
    uint? ExtendedAttributeSize, uint? ReparseTag, string? ShortName,
    ulong? FileId64, SmbFileId128? FileId128);

/// <summary>一次目录查询的结果；只有终止状态才保证目录枚举已结束。</summary>
/// <param name="Entries">当前响应中完整解码的条目。</param>
/// <param name="IsComplete">服务器返回 NO_MORE_FILES 或 NO_SUCH_FILE 时为真。</param>
/// <param name="HasMoreData">当前响应状态是否为 BUFFER_OVERFLOW；不等同于整个目录是否结束。</param>
public sealed record SmbDirectoryPage(IReadOnlyList<SmbDirectoryInformationEntry> Entries,
    bool IsComplete, bool HasMoreData);

/// <summary>目录查询选项，显式控制格式、扫描标志、索引和事务输出预算。</summary>
public sealed record SmbDirectoryQuery
{

    /// <summary>单级名称通配符，默认星号；不得包含路径分隔符或数据流分隔符。</summary>
    public string Pattern { get; init; } = "*";

    /// <summary>服务器应编码的目录结果格式。</summary>
    public SmbDirectoryInformationClass InformationClass { get; init; } = SmbDirectoryInformationClass.Directory;

    /// <summary>重新从当前模式的起点开始枚举。</summary>
    public bool RestartScan
    {
        get; init;
    }

    /// <summary>请求最多返回一个目录条目。</summary>
    public bool ReturnSingleEntry
    {
        get; init;
    }

    /// <summary>要求服务器重新开始目录枚举。</summary>
    public bool Reopen
    {
        get; init;
    }

    /// <summary>可选的目录枚举索引；某些文件系统可忽略它。</summary>
    public uint? FileIndex
    {
        get; init;
    }

    /// <summary>最大输出字节数，默认 65536；显式更大值仅限支持多 credit 的协商连接。</summary>
    public int BufferSize { get; init; } = 65536;
}