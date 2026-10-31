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
using MonsterSyncDrive.Library.SMB.Protocol;
using System.Collections.Concurrent;
using System.Runtime.CompilerServices;

namespace MonsterSyncDrive.Library.SMB;

/// <summary>已连接的磁盘或 IPC 共享；释放时关闭其拥有的文件句柄，并释放树连接引用。</summary>
public sealed partial class SmbShare : IAsyncDisposable
{
    /// <summary>此共享使用对象拥有的远程打开句柄索引，用于关闭和主动撤销通知分发。</summary>
    private readonly ConcurrentDictionary<SmbFileId, SmbFileHandle> handles = new();
    /// <summary>拥有树连接并负责选择通道的已认证会话。</summary>
    private readonly SmbClient client;
    /// <summary>以原子状态阻止新操作和重复释放共享。</summary>
    private int disposed;
    /// <summary>服务器分配的树标识符，引用同一底层树连接的对象共享此值。</summary>
    internal uint TreeId
    {
        get;
    }
    /// <summary>不包含服务器前缀和路径的共享名称。</summary>
    public string Name
    {
        get;
    }
    /// <summary>服务器是否将此树连接声明为磁盘共享。</summary>
    public bool IsDiskShare => ShareType == 1;
    /// <summary>服务器是否将此树连接声明为命名管道共享。</summary>
    public bool IsPipeShare => ShareType == 2;
    /// <summary>原始 SMB2 共享类型：磁盘为 1、管道为 2、打印机为 3。</summary>
    public byte ShareType
    {
        get;
    }
    /// <summary>TREE_CONNECT 返回的未经修改的 SMB2 共享标志。</summary>
    public uint Flags
    {
        get;
    }
    /// <summary>TREE_CONNECT 返回的未经修改的共享能力标志。</summary>
    public uint Capabilities
    {
        get;
    }
    /// <summary>服务器为当前认证身份返回的共享级最大访问权限掩码。</summary>
    public SmbAccessMask MaximumAccess
    {
        get;
    }
    /// <summary>此树连接是否要求 SMB 加密，该要求独立于客户端的偏好策略。</summary>
    public bool EncryptionRequired => (Flags & 0x8000) != 0;
    /// <summary>所属会话，供文件句柄和内部协议扩展调用。</summary>
    internal SmbClient Client => client;

    /// <summary>创建一个可独立释放的已认证树连接引用。</summary>
    /// <param name="client">所属 SMB 会话。</param>
    /// <param name="treeId">服务器树标识符。</param>
    /// <param name="name">已经规范化的共享名称。</param>
    /// <param name="shareType">TREE_CONNECT 返回的共享类型。</param>
    /// <param name="flags">服务器返回的共享标志。</param>
    /// <param name="capabilities">服务器返回的共享能力。</param>
    /// <param name="maximumAccess">当前身份对应的共享级访问掩码。</param>
    internal SmbShare(SmbClient client, uint treeId, string name, byte shareType, uint flags, uint capabilities, SmbAccessMask maximumAccess)
    {
        this.client = client;
        TreeId = treeId;
        Name = name;
        ShareType = shareType;
        Flags = flags;
        Capabilities = capabilities;
        MaximumAccess = maximumAccess;
    }

    /// <summary>打开或创建文件、目录或管道，并校验返回的标识符和机会锁授予级别。</summary>
    /// <param name="path">相对于共享的路径；空路径表示打开共享根目录。</param>
    /// <param name="options">访问、共享、创建、IO 及可选缓存撤销处理设置。</param>
    /// <param name="cancellationToken">取消远程 CREATE 操作。</param>
    /// <returns>由此共享使用对象管理的句柄。</returns>
    /// <exception cref="ArgumentException">路径或打开选项组合无效。</exception>
    /// <exception cref="SmbException">服务器拒绝打开请求。</exception>
    /// <exception cref="SmbProtocolException">对端复用了仍在使用的 FileId，或返回了无效授予级别。</exception>
    /// <remarks>应用程序依赖机会锁进行缓存时，必须在本次调用之前配置缓存处理程序。</remarks>
    public Task<SmbFileHandle> OpenFileAsync(string path, SmbOpenOptions? options = null, CancellationToken cancellationToken = default)
    {
        return OpenFileCoreAsync(path, options, quotaControl: false, cancellationToken);
    }

    /// <summary>复用统一的 CREATE、机会锁跟踪和句柄登记流程；只有固定配额索引允许特殊流类型。</summary>
    /// <param name="path">普通共享相对路径，或内部专用配额控制流常量。</param>
    /// <param name="options">文件访问和创建选项。</param>
    /// <param name="quotaControl">是否由专用配额接口打开唯一允许的索引流。</param>
    /// <param name="cancellationToken">取消 CREATE 的令牌。</param>
    /// <returns>由当前共享使用对象管理的远程句柄。</returns>
    /// <exception cref="ArgumentException">内部控制流名称或公开打开参数无效。</exception>
    private async Task<SmbFileHandle> OpenFileCoreAsync(string path, SmbOpenOptions? options, bool quotaControl,
        CancellationToken cancellationToken)
    {
        ThrowIfDisposed();
        if (quotaControl)
        {
            // 不接受调用者提供的任意 $INDEX_ALLOCATION 路径，也不放宽普通文件 ADS 的 $DATA 限制。
            if (!IsDiskShare || !path.Equals(QuotaControlPath, StringComparison.Ordinal))
                throw new ArgumentException("Quota control requires the reserved index stream on a disk share.", nameof(path));
        }
        else
            path = SmbPath.Normalize(path);
        options ??= new SmbOpenOptions();
        SmbOpenSemantics.Validate(options);
        if (!Enum.IsDefined(options.Disposition) || (options.ShareAccess & ~SmbShareAccess.All) != 0 ||
            !Enum.IsDefined(options.RequestedOplockLevel) ||
            ((options.CreateOptions & (SmbCreateOptions.DirectoryFile | SmbCreateOptions.NonDirectoryFile)) ==
             (SmbCreateOptions.DirectoryFile | SmbCreateOptions.NonDirectoryFile)))
            throw new ArgumentException("Invalid file open options.", nameof(options));
        if ((options.CreateOptions & SmbCreateOptions.OpenByFileId) != 0)
            throw new ArgumentException("OpenByFileId requires a binary file identifier and cannot be used with a path.", nameof(options));
        byte[] name = Wire.Unicode.GetBytes(path);
        byte[] body = new byte[56 + Math.Max(1, name.Length)];
        Wire.Put16(body, 0, 57);
        body[3] = (byte)options.RequestedOplockLevel;
        Wire.Put32(body, 4, 2); // SecurityImpersonation：使用模拟级别，不请求身份委派。
        Wire.Put32(body, 24, (uint)options.Access);
        Wire.Put32(body, 28, (uint)options.Attributes);
        Wire.Put32(body, 32, (uint)options.ShareAccess);
        Wire.Put32(body, 36, (uint)options.Disposition);
        Wire.Put32(body, 40, (uint)options.CreateOptions);
        Wire.Put16(body, 44, 120);
        Wire.Put16(body, 46, checked((ushort)name.Length));
        name.CopyTo(body, 56);
        // 在发送 CREATE 前开始跟踪；同一次 TCP 读取可能同时收到创建响应和撤销通知。
        // 会话暂存有限数量的未知 FileId 通知，等待本段后续代码完成打开句柄注册。
        client.BeginOplockOpen();
        try
        {
            Response response = await SendAsync(Command.Create, body, cancellationToken).ConfigureAwait(false);
            response.EnsureSuccess();
            Wire.Structure(response.Packet, 89, 88);
            var id = SmbFileId.Read(response.Packet, 128);
            var handle = new SmbFileHandle(this, id, path, options, response.Packet);
            if (quotaControl)
                handle.InitializeQuotaControlHandle();
            // 只发布已经校验的授予级别；服务器意外返回更强级别不能成为应用程序缓存的依据。
            try
            {
                handle.InitializeOplock(response.Packet[66]);
            }
            catch (SmbProtocolException error)
            {
                client.Abort(error);
                throw;
            }
            if (!handles.TryAdd(id, handle))
            {
                client.Abort(new SmbProtocolException("The server reused a live SMB file ID."));
                throw new SmbProtocolException("The server reused a live SMB file ID.");
            }
            client.OplockHandleRegistered();
            if (!client.IsTransportAlive)
                handle.InvalidateOplock();
            return handle;
        }
        finally
        {
            client.EndOplockOpen();
        }
    }

    /// <summary>将磁盘文件打开为可定位的 Stream，支持同步和异步 IO。</summary>
    /// <param name="path">相对于共享的文件路径。</param>
    /// <param name="mode">.NET 文件打开、创建、截断或追加模式。</param>
    /// <param name="access">所需的流读取和写入权限。</param>
    /// <param name="share">允许其他打开句柄执行的读取、写入和删除共享访问。</param>
    /// <param name="cancellationToken">取消打开远程文件。</param>
    /// <returns>拥有其远程文件句柄的流。</returns>
    /// <exception cref="NotSupportedException">当前树连接不是磁盘共享。</exception>
    /// <exception cref="ArgumentException">模式、访问权限或共享访问组合无效。</exception>
    /// <remarks>追加从打开时记录的 EOF 开始，不保证不同会话之间的并发原子追加。</remarks>
    public async Task<SmbFileStream> OpenStreamAsync(string path, FileMode mode = FileMode.Open,
        FileAccess access = FileAccess.Read, FileShare share = FileShare.Read, CancellationToken cancellationToken = default)
    {
        if (!IsDiskShare)
            throw new NotSupportedException("Seekable file streams require a disk share. Use a file handle for named pipes.");
        if (!Enum.IsDefined(mode) || !Enum.IsDefined(access) || (share & ~(FileShare.ReadWrite | FileShare.Delete)) != 0)
            throw new ArgumentException("Invalid stream open arguments.");
        if (mode is FileMode.Create or FileMode.CreateNew or FileMode.Truncate or FileMode.Append && access == FileAccess.Read)
            throw new ArgumentException("This file mode requires write access.", nameof(access));
        if (mode == FileMode.Append && access != FileAccess.Write)
            throw new ArgumentException("Append requires write-only access.", nameof(access));
        var options = new SmbOpenOptions
        {
            Access = SmbAccessMask.ReadAttributes | SmbAccessMask.Synchronize |
                (access is FileAccess.Read or FileAccess.ReadWrite ? SmbAccessMask.ReadData : 0) |
                (access is FileAccess.Write or FileAccess.ReadWrite ? SmbAccessMask.WriteData : 0),
            ShareAccess = (SmbShareAccess)share,
            Disposition = mode switch
            {
                FileMode.CreateNew => SmbCreateDisposition.Create,
                FileMode.Create => SmbCreateDisposition.OverwriteIf,
                FileMode.Open => SmbCreateDisposition.Open,
                FileMode.OpenOrCreate or FileMode.Append => SmbCreateDisposition.OpenIf,
                FileMode.Truncate => SmbCreateDisposition.Overwrite,
                _ => throw new ArgumentOutOfRangeException(nameof(mode))
            }
        };
        SmbFileHandle handle = await OpenFileAsync(path, options, cancellationToken).ConfigureAwait(false);
        return new SmbFileStream(handle, access, mode == FileMode.Append);
    }

    /// <summary>读取路径对象自身的聚合属性、时间、大小、链接数和标识信息。</summary>
    /// <param name="path">相对于共享的待检查路径，不跟随最后一级重解析点。</param>
    /// <param name="cancellationToken">取消打开句柄及信息查询。</param>
    /// <returns>将服务器 FileAllInformation 映射到公开元数据模型后的结果。</returns>
    public async Task<SmbFileInfo> GetInfoAsync(string path, CancellationToken cancellationToken = default)
    {
        await using SmbFileHandle handle = await OpenMetadataAsync(path, SmbAccessMask.ReadAttributes, cancellationToken).ConfigureAwait(false);
        return await handle.GetInfoAsync(cancellationToken).ConfigureAwait(false);
    }

    /// <summary>尝试打开路径以读取元数据，仅在服务器明确报告不存在时返回 false。</summary>
    /// <param name="path">相对于共享的路径。</param>
    /// <param name="cancellationToken">取消远程打开操作。</param>
    /// <returns>路径存在时为 true；文件或路径不存在时为 false。</returns>
    /// <exception cref="SmbException">服务器返回不存在以外的错误，包括访问被拒绝。</exception>
    public async Task<bool> ExistsAsync(string path, CancellationToken cancellationToken = default)
    {
        try
        {
            await using SmbFileHandle handle = await OpenMetadataAsync(path, SmbAccessMask.ReadAttributes, cancellationToken).ConfigureAwait(false);
            return true;
        }
        catch (SmbException ex) when (ex.IsNotFound)
        {
            return false;
        }
    }

    /// <summary>逐页返回全部 FileDirectoryInformation 条目，并排除当前目录和父目录项。</summary>
    /// <param name="directory">目录路径；空字符串表示共享根目录。</param>
    /// <param name="searchPattern">由服务器匹配的单级名称通配符模式。</param>
    /// <param name="cancellationToken">取消打开目录或后续分页请求。</param>
    /// <returns>异步返回的目录元数据条目序列。</returns>
    /// <exception cref="ArgumentException">模式包含路径分隔符、数据流分隔符或 NUL。</exception>
    /// <exception cref="SmbProtocolException">对端返回了成功但无条目的页面，且未报告搜索结束。</exception>
    public async IAsyncEnumerable<SmbDirectoryEntry> EnumerateDirectoryAsync(string directory = "", string searchPattern = "*",
        [EnumeratorCancellation] CancellationToken cancellationToken = default)
    {
        ThrowIfDisposed();
        directory = SmbPath.Normalize(directory);
        ArgumentException.ThrowIfNullOrWhiteSpace(searchPattern);
        if (searchPattern.IndexOfAny(['\\', '/', '\0', ':']) >= 0)
            throw new ArgumentException("A search pattern must be a single name pattern.", nameof(searchPattern));
        await using SmbFileHandle handle = await OpenFileAsync(directory, new SmbOpenOptions
        {
            Access = SmbAccessMask.ReadData | SmbAccessMask.ReadAttributes,
            CreateOptions = SmbCreateOptions.DirectoryFile,
            Attributes = FileAttributes.Directory
        }, cancellationToken).ConfigureAwait(false);
        bool restart = true;
        while (true)
        {
            cancellationToken.ThrowIfCancellationRequested();
            IReadOnlyList<SmbDirectoryEntry>? entries = await handle.QueryDirectoryAsync(searchPattern, restart, cancellationToken).ConfigureAwait(false);
            restart = false;
            if (entries is null)
                yield break;
            if (entries.Count == 0)
                throw new SmbProtocolException("A directory query succeeded without entries or an end-of-search status.");
            foreach (SmbDirectoryEntry entry in entries)
                if (entry.Name is not ("." or ".."))
                    yield return entry;
        }
    }

    /// <summary>创建目录，并可使用 OpenIf 语义逐级创建缺失的父目录。</summary>
    /// <param name="path">相对于共享的目录路径。</param>
    /// <param name="recursive">为 true 时创建父目录；为 false 时要求父目录已经存在。</param>
    /// <param name="cancellationToken">在远程创建前或创建期间取消。</param>
    /// <returns>全部所需目录句柄关闭后完成的任务。</returns>
    public async Task CreateDirectoryAsync(string path, bool recursive = true, CancellationToken cancellationToken = default)
    {
        path = SmbPath.Normalize(path);
        if (path.Length == 0)
            return;
        string[] parts = recursive ? path.Split('\\') : [path];
        string current = "";
        foreach (string part in parts)
        {
            current = SmbPath.Combine(current, part);
            await using SmbFileHandle handle = await OpenFileAsync(current, new SmbOpenOptions
            {
                Access = SmbAccessMask.ReadAttributes,
                Disposition = SmbCreateDisposition.OpenIf,
                CreateOptions = SmbCreateOptions.DirectoryFile,
                Attributes = FileAttributes.Directory
            }, cancellationToken).ConfigureAwait(false);
        }
    }

    /// <summary>将指定文件或最后一级重解析点标记为删除，并关闭删除句柄。</summary>
    /// <param name="path">不指向根目录的共享相对文件路径。</param>
    /// <param name="cancellationToken">取消打开文件或设置删除标志。</param>
    /// <returns>表示删除操作的任务。</returns>
    /// <exception cref="ArgumentException">目标为共享根目录。</exception>
    public async Task DeleteFileAsync(string path, CancellationToken cancellationToken = default)
    {
        EnsureNotRoot(path);
        await using SmbFileHandle handle = await OpenFileAsync(path, new SmbOpenOptions
        {
            Access = SmbAccessMask.Delete,
            CreateOptions = SmbCreateOptions.NonDirectoryFile | SmbCreateOptions.OpenReparsePoint
        }, cancellationToken).ConfigureAwait(false);
        await handle.SetDeletePendingAsync(true, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>删除目录，并可先移除其后代条目，但不遍历目录重解析点。</summary>
    /// <param name="path">不指向根目录的共享相对目录路径。</param>
    /// <param name="recursive">为 true 时先删除目录条目；为 false 时保留服务器对非空目录的正常拒绝。</param>
    /// <param name="cancellationToken">取消元数据查询、目录枚举或删除。</param>
    /// <returns>表示全部所需删除操作的任务。</returns>
    /// <exception cref="ArgumentException">目标为共享根目录。</exception>
    /// <exception cref="IOException">目标不是目录。</exception>
    /// <remarks>并发重命名可能导致服务器错误；这种基于路径的操作不构成文件系统事务。</remarks>
    public async Task DeleteDirectoryAsync(string path, bool recursive = false, CancellationToken cancellationToken = default)
    {
        path = SmbPath.Normalize(path);
        EnsureNotRoot(path);
        // 向下遍历之前先检查目标对象自身，不跟随重解析点。
        SmbFileInfo info = await GetInfoAsync(path, cancellationToken).ConfigureAwait(false);
        if (!info.IsDirectory)
            throw new IOException("The path is not a directory.");
        if (recursive && (info.Attributes & FileAttributes.ReparsePoint) == 0)
        {
            await foreach (SmbDirectoryEntry? entry in EnumerateDirectoryAsync(path, cancellationToken: cancellationToken).ConfigureAwait(false))
            {
                string child = SmbPath.Combine(path, entry.Name);
                if (entry.IsDirectory)
                    await DeleteDirectoryAsync(child, !entry.IsReparsePoint, cancellationToken).ConfigureAwait(false);
                else
                    await DeleteFileAsync(child, cancellationToken).ConfigureAwait(false);
            }
        }
        await using SmbFileHandle handle = await OpenFileAsync(path, new SmbOpenOptions
        {
            Access = SmbAccessMask.Delete,
            CreateOptions = SmbCreateOptions.DirectoryFile | SmbCreateOptions.OpenReparsePoint,
            Attributes = FileAttributes.Directory
        }, cancellationToken).ConfigureAwait(false);
        await handle.SetDeletePendingAsync(true, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>在当前共享内重命名或移动文件及目录。</summary>
    /// <param name="source">已经存在且不指向根目录的源路径。</param>
    /// <param name="destination">不指向根目录的目标路径。</param>
    /// <param name="replaceIfExists">是否允许服务器替换已经存在的目标。</param>
    /// <param name="cancellationToken">取消打开源对象或重命名请求。</param>
    /// <returns>表示服务器端重命名的任务。</returns>
    public async Task MoveAsync(string source, string destination, bool replaceIfExists = false, CancellationToken cancellationToken = default)
    {
        EnsureNotRoot(source);
        EnsureNotRoot(destination);
        await using SmbFileHandle handle = await OpenMetadataAsync(source, SmbAccessMask.Delete, cancellationToken).ConfigureAwait(false);
        await handle.RenameAsync(destination, replaceIfExists, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>设置基本文件属性，以及可选的创建、访问和修改时间。</summary>
    /// <param name="path">相对于共享的目标，打开时不跟随最后一级重解析点。</param>
    /// <param name="attributes">新属性；为零时保持属性字段不变。</param>
    /// <param name="creationTime">新的创建时间；为 null 时保留原值。</param>
    /// <param name="lastAccessTime">新的访问时间；为 null 时保留原值。</param>
    /// <param name="lastWriteTime">新的修改时间；为 null 时保留原值。</param>
    /// <param name="cancellationToken">取消打开目标或设置元数据。</param>
    /// <returns>表示元数据更新的任务。</returns>
    public async Task SetAttributesAsync(string path, FileAttributes attributes, DateTimeOffset? creationTime = null,
        DateTimeOffset? lastAccessTime = null, DateTimeOffset? lastWriteTime = null, CancellationToken cancellationToken = default)
    {
        await using SmbFileHandle handle = await OpenMetadataAsync(path, SmbAccessMask.WriteAttributes, cancellationToken).ConfigureAwait(false);
        await handle.SetBasicInfoAsync(attributes, creationTime, lastAccessTime, lastWriteTime,
            cancellationToken: cancellationToken).ConfigureAwait(false);
    }

    /// <summary>查询总分配单元数、调用者可用单元数和实际可用单元数。</summary>
    /// <param name="cancellationToken">取消打开根目录或查询卷信息。</param>
    /// <returns>经过校验的 FileFsFullSizeInformation 数值及具有溢出检查的字节换算结果。</returns>
    public async Task<SmbFileSystemSpace> GetSpaceAsync(CancellationToken cancellationToken = default)
    {
        await using SmbFileHandle root = await OpenMetadataAsync("", SmbAccessMask.ReadAttributes, cancellationToken).ConfigureAwait(false);
        byte[] data = await root.QueryInfoAsync(SmbInfoType.FileSystem, 7, cancellationToken: cancellationToken).ConfigureAwait(false);
        _ = Wire.Slice(data, 0, 32);
        return Wire.I64(data, 0) < 0 || Wire.I64(data, 8) < 0 || Wire.I64(data, 16) < 0 ||
            Wire.U32(data, 24) == 0 || Wire.U32(data, 28) == 0
            ? throw new SmbProtocolException("Invalid SMB filesystem capacity information.")
            : new SmbFileSystemSpace(Wire.I64(data, 0), Wire.I64(data, 8), Wire.I64(data, 16),
            Wire.U32(data, 24), Wire.U32(data, 28));
    }

    /// <summary>查询卷标、序列号、创建时间和对象支持标志。</summary>
    /// <param name="cancellationToken">取消打开远程根目录或查询卷信息。</param>
    /// <returns>服务器声明的卷信息。</returns>
    public async Task<SmbVolumeInfo> GetVolumeInfoAsync(CancellationToken cancellationToken = default)
    {
        await using SmbFileHandle root = await OpenMetadataAsync("", SmbAccessMask.ReadAttributes, cancellationToken).ConfigureAwait(false);
        byte[] data = await root.QueryInfoAsync(SmbInfoType.FileSystem, 1, cancellationToken: cancellationToken).ConfigureAwait(false);
        _ = Wire.Slice(data, 0, 18);
        return new SmbVolumeInfo(Wire.Time(data, 0), Wire.U32(data, 8),
            Wire.Text(data, 18, Wire.Int32(Wire.U32(data, 12))), data[16] != 0);
    }

    /// <summary>查询文件系统名称、能力标志和单个名称组件的最大长度。</summary>
    /// <param name="cancellationToken">取消打开根目录或查询属性。</param>
    /// <returns>服务器声明的文件系统属性。</returns>
    public async Task<SmbFileSystemAttributes> GetFileSystemAttributesAsync(CancellationToken cancellationToken = default)
    {
        await using SmbFileHandle root = await OpenMetadataAsync("", SmbAccessMask.ReadAttributes, cancellationToken).ConfigureAwait(false);
        byte[] data = await root.QueryInfoAsync(SmbInfoType.FileSystem, 5, cancellationToken: cancellationToken).ConfigureAwait(false);
        _ = Wire.Slice(data, 0, 12);
        return new SmbFileSystemAttributes(Wire.U32(data, 0), Wire.Int32(Wire.U32(data, 4)),
            Wire.Text(data, 12, Wire.Int32(Wire.U32(data, 8))));
    }

    /// <summary>上传可读流，并在传输结束后刷新远程文件。</summary>
    /// <param name="path">相对于共享的目标文件路径。</param>
    /// <param name="source">可读的源流，其所有权仍归调用者。</param>
    /// <param name="overwrite">为 true 时替换已有内容；为 false 时要求创建新文件。</param>
    /// <param name="progress">可选的字节进度；源流不可定位时总量为 null。</param>
    /// <param name="cancellationToken">取消打开文件或传输数据。</param>
    /// <returns>表示数据传输及最终刷新的任务。</returns>
    /// <remarks>取消操作可能留下部分远程文件；此接口不执行原子提交。</remarks>
    public async Task UploadAsync(string path, Stream source, bool overwrite = true,
        IProgress<SmbTransferProgress>? progress = null, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(source);
        if (!source.CanRead)
            throw new ArgumentException("The source stream must be readable.", nameof(source));
        await using SmbFileStream destination = await OpenStreamAsync(path, overwrite ? FileMode.Create : FileMode.CreateNew,
            FileAccess.Write, FileShare.None, cancellationToken).ConfigureAwait(false);
        long? total = source.CanSeek ? source.Length - source.Position : null;
        await TransferAsync(source, destination, total, progress, cancellationToken).ConfigureAwait(false);
        await destination.FlushAsync(cancellationToken).ConfigureAwait(false);
    }

    /// <summary>将远程文件内容复制到调用者拥有的可写流。</summary>
    /// <param name="path">相对于共享的源文件路径。</param>
    /// <param name="destination">可写的目标流，传输完成后仍保持打开。</param>
    /// <param name="progress">可选的已传输字节进度。</param>
    /// <param name="cancellationToken">取消打开文件或传输数据。</param>
    /// <returns>表示下载过程的任务。</returns>
    /// <remarks>取消时保留已经写入目标流的字节。</remarks>
    public async Task DownloadAsync(string path, Stream destination, IProgress<SmbTransferProgress>? progress = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(destination);
        if (!destination.CanWrite)
            throw new ArgumentException("The destination stream must be writable.", nameof(destination));
        await using SmbFileStream source = await OpenStreamAsync(path, cancellationToken: cancellationToken).ConfigureAwait(false);
        await TransferAsync(source, destination, source.Length, progress, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>在当前共享内通过客户端复制文件的默认数据流。</summary>
    /// <param name="source">已经存在的源路径。</param>
    /// <param name="destination">与源路径不同的目标路径。</param>
    /// <param name="overwrite">是否允许替换目标文件的已有内容。</param>
    /// <param name="progress">可选的传输进度。</param>
    /// <param name="cancellationToken">取消任一文件打开操作或数据传输。</param>
    /// <returns>表示文件内容复制的任务。</returns>
    /// <remarks>此便捷接口不复制 ACL、备用数据流、时间戳和稀疏布局。</remarks>
    public async Task CopyFileAsync(string source, string destination, bool overwrite = false,
        IProgress<SmbTransferProgress>? progress = null, CancellationToken cancellationToken = default)
    {
        if (string.Equals(SmbPath.Normalize(source), SmbPath.Normalize(destination), StringComparison.OrdinalIgnoreCase))
            throw new ArgumentException("Source and destination must be different paths.");
        await using SmbFileStream sourceStream = await OpenStreamAsync(source, cancellationToken: cancellationToken).ConfigureAwait(false);
        await UploadAsync(destination, sourceStream, overwrite, progress, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>按有界数据块传输，即使 IO 或进度回调失败也清理池化缓冲区。</summary>
    /// <param name="source">可读流。</param>
    /// <param name="destination">可写流。</param>
    /// <param name="total">可选的进度总字节数。</param>
    /// <param name="progress">可选的应用程序进度回调。</param>
    /// <param name="cancellationToken">取消源流读取或目标流写入。</param>
    /// <returns>表示全部流复制迭代的任务。</returns>
    private async Task TransferAsync(Stream source, Stream destination, long? total,
        IProgress<SmbTransferProgress>? progress, CancellationToken cancellationToken)
    {
        byte[] buffer = System.Buffers.ArrayPool<byte>.Shared.Rent(client.Options.TransferBufferSize);
        long transferred = 0;
        try
        {
            progress?.Report(new SmbTransferProgress(0, total));
            while (true)
            {
                int length = await source.ReadAsync(buffer.AsMemory(0, client.Options.TransferBufferSize), cancellationToken).ConfigureAwait(false);
                if (length == 0)
                    break;
                await destination.WriteAsync(buffer.AsMemory(0, length), cancellationToken).ConfigureAwait(false);
                transferred += length;
                progress?.Report(new SmbTransferProgress(transferred, total));
            }
        }
        finally
        {
            System.Buffers.ArrayPool<byte>.Shared.Return(buffer, clearArray: true);
        }
    }

    /// <summary>通过可用会话通道发送树连接范围内的请求，并遵守该树的加密要求。</summary>
    /// <param name="command">SMB2 命令。</param>
    /// <param name="body">不包含 SMB2 消息头的命令正文。</param>
    /// <param name="cancellationToken">取消本次操作。</param>
    /// <param name="maximumResponse">用于 credit 计费的预期响应数据上限。</param>
    /// <param name="infiniteTimeout">等待期限由调用者令牌控制时为 true。</param>
    /// <returns>通过协议校验的响应。</returns>
    internal Task<Response> SendAsync(Command command, ReadOnlyMemory<byte> body, CancellationToken cancellationToken,
        int maximumResponse = 0, bool infiniteTimeout = false)
    {
        return client.SendAsync(command, body, TreeId, cancellationToken, maximumResponse, EncryptionRequired, infiniteTimeout);
    }

    /// <summary>打开路径对象自身，以执行小型元数据或安全信息操作。</summary>
    /// <param name="path">目标路径；空字符串表示共享根目录。</param>
    /// <param name="access">元数据操作所需的具体访问权限。</param>
    /// <param name="cancellationToken">取消打开目标。</param>
    /// <returns>不跟随最后一级重解析点的临时句柄。</returns>
    private Task<SmbFileHandle> OpenMetadataAsync(string path, SmbAccessMask access, CancellationToken cancellationToken)
    {
        return OpenFileAsync(path, new SmbOpenOptions { Access = access, CreateOptions = SmbCreateOptions.OpenReparsePoint }, cancellationToken);
    }

    /// <summary>拒绝可能删除或重命名共享根目录的操作。</summary>
    /// <param name="path">需要规范化并检查的路径。</param>
    /// <exception cref="ArgumentException">规范化后的路径为空。</exception>
    private static void EnsureNotRoot(string path)
    {
        if (SmbPath.Normalize(path).Length == 0)
            throw new ArgumentException("This operation cannot target the root of a share.", nameof(path));
    }

    /// <summary>在当前共享使用对象的句柄表中查找已校验撤销通知的 FileId。</summary>
    /// <param name="packet">已经过连接安全校验的主动通知。</param>
    /// <param name="wasEncrypted">通知是否实际采用 SMB 消息加密，用于校验当前共享的强制加密要求。</param>
    /// <returns>拥有的句柄接收通知时为 true；未知 FileId 返回 false。</returns>
    internal bool TryQueueOplockBreak(byte[] packet, bool wasEncrypted)
    {
        (SmbFileId Id, SmbOplockLevel Level) = SmbOplockProtocol.ReadNotification(packet);
        if (!handles.TryGetValue(Id, out SmbFileHandle? handle))
            return false;
        // OPLOCK_BREAK 的 TreeId 固定为零，只有解析 FileId 后才能得知其所属共享。
        // 客户端 WhenAvailable 发送偏好不强制主动通知加密，但共享声明的加密要求始终必须执行。
        if (EncryptionRequired && !wasEncrypted)
            throw new SmbProtocolException("An unencrypted oplock notification targeted an encryption-required share.");
        handle.QueueOplockBreak(Level);
        return true;
    }

    /// <summary>会话不再有可用传输通道时，撤销全部本地缓存授予。</summary>
    /// <param name="error">需要交付给待完成观察者的失败原因。</param>
    internal void InvalidateOplocks(Exception error)
    {
        foreach (SmbFileHandle handle in handles.Values)
            handle.InvalidateOplock(error);
    }

    /// <summary>从共享的关闭与通知索引中移除应用程序已关闭的句柄。</summary>
    /// <param name="id">远程打开句柄标识符。</param>
    internal void RemoveHandle(SmbFileId id)
    {
        _ = handles.TryRemove(id, out _);
    }

    /// <summary>拒绝使用已释放的共享或其所属会话。</summary>
    /// <exception cref="ObjectDisposedException">共享或会话已经释放。</exception>
    internal void ThrowIfDisposed()
    {
        ObjectDisposedException.ThrowIf(Volatile.Read(ref disposed) != 0, this);
        client.ThrowIfDisposed();
    }

    /// <summary>关闭当前对象拥有的句柄，并且只释放一次底层树连接引用。</summary>
    /// <returns>关闭和树连接引用清理结束后完成的任务式返回值。</returns>
    /// <remarks>同一树连接的其他引用在各自释放之前仍可继续使用。</remarks>
    public async ValueTask DisposeAsync()
    {
        if (Interlocked.Exchange(ref disposed, 1) != 0)
            return;
        try
        {
            foreach (SmbFileHandle handle in handles.Values)
                try
                {
                    await handle.DisposeAsync().ConfigureAwait(false);
                }
                catch (IOException) { }
        }
        finally
        {
            await client.ReleaseShareAsync(this).ConfigureAwait(false);
        }
    }
}