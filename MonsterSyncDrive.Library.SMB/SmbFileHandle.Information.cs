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
using System.Runtime.CompilerServices;
using MonsterSyncDrive.SMB.Protocol;

namespace MonsterSyncDrive.SMB;


/// <summary>远程句柄的标准文件信息扩展，提供类型化查询、设置、EA 分页和目录格式选择。</summary>
public sealed partial class SmbFileHandle
{

    /// <summary>串行化友好 EA 扫描状态，防止同一句柄的并发页请求互相覆盖客户端索引。</summary>
    private readonly SemaphoreSlim extendedAttributeGate = new(1, 1);

    /// <summary>下次无显式起点的友好 EA 查询所使用的一基索引。</summary>
    private uint nextExtendedAttributeIndex = 1;

    /// <summary>友好 EA 扫描是否已经收到完整尾页；RestartScan 会绕过该缓存状态。</summary>
    private bool extendedAttributeScanComplete;


    /// <summary>读取当前打开句柄实际获授的 FileAccessInformation。</summary>
    /// <param name="cancellationToken">取消等待和网络操作的令牌。请求已发送后取消不会回滚服务器可能已执行的修改。</param>
    /// <returns>访问掩码；不是对其他身份的有效权限计算。</returns>
    public async Task<SmbAccessMask> GetAccessMaskAsync(CancellationToken cancellationToken = default)
        => (SmbAccessMask)Wire.U32(await FileInformationAsync(SmbFileInformationClass.Access, cancellationToken).ConfigureAwait(false), 0);

    /// <summary>读取并校验 FileAlignmentInformation 的设备对齐掩码。</summary>
    /// <param name="cancellationToken">取消等待和网络操作的令牌。请求已发送后取消不会回滚服务器可能已执行的修改。</param>
    /// <returns>对齐掩码与字节边界。</returns>
    public async Task<SmbAlignmentInformation> GetAlignmentInformationAsync(CancellationToken cancellationToken = default)
        => SmbFileInformationCodec.Alignment(await FileInformationAsync(SmbFileInformationClass.Alignment, cancellationToken).ConfigureAwait(false));

    /// <summary>读取 FileBasicInformation 的四类时间和文件属性。</summary>
    /// <param name="cancellationToken">取消等待和网络操作的令牌。请求已发送后取消不会回滚服务器可能已执行的修改。</param>
    /// <returns>基本文件信息快照。</returns>
    public async Task<SmbBasicInformation> GetBasicInformationAsync(CancellationToken cancellationToken = default)
        => SmbFileInformationCodec.Basic(await FileInformationAsync(SmbFileInformationClass.Basic, cancellationToken).ConfigureAwait(false));

    /// <summary>读取 FileStandardInformation 的大小、链接和删除状态。</summary>
    /// <param name="cancellationToken">取消等待和网络操作的令牌。请求已发送后取消不会回滚服务器可能已执行的修改。</param>
    /// <returns>标准文件信息快照。</returns>
    public async Task<SmbStandardInformation> GetStandardInformationAsync(CancellationToken cancellationToken = default)
        => SmbFileInformationCodec.Standard(await FileInformationAsync(SmbFileInformationClass.Standard, cancellationToken).ConfigureAwait(false));

    /// <summary>读取并完整解码 FileAllInformation，包括访问、模式、游标、EA 和对齐。</summary>
    /// <param name="cancellationToken">取消等待和网络操作的令牌。请求已发送后取消不会回滚服务器可能已执行的修改。</param>
    /// <returns>完整聚合信息模型。</returns>
    public async Task<SmbAllInformation> GetAllInformationAsync(CancellationToken cancellationToken = default)
        => SmbFileInformationCodec.All(await FileInformationAsync(SmbFileInformationClass.All, cancellationToken).ConfigureAwait(false));

    /// <summary>读取 FileInternalInformation 中的文件系统 64 位索引。</summary>
    /// <param name="cancellationToken">取消等待和网络操作的令牌。请求已发送后取消不会回滚服务器可能已执行的修改。</param>
    /// <returns>内部文件索引，不是 SMB 句柄。</returns>
    public async Task<ulong> GetInternalFileIndexAsync(CancellationToken cancellationToken = default)
        => Wire.U64(await FileInformationAsync(SmbFileInformationClass.Internal, cancellationToken).ConfigureAwait(false), 0);

    /// <summary>读取 FileEaInformation 的 EA 总字节数。</summary>
    /// <param name="cancellationToken">取消等待和网络操作的令牌。请求已发送后取消不会回滚服务器可能已执行的修改。</param>
    /// <returns>服务端报告的 EA 大小。</returns>
    public async Task<uint> GetExtendedAttributeSizeAsync(CancellationToken cancellationToken = default)
        => Wire.U32(await FileInformationAsync(SmbFileInformationClass.Ea, cancellationToken).ConfigureAwait(false), 0);

    /// <summary>查询 FileAlternateNameInformation 中的短文件名。</summary>
    /// <param name="cancellationToken">取消等待和网络操作的令牌。请求已发送后取消不会回滚服务器可能已执行的修改。</param>
    /// <returns>服务端存储的短名称；不支持时保留服务器错误。</returns>
    public async Task<string> GetAlternateNameAsync(CancellationToken cancellationToken = default)
        => SmbFileInformationCodec.Name(await FileInformationAsync(SmbFileInformationClass.AlternateName, cancellationToken).ConfigureAwait(false));

    /// <summary>查询共享相对的规范化路径；旧协议或服务器可以拒绝该可选类。</summary>
    /// <param name="cancellationToken">取消等待和网络操作的令牌。请求已发送后取消不会回滚服务器可能已执行的修改。</param>
    /// <returns>服务器报告的规范化名称。</returns>
    public async Task<string> GetNormalizedNameAsync(CancellationToken cancellationToken = default)
        => SmbFileInformationCodec.Name(await FileInformationAsync(SmbFileInformationClass.NormalizedName, cancellationToken).ConfigureAwait(false));

    /// <summary>查询文件系统压缩信息，保留格式编号及各类移位。</summary>
    /// <param name="cancellationToken">取消等待和网络操作的令牌。请求已发送后取消不会回滚服务器可能已执行的修改。</param>
    /// <returns>文件系统压缩大小和参数，不是网络压缩状态。</returns>
    public async Task<SmbFileCompressionInformation> GetCompressionInformationAsync(CancellationToken cancellationToken = default)
        => SmbFileInformationCodec.Compression(await FileInformationAsync(SmbFileInformationClass.Compression, cancellationToken).ConfigureAwait(false));

    /// <summary>查询适用于网络打开操作的时间、大小和属性。</summary>
    /// <param name="cancellationToken">取消等待和网络操作的令牌。请求已发送后取消不会回滚服务器可能已执行的修改。</param>
    /// <returns>网络打开信息模型。</returns>
    public async Task<SmbNetworkOpenInformation> GetNetworkOpenInformationAsync(CancellationToken cancellationToken = default)
        => SmbFileInformationCodec.NetworkOpen(await FileInformationAsync(SmbFileInformationClass.NetworkOpen, cancellationToken).ConfigureAwait(false));

    /// <summary>查询 FileIdInformation，保留卷序列号和全部 128 位 ID。</summary>
    /// <param name="cancellationToken">取消等待和网络操作的令牌。请求已发送后取消不会回滚服务器可能已执行的修改。</param>
    /// <returns>文件系统标识，不具备 durable handle 恢复语义。</returns>
    public async Task<SmbFileIdentity> GetFileIdentityAsync(CancellationToken cancellationToken = default)
        => SmbFileInformationCodec.Identity(await FileInformationAsync(SmbFileInformationClass.Id, cancellationToken).ConfigureAwait(false));

    /// <summary>读取 FileAttributeTagInformation 的属性及重解析标签。</summary>
    /// <param name="cancellationToken">取消等待和网络操作的令牌。请求已发送后取消不会回滚服务器可能已执行的修改。</param>
    /// <returns>文件属性和原始标签。</returns>
    public async Task<SmbFileAttributeTag> GetAttributeTagAsync(CancellationToken cancellationToken = default)
    {
        var data = await FileInformationAsync(SmbFileInformationClass.AttributeTag, cancellationToken).ConfigureAwait(false);
        return new((FileAttributes)Wire.U32(data, 0), Wire.U32(data, 4));
    }

    /// <summary>读取服务端报告的打开模式位，不修改客户端 Stream 行为。</summary>
    /// <param name="cancellationToken">取消等待和网络操作的令牌。请求已发送后取消不会回滚服务器可能已执行的修改。</param>
    /// <returns>当前服务端文件模式。</returns>
    public async Task<SmbFileMode> GetFileModeAsync(CancellationToken cancellationToken = default)
        => (SmbFileMode)Wire.U32(await FileInformationAsync(SmbFileInformationClass.Mode, cancellationToken).ConfigureAwait(false), 0);

    /// <summary>查询服务器游标；普通 SMB 读写使用显式偏移，因此服务器可以报告零。</summary>
    /// <param name="cancellationToken">取消等待和服务器请求的令牌。</param>
    /// <returns>非负的服务器游标；它与 SmbFileStream.Position 独立。</returns>
    public async Task<long> GetServerPositionAsync(CancellationToken cancellationToken = default)
    {
        var value = Wire.I64(await FileInformationAsync(SmbFileInformationClass.Position, cancellationToken).ConfigureAwait(false), 0);
        return value >= 0 ? value : throw new SmbProtocolException("The server returned a negative file position.");
    }


    /// <summary>将基本信息模型转换为已有的时间和属性设置请求；空时间表示保留。</summary>
    /// <param name="information">目标基本信息，不允许为空。</param>
    /// <param name="cancellationToken">取消等待和网络操作的令牌。请求已发送后取消不会回滚服务器可能已执行的修改。</param>
    /// <returns>服务器确认修改后的任务。</returns>
    public Task SetBasicInformationAsync(SmbBasicInformation information, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(information);
        return SetBasicInfoAsync(information.Attributes, information.CreationTime, information.LastAccessTime,
            information.LastWriteTime, information.ChangeTime, cancellationToken);
    }

    /// <summary>设置 MS-FSCC 允许修改的模式位；仅在打开时生效的选项不能在此更改。</summary>
    /// <param name="mode">直写、顺序和至多一种同步模式；不能通过此调用切换无缓冲选项。</param>
    /// <param name="cancellationToken">取消请求的令牌；不回滚已执行的服务端操作。</param>
    /// <returns>服务端接受模式修改后完成的任务。</returns>
    public Task SetFileModeAsync(SmbFileMode mode, CancellationToken cancellationToken = default)
    {
        if (((uint)mode & ~0x36u) != 0 || (mode & (SmbFileMode.SynchronousIoAlert | SmbFileMode.SynchronousIoNonAlert)) ==
            (SmbFileMode.SynchronousIoAlert | SmbFileMode.SynchronousIoNonAlert))
            throw new ArgumentOutOfRangeException(nameof(mode));
        var data = new byte[4]; Wire.Put32(data, 0, (uint)mode);
        return SetInfoAsync(SmbInfoType.File, (byte)SmbFileInformationClass.Mode, data, cancellationToken: cancellationToken);
    }


    /// <summary>设置服务器句柄游标；普通 SMB READ/WRITE 仍使用显式偏移，因此不改变 SmbFileStream.Position。</summary>
    /// <param name="position">非负的服务器游标位置。</param>
    /// <param name="cancellationToken">取消等待和网络操作的令牌。请求已发送后取消不会回滚服务器可能已执行的修改。</param>
    /// <returns>服务器接受设置后的任务。</returns>
    public Task SetServerPositionAsync(long position, CancellationToken cancellationToken = default)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(position);
        var data = new byte[8]; Wire.PutI64(data, 0, position);
        return SetInfoAsync(SmbInfoType.File, (byte)SmbFileInformationClass.Position, data, cancellationToken: cancellationToken);
    }

    /// <summary>请求设置有效数据长度，需要服务端授予相应特权；此操作不会初始化文件内容。</summary>
    /// <param name="length">非负的已初始化数据长度，不能代替写入实际文件内容。</param>
    /// <param name="cancellationToken">取消请求的令牌。</param>
    /// <returns>服务器确认设置后的任务；权限与现有 EOF 条件由服务器检查。</returns>
    public Task SetValidDataLengthAsync(long length, CancellationToken cancellationToken = default)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(length);
        var data = new byte[8]; Wire.PutI64(data, 0, length);
        return SetInfoAsync(SmbInfoType.File, (byte)SmbFileInformationClass.ValidDataLength, data, cancellationToken: cancellationToken);
    }


    /// <summary>设置最多 12 个 UTF-16 单元的短名称；空字符串请求移除已有短名称。</summary>
    /// <param name="shortName">单个短名称，不得包含路径分隔符、数据流分隔符或 NUL。</param>
    /// <param name="cancellationToken">取消等待和网络操作的令牌。请求已发送后取消不会回滚服务器可能已执行的修改。</param>
    /// <returns>服务端确认后的任务；8.3 规则和权限仍由服务端验证。</returns>
    public Task SetShortNameAsync(string shortName, CancellationToken cancellationToken = default)
        => SetInfoAsync(SmbInfoType.File, (byte)SmbFileInformationClass.ShortName,
            SmbFileInformationCodec.EncodeShortName(shortName), cancellationToken: cancellationToken);


    /// <summary>发送 FILE_DISPOSITION_INFORMATION_EX，以显式标志控制普通或 POSIX 删除行为。</summary>
    /// <param name="flags">不含未知位的删除标志组合。</param>
    /// <param name="cancellationToken">取消等待和网络操作的令牌。请求已发送后取消不会回滚服务器可能已执行的修改。</param>
    /// <returns>服务器确认扩展删除设置后的任务。</returns>
    public Task SetDispositionAsync(SmbDispositionFlags flags, CancellationToken cancellationToken = default)
    {
        if (((uint)flags & ~0x1Fu) != 0) throw new ArgumentOutOfRangeException(nameof(flags));
        var data = new byte[4]; Wire.Put32(data, 0, (uint)flags);
        return SetInfoAsync(SmbInfoType.File, (byte)SmbFileInformationClass.DispositionEx, data, cancellationToken: cancellationToken);
    }


    /// <summary>使用 FILE_RENAME_INFORMATION_EX 进行共享内重命名，并在成功后更新 Path。</summary>
    /// <param name="destination">非空的共享相对目标路径。</param>
    /// <param name="flags">替换、POSIX 和存储预留等扩展标志。</param>
    /// <param name="cancellationToken">取消等待和网络操作的令牌。请求已发送后取消不会回滚服务器可能已执行的修改。</param>
    /// <returns>服务端确认重命名后的任务。</returns>
    public async Task RenameExtendedAsync(string destination, SmbRenameFlags flags = SmbRenameFlags.None,
        CancellationToken cancellationToken = default)
    {
        var data = SmbFileInformationCodec.EncodeRename(destination, flags);
        await SetInfoAsync(SmbInfoType.File, (byte)SmbFileInformationClass.RenameEx, data,
            cancellationToken: cancellationToken).ConfigureAwait(false);
        Path = SmbPath.Normalize(destination);
    }


    /// <summary>读取命名管道的读取和完成模式；磁盘共享句柄会被拒绝。</summary>
    /// <param name="cancellationToken">取消等待和网络操作的令牌。请求已发送后取消不会回滚服务器可能已执行的修改。</param>
    /// <returns>命名管道模式。</returns>
    public async Task<SmbPipeInformation> GetPipeInformationAsync(CancellationToken cancellationToken = default)
    {
        EnsurePipe();
        return SmbFileInformationCodec.Pipe(await FileInformationAsync(SmbFileInformationClass.Pipe, cancellationToken).ConfigureAwait(false));
    }

    /// <summary>设置 IPC 命名管道的读取模式和完成模式。</summary>
    /// <param name="information">包含两个合法枚举值的管道模式。</param>
    /// <param name="cancellationToken">取消等待和网络操作的令牌。请求已发送后取消不会回滚服务器可能已执行的修改。</param>
    /// <returns>服务端接受管道模式后的任务。</returns>
    public Task SetPipeInformationAsync(SmbPipeInformation information, CancellationToken cancellationToken = default)
    {
        EnsurePipe(); ArgumentNullException.ThrowIfNull(information);
        if (!Enum.IsDefined(information.ReadMode) || !Enum.IsDefined(information.CompletionMode))
            throw new ArgumentException("Invalid named-pipe mode.", nameof(information));
        var data = new byte[8]; Wire.Put32(data, 0, (uint)information.ReadMode); Wire.Put32(data, 4, (uint)information.CompletionMode);
        return SetInfoAsync(SmbInfoType.File, (byte)SmbFileInformationClass.Pipe, data, cancellationToken: cancellationToken);
    }

    /// <summary>读取服务器管道的实例数量、配额、可用数据及连接状态。</summary>
    /// <param name="cancellationToken">取消等待和网络操作的令牌。请求已发送后取消不会回滚服务器可能已执行的修改。</param>
    /// <returns>完整管道本地信息。</returns>
    public async Task<SmbPipeLocalInformation> GetPipeLocalInformationAsync(CancellationToken cancellationToken = default)
    {
        EnsurePipe();
        return SmbFileInformationCodec.PipeLocal(await FileInformationAsync(SmbFileInformationClass.PipeLocal, cancellationToken).ConfigureAwait(false));
    }

    /// <summary>读取管道的收集时长和最大收集字节数。</summary>
    /// <param name="cancellationToken">取消等待和网络操作的令牌。请求已发送后取消不会回滚服务器可能已执行的修改。</param>
    /// <returns>原始远程管道收集参数。</returns>
    public async Task<SmbPipeRemoteInformation> GetPipeRemoteInformationAsync(CancellationToken cancellationToken = default)
    {
        EnsurePipe();
        return SmbFileInformationCodec.PipeRemote(await FileInformationAsync(SmbFileInformationClass.PipeRemote, cancellationToken).ConfigureAwait(false));
    }

    /// <summary>按名称或一基 EA 索引查询一页；同一句柄的游标分页请求串行执行。</summary>
    /// <param name="query">名称筛选或一基索引、首轮缓冲大小、是否允许受限扩容等选项。</param>
    /// <param name="cancellationToken">取消 EA 扫描锁等待或网络请求的令牌。</param>
    /// <returns>完整 EA 条目和继续查询指示；没有 EA 时返回空页。</returns>
    /// <remarks>每页使用明确索引以允许安全重试截断响应，不能把受限缓冲导致的残缺值当成完整 EA。</remarks>
    public async Task<SmbExtendedAttributePage> GetExtendedAttributesPageAsync(SmbExtendedAttributeQuery? query = null,
        CancellationToken cancellationToken = default)
    {
        ThrowIfClosed(); query ??= new();
        if (query.StartIndex == 0 || (query.StartIndex is not null && query.Names is { Count: > 0 }))
            throw new ArgumentException("Specify EA names or a nonzero EA index, not both.", nameof(query));
        if (query.BufferSize < 1 || query.BufferSize > MaximumTransactionCapacity)
            throw new ArgumentOutOfRangeException(nameof(query));
        var input = query.Names is { Count: > 0 } names ? SmbFileInformationCodec.EncodeEaNames(names, MaximumTransactionCapacity) : [];
        await extendedAttributeGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            var indexed = input.Length == 0;
            // EA 索引放在 AdditionalInformation，不能放进输入缓冲区；后者属于名称筛选链。
            // 使用明确的一基索引，使扩容重试不受服务端 Open.CurrentEaIndex 是否已推进的影响。
            var index = query.StartIndex ?? (query.RestartScan ? 1u : nextExtendedAttributeIndex);
            if (indexed && query.StartIndex is null && !query.RestartScan && extendedAttributeScanComplete)
                return new([], false);
            var flags = (query.ReturnSingleEntry ? 2u : 0) | (indexed ? 4u : 0);
            var size = query.BufferSize;
            while (true)
            {
                var result = await QueryInfoCoreAsync(SmbInfoType.File, (byte)SmbFileInformationClass.FullEa,
                    size, indexed ? index : 0, input, flags, cancellationToken, SmbStatus.BufferOverflow,
                    SmbStatus.BufferTooSmall, (SmbStatus)0x80000012, (SmbStatus)0xC0000051, (SmbStatus)0xC0000052).ConfigureAwait(false);
                var truncated = result.Status == SmbStatus.BufferTooSmall ||
                    (result.Status == SmbStatus.BufferOverflow && (result.Data.Length == 0 || SmbFileInformationCodec.ContainsTruncatedEa(result.Data)));
                if (truncated)
                {
                    if (!query.AllowBufferGrowth || size >= MaximumTransactionCapacity)
                        throw new IOException("An extended attribute does not fit the available transaction buffer. Increase the buffer or use a server supporting multi-credit transactions.");
                    // 最大单个 EA 为 8 字节头 + 254 字节名称 + NUL + 65535 字节值。
                    // 只扩大同一索引的查询，不重复修改文件，也不把残缺值返回给调用者。
                    size = (int)Math.Min(MaximumTransactionCapacity, Math.Max((long)size * 2, 65798));
                    continue;
                }
                var entries = SmbFileInformationCodec.ExtendedAttributes(result.Data);
                var more = result.Status == SmbStatus.BufferOverflow ||
                    (query.ReturnSingleEntry && result.Status == SmbStatus.Success && entries.Count != 0);
                if (indexed)
                {
                    // 只有完整解码之后才推进本地索引；异常和取消不会跳过尚未交付的 EA。
                    nextExtendedAttributeIndex = checked(index + (uint)entries.Count);
                    extendedAttributeScanComplete = !more;
                }
                return new(entries, more);
            }
        }
        finally { extendedAttributeGate.Release(); }
    }


    /// <summary>通过显式一基索引逐页枚举全部 EA，保留顺序并拒绝无进展的溢出响应。</summary>
    /// <param name="cancellationToken">取消等待和网络操作的令牌。请求已发送后取消不会回滚服务器可能已执行的修改。</param>
    /// <returns>逐个返回名称、二进制值和 Required 标志的异步序列。</returns>
    public async IAsyncEnumerable<SmbExtendedAttribute> EnumerateExtendedAttributesAsync(
        [EnumeratorCancellation] CancellationToken cancellationToken = default)
    {
        uint index = 1;
        while (true)
        {
            var page = await GetExtendedAttributesPageAsync(new() { StartIndex = index }, cancellationToken).ConfigureAwait(false);
            foreach (var entry in page.Entries) yield return entry;
            if (!page.HasMoreData) yield break;
            if (page.Entries.Count == 0) throw new SmbProtocolException("An EA query did not advance.");
            index = checked(index + (uint)page.Entries.Count);
        }
    }


    /// <summary>编码并原子发送一组 FILE_FULL_EA_INFORMATION；空值表示删除该名称，单个值最多 65535 字节。</summary>
    /// <param name="attributes">至少一个名称不重复且符合 ASCII 规则的 EA。</param>
    /// <param name="cancellationToken">取消等待和网络操作的令牌。请求已发送后取消不会回滚服务器可能已执行的修改。</param>
    /// <returns>服务端确认全部 EA 设置后的任务。</returns>
    /// <remarks>超过单 credit 的最大值需要服务器支持多 credit 和足够事务容量；不会拆分成有歧义的部分修改。</remarks>
    public Task SetExtendedAttributesAsync(IReadOnlyList<SmbExtendedAttribute> attributes, CancellationToken cancellationToken = default)
        => SetInfoAsync(SmbInfoType.File, (byte)SmbFileInformationClass.FullEa,
            SmbFileInformationCodec.EncodeExtendedAttributes(attributes, MaximumTransactionCapacity), cancellationToken: cancellationToken);

    /// <summary>使用标准单 credit 页预算，以选定的目录信息类执行一次 QUERY_DIRECTORY。</summary>
    /// <param name="pattern">不含路径分隔符的单级名称搜索模式。</param>
    /// <param name="informationClass">服务器应返回的目录结果格式。</param>
    /// <param name="restart">是否重新从扫描起点开始。</param>
    /// <param name="returnSingleEntry">是否请求单个条目。</param>
    /// <param name="reopen">是否重新开启服务器枚举状态。</param>
    /// <param name="fileIndex">可选的目录枚举索引。</param>
    /// <param name="cancellationToken">取消请求的令牌。</param>
    /// <returns>当前页的统一条目、明确的结束标志及缓冲溢出标志。</returns>
    public Task<SmbDirectoryPage> QueryDirectoryPageAsync(string pattern = "*",
        SmbDirectoryInformationClass informationClass = SmbDirectoryInformationClass.Directory,
        bool restart = false, bool returnSingleEntry = false, bool reopen = false,
        uint? fileIndex = null, CancellationToken cancellationToken = default)
        => QueryDirectoryPageAsync(new SmbDirectoryQuery
        {
            Pattern = pattern,
            InformationClass = informationClass,
            RestartScan = restart,
            ReturnSingleEntry = returnSingleEntry,
            Reopen = reopen,
            FileIndex = fileIndex
        }, cancellationToken);

    /// <summary>按完整目录查询选项发送请求，允许在支持多 credit 的连接上显式选择更大的结果缓冲区。</summary>
    /// <param name="query">名称模式、信息类、扫描标志和输出预算。</param>
    /// <param name="cancellationToken">取消服务器请求的令牌。</param>
    /// <returns>当前页；仅 NO_MORE_FILES 或 NO_SUCH_FILE 状态设置 IsComplete。</returns>
    public async Task<SmbDirectoryPage> QueryDirectoryPageAsync(SmbDirectoryQuery query,
        CancellationToken cancellationToken = default)
    {
        ThrowIfClosed(); ArgumentNullException.ThrowIfNull(query);
        if (!IsDirectory) throw new InvalidOperationException("Directory queries require a directory handle.");
        _ = SmbFileInformationCodec.DirectoryLayout(query.InformationClass);
        ArgumentException.ThrowIfNullOrWhiteSpace(query.Pattern);
        if (query.Pattern.IndexOfAny(['\\', '/', '\0', ':']) >= 0) throw new ArgumentException("The query pattern must be a single name.", nameof(query));
        if (query.BufferSize < 1 || query.BufferSize > MaximumTransactionCapacity) throw new ArgumentOutOfRangeException(nameof(query));
        var name = Wire.Unicode.GetBytes(query.Pattern);
        if (name.Length > ushort.MaxValue) throw new ArgumentOutOfRangeException(nameof(query));
        var body = new byte[32 + name.Length]; Wire.Put16(body, 0, 33);
        body[2] = (byte)query.InformationClass;
        body[3] = (byte)((query.RestartScan ? 1 : 0) | (query.ReturnSingleEntry ? 2 : 0) | (query.FileIndex.HasValue ? 4 : 0) | (query.Reopen ? 0x10 : 0));
        Wire.Put32(body, 4, query.FileIndex ?? 0); Id.Write(body, 8);
        Wire.Put16(body, 24, 96); Wire.Put16(body, 26, (ushort)name.Length);
        Wire.Put32(body, 28, (uint)query.BufferSize); name.CopyTo(body, 32);
        var response = await share.SendAsync(Command.QueryDirectory, body, cancellationToken, query.BufferSize).ConfigureAwait(false);
        response.EnsureSuccess(SmbStatus.NoMoreFiles, SmbStatus.NoSuchFile, SmbStatus.BufferOverflow);
        if (response.Status is SmbStatus.NoMoreFiles or SmbStatus.NoSuchFile) return new([], true, false);
        Wire.Structure(response.Packet, 9, 8);
        var length = Wire.U32(response.Packet, 68);
        if (length > query.BufferSize) throw new SmbProtocolException("A directory response exceeded its output buffer.");
        var data = Wire.Buffer(response.Packet, Wire.U16(response.Packet, 66), length, 72);
        return new(SmbFileInformationCodec.Directory(data, query.InformationClass), false, response.Status == SmbStatus.BufferOverflow);
    }


    /// <summary>供各类型化查询共用的 File 路由检查，阻止把本地、目录和配额类误发成普通 QUERY_INFO。</summary>
    /// <param name="informationClass">目录中已定义且允许查询的 File 信息类。</param>
    /// <param name="cancellationToken">取消等待和网络操作的令牌。请求已发送后取消不会回滚服务器可能已执行的修改。</param>
    /// <returns>未经模型解码的结果字节。</returns>
    private Task<byte[]> FileInformationAsync(SmbFileInformationClass informationClass, CancellationToken cancellationToken)
    {
        var support = SmbFileInformationCatalog.Get(informationClass);
        if (support.Route != SmbInformationRoute.File || !support.CanQuery)
            throw new ArgumentException("This class is not queried with SMB2 file QUERY_INFO.", nameof(informationClass));
        return QueryInfoAsync(SmbInfoType.File, (byte)informationClass, cancellationToken: cancellationToken);
    }


    /// <summary>检查句柄生命周期与 IPC 共享类型，避免把磁盘文件当成命名管道操作。</summary>
    private void EnsurePipe()
    {
        ThrowIfClosed();
        if (!share.IsPipeShare) throw new InvalidOperationException("This operation requires an IPC named-pipe handle.");
    }
}