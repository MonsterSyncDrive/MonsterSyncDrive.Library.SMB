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

namespace MonsterSyncDrive.Library.SMB;


/// <summary>SMB2 打开句柄的两个 64 位标识；名称 Persistent 是协议字段名，不代表已实现 persistent handle 恢复。</summary>
/// <param name="Persistent">服务端返回的 persistent 部分原始值。</param>
/// <param name="Volatile">当前打开实例的 volatile 部分原始值。</param>
public readonly record struct SmbFileId(ulong Persistent, ulong Volatile)
{

    /// <summary>从协议缓冲区读取连续的两个小端 64 位文件句柄字段，并验证边界。</summary>
    /// <param name="packet">含 SMB 句柄的协议数据。</param>
    /// <param name="offset">16 字节句柄的起始偏移。</param>
    /// <returns>原始 SMB 句柄标识。</returns>
    internal static SmbFileId Read(ReadOnlySpan<byte> packet, int offset)
    {
        return new(Wire.U64(packet, offset), Wire.U64(packet, offset + 8));
    }

    /// <summary>把句柄标识写入请求中连续的 16 字节区域。</summary>
    /// <param name="packet">可写请求缓冲区。</param>
    /// <param name="offset">目标句柄字段的起始偏移。</param>
    internal void Write(Span<byte> packet, int offset)
    {
        Wire.Put64(packet, offset, Persistent);
        Wire.Put64(packet, offset + 8, Volatile);
    }
}

/// <summary>已打开的远程文件、目录或命名管道，支持按偏移读写及 SMB 控制操作。</summary>
public sealed partial class SmbFileHandle : IAsyncDisposable
{

    /// <summary>通过 Interlocked 维护的关闭标志；零为打开，非零为已开始关闭。</summary>
    private int closed;

    /// <summary>本次远程打开的 SMB 文件句柄标识，不用于重新按文件系统 ID 打开。</summary>
    public SmbFileId Id
    {
        get;
    }

    /// <summary>创建此句柄时的共享相对路径；成功重命名后更新为目标路径。</summary>
    public string Path
    {
        get; private set;
    }

    /// <summary>本次打开的访问掩码、共享模式、处置方式及文件选项快照。</summary>
    public SmbOpenOptions OpenOptions
    {
        get;
    }

    /// <summary>CREATE 响应中的文件长度快照；外部写入后不会自动更新。</summary>
    public long InitialLength
    {
        get;
    }

    /// <summary>CREATE 响应中的属性快照；查询最新属性应调用 GetInfoAsync。</summary>
    public FileAttributes Attributes
    {
        get;
    }

    /// <summary>打开时的属性是否含 Directory 标志。</summary>
    public bool IsDirectory => (Attributes & FileAttributes.Directory) != 0;

    /// <summary>是否已开始释放本句柄；远程连接断开可通过所属客户端状态另行判断。</summary>
    public bool IsClosed => Volatile.Read(ref closed) != 0;

    /// <summary>供库内功能使用的所属共享对象。</summary>
    internal SmbShare Share
    {
        get;
    }
    // 单 credit 数据块确保只授予一个 credit 的服务器也能持续处理请求。

    /// <summary>普通文件单次读取预算，取服务器限制、传输缓冲设置和 65536 的最小值，以便单 credit 也能推进。</summary>
    internal int ReadSize => Math.Min(65536, Math.Min(Share.Client.ConnectionInfo.MaxReadSize, Share.Client.Options.TransferBufferSize));

    /// <summary>普通文件单次写入预算，取服务器限制、传输缓冲设置和 65536 的最小值。</summary>
    internal int WriteSize => Math.Min(65536, Math.Min(Share.Client.ConnectionInfo.MaxWriteSize, Share.Client.Options.TransferBufferSize));

    /// <summary>控制和默认分页操作的单 credit 输出预算，最多 65536 字节。</summary>
    private int TransactionSize => Math.Min(65536, Share.Client.ConnectionInfo.MaxTransactionSize);

    /// <summary>显式大型信息请求的容量上界，受服务端事务限制、传输消息预算和客户端包大小限制共同约束。</summary>
    private int MaximumTransactionCapacity => Math.Min(Share.Client.SupportsMultiCredit ?
        Share.Client.ConnectionInfo.MaxTransactionSize : 65536, Math.Min(Share.Client.Options.MaximumPacketSize,
            Share.Client.MaximumTransportMessageSize) - 256);


    /// <summary>从成功的 CREATE 响应建立句柄，保存标识、属性和初始长度，并拒绝无效负长度。</summary>
    /// <param name="share">拥有句柄的已连接共享。</param>
    /// <param name="id">服务端分配的 SMB 句柄。</param>
    /// <param name="path">经过规范化的共享相对路径。</param>
    /// <param name="options">打开参数快照。</param>
    /// <param name="createResponse">包含固定 CREATE 响应字段的完整 SMB 消息。</param>
    internal SmbFileHandle(SmbShare share, SmbFileId id, string path, SmbOpenOptions options, byte[] createResponse)
    {
        Share = share;
        Id = id;
        Path = path;
        OpenOptions = options;
        InitialLength = Wire.I64(createResponse, 112);
        if (InitialLength < 0)
            throw new SmbProtocolException("The server returned a negative file size.");
        Attributes = (FileAttributes)Wire.U32(createResponse, 120);
    }

    /// <summary>最多读取一个协商数据块；零表示文件结束，短读属于合法结果。</summary>
    /// <param name="buffer">目标缓冲区；最多填充一个协商的数据块。</param>
    /// <param name="offset">文件内非负的字节偏移。</param>
    /// <param name="cancellationToken">取消读取或下载带宽等待的令牌。</param>
    /// <returns>实际读取字节数；零表示 EOF 或空目标缓冲区。</returns>
    /// <remarks>
    /// 无缓冲打开先校验扇区范围；符合未签名、未加密且未压缩条件的 RDMA 通道可以使用注册内存直接放置。
    /// 已发出直接放置请求后的取消会终止并排空选中的通道，再释放注册内存；其他情况继续使用普通消息传输。
    /// 返回前遵守下载限速并更新实际完成字节统计。
    /// </remarks>
    public async ValueTask<int> ReadAsync(Memory<byte> buffer, long offset, CancellationToken cancellationToken = default)
    {
        ThrowIfClosed();
        ArgumentOutOfRangeException.ThrowIfNegative(offset);
        if (buffer.Length == 0)
            return 0;
        int count = Math.Min(buffer.Length, ReadSize);
        await ValidateUnbufferedIoAsync(offset, count, cancellationToken).ConfigureAwait(false);
        if (offset > long.MaxValue - count)
            throw new ArgumentOutOfRangeException(nameof(offset));
        if (TrySelectRdmaIo(count, false, out SmbConnection? rdmaConnection, out SmbDirectConnection? rdma))
            return await ReadRdmaAsync(buffer[..count], offset, rdmaConnection, rdma, cancellationToken).ConfigureAwait(false);
        byte[] body = new byte[49];
        Wire.Put16(body, 0, 49);
        // 磁盘文件声明压缩响应意图；发送通道会依据其实际协商结果和传输类型再次过滤。
        if (Share.IsDiskShare && Share.Client.Options.Compression.Enabled)
            body[3] |= 0x02;
        Wire.Put32(body, 4, (uint)count);
        Wire.PutI64(body, 8, offset);
        Id.Write(body, 16);
        Response response = await Share.SendAsync(Command.Read, body, cancellationToken, count).ConfigureAwait(false);
        response.EnsureSuccess(SmbStatus.EndOfFile, SmbStatus.BufferOverflow);
        if (response.Status == SmbStatus.EndOfFile)
            return 0;
        Wire.Structure(response.Packet, 17, 16);
        uint length = Wire.U32(response.Packet, 68);
        if (length > count)
            throw new SmbProtocolException("The server returned more file data than requested.");
        byte[] data = Wire.Buffer(response.Packet, response.Packet[66], length, 80);
        await Share.Client.QosState.LimitDownloadAsync(data.Length, cancellationToken).ConfigureAwait(false);
        data.CopyTo(buffer);
        Share.Client.QosState.Downloaded(data.Length);
        return data.Length;
    }

    /// <summary>最多写入一个数据块，返回服务器实际确认的字节数。</summary>
    /// <param name="buffer">本次待写数据；超出单块预算的剩余部分由调用者继续提交。</param>
    /// <param name="offset">文件内非负的写入偏移。</param>
    /// <param name="writeThrough">是否设置服务器直写标志。</param>
    /// <param name="cancellationToken">取消上传带宽等待或服务器请求的令牌。</param>
    /// <returns>服务端实际确认的字节数；成功时不返回零。</returns>
    /// <remarks>
    /// 满足设备和会话安全条件时自动使用 RDMA V1 描述符；已启用的签名或加密绝不降级到不受保护的直接放置。
    /// 直接放置固定在同一队列对；发出请求后若取消，先结束该通道的设备访问，再注销私有源缓冲区。
    /// </remarks>
    public async ValueTask<int> WriteAsync(ReadOnlyMemory<byte> buffer, long offset, bool writeThrough = false,
        CancellationToken cancellationToken = default)
    {
        ThrowIfClosed();
        ArgumentOutOfRangeException.ThrowIfNegative(offset);
        if (buffer.Length == 0)
            return 0;
        int count = Math.Min(buffer.Length, WriteSize);
        await ValidateUnbufferedIoAsync(offset, count, cancellationToken).ConfigureAwait(false);
        if (offset > long.MaxValue - count)
            throw new ArgumentOutOfRangeException(nameof(offset));
        if (TrySelectRdmaIo(count, true, out SmbConnection? rdmaConnection, out SmbDirectConnection? rdma))
            return await WriteRdmaAsync(buffer[..count], offset, writeThrough, rdmaConnection, rdma, cancellationToken).ConfigureAwait(false);
        byte[] body = new byte[48 + count];
        Wire.Put16(body, 0, 49);
        Wire.Put16(body, 2, 112);
        Wire.Put32(body, 4, (uint)count);
        Wire.PutI64(body, 8, offset);
        Id.Write(body, 16);
        Wire.Put32(body, 44, writeThrough ? 1u : 0);
        buffer.Span[..count].CopyTo(body.AsSpan(48));
        await Share.Client.QosState.LimitUploadAsync(count, cancellationToken).ConfigureAwait(false);
        Response response = await Share.SendAsync(Command.Write, body, cancellationToken).ConfigureAwait(false);
        response.EnsureSuccess();
        Wire.Structure(response.Packet, 17, 16);
        uint written = Wire.U32(response.Packet, 68);
        if (written == 0 || written > count)
            throw new SmbProtocolException("The server returned an invalid write count.");
        Share.Client.QosState.Uploaded((int)written);
        return (int)written;
    }


    /// <summary>按协商块大小写完整个调用者缓冲区，处理服务器短写，并在发送第一块前验证无缓冲 I/O 的整个范围。</summary>
    /// <param name="buffer">要写入的完整字节序列。</param>
    /// <param name="offset">非负的文件起始字节偏移。</param>
    /// <param name="writeThrough">是否为每块设置 WRITE_THROUGH。</param>
    /// <param name="cancellationToken">取消等待和网络操作的令牌。请求已发送后取消不会回滚服务器可能已执行的修改。</param>
    /// <returns>全部字节都获得服务器确认后完成的任务。</returns>
    /// <remarks>本操作不是事务；后续块失败时，先前已确认的写入仍存在。</remarks>
    public async Task WriteAllAsync(ReadOnlyMemory<byte> buffer, long offset, bool writeThrough = false, CancellationToken cancellationToken = default)
    {
        ThrowIfClosed();
        cancellationToken.ThrowIfCancellationRequested();
        ArgumentOutOfRangeException.ThrowIfNegative(offset);
        if (offset > long.MaxValue - buffer.Length)
            throw new ArgumentOutOfRangeException(nameof(offset));
        await ValidateUnbufferedIoAsync(offset, buffer.Length, cancellationToken).ConfigureAwait(false);
        int written = 0;
        while (written < buffer.Length)
            written += await WriteAsync(buffer[written..], offset + written, writeThrough, cancellationToken).ConfigureAwait(false);
    }


    /// <summary>发送 SMB2 FLUSH，使服务端按其持久化语义刷新该句柄的数据。</summary>
    /// <param name="cancellationToken">取消等待和网络操作的令牌。请求已发送后取消不会回滚服务器可能已执行的修改。</param>
    /// <returns>服务器确认刷新后的任务。</returns>
    public async Task FlushAsync(CancellationToken cancellationToken = default)
    {
        ThrowIfClosed();
        byte[] body = FileIdBody(24, 24, 8);
        Response response = await Share.SendAsync(Command.Flush, body, cancellationToken).ConfigureAwait(false);
        response.EnsureSuccess();
        Wire.Structure(response.Packet, 4, 4);
    }

    /// <summary>返回 MS-FSCC 为所选信息类定义的原始数据缓冲区，不改写其内容。</summary>
    /// <param name="type">File、FileSystem、Security 或 Quota 类型。</param>
    /// <param name="informationClass">与请求类型相符的信息类编号。</param>
    /// <param name="maximumOutput">最大输出字节数；大于单 credit 的值需要足够的协商事务容量。</param>
    /// <param name="additionalInformation">安全选择位或 EA 一基索引。</param>
    /// <param name="input">可选 EA 名称筛选或配额输入数据。</param>
    /// <param name="flags">EA 扫描位；其他信息类型应使用零。</param>
    /// <param name="cancellationToken">取消网络查询的令牌。</param>
    /// <returns>验证响应结构和容量后的原始信息数据。</returns>
    public async Task<byte[]> QueryInfoAsync(SmbInfoType type, byte informationClass, int maximumOutput = 65536,
        uint additionalInformation = 0, ReadOnlyMemory<byte> input = default, uint flags = 0, CancellationToken cancellationToken = default)
    {
        return (await QueryInfoCoreAsync(type, informationClass, maximumOutput, additionalInformation, input, flags,
                cancellationToken).ConfigureAwait(false)).Data;
    }


    /// <summary>构造有界的 QUERY_INFO 并保留允许的终止或溢出状态，供原始查询和 EA 分页共享。</summary>
    /// <param name="type">File、FileSystem、Security 或 Quota 信息类型。</param>
    /// <param name="informationClass">与类型匹配的数值信息类。</param>
    /// <param name="maximumOutput">最大接受的响应字节数，不得超过事务容量。</param>
    /// <param name="additionalInformation">安全信息位或 EA 一基索引；其他请求应为零。</param>
    /// <param name="input">可选 EA 名称或配额请求数据。</param>
    /// <param name="flags">EA 扫描标志；其他请求应为零。</param>
    /// <param name="cancellationToken">取消等待和网络操作的令牌。请求已发送后取消不会回滚服务器可能已执行的修改。</param>
    /// <param name="accepted">调用方明确允许的非成功状态。</param>
    /// <returns>原始信息字节及服务器状态；允许的纯终止错误返回空数据。</returns>
    /// <remarks>BUFFER_OVERFLOW 的数据仍验证结构与长度；不将权限错误等任意错误当作枚举结束。</remarks>
    private async Task<(byte[] Data, SmbStatus Status)> QueryInfoCoreAsync(SmbInfoType type, byte informationClass,
        int maximumOutput, uint additionalInformation, ReadOnlyMemory<byte> input, uint flags,
        CancellationToken cancellationToken, params SmbStatus[] accepted)
    {
        ThrowIfClosed();
        if (!Enum.IsDefined(type))
            throw new ArgumentOutOfRangeException(nameof(type));
        if (maximumOutput < 1 || maximumOutput > MaximumTransactionCapacity || input.Length > MaximumTransactionCapacity)
            throw new ArgumentOutOfRangeException(nameof(maximumOutput));
        byte[] body = new byte[40 + Math.Max(1, input.Length)];
        Wire.Put16(body, 0, 41);
        body[2] = (byte)type;
        body[3] = informationClass;
        Wire.Put32(body, 4, (uint)maximumOutput);
        if (input.Length > 0)
            Wire.Put16(body, 8, 104);
        Wire.Put32(body, 12, (uint)input.Length);
        Wire.Put32(body, 16, additionalInformation);
        Wire.Put32(body, 20, flags);
        Id.Write(body, 24);
        input.Span.CopyTo(body.AsSpan(40));
        Response response = await Share.SendAsync(Command.QueryInfo, body, cancellationToken, maximumOutput).ConfigureAwait(false);
        response.EnsureSuccess(accepted);
        if (response.Status is not (SmbStatus.Success or SmbStatus.BufferOverflow))
            return ([], response.Status);
        Wire.Structure(response.Packet, 9, 8);
        uint length = Wire.U32(response.Packet, 68);
        return length > maximumOutput
            ? throw new SmbProtocolException("An information response exceeded its requested buffer.")
            : ((byte[] Data, SmbStatus Status))(Wire.Buffer(response.Packet, Wire.U16(response.Packet, 66), length, 72), response.Status);
    }


    /// <summary>发送原始 SET_INFO 数据；高级信息封装使用相同的容量、标识和状态检查。</summary>
    /// <param name="type">被设置的 File、FileSystem、Security 或 Quota 类型。</param>
    /// <param name="informationClass">该类型定义的信息类编号。</param>
    /// <param name="data">按相应规范编码的完整设置数据。</param>
    /// <param name="additionalInformation">安全描述符选择位；其他信息通常为零。</param>
    /// <param name="cancellationToken">取消等待和网络操作的令牌。请求已发送后取消不会回滚服务器可能已执行的修改。</param>
    /// <returns>服务端确认设置后的任务。</returns>
    public async Task SetInfoAsync(SmbInfoType type, byte informationClass, ReadOnlyMemory<byte> data,
        uint additionalInformation = 0, CancellationToken cancellationToken = default)
    {
        ThrowIfClosed();
        if (!Enum.IsDefined(type) || data.Length > MaximumTransactionCapacity)
            throw new ArgumentException("Invalid information type or buffer.");
        byte[] body = new byte[32 + Math.Max(1, data.Length)];
        Wire.Put16(body, 0, 33);
        body[2] = (byte)type;
        body[3] = informationClass;
        Wire.Put32(body, 4, (uint)data.Length);
        Wire.Put16(body, 8, 96);
        Wire.Put32(body, 12, additionalInformation);
        Id.Write(body, 16);
        data.Span.CopyTo(body.AsSpan(32));
        Response response = await Share.SendAsync(Command.SetInfo, body, cancellationToken).ConfigureAwait(false);
        response.EnsureSuccess();
        Wire.Structure(response.Packet, 2, 2);
    }


    /// <summary>查询 FILE_ALL_INFORMATION 并返回常用文件属性、大小、链接和名称信息。</summary>
    /// <param name="cancellationToken">取消等待和网络操作的令牌。请求已发送后取消不会回滚服务器可能已执行的修改。</param>
    /// <returns>当前服务器报告的文件信息。</returns>
    public async Task<SmbFileInfo> GetInfoAsync(CancellationToken cancellationToken = default)
    {
        byte[] data = await QueryInfoAsync(SmbInfoType.File, 18, cancellationToken: cancellationToken).ConfigureAwait(false);
        _ = Wire.Slice(data, 0, 100);
        return Wire.I64(data, 40) < 0 || Wire.I64(data, 48) < 0
            ? throw new SmbProtocolException("Invalid remote file size.")
            : new SmbFileInfo(Wire.Time(data, 0), Wire.Time(data, 8), Wire.Time(data, 16), Wire.Time(data, 24),
            Wire.I64(data, 40), Wire.I64(data, 48), (FileAttributes)Wire.U32(data, 32), Wire.U32(data, 56),
            data[60] != 0, data[61] != 0, Wire.U64(data, 64),
            Wire.Text(data, 100, Wire.Int32(Wire.U32(data, 96))));
    }


    /// <summary>用 FILE_END_OF_FILE_INFORMATION 扩展或截断逻辑文件长度。</summary>
    /// <param name="length">非负的目标 EOF，以字节计。</param>
    /// <param name="cancellationToken">取消等待和网络操作的令牌。请求已发送后取消不会回滚服务器可能已执行的修改。</param>
    /// <returns>服务端接受目标长度后的任务。</returns>
    public Task SetLengthAsync(long length, CancellationToken cancellationToken = default)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(length);
        byte[] data = new byte[8];
        Wire.PutI64(data, 0, length);
        return SetInfoAsync(SmbInfoType.File, 20, data, cancellationToken: cancellationToken);
    }


    /// <summary>请求设置文件分配量；缩小到当前 EOF 以下可截断文件，扩大并不保证服务器真正预留物理空间。</summary>
    /// <param name="length">非负的分配字节数。</param>
    /// <param name="cancellationToken">取消等待和网络操作的令牌。请求已发送后取消不会回滚服务器可能已执行的修改。</param>
    /// <returns>服务器接受请求后的任务；实际结果可再次查询。</returns>
    public Task SetAllocationSizeAsync(long length, CancellationToken cancellationToken = default)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(length);
        byte[] data = new byte[8];
        Wire.PutI64(data, 0, length);
        return SetInfoAsync(SmbInfoType.File, 19, data, cancellationToken: cancellationToken);
    }


    /// <summary>设置文件属性与四类时间；空时间和零属性按协议表示保留对应现值。</summary>
    /// <param name="attributes">要设置的属性位；零表示保留。</param>
    /// <param name="creationTime">新的创建时间；空表示保留。</param>
    /// <param name="lastAccessTime">新的访问时间；空表示保留。</param>
    /// <param name="lastWriteTime">新的写入时间；空表示保留。</param>
    /// <param name="changeTime">新的元数据变化时间；空表示保留。</param>
    /// <param name="cancellationToken">取消等待和网络操作的令牌。请求已发送后取消不会回滚服务器可能已执行的修改。</param>
    /// <returns>服务器确认基本信息修改后的任务。</returns>
    public Task SetBasicInfoAsync(FileAttributes attributes = 0, DateTimeOffset? creationTime = null,
        DateTimeOffset? lastAccessTime = null, DateTimeOffset? lastWriteTime = null,
        DateTimeOffset? changeTime = null, CancellationToken cancellationToken = default)
    {
        byte[] data = new byte[40];
        Wire.PutI64(data, 0, creationTime?.ToFileTime() ?? 0);
        Wire.PutI64(data, 8, lastAccessTime?.ToFileTime() ?? 0);
        Wire.PutI64(data, 16, lastWriteTime?.ToFileTime() ?? 0);
        Wire.PutI64(data, 24, changeTime?.ToFileTime() ?? 0);
        Wire.Put32(data, 32, (uint)attributes);
        return SetInfoAsync(SmbInfoType.File, 4, data, cancellationToken: cancellationToken);
    }


    /// <summary>设置或撤销普通 FILE_DISPOSITION_INFORMATION 删除意图。</summary>
    /// <param name="delete">是否请求在适当的关闭时机删除文件。</param>
    /// <param name="cancellationToken">取消等待和网络操作的令牌。请求已发送后取消不会回滚服务器可能已执行的修改。</param>
    /// <returns>服务器确认设置后的任务。</returns>
    public Task SetDeletePendingAsync(bool delete, CancellationToken cancellationToken = default)
    {
        return SetInfoAsync(SmbInfoType.File, 13, new byte[] { delete ? (byte)1 : (byte)0 }, cancellationToken: cancellationToken);
    }


    /// <summary>使用普通重命名信息类在同一共享内更改名称；只有服务端成功后才更新 Path。</summary>
    /// <param name="destination">规范化后的共享相对目标路径。</param>
    /// <param name="replaceIfExists">是否允许覆盖已有目标名称。</param>
    /// <param name="cancellationToken">取消等待和网络操作的令牌。请求已发送后取消不会回滚服务器可能已执行的修改。</param>
    /// <returns>成功重命名后的任务。</returns>
    public async Task RenameAsync(string destination, bool replaceIfExists = false, CancellationToken cancellationToken = default)
    {
        await SetNameAsync(10, destination, replaceIfExists, cancellationToken).ConfigureAwait(false);
        Path = SmbPath.Normalize(destination);
    }


    /// <summary>通过 FILE_LINK_INFORMATION 为同一文件创建另一个名称，不复制文件数据。</summary>
    /// <param name="destination">共享内的新硬链接路径。</param>
    /// <param name="replaceIfExists">是否替换同名目标。</param>
    /// <param name="cancellationToken">取消等待和网络操作的令牌。请求已发送后取消不会回滚服务器可能已执行的修改。</param>
    /// <returns>服务器确认硬链接创建后的任务。</returns>
    public Task CreateHardLinkAsync(string destination, bool replaceIfExists = false, CancellationToken cancellationToken = default)
    {
        return SetNameAsync(11, destination, replaceIfExists, cancellationToken);
    }


    /// <summary>构造共享相对的重命名或链接结构；网络 RootDirectory 固定为零。</summary>
    /// <param name="informationClass">Rename 或 Link 信息类。</param>
    /// <param name="destination">非空目标名称。</param>
    /// <param name="replaceIfExists">是否替换目标。</param>
    /// <param name="cancellationToken">取消等待和网络操作的令牌。请求已发送后取消不会回滚服务器可能已执行的修改。</param>
    /// <returns>相应 SET_INFO 完成后的任务。</returns>
    private Task SetNameAsync(byte informationClass, string destination, bool replaceIfExists, CancellationToken cancellationToken)
    {
        byte[] name = Wire.Unicode.GetBytes(SmbPath.Normalize(destination));
        if (name.Length == 0)
            throw new ArgumentException("A destination filename is required.", nameof(destination));
        byte[] data = new byte[20 + name.Length];
        data[0] = replaceIfExists ? (byte)1 : (byte)0;
        Wire.Put32(data, 16, (uint)name.Length);
        name.CopyTo(data, 20);
        return SetInfoAsync(SmbInfoType.File, informationClass, data, cancellationToken: cancellationToken);
    }


    /// <summary>读取跨平台 self-relative 安全描述符，不依赖 Windows ACL 对象。</summary>
    /// <param name="information">选择 Owner、Group、DACL、SACL 等所需部分。</param>
    /// <param name="cancellationToken">取消等待和网络操作的令牌。请求已发送后取消不会回滚服务器可能已执行的修改。</param>
    /// <returns>原始安全描述符字节；服务端检查句柄权限和相应特权。</returns>
    public Task<byte[]> GetSecurityDescriptorAsync(SmbSecurityInformation information = SmbSecurityInformation.Owner |
        SmbSecurityInformation.Group | SmbSecurityInformation.Dacl, CancellationToken cancellationToken = default)
    {
        return QueryInfoAsync(SmbInfoType.Security, 0, additionalInformation: (uint)information, cancellationToken: cancellationToken);
    }

    /// <summary>设置自相对安全描述符，无需依赖仅限 Windows 的 ACL 类型。</summary>
    /// <param name="descriptor">至少 20 字节、版本为 1 且设置 SELF_RELATIVE 的描述符。</param>
    /// <param name="information">要修改的 Owner、Group、DACL、SACL 等选择位。</param>
    /// <param name="cancellationToken">取消请求的令牌。</param>
    /// <returns>服务器确认后的任务；描述符中的权限及特权由服务器验证。</returns>
    public Task SetSecurityDescriptorAsync(ReadOnlyMemory<byte> descriptor, SmbSecurityInformation information,
        CancellationToken cancellationToken = default)
    {
        return descriptor.Length < 20 || descriptor.Span[0] != 1 || (Wire.U16(descriptor.Span, 2) & 0x8000) == 0
            ? throw new ArgumentException("A revision 1, self-relative security descriptor is required.", nameof(descriptor))
            : SetInfoAsync(SmbInfoType.Security, 0, descriptor, (uint)information, cancellationToken);
    }


    /// <summary>现有目录便利 API 使用的基本格式分页请求；末尾状态返回空引用，条目列表只含当前页。</summary>
    /// <param name="pattern">单级名称搜索模式。</param>
    /// <param name="restart">是否从扫描起点重新开始。</param>
    /// <param name="cancellationToken">取消等待和网络操作的令牌。请求已发送后取消不会回滚服务器可能已执行的修改。</param>
    /// <returns>当前页，或枚举结束时的空引用。</returns>
    internal async Task<IReadOnlyList<SmbDirectoryEntry>?> QueryDirectoryAsync(string pattern, bool restart, CancellationToken cancellationToken)
    {
        ThrowIfClosed();
        byte[] name = Wire.Unicode.GetBytes(pattern);
        byte[] body = new byte[32 + name.Length];
        Wire.Put16(body, 0, 33);
        body[2] = 1; // 使用 MS-FSCC 2.4.10 定义的 FileDirectoryInformation 基本目录格式。
        body[3] = restart ? (byte)1 : (byte)0;
        Id.Write(body, 8);
        Wire.Put16(body, 24, 96);
        Wire.Put16(body, 26, checked((ushort)name.Length));
        Wire.Put32(body, 28, (uint)TransactionSize);
        name.CopyTo(body, 32);
        Response response = await Share.SendAsync(Command.QueryDirectory, body, cancellationToken, TransactionSize).ConfigureAwait(false);
        response.EnsureSuccess(SmbStatus.NoMoreFiles, SmbStatus.NoSuchFile, SmbStatus.BufferOverflow);
        if (response.Status is SmbStatus.NoMoreFiles or SmbStatus.NoSuchFile)
            return null;
        Wire.Structure(response.Packet, 9, 8);
        uint length = Wire.U32(response.Packet, 68);
        return length > TransactionSize
            ? throw new SmbProtocolException("Oversized SMB directory response.")
            : ParseDirectory(Wire.Buffer(response.Packet, Wire.U16(response.Packet, 66), length, 72));
    }


    /// <summary>严格解析 FILE_DIRECTORY_INFORMATION 链，验证长度、8 字节偏移、名称及非负大小。</summary>
    /// <param name="data">QUERY_DIRECTORY 的输出缓冲区。</param>
    /// <returns>基本目录条目集合；不主动过滤点目录。</returns>
    internal static IReadOnlyList<SmbDirectoryEntry> ParseDirectory(ReadOnlySpan<byte> data)
    {
        var entries = new List<SmbDirectoryEntry>();
        int offset = 0;
        while (offset < data.Length)
        {
            ReadOnlySpan<byte> entry = data[offset..];
            _ = Wire.Slice(entry, 0, 64);
            uint next = Wire.U32(entry, 0);
            uint length = Wire.U32(entry, 60);
            if (length > int.MaxValue || (next != 0 && (next % 8 != 0 || next < 64 + length || next >= entry.Length)))
                throw new SmbProtocolException("Invalid SMB directory entry chain.");
            string name = Wire.Text(entry, 64, (int)length);
            if (name.Length == 0 || name.IndexOfAny(['\\', '/', '\0', ':']) >= 0 ||
                Wire.I64(entry, 40) < 0 || Wire.I64(entry, 48) < 0)
                throw new SmbProtocolException("Invalid SMB directory entry name or size.");
            entries.Add(new SmbDirectoryEntry(name, Wire.I64(entry, 40), Wire.I64(entry, 48),
                (FileAttributes)Wire.U32(entry, 56), Wire.Time(entry, 8), Wire.Time(entry, 16),
                Wire.Time(entry, 24), Wire.Time(entry, 32), Wire.U32(entry, 4)));
            if (next == 0)
                break;
            offset = checked(offset + (int)next);
        }
        return entries;
    }


    /// <summary>发送一组共享、独占或解锁范围；等待式加锁通过调用者取消令牌终止。</summary>
    /// <param name="ranges">1 至 2048 个非负偏移、正长度且标志合法的字节范围。</param>
    /// <param name="cancellationToken">取消等待和网络操作的令牌。请求已发送后取消不会回滚服务器可能已执行的修改。</param>
    /// <returns>服务器确认所有范围操作后的任务。</returns>
    /// <remarks>普通操作超时不应用于需要等待的锁；不会把网络断开当作已获得锁。</remarks>
    public async Task LockAsync(IReadOnlyList<SmbLockRange> ranges, CancellationToken cancellationToken = default)
    {
        ThrowIfClosed();
        ArgumentNullException.ThrowIfNull(ranges);
        if (ranges.Count is < 1 or > 2048)
            throw new ArgumentOutOfRangeException(nameof(ranges));
        byte[] body = new byte[24 + (ranges.Count * 24)];
        Wire.Put16(body, 0, 48);
        Wire.Put16(body, 2, (ushort)ranges.Count);
        Id.Write(body, 8);
        for (int i = 0; i < ranges.Count; i++)
        {
            SmbLockRange range = ranges[i];
            SmbLockFlags kind = range.Flags & ~SmbLockFlags.FailImmediately;
            if (range.Offset < 0 || range.Length <= 0 || range.Offset > long.MaxValue - range.Length ||
                kind is not (SmbLockFlags.Shared or SmbLockFlags.Exclusive or SmbLockFlags.Unlock))
                throw new ArgumentException("Invalid SMB lock range.", nameof(ranges));
            Wire.PutI64(body, 24 + (i * 24), range.Offset);
            Wire.PutI64(body, 32 + (i * 24), range.Length);
            Wire.Put32(body, 40 + (i * 24), (uint)range.Flags);
        }
        Response response = await Share.SendAsync(Command.Lock, body, cancellationToken,
            infiniteTimeout: ranges.Any(range => (range.Flags & (SmbLockFlags.FailImmediately | SmbLockFlags.Unlock)) == 0)).ConfigureAwait(false);
        response.EnsureSuccess();
        Wire.Structure(response.Packet, 4, 4);
    }


    /// <summary>提交一次异步目录变更请求，返回当前变更批次或要求重新扫描的标志。</summary>
    /// <param name="filter">关心的文件名、属性、大小、安全或数据流变更位。</param>
    /// <param name="watchSubtree">是否包含子目录。</param>
    /// <param name="cancellationToken">取消等待和网络操作的令牌。请求已发送后取消不会回滚服务器可能已执行的修改。</param>
    /// <returns>一次通知结果；持续监听需要调用方再次提交。</returns>
    public async Task<SmbChangeBatch> NotifyChangesAsync(SmbNotifyFilter filter = SmbNotifyFilter.FileName |
        SmbNotifyFilter.DirectoryName | SmbNotifyFilter.LastWrite, bool watchSubtree = false, CancellationToken cancellationToken = default)
    {
        ThrowIfClosed();
        if (filter == 0 || (filter & ~SmbNotifyFilter.All) != 0)
            throw new ArgumentOutOfRangeException(nameof(filter));
        byte[] body = FileIdBody(32, 32, 8);
        Wire.Put16(body, 2, watchSubtree ? (ushort)1 : (ushort)0);
        Wire.Put32(body, 4, (uint)TransactionSize);
        Wire.Put32(body, 24, (uint)filter);
        Response response = await Share.SendAsync(Command.ChangeNotify, body, cancellationToken, TransactionSize, true).ConfigureAwait(false);
        response.EnsureSuccess(SmbStatus.NotifyEnumDir, SmbStatus.BufferOverflow);
        if (response.Status == SmbStatus.NotifyEnumDir)
            return new SmbChangeBatch([], true);
        Wire.Structure(response.Packet, 9, 8);
        uint length = Wire.U32(response.Packet, 68);
        if (length > TransactionSize)
            throw new SmbProtocolException("Oversized SMB notification response.");
        byte[] data = Wire.Buffer(response.Packet, Wire.U16(response.Packet, 66), length, 72);
        return new SmbChangeBatch(ParseNotifications(data), response.Status == SmbStatus.BufferOverflow);
    }


    /// <summary>解码通知链，拒绝重叠偏移、截断字符串、未知动作和越界路径。</summary>
    /// <param name="data">CHANGE_NOTIFY 的原始结果数据。</param>
    /// <returns>按服务器顺序排列的变更事件。</returns>
    internal static IReadOnlyList<SmbChangeNotification> ParseNotifications(ReadOnlySpan<byte> data)
    {
        var changes = new List<SmbChangeNotification>();
        int offset = 0;
        while (offset < data.Length)
        {
            ReadOnlySpan<byte> entry = data[offset..];
            _ = Wire.Slice(entry, 0, 12);
            uint next = Wire.U32(entry, 0);
            uint length = Wire.U32(entry, 8);
            if (length > int.MaxValue || (next != 0 && (next % 4 != 0 || next < 12 + length || next >= entry.Length)))
                throw new SmbProtocolException("Invalid SMB change notification chain.");
            var action = (SmbChangeAction)Wire.U32(entry, 4);
            if (!Enum.IsDefined(action))
                throw new SmbProtocolException("Invalid SMB change notification action.");
            string name = Wire.Text(entry, 12, (int)length);
            try
            {
                _ = SmbPath.Normalize(name);
            }
            catch (ArgumentException ex)
            {
                throw new SmbProtocolException("Invalid SMB notification path.", ex);
            }
            changes.Add(new SmbChangeNotification(action, name));
            if (next == 0)
                break;
            offset = checked(offset + (int)next);
        }
        return changes;
    }

    /// <summary>发出 FSCTL 或 IOCTL；输出受单 credit 预算限制，并与原请求核对。</summary>
    /// <param name="controlCode">完整的设备或文件系统控制码。</param>
    /// <param name="input">控制操作输入字节。</param>
    /// <param name="maximumOutput">不超过单 credit 事务预算的最大输出字节数。</param>
    /// <param name="isFsctl">是否设置 IS_FSCTL 标志。</param>
    /// <param name="cancellationToken">取消服务器请求的令牌。</param>
    /// <returns>与控制码及当前 FileId 匹配的输出数据。</returns>
    public async Task<byte[]> IoControlAsync(uint controlCode, ReadOnlyMemory<byte> input = default, int maximumOutput = 65536,
        bool isFsctl = true, CancellationToken cancellationToken = default)
    {
        return (await IoControlCoreAsync(controlCode, input, maximumOutput, isFsctl, false, cancellationToken).ConfigureAwait(false)).Output;
    }


    /// <summary>构造句柄型 IOCTL/FSCTL，限制输入输出并核对返回控制码和 FileId。</summary>
    /// <param name="controlCode">完整控制码。</param>
    /// <param name="input">输入数据。</param>
    /// <param name="maximumOutput">最大输出容量。</param>
    /// <param name="isFsctl">是否设置 IS_FSCTL 标志。</param>
    /// <param name="allowOverflow">是否把 BUFFER_OVERFLOW 作为分页状态返回。</param>
    /// <param name="cancellationToken">取消等待和网络操作的令牌。请求已发送后取消不会回滚服务器可能已执行的修改。</param>
    /// <returns>输出字节和是否溢出的标志。</returns>
    /// <remarks>特殊无句柄控制请求不能直接使用此入口；它总是携带并验证当前句柄 ID。</remarks>
    private async Task<(byte[] Output, bool Overflow)> IoControlCoreAsync(uint controlCode, ReadOnlyMemory<byte> input,
        int maximumOutput, bool isFsctl, bool allowOverflow, CancellationToken cancellationToken)
    {
        ThrowIfClosed();
        if (maximumOutput < 0 || maximumOutput > TransactionSize || input.Length > TransactionSize)
            throw new ArgumentOutOfRangeException(nameof(maximumOutput));
        byte[] body = new byte[56 + Math.Max(1, input.Length)];
        Wire.Put16(body, 0, 57);
        Wire.Put32(body, 4, controlCode);
        Id.Write(body, 8);
        if (input.Length > 0)
            Wire.Put32(body, 24, 120);
        Wire.Put32(body, 28, (uint)input.Length);
        Wire.Put32(body, 44, (uint)maximumOutput);
        Wire.Put32(body, 48, isFsctl ? 1u : 0);
        input.Span.CopyTo(body.AsSpan(56));
        Response response = await Share.SendAsync(Command.Ioctl, body, cancellationToken, maximumOutput).ConfigureAwait(false);
        if (allowOverflow)
            response.EnsureSuccess(SmbStatus.BufferOverflow);
        else
            response.EnsureSuccess();
        Wire.Structure(response.Packet, 49, 48);
        return Wire.U32(response.Packet, 68) != controlCode || SmbFileId.Read(response.Packet, 72) != Id ||
            Wire.U32(response.Packet, 100) > maximumOutput
            ? throw new SmbProtocolException("Invalid SMB IOCTL response.")
            : ((byte[] Output, bool Overflow))(Wire.Buffer(response.Packet, Wire.Int32(Wire.U32(response.Packet, 96)), Wire.U32(response.Packet, 100), 112),
            response.Status == SmbStatus.BufferOverflow);
    }


    /// <summary>在 IPC 命名管道上执行一次 PIPE_TRANSCEIVE 请求和响应交换。</summary>
    /// <param name="request">要发送的管道消息。</param>
    /// <param name="maximumResponse">最大响应字节数。</param>
    /// <param name="cancellationToken">取消等待和网络操作的令牌。请求已发送后取消不会回滚服务器可能已执行的修改。</param>
    /// <returns>服务端返回的管道数据。</returns>
    public Task<byte[]> TransceivePipeAsync(ReadOnlyMemory<byte> request, int maximumResponse = 65536, CancellationToken cancellationToken = default)
    {
        return !Share.IsPipeShare
            ? throw new InvalidOperationException("Pipe transceive requires an IPC share.")
            : IoControlAsync(0x0011C017, request, maximumResponse, cancellationToken: cancellationToken);
    }


    /// <summary>供 srvsvc RPC 使用的管道交换，允许 BUFFER_OVERFLOW 后继续读取剩余片段。</summary>
    /// <param name="request">首段请求数据。</param>
    /// <param name="cancellationToken">取消等待和网络操作的令牌。请求已发送后取消不会回滚服务器可能已执行的修改。</param>
    /// <returns>当前可返回的响应片段。</returns>
    internal async Task<byte[]> TransceivePipeFragmentAsync(ReadOnlyMemory<byte> request, CancellationToken cancellationToken)
    {
        return !Share.IsPipeShare
            ? throw new InvalidOperationException("Pipe transceive requires an IPC share.")
            : (await IoControlCoreAsync(0x0011C017, request, 65536, true, true, cancellationToken).ConfigureAwait(false)).Output;
    }


    /// <summary>创建含结构长度和当前 FileId 的固定请求体。</summary>
    /// <param name="length">请求体的分配字节数。</param>
    /// <param name="structureSize">协议规定的 StructureSize 值。</param>
    /// <param name="idOffset">请求体内 FileId 的偏移。</param>
    /// <returns>零初始化并写好公共字段的字节数组。</returns>
    private byte[] FileIdBody(int length, ushort structureSize, int idOffset)
    {
        byte[] body = new byte[length];
        Wire.Put16(body, 0, structureSize);
        Id.Write(body, idOffset);
        return body;
    }


    /// <summary>统一检查句柄与所属共享是否仍可操作；已释放对象抛出 ObjectDisposedException。</summary>
    private void ThrowIfClosed()
    {
        ObjectDisposedException.ThrowIf(IsClosed, this);
        Share.ThrowIfDisposed();
    }


    /// <summary>原子关闭本地句柄状态，终止 oplock 等待者，并在连接存活时发送 CLOSE；无论网络结果如何都从共享中注销。</summary>
    /// <returns>关闭流程完成后的值任务。</returns>
    /// <remarks>本地 closed 标志首先设置，因此并发或重复释放不会重复发送 CLOSE。</remarks>
    public async ValueTask DisposeAsync()
    {
        if (Interlocked.Exchange(ref closed, 1) != 0)
            return;
        InvalidateOplock();
        try
        {
            if (!Share.Client.IsTransportAlive)
                return;
            Response response = await Share.SendAsync(Command.Close, FileIdBody(24, 24, 8), CancellationToken.None).ConfigureAwait(false);
            response.EnsureSuccess(SmbStatus.FileClosed, SmbStatus.InvalidHandle);
            if (response.Status == SmbStatus.Success)
                Wire.Structure(response.Packet, 60, 60);
        }
        finally
        {
            Share.RemoveHandle(Id);
        }
    }
}