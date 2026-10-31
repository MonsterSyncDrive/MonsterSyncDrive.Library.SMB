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
using MonsterSyncDrive.SMB.Protocol;

namespace MonsterSyncDrive.SMB;

/// <summary>文件的默认或备用数据流名称及服务器报告的逻辑、分配长度。</summary>
/// <param name="Name">包含冒号和 :$DATA 类型后缀的服务器数据流名称。</param>
/// <param name="Length">数据流的逻辑字节长度。</param>
/// <param name="AllocationSize">服务器报告的分配字节数。</param>
public sealed record SmbDataStreamInfo(string Name, long Length, long AllocationSize);
/// <summary>文件指定范围内由服务器报告的一段已分配区间。</summary>
/// <param name="Offset">区间的文件起始字节偏移。</param>
/// <param name="Length">区间的正数字节长度。</param>
public readonly record struct SmbAllocatedRange(long Offset, long Length);
/// <summary>一个重解析点的标签及不包含通用八字节头的原始类型数据。</summary>
/// <param name="Tag">决定重解析点类型的 IO_REPARSE_TAG 值。</param>
/// <param name="Data">标签专属数据；此模型不自动解释或跟随符号链接目标。</param>
public sealed record SmbReparsePoint(uint Tag, ReadOnlyMemory<byte> Data);

/// <summary>远端文件句柄的数据流、稀疏区间、重解析点和服务器复制控制操作。</summary>
public sealed partial class SmbFileHandle
{
    /// <summary>枚举服务器为当前文件返回的默认和备用数据流。</summary>
    /// <param name="cancellationToken">取消信息查询的令牌。</param>
    /// <returns>经名称和链边界检查的数据流集合。</returns>
    /// <exception cref="SmbException">文件系统不支持数据流信息或服务器拒绝读取。</exception>
    /// <exception cref="SmbProtocolException">服务器返回的数据流链、名称或长度无效。</exception>
    public async Task<IReadOnlyList<SmbDataStreamInfo>> ListDataStreamsAsync(CancellationToken cancellationToken = default)
    {
        var data = await QueryInfoAsync(SmbInfoType.File, 22, cancellationToken: cancellationToken).ConfigureAwait(false);
        return ParseDataStreams(data);
    }

    /// <summary>解码 FileStreamInformation 的八字节对齐记录链，并验证 :name:$DATA 名称。</summary>
    /// <param name="data">查询响应的数据流信息区。</param>
    /// <returns>按服务器顺序排列的数据流信息。</returns>
    /// <exception cref="SmbProtocolException">记录截断、链不前进、名称格式错误或长度为负。</exception>
    internal static IReadOnlyList<SmbDataStreamInfo> ParseDataStreams(ReadOnlySpan<byte> data)
    {
        var streams = new List<SmbDataStreamInfo>();
        var offset = 0;
        while (offset < data.Length)
        {
            var entry = data[offset..];
            Wire.Slice(entry, 0, 24);
            var next = Wire.U32(entry, 0);
            var nameLength = Wire.U32(entry, 4);
            // 下一个偏移相对当前记录，必须覆盖固定头和完整 UTF-16 名称，且不能指向本页末尾之外。
            if (nameLength > int.MaxValue || (next != 0 && (next % 8 != 0 || next < 24 + nameLength || next >= entry.Length)) ||
                Wire.I64(entry, 8) < 0 || Wire.I64(entry, 16) < 0)
                throw new SmbProtocolException("Invalid alternate data stream information.");
            var name = Wire.Text(entry, 24, (int)nameLength);
            if (!name.StartsWith(':') || !name.EndsWith(":$DATA", StringComparison.OrdinalIgnoreCase) ||
                name.IndexOfAny(['\0', '\\', '/']) >= 0)
                throw new SmbProtocolException("Invalid alternate data stream name.");
            streams.Add(new SmbDataStreamInfo(name, Wire.I64(entry, 8), Wire.I64(entry, 16)));
            if (next == 0)
                break;
            offset = checked(offset + (int)next);
        }
        return streams;
    }

    /// <summary>请求服务器设置或清除当前文件的稀疏标志。</summary>
    /// <param name="sparse">true 设置稀疏标志，false 请求清除。</param>
    /// <param name="cancellationToken">取消控制请求的令牌。</param>
    /// <returns>服务器确认控制操作的任务。</returns>
    /// <exception cref="SmbException">服务器不支持稀疏文件、文件状态不允许转换或权限不足。</exception>
    public async Task SetSparseAsync(bool sparse = true, CancellationToken cancellationToken = default)
        => _ = await IoControlAsync(0x000900C4, new byte[] { sparse ? (byte)1 : (byte)0 }, 0,
            cancellationToken: cancellationToken).ConfigureAwait(false);

    /// <summary>请求服务器将指定区间的数据清零；稀疏文件可能同时回收相应分配空间。</summary>
    /// <param name="offset">非负文件起始偏移。</param>
    /// <param name="length">非负区间字节长度。</param>
    /// <param name="cancellationToken">取消控制请求的令牌。</param>
    /// <returns>服务器确认 FSCTL_SET_ZERO_DATA 的任务。</returns>
    /// <exception cref="ArgumentOutOfRangeException">区间为负数或起点加长度溢出。</exception>
    public async Task ZeroRangeAsync(long offset, long length, CancellationToken cancellationToken = default)
    {
        ValidateRange(offset, length);
        var input = new byte[16];
        Wire.PutI64(input, 0, offset); Wire.PutI64(input, 8, offset + length);
        _ = await IoControlAsync(0x000980C8, input, 0, cancellationToken: cancellationToken).ConfigureAwait(false);
    }

    /// <summary>分页面查询指定文件范围内的已分配区间，自动继续读取溢出页面。</summary>
    /// <param name="offset">查询起始字节偏移。</param>
    /// <param name="length">查询字节长度，零长度返回空集合。</param>
    /// <param name="cancellationToken">取消查询或后续页面的令牌。</param>
    /// <returns>按偏移排列的已分配区间；服务器可能报告覆盖查询边界的完整分配区间。</returns>
    /// <exception cref="ArgumentOutOfRangeException">查询范围无效或溢出。</exception>
    /// <exception cref="SmbProtocolException">服务器返回畸形、重叠、不前进或越界区间。</exception>
    public async Task<IReadOnlyList<SmbAllocatedRange>> GetAllocatedRangesAsync(long offset, long length,
        CancellationToken cancellationToken = default)
    {
        ThrowIfClosed();
        cancellationToken.ThrowIfCancellationRequested();
        ValidateRange(offset, length);
        var input = new byte[16];
        Wire.PutI64(input, 0, offset); Wire.PutI64(input, 8, length);
        // 一页至多容纳 4096 个十六字节区间；BUFFER_OVERFLOW 表示还有后续区间，不能直接当成失败丢弃本页。
        var ranges = new List<SmbAllocatedRange>();
        var end = offset + length;
        while (offset < end)
        {
            Wire.PutI64(input, 0, offset); Wire.PutI64(input, 8, end - offset);
            var result = await IoControlCoreAsync(0x000940CF, input, 65536, true, true, cancellationToken).ConfigureAwait(false);
            var data = result.Output;
            if (data.Length % 16 != 0)
                throw new SmbProtocolException("Invalid allocated range response length.");
            var next = offset;
            for (var position = 0; position < data.Length; position += 16)
            {
                var start = Wire.I64(data, position);
                var count = Wire.I64(data, position + 8);
                if (start < next || count <= 0 || start > long.MaxValue - count || start >= end)
                    throw new SmbProtocolException("Invalid or unordered allocated ranges.");
                ranges.Add(new SmbAllocatedRange(start, count));
                next = start + count;
            }
            if (!result.Overflow)
                break;
            // 用本页最后一个区间末尾推进，防止异常服务器的空溢出页造成无限查询。
            if (next <= offset)
                throw new SmbProtocolException("An allocated range query did not make progress.");
            offset = next;
        }
        return ranges;
    }

    /// <summary>读取当前重解析点的 Microsoft 标签和原始类型数据，不解析链接目标。</summary>
    /// <param name="cancellationToken">取消控制查询的令牌。</param>
    /// <returns>已校验通用头长度的标签及类型数据。</returns>
    /// <exception cref="SmbException">对象不是重解析点、文件系统不支持或读取被拒绝。</exception>
    /// <exception cref="SmbProtocolException">返回的重解析数据长度与通用头不一致。</exception>
    public async Task<SmbReparsePoint> GetReparsePointAsync(CancellationToken cancellationToken = default)
    {
        var data = await IoControlAsync(0x000900A8, maximumOutput: 16384, cancellationToken: cancellationToken).ConfigureAwait(false);
        if (data.Length < 8 || Wire.U16(data, 4) != data.Length - 8)
            throw new SmbProtocolException("Invalid reparse point data.");
        return new SmbReparsePoint(Wire.U32(data, 0), data.AsMemory(8));
    }

    /// <summary>设置 Microsoft 重解析标签和其原始数据，不提供第三方 GUID 头或符号链接目标编解码。</summary>
    /// <param name="tag">最高位为 1 的 Microsoft 重解析标签。</param>
    /// <param name="data">不含通用八字节头的数据，最多 16376 字节。</param>
    /// <param name="cancellationToken">取消控制请求的令牌。</param>
    /// <returns>服务器确认设置的任务；不代表当前服务器提供所有重解析点类型。</returns>
    /// <exception cref="ArgumentException">标签不是 Microsoft 标签或数据超过协议上限。</exception>
    /// <exception cref="SmbException">服务器拒绝创建、权限不足或不支持所给标签。</exception>
    public async Task SetReparsePointAsync(uint tag, ReadOnlyMemory<byte> data, CancellationToken cancellationToken = default)
    {
        if ((tag & 0x80000000) == 0 || data.Length > 16376)
            throw new ArgumentException("Use a Microsoft reparse tag with at most 16376 bytes of reparse data.");
        var input = new byte[8 + data.Length];
        Wire.Put32(input, 0, tag); Wire.Put16(input, 4, (ushort)data.Length);
        data.Span.CopyTo(input.AsSpan(8));
        _ = await IoControlAsync(0x000900A4, input, 0, cancellationToken: cancellationToken).ConfigureAwait(false);
    }

    /// <summary>删除与指定标签匹配的重解析数据，保留对象本身。</summary>
    /// <param name="tag">必须与服务器现有重解析点一致的标签。</param>
    /// <param name="cancellationToken">取消控制请求的令牌。</param>
    /// <returns>服务器确认删除重解析数据的任务。</returns>
    /// <exception cref="SmbException">标签不匹配、对象不是重解析点或服务器拒绝操作。</exception>
    public async Task DeleteReparsePointAsync(uint tag, CancellationToken cancellationToken = default)
    {
        var input = new byte[8]; Wire.Put32(input, 0, tag);
        _ = await IoControlAsync(0x000900AC, input, 0, cancellationToken: cancellationToken).ConfigureAwait(false);
    }

    /// <summary>在同一已认证 SMB 会话内使用 COPYCHUNK_WRITE 复制数据，文件内容不经过客户端。</summary>
    /// <param name="destination">具有写权限且属于同一客户端会话的目标句柄。</param>
    /// <param name="sourceOffset">源文件的非负起始偏移。</param>
    /// <param name="destinationOffset">目标文件的非负起始偏移。</param>
    /// <param name="length">需要复制的非负字节数。</param>
    /// <param name="cancellationToken">取消后续复制块的令牌；已复制的块不会回滚。</param>
    /// <returns>全部复制块均经服务器确认的任务，不复制 ACL、时间或备用数据流。</returns>
    /// <exception cref="ArgumentException">源目标句柄相同，或不属于同一客户端会话。</exception>
    /// <exception cref="ArgumentOutOfRangeException">任一区间为负数或溢出。</exception>
    /// <exception cref="SmbProtocolException">服务器确认的复制块和请求不一致。</exception>
    public async Task CopyToOnServerAsync(SmbFileHandle destination, long sourceOffset, long destinationOffset, long length,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(destination);
        ThrowIfClosed(); destination.ThrowIfClosed();
        ValidateRange(sourceOffset, length); ValidateRange(destinationOffset, length);
        if (!ReferenceEquals(share.Client, destination.share.Client))
            throw new ArgumentException("Server-side copy requires handles on the same SMB session.", nameof(destination));
        if (Id == destination.Id && ReferenceEquals(share, destination.share))
            throw new ArgumentException("Source and destination handles must differ.", nameof(destination));
        // 先从源句柄获取会话内的 24 字节 resume key，再在目标句柄上发送复制控制请求。
        var resume = await IoControlAsync(0x00140078, maximumOutput: 32, cancellationToken: cancellationToken).ConfigureAwait(false);
        Wire.Slice(resume, 0, 24);
        uint chunkSize = 1024 * 1024;
        var limitRetries = 0;
        while (length > 0)
        {
            var count = (uint)Math.Min(length, chunkSize);
            var input = new byte[56];
            resume.AsSpan(0, 24).CopyTo(input);
            Wire.Put32(input, 24, 1);
            Wire.PutI64(input, 32, sourceOffset);
            Wire.PutI64(input, 40, destinationOffset);
            Wire.Put32(input, 48, count);
            byte[] output;
            try { output = await destination.IoControlAsync(0x001480F2, input, 12, cancellationToken: cancellationToken).ConfigureAwait(false); }
            // 某些服务器通过 INVALID_PARAMETER 的 12 字节数据报告允许的复制块上限。
            // 只接受严格减小的上限，并限制调整次数；已完成的块绝不重复发送。
            catch (SmbException ex) when (ex.Status == SmbStatus.InvalidParameter && ex.ErrorData.Length == 12 && limitRetries++ < 4)
            {
                var maximumChunk = Math.Min(Wire.U32(ex.ErrorData.Span, 4), Wire.U32(ex.ErrorData.Span, 8));
                if (Wire.U32(ex.ErrorData.Span, 0) == 0 || maximumChunk == 0 || maximumChunk >= count)
                    throw;
                chunkSize = maximumChunk;
                continue;
            }
            if (output.Length != 12 || Wire.U32(output, 0) != 1 || Wire.U32(output, 4) != 0 || Wire.U32(output, 8) != count)
                throw new SmbProtocolException("The server did not complete the requested copy chunk.");
            sourceOffset += count; destinationOffset += count; length -= count;
        }
    }

    /// <summary>校验控制操作的非负文件区间，并在偏移加长度之前防止溢出。</summary>
    /// <param name="offset">区间起始字节偏移。</param>
    /// <param name="length">区间字节长度。</param>
    /// <exception cref="ArgumentOutOfRangeException">值为负数或区间末尾无法表示为 long。</exception>
    private static void ValidateRange(long offset, long length)
    {
        if (offset < 0 || length < 0 || offset > long.MaxValue - length)
            throw new ArgumentOutOfRangeException(nameof(length), "The file range is invalid.");
    }
}