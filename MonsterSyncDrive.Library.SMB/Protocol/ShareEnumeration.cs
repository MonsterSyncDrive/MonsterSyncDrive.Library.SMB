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
using System.Buffers.Binary;

namespace MonsterSyncDrive.SMB.Protocol;

/// <summary>通过面向连接的 DCE/RPC 和 NDR32，使用 MS-SRVS NetrShareEnum 级别 1 枚举服务器共享。</summary>
/// <param name="pipe">调用者拥有且已经认证的 srvsvc 命名管道句柄。</param>
/// <param name="host">RPC 请求使用的逻辑服务器名称。</param>
/// <remarks>身份认证和加密由 SMB 提供，无需依赖平台 RPC 运行时或 Netapi32。</remarks>
internal sealed class ShareEnumeration(SmbFileHandle pipe, string host)
{
    /// <summary>srvsvc 抽象语法的 UUID。</summary>
    private static readonly Guid Srvsvc = new("4b324fc8-1670-01d3-1278-5a47bf6ee188");
    /// <summary>小端 NDR32 传输语法的 UUID。</summary>
    private static readonly Guid Ndr32 = new("8a885d04-1ceb-11c9-9fe8-08002b104860");
    /// <summary>限制重组后的 RPC 数据及管道缓冲字节数，不信任对端声明的长度。</summary>
    private const int MaximumStub = 1024 * 1024;
    /// <summary>尚未消费的管道字节，可能包含不完整 PDU 或多个完整 PDU。</summary>
    private byte[] buffered = [];
    /// <summary>单调递增的 RPC 调用标识符，用于匹配绑定和枚举响应。</summary>
    private uint callId;

    /// <summary>绑定 NDR32 srvsvc 上下文，然后在页数限制内获取全部续页。</summary>
    /// <param name="cancellationToken">取消管道收发、读取或下一页枚举。</param>
    /// <returns>服务器返回的共享名称、类型和备注。</returns>
    /// <exception cref="SmbRpcException">RPC 服务器返回故障或非成功的枚举状态。</exception>
    /// <exception cref="SmbProtocolException">绑定、帧结构、分片推进、分页推进或数量限制无效。</exception>
    internal async Task<IReadOnlyList<SmbShareInfo>> EnumerateAsync(CancellationToken cancellationToken)
    {
        var bind = Pdu(11, 72, ++callId);
        Wire.Put16(bind, 16, 4280); Wire.Put16(bind, 18, 4280);
        bind[24] = 1; bind[30] = 1;
        Srvsvc.TryWriteBytes(bind.AsSpan(32, 16));
        Wire.Put16(bind, 48, 3);
        Ndr32.TryWriteBytes(bind.AsSpan(52, 16));
        Wire.Put32(bind, 68, 2);
        buffered = await pipe.TransceivePipeFragmentAsync(bind, cancellationToken).ConfigureAwait(false);
        var ack = await ReadPduAsync(cancellationToken).ConfigureAwait(false);
        ValidatePdu(ack, 12, callId);
        // 辅助地址字符串长度可变，上下文结果列表在该字符串之后对齐，
        // 并不位于固定偏移；解释任何 NDR32 响应前必须验证服务器接受的语法。
        var secondaryAddressLength = Wire.U16(ack, 24);
        var resultsOffset = checked((26 + secondaryAddressLength + 3) & ~3);
        var results = Wire.Slice(ack, resultsOffset, 28);
        if (ack[3] != 3 || results[0] != 1 || Wire.U16(results, 4) != 0 ||
            new Guid(results.Slice(8, 16)) != Ndr32 || Wire.U32(results, 24) != 2)
            throw new SmbProtocolException("The RPC server rejected the srvsvc NDR32 binding.");
        var shares = new List<SmbShareInfo>();
        var resumes = new HashSet<uint>();
        uint resume = 0;
        for (var page = 0; page < 4096; page++)
        {
            var stub = BuildRequest(host, resume);
            var request = Pdu(0, 24 + stub.Length, ++callId);
            Wire.Put32(request, 16, (uint)stub.Length);
            Wire.Put16(request, 22, 15);
            stub.CopyTo(request, 24);
            var incoming = await pipe.TransceivePipeFragmentAsync(request, cancellationToken).ConfigureAwait(false);
            buffered = Concat(buffered, incoming);
            var response = await ReadResponseAsync(cancellationToken).ConfigureAwait(false);
            var decoded = ParseResponse(response);
            shares.AddRange(decoded.Shares);
            if (decoded.Status == 0)
                return shares;
            if (decoded.Status != 234)
                throw new SmbRpcException(decoded.Status, false);
            // ERROR_MORE_DATA 若没有新的非零续页句柄，将导致 RPC 枚举无限循环。
            if (decoded.Resume == 0 || !resumes.Add(decoded.Resume))
                throw new SmbProtocolException("The server did not advance the share enumeration resume handle.");
            resume = decoded.Resume;
        }
        throw new SmbProtocolException("The share enumeration exceeded its page limit.");
    }

    /// <summary>构造 NetrShareEnum 级别 1 的 NDR32 请求，包含偏好页大小和续页指针。</summary>
    /// <param name="host">不含 UNC 前缀的逻辑 SMB 服务器名称。</param>
    /// <param name="resume">首次调用时为零，之后使用服务器上次返回的续页值。</param>
    /// <returns>小端 NDR32 请求数据。</returns>
    internal static byte[] BuildRequest(string host, uint resume)
    {
        using var stream = new MemoryStream();
        Write32(stream, 0x20000);
        WriteString(stream, @"\\" + host);
        Write32(stream, 1); // 信息级别。
        Write32(stream, 1); // 联合体判别值。
        Write32(stream, 0x20004); // 共享记录容器指针。
        Write32(stream, 0); // EntriesRead：已读取条目数。
        Write32(stream, 0); // 记录缓冲区指针。
        Write32(stream, 16384); // PreferredMaximumLength：偏好的最大响应数据长度。
        Write32(stream, 0x20008); // 续页指针。
        Write32(stream, resume);
        return stream.ToArray();
    }

    /// <summary>一页已解析的 NetrShareEnum 结果，包含服务器续页值和 Win32 状态。</summary>
    /// <param name="Shares">级别 1 的共享记录。</param>
    /// <param name="Resume">下一次使用的续页值；服务器未返回续页指针时为零。</param>
    /// <param name="Status">接口状态；234 表示仍有下一页。</param>
    internal sealed record Page(IReadOnlyList<SmbShareInfo> Shares, uint Resume, uint Status);

    /// <summary>解析完整的级别 1 NDR32 结果，检查数组边界和 UTF-16 字符串终止符。</summary>
    /// <param name="stub">已经重组且不含 RPC 帧结构的响应数据。</param>
    /// <returns>解析后的共享列表、续页值和状态。</returns>
    /// <exception cref="SmbProtocolException">级别、指针、计数、字符串、名称或尾部字节无效。</exception>
    internal static Page ParseResponse(ReadOnlySpan<byte> stub)
    {
        var reader = new NdrReader(stub);
        if (reader.UInt32() != 1 || reader.UInt32() != 1)
            throw new SmbProtocolException("Unexpected share enumeration information level.");
        var shares = new List<SmbShareInfo>();
        if (reader.UInt32() != 0)
        {
            var count = reader.UInt32();
            var pointer = reader.UInt32();
            if (count > 65536 || (count != 0 && pointer == 0))
                throw new SmbProtocolException("Invalid RPC share count.");
            if (pointer != 0)
            {
                var maximum = reader.UInt32();
                if (maximum != count)
                    throw new SmbProtocolException("Inconsistent RPC conformant array length.");
                // NDR 先写入一致性数组的固定记录，再写入延迟解引用的字符串内容。
                // 应先读取指针存在标志，再按声明顺序读取指针指向的内容。
                var records = new (bool Name, uint Type, bool Remark)[count];
                for (var i = 0; i < records.Length; i++)
                    records[i] = (reader.UInt32() != 0, reader.UInt32(), reader.UInt32() != 0);
                foreach (var record in records)
                {
                    var name = record.Name ? reader.String() : "";
                    var remark = record.Remark ? reader.String() : "";
                    try { SmbPath.ValidateShare(name); }
                    catch (ArgumentException ex) { throw new SmbProtocolException("Invalid RPC share name.", ex); }
                    shares.Add(new SmbShareInfo(name, record.Type, remark));
                }
            }
        }
        reader.UInt32(); // TotalEntries：服务器报告的条目总数。
        var resume = reader.UInt32() != 0 ? reader.UInt32() : 0;
        var status = reader.UInt32();
        reader.End();
        return new Page(shares, resume, status);
    }

    /// <summary>按首段、中间段和末段的顺序，将响应 PDU 重组为完整 RPC 结果。</summary>
    /// <param name="cancellationToken">取消后续管道读取。</param>
    /// <returns>大小受限的重组 RPC 数据。</returns>
    /// <exception cref="SmbRpcException">接收到故障 PDU。</exception>
    /// <exception cref="SmbProtocolException">分片顺序、调用标识符、推进状态或大小限制无效。</exception>
    private async Task<byte[]> ReadResponseAsync(CancellationToken cancellationToken)
    {
        using var output = new MemoryStream();
        var first = true;
        for (var fragment = 0; fragment < 4096; fragment++)
        {
            var pdu = await ReadPduAsync(cancellationToken).ConfigureAwait(false);
            if (pdu[2] == 3)
            {
                ValidatePdu(pdu, 3, callId);
                throw new SmbRpcException(Wire.U32(pdu, 24), true);
            }
            ValidatePdu(pdu, 2, callId);
            if (pdu.Length < 24 || Wire.U16(pdu, 20) != 0 || ((pdu[3] & 1) != 0) != first)
                throw new SmbProtocolException("Invalid RPC response fragment sequence.");
            // 最后一段的数据可以为空；非末段若为空则无法推进重组，必须拒绝。
            if (pdu.Length == 24 && (pdu[3] & 2) == 0)
                throw new SmbProtocolException("An RPC fragment did not make progress.");
            first = false;
            if (output.Length + pdu.Length - 24 > MaximumStub)
                throw new SmbProtocolException("The RPC response exceeds the configured limit.");
            output.Write(pdu, 24, pdu.Length - 24);
            if ((pdu[3] & 2) != 0)
                return output.ToArray();
        }
        throw new SmbProtocolException("The RPC response exceeded its fragment limit.");
    }

    /// <summary>读取一个 RPC PDU，并保留属于下一个分片的剩余字节。</summary>
    /// <param name="cancellationToken">取消补齐尚不完整的 PDU。</param>
    /// <returns>FragLength 指定的完整消息头和正文。</returns>
    private async Task<byte[]> ReadPduAsync(CancellationToken cancellationToken)
    {
        await FillAsync(16, cancellationToken).ConfigureAwait(false);
        var length = Wire.U16(buffered, 8);
        if (length < 16)
            throw new SmbProtocolException("Invalid RPC fragment length.");
        await FillAsync(length, cancellationToken).ConfigureAwait(false);
        var result = buffered[..length];
        buffered = buffered[length..];
        return result;
    }

    /// <summary>累积管道字节，直到能够读取受大小约束的 RPC 消息头或分片。</summary>
    /// <param name="minimum">所需的缓冲字节数。</param>
    /// <param name="cancellationToken">取消一次管道读取。</param>
    /// <returns>缓冲达到所需字节数后完成的任务。</returns>
    /// <exception cref="SmbProtocolException">管道提前结束，或接收数据超过上限。</exception>
    private async Task FillAsync(int minimum, CancellationToken cancellationToken)
    {
        while (buffered.Length < minimum)
        {
            var block = new byte[65536];
            var count = await pipe.ReadAsync(block, 0, cancellationToken).ConfigureAwait(false);
            if (count == 0)
                throw new SmbProtocolException("The RPC pipe closed before a complete response arrived.");
            buffered = Concat(buffered, block.AsSpan(0, count));
            if (buffered.Length > MaximumStub)
                throw new SmbProtocolException("The RPC receive buffer exceeds its limit.");
        }
    }

    /// <summary>校验 RPC 版本、消息类型、小端表示、长度和调用标识符。</summary>
    /// <param name="pdu">完整 RPC 分片。</param>
    /// <param name="type">预期的绑定确认、普通响应或故障类型。</param>
    /// <param name="expectedCallId">当前等待响应的 RPC 调用标识符。</param>
    /// <exception cref="SmbProtocolException">任一必须校验的帧字段不一致。</exception>
    /// <remarks>此处不协商 RPC 级认证尾部，安全保护由外层 SMB 会话提供。</remarks>
    private static void ValidatePdu(byte[] pdu, byte type, uint expectedCallId)
    {
        if (pdu.Length < 16 || pdu[0] != 5 || pdu[1] != 0 || pdu[2] != type ||
            Wire.U32(pdu, 4) != 0x10 || Wire.U16(pdu, 8) != pdu.Length || Wire.U16(pdu, 10) != 0 ||
            Wire.U32(pdu, 12) != expectedCallId)
            throw new SmbProtocolException("Invalid or unauthenticated RPC framing.");
    }

    /// <summary>创建小端、单分片 RPC 请求或绑定 PDU 的消息头。</summary>
    /// <param name="type">RPC 消息类型。</param>
    /// <param name="length">包含 16 字节消息头在内的完整 PDU 长度。</param>
    /// <param name="id">调用标识符。</param>
    /// <returns>经过清零并设置首段和末段标志的消息。</returns>
    private static byte[] Pdu(byte type, int length, uint id)
    {
        var data = new byte[length];
        data[0] = 5; data[2] = type; data[3] = 3; data[4] = 0x10;
        Wire.Put16(data, 8, checked((ushort)length)); Wire.Put32(data, 12, id);
        return data;
    }

    /// <summary>通过具有溢出检查的长度计算合并两个字节区域。</summary>
    /// <param name="first">已经缓冲的字节。</param>
    /// <param name="second">新读取的字节。</param>
    /// <returns>新分配并拥有的连续字节数组。</returns>
    private static byte[] Concat(ReadOnlySpan<byte> first, ReadOnlySpan<byte> second)
    {
        var result = new byte[checked(first.Length + second.Length)];
        first.CopyTo(result); second.CopyTo(result.AsSpan(first.Length));
        return result;
    }

    /// <summary>追加一个小端 NDR32 无符号整数。</summary>
    /// <param name="stream">请求数据流。</param>
    /// <param name="value">需要编码的整数。</param>
    private static void Write32(Stream stream, uint value)
    {
        Span<byte> bytes = stackalloc byte[4];
        BinaryPrimitives.WriteUInt32LittleEndian(bytes, value);
        stream.Write(bytes);
    }

    /// <summary>追加一致性变长 UTF-16LE 字符串、NUL 终止符及四字节对齐填充。</summary>
    /// <param name="stream">NDR32 请求数据流。</param>
    /// <param name="text">尚未包含线上终止符的托管字符串。</param>
    private static void WriteString(Stream stream, string text)
    {
        var bytes = Wire.Unicode.GetBytes(text + "\0");
        Write32(stream, (uint)bytes.Length / 2); Write32(stream, 0); Write32(stream, (uint)bytes.Length / 2);
        stream.Write(bytes);
        while (stream.Position % 4 != 0)
            stream.WriteByte(0);
    }

    /// <summary>用于级别 1 共享枚举响应的栈上 NDR32 游标，所有读取均检查边界。</summary>
    private ref struct NdrReader
    {
        /// <summary>已经重组的原始响应数据字节。</summary>
        private readonly ReadOnlySpan<byte> data;
        /// <summary>进行对应类型的 NDR 对齐之前，下一次读取的字节位置。</summary>
        private int position;
        /// <summary>在响应数据起点创建读取游标。</summary>
        /// <param name="data">需要解析的完整响应数据。</param>
        internal NdrReader(ReadOnlySpan<byte> data) { this.data = data; position = 0; }
        /// <summary>读取下一个按四字节对齐的小端无符号整数。</summary>
        /// <returns>解析得到的数值。</returns>
        internal uint UInt32()
        {
            position = checked((position + 3) & ~3);
            var value = Wire.U32(data, position);
            position += 4;
            return value;
        }
        /// <summary>读取有界的一致性变长字符串，并去除必需的末尾 NUL。</summary>
        /// <returns>经过校验、不含终止符的 UTF-16 文本。</returns>
        /// <exception cref="SmbProtocolException">数组边界、编码字节或终止符无效。</exception>
        internal string String()
        {
            var maximum = UInt32();
            var offset = UInt32();
            var actual = UInt32();
            if (actual == 0 || actual > int.MaxValue / 2 || maximum > MaximumStub / 2 ||
                offset > maximum || actual > maximum - offset)
                throw new SmbProtocolException("Invalid NDR string bounds.");
            var length = (int)actual * 2;
            var text = Wire.Text(data, position, length);
            position = checked(position + length);
            if (text[^1] != '\0' || text[..^1].Contains('\0'))
                throw new SmbProtocolException("An NDR string is not correctly terminated.");
            return text[..^1];
        }
        /// <summary>要求解析器完全消费响应数据，不允许存在无法解释的尾部字节。</summary>
        /// <exception cref="SmbProtocolException">仍有尚未解析的字节。</exception>
        internal void End()
        {
            if (position != data.Length)
                throw new SmbProtocolException("Unexpected trailing data in the RPC response.");
        }
    }
}