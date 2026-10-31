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
using System.Numerics;

namespace MonsterSyncDrive.SMB.Protocol.Compression;

/// <summary>MS-XCA 三种编码及 LZ4 原始块的托管编解码器，不调用平台专有压缩库。</summary>
/// <remarks>
/// 解码器只向调用方声明大小的数组写入，所有后向引用采用逐字节复制以支持重叠匹配。
/// 字典使用固定大小散列表并验证实际字节；散列冲突只降低压缩率，不影响输出正确性。
/// </remarks>
internal static partial class SmbCompressionCodec
{
    /// <summary>把一段原始片段编码为指定算法的原始块，不添加 SMB 变换头。</summary>
    /// <param name="algorithm">实际协商的算法。</param>
    /// <param name="input">待编码字节。</param>
    /// <returns>算法自身的编码数据；NONE 返回副本。</returns>
    /// <exception cref="SmbProtocolException">算法编号未知。</exception>
    internal static byte[] Compress(SmbCompressionAlgorithm algorithm, ReadOnlySpan<byte> input) => algorithm switch
    {
        SmbCompressionAlgorithm.None => input.ToArray(),
        SmbCompressionAlgorithm.Lznt1 => CompressLznt1(input),
        SmbCompressionAlgorithm.Lz77 => CompressLz77(input),
        SmbCompressionAlgorithm.Lz77Huffman => CompressHuffman(input),
        SmbCompressionAlgorithm.PatternV1 => CompressPattern(input),
        SmbCompressionAlgorithm.Lz4 => CompressLz4(input),
        _ => throw Invalid("Unknown compression algorithm.")
    };

    /// <summary>在明确的展开大小内解码一个原始块。</summary>
    /// <param name="algorithm">已经核对的线路算法编号。</param>
    /// <param name="input">单个压缩片段，不包含 OriginalPayloadSize 字段。</param>
    /// <param name="expectedSize">必须精确产生的字节数；不得超过 24 位消息限额。</param>
    /// <returns>大小恰为声明值的独立数组。</returns>
    /// <exception cref="SmbProtocolException">算法、块结构、后向引用或输出大小无效。</exception>
    internal static byte[] Decompress(SmbCompressionAlgorithm algorithm, ReadOnlySpan<byte> input, int expectedSize)
    {
        if (expectedSize < 0 || expectedSize > 0xFFFFFF)
            throw Invalid("Invalid decompressed size.");
        var output = new byte[expectedSize];
        switch (algorithm)
        {
            case SmbCompressionAlgorithm.None:
                if (input.Length != expectedSize) throw Invalid("Invalid uncompressed payload size.");
                input.CopyTo(output); break;
            case SmbCompressionAlgorithm.Lznt1: DecompressLznt1(input, output); break;
            case SmbCompressionAlgorithm.Lz77: DecompressLz77(input, output); break;
            case SmbCompressionAlgorithm.Lz77Huffman: DecompressHuffman(input, output); break;
            case SmbCompressionAlgorithm.Lz4: DecompressLz4(input, output); break;
            case SmbCompressionAlgorithm.PatternV1:
                if (input.Length != 8 || Read32(input, 4) != expectedSize) throw Invalid("Invalid pattern payload.");
                output.AsSpan().Fill(input[0]); break;
            default: throw Invalid("Unknown compression algorithm.");
        }
        return output;
    }

    /// <summary>把完全相同的字节游程编码为 8 字节 PatternV1 结构。</summary>
    /// <param name="input">非空、由同一个字节重复组成的片段。</param>
    /// <returns>模式字节、零保留字段及 32 位重复次数。</returns>
    /// <exception cref="ArgumentException">输入为空或不是单字节重复模式。</exception>
    private static byte[] CompressPattern(ReadOnlySpan<byte> input)
    {
        if (input.Length == 0) throw new ArgumentException("A pattern must contain data.");
        for (var i = 1; i < input.Length; i++)
            if (input[i] != input[0]) throw new ArgumentException("The input is not a repeated byte pattern.");
        var result = new byte[8]; result[0] = input[0];
        BinaryPrimitives.WriteUInt32LittleEndian(result.AsSpan(4), (uint)input.Length);
        return result;
    }

    /// <summary>按独立的 4096 字节块进行 LZNT1 编码，压缩无收益的块保留为原样块。</summary>
    /// <param name="input">原始片段。</param>
    /// <returns>带逐块 LZNT1 头的编码流。</returns>
    /// <remarks>
    /// 每个块重置散列表；匹配长度与距离位宽随块内已产生字节数变化。
    /// 仅当编码后短于原块才设置压缩位，因此低 12 位块长度始终可表达。
    /// </remarks>
    private static byte[] CompressLznt1(ReadOnlySpan<byte> input)
    {
        var result = new List<byte>(input.Length + (input.Length / 4096 + 1) * 2);
        var heads = new int[4096];
        for (var start = 0; start < input.Length; start += 4096)
        {
            var chunk = input.Slice(start, Math.Min(4096, input.Length - start));
            var encoded = new List<byte>(chunk.Length); Array.Fill(heads, -1);
            var position = 0;
            while (position < chunk.Length)
            {
                var flagAt = encoded.Count; encoded.Add(0); byte flags = 0;
                for (var bit = 0; bit < 8 && position < chunk.Length; bit++)
                {
                    LzntParameters(position, out var mask, out var shift);
                    var match = FindMatch(chunk, position, chunk.Length, 1 << (16 - shift), mask + 3, heads);
                    if (match.Length >= 3)
                    {
                        flags |= (byte)(1 << bit);
                        Add16(encoded, (ushort)(((match.Distance - 1) << shift) | (match.Length - 3)));
                        UpdateHeads(chunk, position + 1, position + match.Length, heads);
                        position += match.Length;
                    }
                    else encoded.Add(chunk[position++]);
                }
                encoded[flagAt] = flags;
            }
            if (encoded.Count < chunk.Length)
            {
                Add16(result, (ushort)(0xB000 | (encoded.Count - 1))); result.AddRange(encoded);
            }
            else
            {
                Add16(result, (ushort)(0x3000 | (chunk.Length - 1)));
                foreach (var value in chunk) result.Add(value);
            }
        }
        return result.ToArray();
    }

    /// <summary>验证块签名并展开 LZNT1，禁止匹配跨越当前 4096 字节块的历史起点。</summary>
    /// <param name="input">带块头的 LZNT1 流。</param>
    /// <param name="output">调用方已按限额分配的精确目标。</param>
    /// <exception cref="SmbProtocolException">头部、分组、引用或块大小无效。</exception>
    private static void DecompressLznt1(ReadOnlySpan<byte> input, Span<byte> output)
    {
        var source = 0; var destination = 0;
        while (source < input.Length)
        {
            var header = Read16(input, source); source += 2;
            if (header == 0)
            {
                if (source != input.Length) throw Invalid("Data follows the LZNT1 terminator.");
                break;
            }
            if ((header & 0x7000) != 0x3000) throw Invalid("Invalid LZNT1 chunk signature.");
            var end = checked(source + (header & 0xFFF) + 1);
            Require(input.Length, source, end - source);
            var chunkStart = destination;
            if ((header & 0x8000) == 0)
            {
                Require(output.Length, destination, end - source);
                input.Slice(source, end - source).CopyTo(output[destination..]);
                destination += end - source; source = end;
            }
            else while (source < end)
            {
                var flags = input[source++];
                for (var bit = 0; bit < 8 && source < end; bit++)
                {
                    if ((flags & (1 << bit)) == 0)
                    {
                        Require(output.Length, destination, 1);
                        output[destination++] = input[source++];
                    }
                    else
                    {
                        if (source > end - 2) throw Invalid("Truncated LZNT1 match.");
                        LzntParameters(destination - chunkStart, out var mask, out var shift);
                        var token = Read16(input, source); source += 2;
                        CopyMatch(output, ref destination, (token >> shift) + 1, (token & mask) + 3, chunkStart);
                    }
                    if (destination - chunkStart > 4096) throw Invalid("Oversized LZNT1 chunk.");
                }
            }
        }
        if (destination != output.Length) throw Invalid("LZNT1 output size mismatch.");
    }

    /// <summary>根据当前块内位置计算 LZNT1 匹配字的长度掩码及距离右移位数。</summary>
    /// <param name="position">当前块已经产生的字节数。</param>
    /// <param name="mask">长度减三字段的有效位掩码。</param>
    /// <param name="shift">距离减一字段的起始位。</param>
    /// <remarks>每跨过一个 2 的幂边界，距离需要多一位，长度相应少一位；使用 position 减一处理边界。</remarks>
    private static void LzntParameters(int position, out int mask, out int shift)
    {
        mask = 0xFFF; shift = 12;
        for (var value = position - 1; value >= 16; value >>= 1) { mask >>= 1; shift--; }
    }

    /// <summary>实现 Plain LZ77 的 32 位标志组、8192 字节距离和多级长度扩展。</summary>
    /// <param name="input">待编码片段。</param>
    /// <returns>不含外层 SMB 头的 XPRESS 原始流。</returns>
    /// <remarks>
    /// 标志按高位到低位消费；两个长匹配共用一个长度半字节，该状态跨标志组保存。
    /// 长度按 4 位、8 位、16 位、32 位依次扩展，不截断超过 65535 的匹配。
    /// </remarks>
    private static byte[] CompressLz77(ReadOnlySpan<byte> input)
    {
        var output = new List<byte>(input.Length + input.Length / 8 + 8);
        var heads = new int[65536]; Array.Fill(heads, -1);
        var position = 0; var halfByte = -1;
        do
        {
            var flagsAt = output.Count; Add32(output, 0); uint flags = uint.MaxValue;
            for (var bit = 31; bit >= 0 && position < input.Length; bit--)
            {
                var match = FindMatch(input, position, input.Length, 8192, int.MaxValue, heads);
                if (match.Length < 3)
                {
                    flags &= ~(1u << bit); output.Add(input[position++]); continue;
                }
                Add16(output, (ushort)(((match.Distance - 1) << 3) | Math.Min(match.Length - 3, 7)));
                if (match.Length >= 10)
                {
                    var length = match.Length - 10;
                    if (halfByte < 0)
                    {
                        halfByte = output.Count; output.Add((byte)Math.Min(length, 15));
                    }
                    else
                    {
                        output[halfByte] |= (byte)(Math.Min(length, 15) << 4); halfByte = -1;
                    }
                    if (length >= 15)
                    {
                        length -= 15; output.Add((byte)Math.Min(length, 255));
                        if (length >= 255)
                        {
                            length = match.Length - 3;
                            if (length <= ushort.MaxValue) Add16(output, (ushort)length);
                            else { Add16(output, 0); Add32(output, (uint)length); }
                        }
                    }
                }
                UpdateHeads(input, position + 1, position + match.Length, heads); position += match.Length;
            }
            Write32(output, flagsAt, flags);
            // 若一组恰好占满且全为文字，则没有剩余的置一标志用于表示结束，需要额外的结束标志组。
            if (position == input.Length && flags == 0) Add32(output, uint.MaxValue);
        } while (position < input.Length);
        return output.ToArray();
    }

    /// <summary>按 MS-XCA 展开 Plain LZ77，并核对长度扩展的最小合法值。</summary>
    /// <param name="input">XPRESS 编码流。</param>
    /// <param name="output">精确目标缓冲。</param>
    /// <exception cref="SmbProtocolException">标志、长度、距离或最终大小不合法。</exception>
    private static void DecompressLz77(ReadOnlySpan<byte> input, Span<byte> output)
    {
        var source = 0; var destination = 0; var halfByte = -1;
        var flagCount = 0; uint flags = 0;
        while (source < input.Length)
        {
            if (flagCount == 0) { flags = Read32(input, source); source += 4; flagCount = 32; }
            flagCount--;
            if ((flags & (1u << flagCount)) == 0)
            {
                Require(input.Length, source, 1); Require(output.Length, destination, 1);
                output[destination++] = input[source++]; continue;
            }
            if (source == input.Length) break;
            var token = Read16(input, source); source += 2;
            var length = token & 7;
            if (length == 7)
            {
                if (halfByte < 0) { Require(input.Length, source, 1); halfByte = source++; length = input[halfByte] & 15; }
                else { length = input[halfByte] >> 4; halfByte = -1; }
                if (length == 15)
                {
                    Require(input.Length, source, 1); length = input[source++];
                    if (length == 255)
                    {
                        length = Read16(input, source); source += 2;
                        if (length == 0)
                        {
                            var extended = Read32(input, source); source += 4;
                            if (extended > int.MaxValue) throw Invalid("Oversized LZ77 length.");
                            length = (int)extended;
                        }
                        if (length < 22) throw Invalid("Invalid LZ77 length extension.");
                        length -= 22;
                    }
                    length += 15;
                }
                length += 7;
            }
            CopyMatch(output, ref destination, (token >> 3) + 1, checked(length + 3));
        }
        if (source != input.Length || destination != output.Length) throw Invalid("LZ77 output size mismatch.");
    }

    /// <summary>构造标准 LZ4 原始块，保留最后至少五个文字字节及末次匹配的 12 字节限制。</summary>
    /// <param name="input">待编码数据。</param>
    /// <returns>LZ4 token、可变长度文字和后向引用序列。</returns>
    /// <remarks>与 LZ4 frame 格式不同，此数据不包含 frame 魔数、块校验或内容校验。</remarks>
    private static byte[] CompressLz4(ReadOnlySpan<byte> input)
    {
        var output = new List<byte>(input.Length + input.Length / 255 + 8);
        var heads = new int[65536]; Array.Fill(heads, -1);
        var position = 0; var anchor = 0;
        while (position <= input.Length - 12)
        {
            var match = FindMatch(input, position, input.Length - 5, 65535, int.MaxValue, heads);
            if (match.Length < 4) { position++; continue; }
            var literalLength = position - anchor;
            output.Add((byte)((Math.Min(literalLength, 15) << 4) | Math.Min(match.Length - 4, 15)));
            if (literalLength >= 15) WriteLz4Length(output, literalLength - 15);
            for (var i = anchor; i < position; i++) output.Add(input[i]);
            Add16(output, (ushort)match.Distance);
            if (match.Length >= 19) WriteLz4Length(output, match.Length - 19);
            UpdateHeads(input, position + 1, position + match.Length, heads);
            position += match.Length; anchor = position;
        }
        var trailing = input.Length - anchor;
        output.Add((byte)(Math.Min(trailing, 15) << 4));
        if (trailing >= 15) WriteLz4Length(output, trailing - 15);
        for (var i = anchor; i < input.Length; i++) output.Add(input[i]);
        return output.ToArray();
    }

    /// <summary>展开 LZ4 token 和 255 字节延续长度，禁止零距离和越界匹配。</summary>
    /// <param name="input">LZ4 原始块。</param>
    /// <param name="output">精确目标缓冲。</param>
    /// <exception cref="SmbProtocolException">文字、长度、距离或输出大小无效。</exception>
    private static void DecompressLz4(ReadOnlySpan<byte> input, Span<byte> output)
    {
        if (input.IsEmpty) throw Invalid("An LZ4 block requires at least its final token.");
        var source = 0; var destination = 0;
        while (source < input.Length)
        {
            var token = input[source++];
            var literal = (int)(token >> 4);
            if (literal == 15) literal = checked(literal + ReadLz4Length(input, ref source));
            Require(input.Length, source, literal); Require(output.Length, destination, literal);
            input.Slice(source, literal).CopyTo(output[destination..]); source += literal; destination += literal;
            if (source == input.Length) break;
            var distance = Read16(input, source); source += 2;
            var length = token & 15;
            if (length == 15) length = checked(length + ReadLz4Length(input, ref source));
            CopyMatch(output, ref destination, distance, checked(length + 4));
        }
        if (destination != output.Length) throw Invalid("LZ4 output size mismatch.");
    }

    /// <summary>写入 LZ4 长度延续：若干 255，最后以小于 255 的字节终止。</summary>
    /// <param name="output">目标编码缓冲。</param>
    /// <param name="length">扣除 token 内置长度后的非负剩余量。</param>
    private static void WriteLz4Length(List<byte> output, int length)
    {
        while (length >= 255) { output.Add(255); length -= 255; }
        output.Add((byte)length);
    }

    /// <summary>有界读取 LZ4 延续长度，使用 checked 累加防止整数回绕。</summary>
    /// <param name="input">编码流。</param>
    /// <param name="source">首个延续字节位置，返回时移到终止字节之后。</param>
    /// <returns>token 内置长度以外的额外长度。</returns>
    private static int ReadLz4Length(ReadOnlySpan<byte> input, ref int source)
    {
        var length = 0; byte next;
        do { Require(input.Length, source, 1); next = input[source++]; length = checked(length + next); } while (next == 255);
        return length;
    }

    /// <summary>以三个字节的散列查找一个历史候选，再逐字节验证并延长匹配。</summary>
    /// <param name="input">同一个原始块或片段。</param>
    /// <param name="position">当前编码位置，同时成为此散列的新候选。</param>
    /// <param name="end">本次匹配允许到达的排他结束位置。</param>
    /// <param name="maxDistance">算法可表示的最大距离。</param>
    /// <param name="maxLength">当前位宽或块边界允许的最大长度。</param>
    /// <param name="heads">固定大小的最后位置表，初值为负一。</param>
    /// <returns>长度至少三的匹配，或全部为零的未匹配结果。</returns>
    /// <remarks>每个散列只保留一个位置，避免链式字典被恶意输入放大为平方时间；字节比较保证冲突不产生错误引用。</remarks>
    private static (int Distance, int Length) FindMatch(ReadOnlySpan<byte> input, int position, int end, int maxDistance, int maxLength, int[] heads)
    {
        if (position > end - 3) return default;
        var hash = Hash(input, position, heads.Length - 1); var candidate = heads[hash]; heads[hash] = position;
        if (candidate < 0 || candidate >= position || position - candidate > maxDistance) return default;
        var length = 0; var limit = Math.Min(end - position, maxLength);
        while (length < limit && input[candidate + length] == input[position + length]) length++;
        return length >= 3 ? (position - candidate, length) : default;
    }

    /// <summary>计算三个字节的确定性散列，并限制到二次幂大小的位置表。</summary>
    /// <param name="input">至少覆盖 offset 后三个字节的原始数据。</param>
    /// <param name="offset">散列起点。</param>
    /// <param name="mask">位置表长度减一。</param>
    /// <returns>合法的表索引。</returns>
    private static int Hash(ReadOnlySpan<byte> input, int offset, int mask)
        => ((input[offset] * 251 + input[offset + 1]) * 251 + input[offset + 2]) & mask;

    /// <summary>把已经被一个长匹配跳过的位置补入字典，使后续匹配能引用最近的历史。</summary>
    /// <param name="input">原始片段。</param>
    /// <param name="from">包含的起点。</param>
    /// <param name="to">不包含的终点。</param>
    /// <param name="heads">固定大小散列位置表。</param>
    /// <remarks>末尾不足三个字节时停止；每个输入位置最多被此流程处理一次。</remarks>
    private static void UpdateHeads(ReadOnlySpan<byte> input, int from, int to, int[] heads)
    {
        for (var i = from; i < to && i < input.Length - 2; i++) heads[Hash(input, i, heads.Length - 1)] = i;
    }

    /// <summary>逐字节复制后向引用，正确处理匹配长度大于距离的重叠重复。</summary>
    /// <param name="output">完整输出缓冲。</param>
    /// <param name="destination">当前写位置；返回时增加 length。</param>
    /// <param name="distance">到已经生成字节的正距离。</param>
    /// <param name="length">展开字节数。</param>
    /// <param name="minimumSource">历史起点，LZNT1 用它隔离不同块。</param>
    /// <exception cref="SmbProtocolException">引用早于历史起点或写入超过输出末尾。</exception>
    private static void CopyMatch(Span<byte> output, ref int destination, int distance, int length, int minimumSource = 0)
    {
        if (distance <= 0 || distance > destination - minimumSource) throw Invalid("Compression match points before its history.");
        Require(output.Length, destination, length);
        for (var i = 0; i < length; i++) { output[destination] = output[destination - distance]; destination++; }
    }

    /// <summary>用减法边界判断验证片段，避免 offset 加 count 溢出。</summary>
    /// <param name="size">容器长度。</param>
    /// <param name="offset">片段起点。</param>
    /// <param name="count">片段长度。</param>
    /// <exception cref="SmbProtocolException">任一值为负或片段越界。</exception>
    private static void Require(int size, int offset, int count)
    {
        if (offset < 0 || count < 0 || offset > size - count) throw Invalid("Compression data exceeds its bounds.");
    }

    /// <summary>有界读取线路小端 16 位值。</summary>
    /// <param name="input">输入字节。</param>
    /// <param name="offset">字段位置。</param>
    /// <returns>无符号字段值。</returns>
    private static ushort Read16(ReadOnlySpan<byte> input, int offset)
    { Require(input.Length, offset, 2); return BinaryPrimitives.ReadUInt16LittleEndian(input[offset..]); }
    /// <summary>有界读取线路小端 32 位值。</summary>
    /// <param name="input">输入字节。</param>
    /// <param name="offset">字段位置。</param>
    /// <returns>无符号字段值。</returns>
    private static uint Read32(ReadOnlySpan<byte> input, int offset)
    { Require(input.Length, offset, 4); return BinaryPrimitives.ReadUInt32LittleEndian(input[offset..]); }
    /// <summary>向可增长编码缓冲追加小端 16 位值。</summary>
    /// <param name="output">目标缓冲。</param>
    /// <param name="value">字段值。</param>
    private static void Add16(List<byte> output, ushort value) { output.Add((byte)value); output.Add((byte)(value >> 8)); }
    /// <summary>向可增长编码缓冲追加小端 32 位值。</summary>
    /// <param name="output">目标缓冲。</param>
    /// <param name="value">字段值。</param>
    private static void Add32(List<byte> output, uint value)
    { output.Add((byte)value); output.Add((byte)(value >> 8)); output.Add((byte)(value >> 16)); output.Add((byte)(value >> 24)); }
    /// <summary>回填先前预留的 32 位标志组，保持低字节在前。</summary>
    /// <param name="output">包含预留位置的缓冲。</param>
    /// <param name="offset">标志组起点。</param>
    /// <param name="value">按消费顺序构建的标志。</param>
    private static void Write32(List<byte> output, int offset, uint value)
    { for (var i = 0; i < 4; i++) output[offset + i] = (byte)(value >> (8 * i)); }
    /// <summary>构建统一的格式或边界错误，便于连接按协议错误关闭。</summary>
    /// <param name="message">不含敏感数据的诊断信息。</param>
    /// <returns>协议异常实例。</returns>
    private static SmbProtocolException Invalid(string message) => new(message);
}