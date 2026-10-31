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

/// <summary>承载 MS-XCA LZ77 加 Huffman 的有界逐块实现。</summary>
/// <remarks>压缩端生成规范码；解压端也接受独立 Windows 编码器生成的不同合法码表。</remarks>
internal static partial class SmbCompressionCodec
{
    /// <summary>保存 LZ77 阶段得到的一个文字或匹配，供统计和 Huffman 最终编码复用。</summary>
    /// <param name="Symbol">文字字节，或按长度和距离高位组合的 256 到 511 符号。</param>
    /// <param name="Distance">匹配距离，文字为零。</param>
    /// <param name="Length">实际匹配长度，文字为零。</param>
    private readonly record struct HuffmanToken(int Symbol, int Distance, int Length);
    /// <summary>优先队列合并得到的 Huffman 树节点。</summary>
    /// <param name="Symbol">叶符号，内部节点为负一。</param>
    /// <param name="Left">内部节点的左子节点索引。</param>
    /// <param name="Right">内部节点的右子节点索引。</param>
    private readonly record struct HuffmanNode(int Symbol, int Left, int Right);

    /// <summary>把数据划分为最多 65536 字节的编码块，每块生成独立的 256 字节码长表。</summary>
    /// <param name="input">原始片段。</param>
    /// <returns>MS-XCA Huffman 原始流。</returns>
    /// <remarks>
    /// 第一遍保存 LZ77 token 并统计频率，第二遍用规范码输出。长匹配的额外长度字节与
    /// 16 位预读字交错存放；不能用常规连续位流写入器替代此布局。
    /// </remarks>
    private static byte[] CompressHuffman(ReadOnlySpan<byte> input)
    {
        var output = new List<byte>(input.Length + input.Length / 8 + 512);
        var heads = new int[65536];
        var start = 0;
        do
        {
            var chunk = input.Slice(start, Math.Min(65536, input.Length - start));
            var tokens = new List<HuffmanToken>(); var frequencies = new int[512];
            Array.Fill(heads, -1);
            for (var position = 0; position < chunk.Length;)
            {
                var match = FindMatch(chunk, position, chunk.Length, 65535, int.MaxValue, heads);
                if (match.Length < 3)
                {
                    var symbol = chunk[position++]; tokens.Add(new(symbol, 0, 0)); frequencies[symbol]++;
                }
                else
                {
                    var symbol = 256 + Math.Min(match.Length - 3, 15) + 16 * BitOperations.Log2((uint)match.Distance);
                    tokens.Add(new(symbol, match.Distance, match.Length)); frequencies[symbol]++;
                    UpdateHeads(chunk, position + 1, position + match.Length, heads); position += match.Length;
                }
            }
            frequencies[256]++;
            var lengths = BuildHuffmanLengths(frequencies);
            var codes = BuildHuffmanCodes(lengths);
            var writer = new HuffmanWriter();
            for (var symbol = 0; symbol < 512; symbol += 2)
                writer.Data[symbol / 2] = (byte)(lengths[symbol] | (lengths[symbol + 1] << 4));
            foreach (var token in tokens)
            {
                writer.WriteBits(lengths[token.Symbol], codes[token.Symbol]);
                if (token.Symbol < 256) continue;
                var length = token.Length - 3;
                if (length >= 15)
                {
                    var extension = length - 15;
                    if (extension < 255) writer.WriteByte((byte)extension);
                    else
                    {
                        writer.WriteByte(255);
                        if (length < 65536) writer.Write16((ushort)length);
                        else { writer.Write16(0); writer.Write32((uint)length); }
                    }
                }
                var distanceBits = BitOperations.Log2((uint)token.Distance);
                writer.WriteBits(distanceBits, (uint)token.Distance - (1u << distanceBits));
            }
            // 最后一个块附带结束符；前面的满块由展开字节数确定边界。
            // 给这些满块再添加结束符会改变后续块头的字节位置，使独立解码器无法正确对齐。
            if (start + chunk.Length == input.Length)
                writer.WriteBits(lengths[256], codes[256]);
            output.AddRange(writer.Finish()); start += chunk.Length;
        } while (start < input.Length);
        return output.ToArray();
    }

    /// <summary>以频率优先队列构造前缀树，并把树深度转换为 512 个符号的码长。</summary>
    /// <param name="frequencies">包含最终结束符的频率表。</param>
    /// <returns>每个符号的位数，未使用符号为零。</returns>
    /// <remarks>
    /// 单个有效符号补一个虚拟叶，以满足完整前缀树。若偏斜树深超过线路允许的 15 位，
    /// 使用完整的 9 位字母表作为合法回退；距离和长度仍使用真实 LZ77 匹配，并非伪压缩。
    /// 优先级中的顺序号使相同频率的遍历结果确定。
    /// </remarks>
    private static byte[] BuildHuffmanLengths(int[] frequencies)
    {
        var queue = new PriorityQueue<int, (int Frequency, int Order)>();
        var nodes = new List<HuffmanNode>(1023); var order = 0;
        for (var symbol = 0; symbol < 512; symbol++)
            if (frequencies[symbol] != 0)
            {
                nodes.Add(new(symbol, -1, -1)); queue.Enqueue(nodes.Count - 1, (frequencies[symbol], order++));
            }
        if (queue.Count == 1)
        {
            var dummy = frequencies[0] == 0 ? 0 : 1;
            nodes.Add(new(dummy, -1, -1)); queue.Enqueue(nodes.Count - 1, (1, order++));
        }
        while (queue.Count > 1)
        {
            queue.TryDequeue(out var left, out var leftPriority); queue.TryDequeue(out var right, out var rightPriority);
            nodes.Add(new(-1, left, right));
            queue.Enqueue(nodes.Count - 1, (leftPriority.Frequency + rightPriority.Frequency, order++));
        }
        var lengths = new byte[512];
        var stack = new Stack<(int Node, int Depth)>(); stack.Push((queue.Dequeue(), 0));
        while (stack.TryPop(out var next))
        {
            var node = nodes[next.Node];
            if (node.Symbol >= 0) lengths[node.Symbol] = checked((byte)next.Depth);
            else { stack.Push((node.Left, next.Depth + 1)); stack.Push((node.Right, next.Depth + 1)); }
        }
        // 完整的 9 位字母表始终合法，可避免偏斜频率树生成超过线路上限 15 位的码字。
        // 回退后仍通过真实的 LZ77 匹配压缩数据，并非用原样数据伪装成压缩流。
        if (lengths.Any(length => length > 15)) Array.Fill(lengths, (byte)9);
        return lengths;
    }

    /// <summary>根据码长统计生成按位数、再按符号顺序排列的规范 Huffman 码。</summary>
    /// <param name="lengths">512 个合法码长。</param>
    /// <returns>与字母表同长的码字数组；码字低位保存有效位。</returns>
    /// <remarks>码长相同的符号连续分配，下一层在上一层计数后左移一位，保证压缩与解压一致。</remarks>
    private static uint[] BuildHuffmanCodes(ReadOnlySpan<byte> lengths)
    {
        Span<int> counts = stackalloc int[16];
        foreach (var length in lengths) if (length != 0) counts[length]++;
        Span<uint> next = stackalloc uint[16];
        uint code = 0;
        for (var length = 1; length < 16; length++) { code = (code + (uint)counts[length - 1]) << 1; next[length] = code; }
        var codes = new uint[512];
        for (var symbol = 0; symbol < 512; symbol++) if (lengths[symbol] != 0) codes[symbol] = next[lengths[symbol]]++;
        return codes;
    }

    /// <summary>构造 15 位直接查找表并逐块解码文字、重叠匹配和长长度扩展。</summary>
    /// <param name="input">MS-XCA Huffman 原始流。</param>
    /// <param name="output">已按声明限额分配的目标缓冲。</param>
    /// <exception cref="SmbProtocolException">码表不完整或超额、输入截断、非法引用或输出越界。</exception>
    /// <remarks>
    /// 表构建严格验证所有前缀槽恰好填满，避免未知码访问。每个普通块在 65536 字节边界结束；
    /// MS-XCA 允许最终预读或结束符区域不足一个码表时在输出完整后结束，不误判为新块。
    /// </remarks>
    private static void DecompressHuffman(ReadOnlySpan<byte> input, Span<byte> output)
    {
        var source = 0; var destination = 0;
        var lengths = new byte[512]; var decoding = new ushort[32768];
        while (true)
        {
            if (input.Length - source < 256)
            {
                // 按 MS-XCA 2.2.4，声明的输出已全部产生且剩余输入放不下新码表时，
                // 允许最后保留不足一张码表的预读或结束符区域，无须误报为截断的新块。
                if (destination == output.Length) return;
                throw Invalid("Truncated Huffman block header.");
            }
            for (var i = 0; i < 256; i++) { lengths[2 * i] = (byte)(input[source + i] & 15); lengths[2 * i + 1] = (byte)(input[source + i] >> 4); }
            source += 256;
            var entry = 0;
            for (var length = 1; length <= 15; length++)
                for (var symbol = 0; symbol < 512; symbol++) if (lengths[symbol] == length)
                {
                    var count = 1 << (15 - length);
                    if (entry > decoding.Length - count) throw Invalid("Oversubscribed Huffman alphabet.");
                    decoding.AsSpan(entry, count).Fill((ushort)symbol); entry += count;
                }
            if (entry != decoding.Length) throw Invalid("Incomplete Huffman alphabet.");
            var reader = new HuffmanReader(input, source);
            var blockEnd = checked(destination + 65536);
            while (destination < blockEnd)
            {
                var symbol = decoding[(int)(reader.NextBits >> 17)]; reader.Consume(lengths[symbol]);
                if (destination == output.Length)
                {
                    if (symbol == 256 && reader.Position == input.Length) return;
                    throw Invalid("Huffman data extends past its declared output.");
                }
                if (symbol < 256)
                {
                    Require(output.Length, destination, 1); output[destination++] = (byte)symbol;
                }
                else
                {
                    var match = symbol - 256;
                    var length = match & 15; var distanceBits = match >> 4;
                    if (length == 15)
                    {
                        length = reader.ReadByte();
                        if (length == 255)
                        {
                            length = reader.Read16();
                            if (length == 0)
                            {
                                var extended = reader.Read32();
                                if (extended > int.MaxValue - 3) throw Invalid("Oversized Huffman length.");
                                length = (int)extended;
                            }
                            if (length < 15) throw Invalid("Invalid Huffman match extension.");
                        }
                        else length += 15;
                    }
                    var distance = (1 << distanceBits) + (distanceBits == 0 ? 0 : (int)(reader.NextBits >> (32 - distanceBits)));
                    reader.Consume(distanceBits);
                    CopyMatch(output, ref destination, distance, checked(length + 3));
                }
                if (destination == output.Length && reader.Position == input.Length) return;
            }
            source = reader.Position;
        }
    }

    /// <summary>实现 MS-XCA 的双 16 位预留字及交错原始长度字节写入器。</summary>
    /// <remarks>每个调用只处理一个最多 64 KiB 的原始块，128 KiB 缓冲足以容纳最坏编码及码表。</remarks>
    private sealed class HuffmanWriter
    {
        /// <summary>包含前 256 字节码长表和后续交错位流的独立块缓冲。</summary>
        internal byte[] Data { get; } = new byte[128 * 1024];
        /// <summary>当前待填 16 位字还剩多少高到低的可写位。</summary>
        private int freeBits = 16;
        /// <summary>尚未写入预留位置的位累加器，最终只取低 16 位。</summary>
        private uint nextWord;
        /// <summary>下一次落盘的位字位置。</summary>
        private int position1 = 256;
        /// <summary>再下一个预留位字位置，使解码器始终能够预取 32 位。</summary>
        private int position2 = 258;
        /// <summary>额外长度字节或新的预留位字的追加位置。</summary>
        private int position = 260;
        /// <summary>按最高有效位在前追加码字，填满一个字时轮换两个预留位置。</summary>
        /// <param name="count">有效位数，最大为 Huffman 或距离位宽 15。</param>
        /// <param name="value">右对齐的有效位。</param>
        internal void WriteBits(int count, uint value)
        {
            if (freeBits >= count) { freeBits -= count; nextWord = (nextWord << count) | value; }
            else
            {
                nextWord = (nextWord << freeBits) | (value >> (count - freeBits));
                freeBits -= count;
                BinaryPrimitives.WriteUInt16LittleEndian(Data.AsSpan(position1), (ushort)nextWord);
                position1 = position2; position2 = position; position += 2;
                Require(Data.Length, position, 0); freeBits += 16; nextWord = value;
            }
        }
        /// <summary>在预留位字之后追加一个长匹配的额外长度字节。</summary>
        /// <param name="value">长度扩展字节。</param>
        internal void WriteByte(byte value) { Require(Data.Length, position, 1); Data[position++] = value; }
        /// <summary>在原始数据区追加一个小端 16 位长度扩展。</summary>
        /// <param name="value">长度扩展值；零表示还有 32 位扩展。</param>
        internal void Write16(ushort value) { Require(Data.Length, position, 2); BinaryPrimitives.WriteUInt16LittleEndian(Data.AsSpan(position), value); position += 2; }
        /// <summary>在原始数据区追加一个小端 32 位超长匹配长度。</summary>
        /// <param name="value">不截断的长度值。</param>
        internal void Write32(uint value) { Require(Data.Length, position, 4); BinaryPrimitives.WriteUInt32LittleEndian(Data.AsSpan(position), value); position += 4; }
        /// <summary>左对齐最后的有效位，清零第二个预留字，并截取实际编码长度。</summary>
        /// <returns>不共享可写工作缓冲的独立编码块。</returns>
        internal byte[] Finish()
        {
            nextWord <<= freeBits;
            BinaryPrimitives.WriteUInt16LittleEndian(Data.AsSpan(position1), (ushort)nextWord);
            BinaryPrimitives.WriteUInt16LittleEndian(Data.AsSpan(position2), 0);
            return Data.AsSpan(0, position).ToArray();
        }
    }

    /// <summary>按 16 位小端字预取并按高位消费的 Huffman 位流读取状态。</summary>
    /// <remarks>ref struct 限制了输入跨度的生命周期；原始长度字段必须从 Position 读取而不是从位寄存器提取。</remarks>
    private ref struct HuffmanReader
    {
        /// <summary>包含当前块及后续块的有界输入视图。</summary>
        private readonly ReadOnlySpan<byte> input;
        /// <summary>下一批最高位有效的码字和距离位。</summary>
        internal uint NextBits { get; private set; }
        /// <summary>已经预读的位字之后的位置，也是额外原始长度字段的读取位置。</summary>
        internal int Position { get; private set; }
        /// <summary>除高 16 位消费窗口外已经缓冲的可用位数。</summary>
        private int extraBits;
        /// <summary>验证并预读两个 16 位字，建立最少 16 位的额外缓冲。</summary>
        /// <param name="input">编码块视图。</param>
        /// <param name="position">码长表之后第一个位字的位置。</param>
        internal HuffmanReader(ReadOnlySpan<byte> input, int position)
        {
            this.input = input; Require(input.Length, position, 4);
            NextBits = ((uint)SmbCompressionCodec.Read16(input, position) << 16) | SmbCompressionCodec.Read16(input, position + 2);
            Position = position + 4; extraBits = 16;
        }
        /// <summary>消费高位并在必要时补读一个 16 位字；一次消费不超过 15 位。</summary>
        /// <param name="count">Huffman 码或距离的有效位数。</param>
        internal void Consume(int count)
        {
            if (count == 0) return;
            NextBits <<= count; extraBits -= count;
            if (extraBits < 0)
            {
                NextBits |= (uint)Read16() << -extraBits; extraBits += 16;
            }
        }
        /// <summary>有界读取一个交错存放的原始长度字节。</summary>
        /// <returns>字节值，并推进 Position。</returns>
        internal byte ReadByte() { Require(input.Length, Position, 1); return input[Position++]; }
        /// <summary>有界读取原始 16 位长度或待补入的位字。</summary>
        /// <returns>小端字段值，并推进 Position。</returns>
        internal ushort Read16() { var value = SmbCompressionCodec.Read16(input, Position); Position += 2; return value; }
        /// <summary>有界读取 32 位长长度扩展。</summary>
        /// <returns>小端字段值，并推进 Position。</returns>
        internal uint Read32() { var value = SmbCompressionCodec.Read32(input, Position); Position += 4; return value; }
    }
}