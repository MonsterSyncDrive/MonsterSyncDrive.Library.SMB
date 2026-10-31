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
namespace MonsterSyncDrive.Library.SMB.Protocol.Compression;

/// <summary>实现 MS-SMB2 协商上下文及有界的链式、非链式压缩变换。</summary>
/// <remarks>
/// 本对象只处理 SMB2 明文消息。调用方应先签名、再压缩、最后加密；接收时以相反顺序处理。
/// 所有输出分配均先检查协商、线路长度、总长度及调用方限额，拒绝嵌套变换和解压缩炸弹。
/// </remarks>
internal sealed class SmbCompression
{
    /// <summary>独立于调用方集合的、经过验证的发送阈值和协商策略快照。</summary>
    private readonly SmbCompressionOptions options;
    /// <summary>当前连接共同协商的算法集合，用于每个接收片段的常数时间授权检查。</summary>
    private readonly HashSet<SmbCompressionAlgorithm> algorithms;
    /// <summary>已实际生成压缩变换的消息数，不包括没有节省的压缩尝试。</summary>
    private long compressedMessagesSent;
    /// <summary>已成功验证结构并解压的压缩变换消息数。</summary>
    private long compressedMessagesReceived;
    /// <summary>实际生成压缩变换之前的完整消息总字节数。</summary>
    private long originalBytesSent;
    /// <summary>实际生成的压缩变换总字节数。</summary>
    private long compressedBytesSent;
    /// <summary>成功解压后的消息总字节数。</summary>
    private long originalBytesReceived;
    /// <summary>成功解压之前的压缩变换总字节数。</summary>
    private long compressedBytesReceived;
    /// <summary>实际输出的非 NONE 算法位集合，以原子或运算累计。</summary>
    private int sentAlgorithmMask;
    /// <summary>成功解压的非 NONE 算法位集合，以原子或运算累计。</summary>
    private int receivedAlgorithmMask;
    /// <summary>按本客户端优先顺序排列的共同算法，只读且不暴露内部可变集合。</summary>
    internal IReadOnlyList<SmbCompressionAlgorithm> Algorithms
    {
        get;
    }
    /// <summary>双方均提供链式能力时为真，接收链式头和发送混合片段均依赖此值。</summary>
    internal bool SupportsChained
    {
        get;
    }

    /// <summary>读取此连接的实际压缩计数及使用过的算法集合，不把能力协商当成数据传输。</summary>
    internal SmbCompressionStatistics Statistics => new(
        Interlocked.Read(ref compressedMessagesSent), Interlocked.Read(ref compressedMessagesReceived),
        Interlocked.Read(ref originalBytesSent), Interlocked.Read(ref compressedBytesSent),
        Interlocked.Read(ref originalBytesReceived), Interlocked.Read(ref compressedBytesReceived),
        AlgorithmsFromMask(Volatile.Read(ref sentAlgorithmMask)), AlgorithmsFromMask(Volatile.Read(ref receivedAlgorithmMask)));

    /// <summary>保存已经核对的协商结果；调用方应通过 Negotiate 创建实例。</summary>
    /// <param name="options">已快照化的本地配置。</param>
    /// <param name="algorithms">双方共同算法，按本地优先顺序排列。</param>
    /// <param name="chained">是否共同允许链式片段。</param>
    private SmbCompression(SmbCompressionOptions options, SmbCompressionAlgorithm[] algorithms, bool chained)
    {
        this.options = options;
        this.algorithms = [.. algorithms];
        Algorithms = Array.AsReadOnly(algorithms);
        SupportsChained = chained;
    }

    /// <summary>编码压缩能力上下文的数据区；不包含 8 字节 NEGOTIATE_CONTEXT 包装头。</summary>
    /// <param name="options">本地压缩配置；必须显式启用。</param>
    /// <returns>算法数量、保留字段、链式标志及 16 位算法数组。</returns>
    /// <exception cref="ArgumentException">配置无效或压缩未启用。</exception>
    internal static byte[] BuildNegotiateContext(SmbCompressionOptions options)
    {
        options = options.Snapshot();
        if (!options.Enabled)
            throw new ArgumentException("Compression is disabled.", nameof(options));
        byte[] result = new byte[8 + (options.Algorithms.Count * 2)];
        Wire.Put16(result, 0, checked((ushort)options.Algorithms.Count));
        Wire.Put32(result, 4, options.AllowChained ? 1u : 0);
        for (int i = 0; i < options.Algorithms.Count; i++)
            Wire.Put16(result, 8 + (i * 2), (ushort)options.Algorithms[i]);
        return result;
    }

    /// <summary>核对服务器返回的压缩能力，并建立本连接的变换处理器。</summary>
    /// <param name="options">原始客户端提议的配置快照。</param>
    /// <param name="serverContext">服务器类型 3 上下文的数据区，不含外层包装头。</param>
    /// <returns>共同能力处理器；服务器只选择 None 时返回空。</returns>
    /// <exception cref="SmbProtocolException">服务器提议未提供的算法、重复项、畸形长度或无效链式组合。</exception>
    internal static SmbCompression? Negotiate(SmbCompressionOptions options, ReadOnlySpan<byte> serverContext)
    {
        options = options.Snapshot();
        if (!options.Enabled)
            throw Invalid("The server returned unrequested compression capabilities.");
        if (serverContext.Length < 10)
            throw Invalid("Truncated compression capabilities.");
        ushort count = Wire.U16(serverContext, 0);
        uint flags = Wire.U32(serverContext, 4);
        if (count == 0 || count > 6 || serverContext.Length != 8 + (count * 2) || (flags & ~1u) != 0)
            throw Invalid("Invalid compression capabilities.");
        HashSet<SmbCompressionAlgorithm> server = new();
        for (int i = 0; i < count; i++)
        {
            SmbCompressionAlgorithm algorithm = (SmbCompressionAlgorithm)Wire.U16(serverContext, 8 + (i * 2));
            if (!server.Add(algorithm) || !Enum.IsDefined(algorithm) ||
                (algorithm != SmbCompressionAlgorithm.None && !options.Algorithms.Contains(algorithm)))
                throw Invalid("The server selected an unoffered or duplicate compression algorithm.");
        }
        var selected = options.Algorithms.Where(server.Contains).ToArray();
        if (selected.Length == 0)
            return null;
        bool chained = options.AllowChained && (flags & 1) != 0;
        return !chained && selected.All(a => a == SmbCompressionAlgorithm.PatternV1)
            ? throw Invalid("The server selected pattern compression without chained compression.")
            : new SmbCompression(options, selected, chained);
    }

    /// <summary>仅检查 FC SMB 魔数；后续解码仍必须验证协商、完整头部和输出大小。</summary>
    /// <param name="packet">不含传输层长度前缀的消息。</param>
    /// <returns>消息以压缩变换标识开始时为真。</returns>
    internal static bool IsCompressed(ReadOnlySpan<byte> packet)
    {
        return packet.Length >= 4 && packet[..4].SequenceEqual(new byte[] { 0xFC, 0x53, 0x4D, 0x42 });
    }

    /// <summary>按共同能力压缩一条已签名或将被加密的 SMB2 消息。</summary>
    /// <param name="packet">完整 FE SMB 消息；不能是另一个压缩或加密变换。</param>
    /// <param name="uncompressedPrefixLength">必须原样保留的前导字节数，默认压缩整个消息。</param>
    /// <returns>节省达到阈值的压缩消息，或内容相同的独立未压缩副本。</returns>
    /// <exception cref="SmbProtocolException">输入不是完整的 SMB2 消息。</exception>
    /// <exception cref="ArgumentOutOfRangeException">前导长度超出输入。</exception>
    internal byte[] Compress(ReadOnlySpan<byte> packet, int uncompressedPrefixLength = 0)
    {
        ValidateSmbMessage(packet);
        if (uncompressedPrefixLength < 0 || uncompressedPrefixLength > packet.Length)
            throw new ArgumentOutOfRangeException(nameof(uncompressedPrefixLength));
        if (packet.Length < options.MinimumMessageSize || uncompressedPrefixLength == packet.Length)
            return packet.ToArray();
        byte[] compressed = SupportsChained ? CompressChained(packet, uncompressedPrefixLength) : CompressUnchained(packet, uncompressedPrefixLength);
        if (compressed.Length >= packet.Length || packet.Length - compressed.Length < options.MinimumSavingsBytes)
            return packet.ToArray();
        _ = Interlocked.Add(ref originalBytesSent, packet.Length);
        _ = Interlocked.Add(ref compressedBytesSent, compressed.Length);
        _ = Interlocked.Or(ref sentAlgorithmMask, UsedAlgorithmMask(compressed));
        _ = Interlocked.Increment(ref compressedMessagesSent);
        return compressed;
    }

    /// <summary>构造非链式头，并保留 Offset 指定的明文字节。</summary>
    /// <param name="packet">待压缩的完整 SMB2 消息。</param>
    /// <param name="prefixLength">前导未压缩长度。</param>
    /// <returns>带 16 字节非链式头的候选消息；调用方负责最终节省比较。</returns>
    /// <remarks>OriginalCompressedSegmentSize 只计算尾部压缩片段，不能把 Offset 再计入该字段。</remarks>
    private byte[] CompressUnchained(ReadOnlySpan<byte> packet, int prefixLength)
    {
        var algorithm = Algorithms.First(a => a != SmbCompressionAlgorithm.PatternV1);
        byte[] encoded = SmbCompressionCodec.Compress(algorithm, packet[prefixLength..]);
        byte[] output = new byte[checked(16 + prefixLength + encoded.Length)];
        WriteProtocolId(output);
        Wire.Put32(output, 4, (uint)(packet.Length - prefixLength));
        Wire.Put16(output, 8, (ushort)algorithm);
        Wire.Put32(output, 12, (uint)prefixLength);
        packet[..prefixLength].CopyTo(output.AsSpan(16));
        encoded.CopyTo(output, 16 + prefixLength);
        return output;
    }

    /// <summary>把消息拆为原样、编码块与单字节重复片段，并构造链式变换。</summary>
    /// <param name="packet">完整 SMB2 消息。</param>
    /// <param name="prefixLength">首个 NONE 片段保留的前导长度。</param>
    /// <returns>包含总展开长度和逐片段大小的候选消息。</returns>
    /// <remarks>重复扫描为线性复杂度；只扫描协商了 PatternV1 的连接，避免虚报算法能力。</remarks>
    private byte[] CompressChained(ReadOnlySpan<byte> packet, int prefixLength)
    {
        List<byte> result = new();
        result.AddRange(new byte[] { 0xFC, 0x53, 0x4D, 0x42 });
        Append32(result, (uint)packet.Length);
        if (prefixLength != 0)
            AppendPayload(result, SmbCompressionAlgorithm.None, packet[..prefixLength], 0);
        int position = prefixLength;
        while (position < packet.Length)
        {
            var (patternStart, patternLength) = algorithms.Contains(SmbCompressionAlgorithm.PatternV1)
                ? FindPattern(packet, position) : (packet.Length, 0);
            if (patternStart > position)
            {
                var plain = packet[position..patternStart];
                var algorithm = Algorithms.FirstOrDefault(a => a != SmbCompressionAlgorithm.PatternV1);
                byte[] encoded = algorithm != SmbCompressionAlgorithm.None && plain.Length > 1024
                    ? SmbCompressionCodec.Compress(algorithm, plain) : [];
                if (encoded.Length != 0 && encoded.Length + 4 < plain.Length)
                    AppendPayload(result, algorithm, encoded, plain.Length);
                else
                    AppendPayload(result, SmbCompressionAlgorithm.None, plain, 0);
                position = patternStart;
            }
            if (patternLength > 0)
            {
                byte[] pattern = new byte[8];
                pattern[0] = packet[position];
                Wire.Put32(pattern, 4, (uint)patternLength);
                AppendPayload(result, SmbCompressionAlgorithm.PatternV1, pattern, 0);
                position += patternLength;
            }
        }
        return result.ToArray();
    }

    /// <summary>定位下一个超过 32 字节的相同字节游程。</summary>
    /// <param name="packet">原始消息。</param>
    /// <param name="position">扫描起点。</param>
    /// <returns>游程位置和长度；不存在时位置为消息末尾、长度为零。</returns>
    private static (int Start, int Length) FindPattern(ReadOnlySpan<byte> packet, int position)
    {
        while (position < packet.Length)
        {
            int end = position + 1;
            while (end < packet.Length && packet[end] == packet[position])
                end++;
            if (end - position > 32)
                return (position, end - position);
            position = end;
        }
        return (packet.Length, 0);
    }

    /// <summary>添加一个链式片段，第一片段设置 CHAINED，后续片段清除该标志。</summary>
    /// <param name="result">已经包含 8 字节总头的目标缓冲。</param>
    /// <param name="algorithm">该片段的算法，NONE 和 PatternV1 不带额外原始大小字段。</param>
    /// <param name="payload">原样字节、模式结构或算法编码数据。</param>
    /// <param name="originalSize">普通压缩块的展开大小；NONE 和模式为零。</param>
    private static void AppendPayload(List<byte> result, SmbCompressionAlgorithm algorithm, ReadOnlySpan<byte> payload, int originalSize)
    {
        Append16(result, (ushort)algorithm);
        Append16(result, result.Count == 10 ? (ushort)1 : (ushort)0);
        Append32(result, checked((uint)(payload.Length + (originalSize == 0 ? 0 : 4))));
        if (originalSize != 0)
            Append32(result, (uint)originalSize);
        foreach (byte value in payload)
            result.Add(value);
    }

    /// <summary>先验证协商和输出限额，再解码一条压缩变换消息。</summary>
    /// <param name="packet">不含传输前缀、已经完成外层解密的 FC SMB 消息。</param>
    /// <param name="maximumSize">该连接允许分配的最大完整 SMB 消息长度。</param>
    /// <returns>完整 FE SMB 消息，供调用方继续检查会话、请求及签名。</returns>
    /// <exception cref="SmbProtocolException">尺寸溢出、算法未协商、片段畸形、解码失败或输出不是 SMB2 消息。</exception>
    internal byte[] Decompress(ReadOnlySpan<byte> packet, int maximumSize)
    {
        try
        {
            if (!IsCompressed(packet) || packet.Length < 16 || maximumSize < 64)
                throw Invalid("Invalid SMB compression transform.");
            ushort flags = Wire.U16(packet, 10);
            byte[] result = flags switch
            {
                0 => DecompressUnchained(packet, maximumSize),
                1 when SupportsChained => DecompressChained(packet, maximumSize),
                _ => throw Invalid("Unnegotiated compression transform flags.")
            };
            ValidateSmbMessage(result);
            _ = Interlocked.Add(ref originalBytesReceived, result.Length);
            _ = Interlocked.Add(ref compressedBytesReceived, packet.Length);
            _ = Interlocked.Or(ref receivedAlgorithmMask, UsedAlgorithmMask(packet));
            _ = Interlocked.Increment(ref compressedMessagesReceived);
            return result;
        }
        catch (OverflowException ex)
        {
            throw new SmbProtocolException("Compression size overflow.", ex);
        }
    }

    /// <summary>使用经过核对的 Offset 和片段大小重建非链式消息。</summary>
    /// <param name="packet">至少含 16 字节变换头的消息。</param>
    /// <param name="maximumSize">总输出限额。</param>
    /// <returns>前导字节与解码尾部的拼接结果。</returns>
    /// <remarks>以 64 位无符号算术核对 Offset 加片段长度，避免加法回绕后分配小缓冲。</remarks>
    private byte[] DecompressUnchained(ReadOnlySpan<byte> packet, int maximumSize)
    {
        uint original = Wire.U32(packet, 4);
        uint offset = Wire.U32(packet, 12);
        ulong total = checked((ulong)original + offset);
        if (original == 0 || total < 64 || total > (ulong)maximumSize || total > 0xFFFFFF || offset > packet.Length - 16)
            throw Invalid("Invalid unchained compression sizes.");
        SmbCompressionAlgorithm algorithm = (SmbCompressionAlgorithm)Wire.U16(packet, 8);
        if (algorithm is SmbCompressionAlgorithm.None or SmbCompressionAlgorithm.PatternV1 || !algorithms.Contains(algorithm))
            throw Invalid("Unnegotiated unchained compression algorithm.");
        byte[] decoded = SmbCompressionCodec.Decompress(algorithm, packet[(16 + (int)offset)..], (int)original);
        byte[] result = new byte[(int)total];
        packet.Slice(16, (int)offset).CopyTo(result);
        decoded.CopyTo(result, (int)offset);
        return result;
    }

    /// <summary>按片段顺序重建链式消息，逐个限制其写入剩余输出范围。</summary>
    /// <param name="packet">带 CHAINED 标志的变换。</param>
    /// <param name="maximumSize">总输出限额。</param>
    /// <returns>与声明总大小严格一致的消息。</returns>
    /// <remarks>每次至少消费一个完整片段头，允许空的原样片段；拒绝重复首段标志、模式重复量越界以及解码长度不符。</remarks>
    private byte[] DecompressChained(ReadOnlySpan<byte> packet, int maximumSize)
    {
        uint original = Wire.U32(packet, 4);
        if (original < 64 || original > maximumSize || original > 0xFFFFFF)
            throw Invalid("Invalid chained output size.");
        byte[] output = new byte[(int)original];
        int source = 8;
        int destination = 0;
        while (source < packet.Length)
        {
            if (source > packet.Length - 8)
                throw Invalid("Truncated chained payload header.");
            SmbCompressionAlgorithm algorithm = (SmbCompressionAlgorithm)Wire.U16(packet, source);
            ushort flags = Wire.U16(packet, source + 2);
            uint length = Wire.U32(packet, source + 4);
            if (flags != (source == 8 ? 1 : 0) || length > packet.Length - source - 8 ||
                (algorithm != SmbCompressionAlgorithm.None && !algorithms.Contains(algorithm)))
                throw Invalid("Invalid or unnegotiated chained payload.");
            source += 8;
            var payload = packet.Slice(source, (int)length);
            source += (int)length;
            int count;
            if (algorithm == SmbCompressionAlgorithm.None)
            {
                count = payload.Length;
                if (count > output.Length - destination)
                    throw Invalid("Chained output exceeds its declared size.");
                payload.CopyTo(output.AsSpan(destination));
            }
            else if (algorithm == SmbCompressionAlgorithm.PatternV1)
            {
                if (payload.Length != 8)
                    throw Invalid("Invalid pattern payload size.");
                uint repetitions = Wire.U32(payload, 4);
                if (repetitions > output.Length - destination)
                    throw Invalid("Pattern exceeds its declared output size.");
                count = (int)repetitions;
                output.AsSpan(destination, count).Fill(payload[0]);
            }
            else
            {
                if (payload.Length < 4)
                    throw Invalid("Truncated chained compressed payload.");
                uint declared = Wire.U32(payload, 0);
                if (declared > output.Length - destination)
                    throw Invalid("Chained payload exceeds its declared output size.");
                count = (int)declared;
                byte[] decoded = SmbCompressionCodec.Decompress(algorithm, payload[4..], count);
                decoded.CopyTo(output, destination);
            }
            destination += count;
        }
        return destination != output.Length ? throw Invalid("Chained compression output size mismatch.") : output;
    }

    /// <summary>从已经验证过的压缩变换提取实际使用的非 NONE 算法位集合。</summary>
    /// <param name="packet">结构已经通过解码或由本对象生成的压缩变换。</param>
    /// <returns>以线路算法编号为位索引的集合。</returns>
    /// <remarks>仅遍历有界片段头，不检查数据内容；不把全 NONE 包装、零重复模式或零展开长度算作算法使用。</remarks>
    private static int UsedAlgorithmMask(ReadOnlySpan<byte> packet)
    {
        if (Wire.U16(packet, 10) == 0)
            return 1 << Wire.U16(packet, 8);
        int mask = 0;
        for (int offset = 8; offset < packet.Length;)
        {
            ushort algorithm = Wire.U16(packet, offset);
            if (algorithm != 0 && Wire.U32(packet, offset + (algorithm == (ushort)SmbCompressionAlgorithm.PatternV1 ? 12 : 8)) != 0)
                mask |= 1 << algorithm;
            offset = checked(offset + 8 + (int)Wire.U32(packet, offset + 4));
        }
        return mask;
    }

    /// <summary>把原子算法位集合转换成独立的只读列表。</summary>
    /// <param name="mask">实际使用的算法位集合。</param>
    /// <returns>按线路编号排序、不含 NONE 的算法列表。</returns>
    private static IReadOnlyList<SmbCompressionAlgorithm> AlgorithmsFromMask(int mask)
    {
        List<SmbCompressionAlgorithm> values = new(5);
        for (int value = 1; value <= 5; value++)
            if ((mask & (1 << value)) != 0)
                values.Add((SmbCompressionAlgorithm)value);
        return values.AsReadOnly();
    }

    /// <summary>要求至少 64 字节并具有 FE SMB 头，防止嵌套压缩或嵌套加密变换。</summary>
    /// <param name="packet">待核对消息。</param>
    /// <exception cref="SmbProtocolException">魔数或最小长度不符。</exception>
    private static void ValidateSmbMessage(ReadOnlySpan<byte> packet)
    {
        if (packet.Length < 64 || !packet[..4].SequenceEqual(new byte[] { 0xFE, 0x53, 0x4D, 0x42 }))
            throw Invalid("Compression must contain exactly an SMB2 message, not another transform.");
    }
    /// <summary>写入压缩变换的 FC SMB 魔数。</summary>
    /// <param name="output">至少 4 字节的目标缓冲。</param>
    private static void WriteProtocolId(Span<byte> output)
    {
        new byte[] { 0xFC, 0x53, 0x4D, 0x42 }.CopyTo(output);
    }

    /// <summary>按线路小端顺序添加 16 位字段。</summary>
    /// <param name="output">目标缓冲。</param>
    /// <param name="value">字段值。</param>
    private static void Append16(List<byte> output, ushort value)
    {
        output.Add((byte)value);
        output.Add((byte)(value >> 8));
    }
    /// <summary>按线路小端顺序添加 32 位字段。</summary>
    /// <param name="output">目标缓冲。</param>
    /// <param name="value">字段值。</param>
    private static void Append32(List<byte> output, uint value)
    {
        output.Add((byte)value);
        output.Add((byte)(value >> 8));
        output.Add((byte)(value >> 16));
        output.Add((byte)(value >> 24));
    }
    /// <summary>为畸形网络压缩数据创建统一的协议异常。</summary>
    /// <param name="message">不含凭据的诊断信息。</param>
    /// <returns>供调用方抛出的异常。</returns>
    private static SmbProtocolException Invalid(string message)
    {
        return new(message);
    }
}