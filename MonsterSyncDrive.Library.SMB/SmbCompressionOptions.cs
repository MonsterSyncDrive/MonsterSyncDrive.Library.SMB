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

/// <summary>MS-SMB2 第 2.2.3.1.3 节分配的网络压缩算法标识。</summary>
/// <remarks>这些值是线路标识，不是 Windows Compression API 或 NTFS 的算法编号。</remarks>
public enum SmbCompressionAlgorithm : ushort
{
    /// <summary>未压缩的链式片段，或服务器明确表示没有共同压缩算法。</summary>
    None = 0,
    /// <summary>MS-XCA LZNT1，每个独立块最多展开为 4096 字节。</summary>
    Lznt1 = 1,
    /// <summary>MS-XCA Plain LZ77，也称 XPRESS，使用 32 位标志组和可变长度匹配。</summary>
    Lz77 = 2,
    /// <summary>MS-XCA LZ77 加规范 Huffman 编码，使用 512 个符号的逐块码表。</summary>
    Lz77Huffman = 3,
    /// <summary>链式变换中的单字节重复模式；不能单独用于非链式变换。</summary>
    PatternV1 = 4,
    /// <summary>LZ4 原始块格式，不包含 LZ4 frame 头或校验尾。</summary>
    Lz4 = 5
}

/// <summary>配置 SMB 3.1.1 网络消息压缩的协商算法、链式能力及发送阈值。</summary>
/// <remarks>
/// 默认关闭，只有连接双方成功协商后才使用。不能把此选项理解为 NTFS 文件压缩或强制每条消息压缩。
/// 发送方会比较包含变换头的最终长度，只有取得实际节省且满足阈值时才发送压缩消息。
/// </remarks>
public sealed record SmbCompressionOptions
{
    /// <summary>是否在 SMB 3.1.1 NEGOTIATE 中提供压缩能力；默认不提供。</summary>
    public bool Enabled
    {
        get; init;
    }
    /// <summary>按优先级排列的真实可用编解码器；连接前会复制为不可变列表。</summary>
    /// <remarks>不接受 None、未知值、重复值或空列表；PatternV1 要求允许链式压缩。</remarks>
    public IReadOnlyList<SmbCompressionAlgorithm> Algorithms
    {
        get; init;
    } =
        [SmbCompressionAlgorithm.PatternV1, SmbCompressionAlgorithm.Lz77, SmbCompressionAlgorithm.Lz77Huffman,
         SmbCompressionAlgorithm.Lznt1, SmbCompressionAlgorithm.Lz4];
    /// <summary>是否提供链式片段支持；实际启用需要服务器也返回该能力。</summary>
    public bool AllowChained { get; init; } = true;
    /// <summary>尝试压缩的最小原始 SMB 消息长度，包含 64 字节 SMB2 头，默认 1024 字节。</summary>
    public int MinimumMessageSize { get; init; } = 1024;
    /// <summary>包含所有变换头后至少节省的字节数，默认 32；零仍要求最终消息严格变短。</summary>
    public int MinimumSavingsBytes { get; init; } = 32;

    /// <summary>验证配置并复制算法列表，避免调用方修改集合改变活动连接的协商结果。</summary>
    /// <returns>字段相同、算法列表独立且只读的配置快照。</returns>
    /// <exception cref="ArgumentException">算法列表无效，或只提供 PatternV1 却禁止链式压缩。</exception>
    /// <exception cref="ArgumentOutOfRangeException">阈值超出 SMB Direct TCP 的 24 位长度范围。</exception>
    internal SmbCompressionOptions Snapshot()
    {
        ArgumentNullException.ThrowIfNull(Algorithms);
        SmbCompressionAlgorithm[] algorithms = Algorithms.ToArray();
        if (algorithms.Length is < 1 or > 5 || algorithms.Any(a => !Enum.IsDefined(a) || a == SmbCompressionAlgorithm.None) ||
            algorithms.Distinct().Count() != algorithms.Length)
            throw new ArgumentException("Compression offers must contain distinct, supported algorithms.", nameof(Algorithms));
        return !AllowChained && algorithms.All(a => a == SmbCompressionAlgorithm.PatternV1)
            ? throw new ArgumentException("Pattern compression requires chained compression.", nameof(Algorithms))
            : MinimumMessageSize < 64 || MinimumMessageSize > 0xFFFFFF || MinimumSavingsBytes < 0 || MinimumSavingsBytes > 0xFFFFFF
            ? throw new ArgumentOutOfRangeException(nameof(MinimumMessageSize))
            : (this with
            {
                Algorithms = Array.AsReadOnly(algorithms)
            });
    }
}