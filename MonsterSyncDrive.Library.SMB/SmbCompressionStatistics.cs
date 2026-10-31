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

/// <summary>活动通道实际生成及成功解压的 SMB 压缩变换统计快照。</summary>
/// <param name="CompressedMessagesSent">已经生成供发送的 FC SMB 消息数；不表示远端已确认收到。</param>
/// <param name="CompressedMessagesReceived">成功解压并通过 SMB2 魔数和长度检查的 FC SMB 消息数。</param>
/// <param name="OriginalBytesSent">上述待发送消息压缩前的总字节数，包含其 SMB2 头。</param>
/// <param name="CompressedBytesSent">上述压缩消息的总字节数，包含压缩头，不含加密头及传输前缀。</param>
/// <param name="OriginalBytesReceived">成功解压消息的展开字节数。</param>
/// <param name="CompressedBytesReceived">成功解压消息原来的压缩字节数，不含外层加密及传输包装。</param>
/// <param name="SentAlgorithms">实际生成的片段中出现过的非 NONE 算法，按线路编号排序。</param>
/// <param name="ReceivedAlgorithms">成功解压片段中出现过的非 NONE 算法，按线路编号排序。</param>
/// <remarks>
/// 配置 Enabled、成功协商、尝试压缩或未压缩回退均不会直接增加计数。
/// 接收统计发生在解压后、调用方随后核对 SMB 会话和签名之前，不代表所有消息已被业务层接受。
/// 各计数器独立原子读取，允许并发操作期间快照的各字段来自略有差异的时刻。
/// </remarks>
public sealed record SmbCompressionStatistics(
    long CompressedMessagesSent, long CompressedMessagesReceived,
    long OriginalBytesSent, long CompressedBytesSent,
    long OriginalBytesReceived, long CompressedBytesReceived,
    IReadOnlyList<SmbCompressionAlgorithm> SentAlgorithms,
    IReadOnlyList<SmbCompressionAlgorithm> ReceivedAlgorithms);