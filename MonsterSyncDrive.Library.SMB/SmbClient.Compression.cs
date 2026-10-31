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

/// <summary>提供会话当前通道的实际 SMB 压缩统计。</summary>
public sealed partial class SmbClient
{
    /// <summary>汇总当前仍由此会话持有的通道压缩统计，区分真实压缩消息和未压缩回退。</summary>
    /// <remarks>
    /// 未协商压缩的通道贡献零；已从通道列表移除的历史通道不再计入。
    /// 列表是一次通道快照，计数器按独立原子值读取，不能作为精确的传输记账事务。
    /// 接收算法集合表示真正解码过的算法，不能仅用协商列表证明服务器实际使用了某算法。
    /// </remarks>
    public SmbCompressionStatistics CompressionStatistics
    {
        get
        {
            long sent = 0, received = 0, originalSent = 0, compressedSent = 0, originalReceived = 0, compressedReceived = 0;
            HashSet<SmbCompressionAlgorithm> sentAlgorithms = [];
            HashSet<SmbCompressionAlgorithm> receivedAlgorithms = [];
            foreach (SmbConnection connection in SnapshotConnections())
            {
                if (connection.Compression is not { } compression)
                    continue;
                SmbCompressionStatistics current = compression.Statistics;
                sent += current.CompressedMessagesSent;
                received += current.CompressedMessagesReceived;
                originalSent += current.OriginalBytesSent;
                compressedSent += current.CompressedBytesSent;
                originalReceived += current.OriginalBytesReceived;
                compressedReceived += current.CompressedBytesReceived;
                sentAlgorithms.UnionWith(current.SentAlgorithms);
                receivedAlgorithms.UnionWith(current.ReceivedAlgorithms);
            }
            return new(sent, received, originalSent, compressedSent, originalReceived, compressedReceived,
                Array.AsReadOnly(sentAlgorithms.Order().ToArray()), Array.AsReadOnly(receivedAlgorithms.Order().ToArray()));
        }
    }
}