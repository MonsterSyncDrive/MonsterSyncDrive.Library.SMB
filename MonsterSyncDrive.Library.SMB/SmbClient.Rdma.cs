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
using System.Diagnostics.CodeAnalysis;
using MonsterSyncDrive.SMB.Protocol;

namespace MonsterSyncDrive.SMB;

/// <summary>客户端 RDMA 直接放置所需的通道固定选择，避免描述符跨队列对使用。</summary>
public sealed partial class SmbClient
{
    /// <summary>选择一次合格的 RDMA 通道；后续注册内存和发出请求必须固定到该连接，不能再次轮转。</summary>
    /// <param name="shareEncryptionRequired">共享是否强制加密；为真时只能使用受保护的常规传输。</param>
    /// <param name="selected">合格通道；找不到时为空。</param>
    /// <returns>是否存在允许直接放置的活动通道。</returns>
    internal bool TrySelectRdmaDirectPlacementConnection(bool shareEncryptionRequired,
        [NotNullWhen(true)] out SmbConnection? selected)
    {
        selected = null;
        if (shareEncryptionRequired) return false;
        ThrowIfDisposed();
        selected = SnapshotConnections().Where(channel => channel.CanUseRdmaDirectPlacement)
            .Select(channel => (Connection: channel, Pending: channel.PendingRequestCount))
            .OrderBy(channel => channel.Pending).Select(channel => channel.Connection).FirstOrDefault();
        return selected is not null;
    }
}