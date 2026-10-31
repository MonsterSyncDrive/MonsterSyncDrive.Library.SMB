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


/// <summary>客户端的应用级调度、流量统计和传输尺寸内部入口。</summary>
public sealed partial class SmbClient
{

    /// <summary>本逻辑客户端所有通道共享的调度器、数据限速器和计数器。</summary>
    internal SmbQosState QosState => connection.QosState;

    /// <summary>主通道是否协商了 Large MTU，可用于允许超过一个 credit 的显式事务。</summary>
    internal bool SupportsMultiCredit => connection.LargeMtu;

    /// <summary>主传输允许的消息上限，含协议头；NetBIOS 的上限小于 Direct TCP。</summary>
    internal int MaximumTransportMessageSize => connection.MaximumMessageSize;

    /// <summary>返回已确认文件数据量和当前调度队列的线程安全快照，不包含协议头流量。</summary>
    public SmbQosStatistics QosStatistics => QosState.Snapshot();
}