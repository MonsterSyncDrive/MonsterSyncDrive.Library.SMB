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
using System.Net;

namespace MonsterSyncDrive.Library.SMB.Transport;

/// <summary>在字节流分帧和 RDMA 分片之外，维持完整 SMB 消息的边界。</summary>
/// <remarks>实现负责持有其连接；部分 IO 完成后发生取消会使该传输连接失效。</remarks>
internal interface ISmbMessageTransport : IAsyncDisposable
{
    /// <summary>获取此连接实际采用的传输方式。</summary>
    SmbTransportKind Kind
    {
        get;
    }
    /// <summary>获取传输层本身是否对消息提供身份认证和加密保护。</summary>
    bool IsSecure
    {
        get;
    }
    /// <summary>获取已连接的本地网络端点；提供程序不公开该信息时可以为 null。</summary>
    EndPoint? LocalEndPoint
    {
        get;
    }
    /// <summary>获取已连接的远端端点，包括经过批准的 NetBIOS 重定向目标。</summary>
    EndPoint? RemoteEndPoint
    {
        get;
    }
    /// <summary>获取传输分帧机制所允许的最大 SMB 消息大小。</summary>
    int MaximumMessageSize
    {
        get;
    }
    /// <summary>发送恰好一条完整 SMB 消息，调用方无需提供传输前缀。</summary>
    /// <param name="message">已经完成签名、压缩或加密处理的 SMB 消息。</param>
    /// <param name="cancellationToken">用于取消完整帧写入的令牌。</param>
    /// <returns>在整条消息交给传输层之后完成的异步任务。</returns>
    ValueTask SendAsync(ReadOnlyMemory<byte> message, CancellationToken cancellationToken = default);
    /// <summary>接收一条完整 SMB 消息，仅移除传输层分帧信息。</summary>
    /// <param name="cancellationToken">用于取消完整帧接收的令牌。</param>
    /// <returns>新建且由调用方持有的消息缓冲区，供协议层进一步验证。</returns>
    ValueTask<byte[]> ReceiveAsync(CancellationToken cancellationToken = default);
    /// <summary>立即终止挂起的 IO；允许重复调用。</summary>
    void Abort();
}