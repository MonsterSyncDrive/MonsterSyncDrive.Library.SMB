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
using System.Net;

namespace MonsterSyncDrive.Library.SMB.Transport;

/// <summary>将 MS-SMBD 连接适配为 SmbConnection 使用的 SMB 消息传输。</summary>
internal sealed class SmbDirectTransport : ISmbMessageTransport
{
    /// <summary>所拥有的直接连接，包含显式注册内存操作。</summary>
    internal SmbDirectConnection Connection
    {
        get;
    }
    /// <summary>报告实际的 MS-SMBD 传输类型，不受选用的原生提供程序影响。</summary>
    public SmbTransportKind Kind => SmbTransportKind.Rdma;
    // RDMA 的可靠性不等于密码学保护；SMB 签名和加密仍保持启用。
    /// <summary>返回假，因为 RDMA 的可靠性不是加密或端点认证。</summary>
    public bool IsSecure => false;
    /// <summary>实际的本地原生 RDMA 地址。</summary>
    public EndPoint? LocalEndPoint => Connection.LocalEndPoint;
    /// <summary>实际的远程原生 RDMA 地址。</summary>
    public EndPoint? RemoteEndPoint => Connection.RemoteEndPoint;
    /// <summary>协商得到的本地完整消息长度限制。</summary>
    public int MaximumMessageSize => Connection.MaximumFragmentedReceiveSize;
    /// <summary>取得已建立直接连接的所有权。</summary>
    private SmbDirectTransport(SmbDirectConnection connection)
    {
        Connection = connection;
    }

    /// <summary>开始 SMB 会话协商前，先连接并协商 RDMA 提供程序。</summary>
    internal static async Task<ISmbMessageTransport> ConnectAsync(string host, int port, SmbDirectOptions options,
        int maximumPacketSize, CancellationToken cancellationToken)
    {
        return new SmbDirectTransport(await SmbDirectConnection.ConnectAsync(host, port, options, maximumPacketSize, cancellationToken).ConfigureAwait(false));
    }

    /// <summary>通过 MS-SMBD 分片和流控发送一个 SMB 数据包。</summary>
    public ValueTask SendAsync(ReadOnlyMemory<byte> message, CancellationToken cancellationToken = default)
    {
        return Connection.SendAsync(message, cancellationToken: cancellationToken);
    }

    /// <summary>返回一个重组后的 SMB 数据包，排除独立的原生失效事件。</summary>
    public async ValueTask<byte[]> ReceiveAsync(CancellationToken cancellationToken = default)
    {
        // 空的 SEND_WITH_INVALIDATE 完成结果属于内存事件，不是 SMB 数据包。
        while (true)
        {
            SmbDirectMessage message = await Connection.ReceiveAsync(cancellationToken).ConfigureAwait(false);
            if (!message.Data.IsEmpty)
                return message.Data.ToArray();
        }
    }
    /// <summary>中止原生队列对，使未完成的数据包操作失败。</summary>
    public void Abort()
    {
        Connection.Abort();
    }

    /// <summary>等待工作任务结束，并释放底层原生端点。</summary>
    public ValueTask DisposeAsync()
    {
        return Connection.DisposeAsync();
    }
}