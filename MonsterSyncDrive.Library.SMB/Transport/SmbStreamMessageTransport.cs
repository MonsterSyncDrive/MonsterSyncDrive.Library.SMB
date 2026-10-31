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

/// <summary>为 Direct TCP、RFC 1002 会话及单条 QUIC 字节流提供共用的分帧实现。</summary>
internal sealed class SmbStreamMessageTransport : ISmbMessageTransport
{
    /// <summary>已经连接的 TCP 或 QUIC 字节流；此处不解释 SMB 协议头。</summary>
    private readonly Stream stream;
    /// <summary>异步释放字节流及其所属连接的回调。</summary>
    private readonly Func<ValueTask> disposeOwner;
    /// <summary>无法继续信任帧边界时，中断所属传输连接的回调。</summary>
    private readonly Action abortOwner;
    /// <summary>防止并发写入将长度前缀和消息正文交错的写入门锁。</summary>
    private readonly SemaphoreSlim writeGate = new(1, 1);
    /// <summary>确保只有一个接收者维护字节流分帧状态的读取门锁。</summary>
    private readonly SemaphoreSlim readGate = new(1, 1);
    /// <summary>以原子方式记录 IO 是否已经中止或请求了释放。</summary>
    private int disposed;
    /// <summary>获取决定此字节流分帧限制的传输方式。</summary>
    public SmbTransportKind Kind
    {
        get;
    }
    /// <summary>获取此字节流是否受到 QUIC 身份认证和 TLS 加密保护。</summary>
    public bool IsSecure => Kind == SmbTransportKind.Quic;
    /// <summary>获取操作系统实际绑定的本地端点。</summary>
    public EndPoint? LocalEndPoint
    {
        get;
    }
    /// <summary>获取经过地址竞速或重定向后实际连接的远端端点。</summary>
    public EndPoint? RemoteEndPoint
    {
        get;
    }
    /// <summary>获取配置的帧长度上限，并限制在 NetBIOS 的 17 位或普通字节流的 24 位范围内。</summary>
    public int MaximumMessageSize
    {
        get;
    }

    /// <summary>封装已经建立的会话，不启动第二个读取循环。</summary>
    /// <param name="stream">已经建立连接的传输字节流。</param>
    /// <param name="kind">分帧和安全模型。</param>
    /// <param name="maximum">配置的最大消息大小。</param>
    /// <param name="local">本地端点元数据。</param>
    /// <param name="remote">远端端点元数据。</param>
    /// <param name="abortOwner">用于同步中断活动 IO 的回调。</param>
    /// <param name="disposeOwner">用于幂等异步释放所属连接的回调。</param>
    internal SmbStreamMessageTransport(Stream stream, SmbTransportKind kind, int maximum, EndPoint? local, EndPoint? remote,
        Action abortOwner, Func<ValueTask> disposeOwner)
    {
        this.stream = stream;
        Kind = kind;
        MaximumMessageSize = Math.Min(maximum, kind == SmbTransportKind.NetBios ? 0x1FFFF : 0xFFFFFF);
        LocalEndPoint = local;
        RemoteEndPoint = remote;
        this.abortOwner = abortOwner;
        this.disposeOwner = disposeOwner;
    }

    /// <summary>在同一写入门锁内写入长度前缀和消息正文。</summary>
    /// <param name="message">包含四字节协议标识符的完整 SMB 消息。</param>
    /// <param name="cancellationToken">用于取消门锁等待及字节流写入的令牌。</param>
    /// <returns>完整帧写入之后完成的异步任务。</returns>
    /// <exception cref="ArgumentOutOfRangeException">消息大小超过分帧机制允许的上限。</exception>
    public async ValueTask SendAsync(ReadOnlyMemory<byte> message, CancellationToken cancellationToken = default)
    {
        ObjectDisposedException.ThrowIf(Volatile.Read(ref disposed) != 0, this);
        if (message.Length < 4 || message.Length > MaximumMessageSize)
            throw new ArgumentOutOfRangeException(nameof(message));
        await writeGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            // NetBIOS 仅使用字节 1 的最低位作为第十七个长度位；上述大小限制
            // 保证共用的前缀布局不会设置其他保留标志。
            byte[] header = new byte[] { 0, (byte)(message.Length >> 16), (byte)(message.Length >> 8), (byte)message.Length };
            await stream.WriteAsync(header, cancellationToken).ConfigureAwait(false);
            await stream.WriteAsync(message, cancellationToken).ConfigureAwait(false);
        }
        catch
        {
            Abort();
            throw;
        }
        finally
        {
            _ = writeGate.Release();
        }
    }

    /// <summary>读取有大小上限的完整帧，并消费传输层保活消息。</summary>
    /// <param name="cancellationToken">用于取消等待和全部读取操作的令牌。</param>
    /// <returns>新建且不含传输前缀的消息缓冲区。</returns>
    /// <exception cref="SmbProtocolException">对端发送了无效的标志、类型或帧长度。</exception>
    public async ValueTask<byte[]> ReceiveAsync(CancellationToken cancellationToken = default)
    {
        ObjectDisposedException.ThrowIf(Volatile.Read(ref disposed) != 0, this);
        await readGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            byte[] header = new byte[4];
            while (true)
            {
                await stream.ReadExactlyAsync(header, cancellationToken).ConfigureAwait(false);
                int length = (header[1] << 16) | (header[2] << 8) | header[3];
                if (header[0] == 0x85 && length == 0 && Kind != SmbTransportKind.Quic)
                    continue;
                // 压缩 SMB 消息可能小于未压缩消息的 64 字节协议头；
                // 此层仅检查分帧。连接层会先解码变换格式，
                // 再验证完整 SMB2 协议头及其签名。
                if (header[0] != 0 || length < 4 || length > MaximumMessageSize || (Kind == SmbTransportKind.NetBios && (header[1] & 0xFE) != 0))
                    throw new SmbProtocolException("Invalid SMB transport message header or length.");
                byte[] message = new byte[length];
                await stream.ReadExactlyAsync(message, cancellationToken).ConfigureAwait(false);
                return message;
            }
        }
        catch
        {
            Abort();
            throw;
        }
        finally
        {
            _ = readGate.Release();
        }
    }

    /// <summary>仅中断当前 IO 一次，并保留门锁供尚未结束的调用清理状态。</summary>
    public void Abort()
    {
        if (Interlocked.Exchange(ref disposed, 1) == 0)
            abortOwner();
    }

    /// <summary>中断挂起的 IO，并异步释放全部所属传输资源。</summary>
    /// <returns>连接资源全部释放之后完成的异步任务。</returns>
    public async ValueTask DisposeAsync()
    {
        Abort();
        await disposeOwner().ConfigureAwait(false);
    }
}