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
using System.Diagnostics.CodeAnalysis;

namespace MonsterSyncDrive.Library.SMB;

/// <summary>文件句柄的 SMB3 RDMA 直接放置路径；安全保护或传输条件不满足时继续使用普通消息传输。</summary>
public sealed partial class SmbFileHandle
{
    /// <summary>选择并固定单个可直接放置的通道，防止把注册在一个队列对上的描述符发送到另一个通道。</summary>
    /// <param name="count">已经过普通读写及无缓冲对齐检查的数据长度。</param>
    /// <param name="write">为真时服务端读取本地源缓冲区；否则服务端写入本地目标缓冲区。</param>
    /// <param name="selected">固定的 SMB 通道。</param>
    /// <param name="direct">该通道实际使用的 MS-SMBD 连接。</param>
    /// <returns>是否满足设备、长度和会话安全策略。</returns>
    private bool TrySelectRdmaIo(int count, bool write, [NotNullWhen(true)] out SmbConnection? selected,
        [NotNullWhen(true)] out SmbDirectConnection? direct)
    {
        selected = null;
        direct = null;
        if (!Share.IsDiskShare || !Share.Client.TrySelectRdmaDirectPlacementConnection(Share.EncryptionRequired, out SmbConnection? candidate))
            return false;
        SmbDirectConnection? rdma = candidate.DirectConnection;
        if (rdma is null || !rdma.DirectPlacementEnabled || count <= rdma.DirectPlacementThreshold || count > rdma.MaximumReadWriteSize ||
            (write ? !rdma.SupportsRemoteRead : !rdma.SupportsRemoteWrite))
            return false;
        selected = candidate;
        direct = rdma;
        return true;
    }

    /// <summary>通过 V1 通道描述符读取文件；收到完整 SMB 回复并注销内存后才向调用者报告完成。</summary>
    /// <remarks>
    /// 未协商 RDMA 变换时不能绕过签名或加密。合格通道已经由客户端排除了这些情况。
    /// 取消已经发出的请求时，普通 SMB CANCEL 可能早于服务端最终回复，因此先关闭并排空固定通道，
    /// 再释放注册缓冲区，避免服务端随后继续 DMA 到已归还或移动的托管内存。
    /// </remarks>
    /// <param name="buffer">本次注册的完整目标范围。</param>
    /// <param name="offset">文件内偏移。</param>
    /// <param name="connection">发出请求的固定 SMB 通道。</param>
    /// <param name="direct">与注册内存相同的 RDMA 队列对。</param>
    /// <param name="cancellationToken">取消本次读取。</param>
    /// <returns>服务端在 DataRemaining 中确认的实际读取字节数。</returns>
    private async ValueTask<int> ReadRdmaAsync(Memory<byte> buffer, long offset, SmbConnection connection,
        SmbDirectConnection direct, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        SmbRdmaMemoryRegistration registration = await direct.RegisterBufferAsync(buffer, SmbRdmaMemoryAccess.RemoteWrite, cancellationToken).ConfigureAwait(false);
        bool requestStarted = false;
        int count = 0;
        try
        {
            // 异常处理先结束固定通道，最后再注销内存，不能让隐式释放先于硬件栅栏。
            byte[] descriptors = EncodeRdmaDescriptors(registration);
            byte[] body = new byte[48 + descriptors.Length];
            Wire.Put16(body, 0, 49);
            Wire.Put32(body, 4, (uint)buffer.Length);
            Wire.PutI64(body, 8, offset);
            Id.Write(body, 16);
            Wire.Put32(body, 36, 1); // SMB2_CHANNEL_RDMA_V1，不请求提供程序尚未承诺支持的远程失效。
            Wire.Put32(body, 40, (uint)buffer.Length);
            Wire.Put16(body, 44, 112);
            Wire.Put16(body, 46, (ushort)descriptors.Length);
            descriptors.CopyTo(body, 48);
            cancellationToken.ThrowIfCancellationRequested();
            requestStarted = true;
            Response response = await connection.SendAsync(Command.Read, body, Share.TreeId, cancellationToken, buffer.Length).ConfigureAwait(false);
            response.EnsureSuccess(SmbStatus.EndOfFile, SmbStatus.BufferOverflow);
            if (response.Status != SmbStatus.EndOfFile)
            {
                Wire.Structure(response.Packet, 17, 16);
                uint placed = Wire.U32(response.Packet, 72);
                // V1 的实际数据已经由设备写入注册范围；不能把内联 DataLength 当成完成长度。
                if (Wire.U32(response.Packet, 68) != 0 || placed > buffer.Length || (response.Packet[67] & 1) != 0)
                    throw new SmbProtocolException("Invalid untransformed RDMA READ completion.");
                count = (int)placed;
            }
        }
        catch (Exception error) when (error is not SmbException)
        {
            if (requestStarted || error is not OperationCanceledException)
            {
                connection.Abort(error);
                await direct.DisposeAsync().ConfigureAwait(false);
            }
            throw;
        }
        finally
        {
            await DeregisterRdmaIoAsync(registration, connection, direct).ConfigureAwait(false);
        }
        await Share.Client.QosState.LimitDownloadAsync(count, cancellationToken).ConfigureAwait(false);
        Share.Client.QosState.Downloaded(count);
        return count;
    }

    /// <summary>通过 V1 通道描述符写入文件；将私有源快照注册为仅远程可读，并保留至完整回复。</summary>
    /// <param name="buffer">已经过单块长度检查的待写数据。</param>
    /// <param name="offset">文件内偏移。</param>
    /// <param name="writeThrough">是否请求服务器持久化直写。</param>
    /// <param name="connection">发出请求的固定 SMB 通道。</param>
    /// <param name="direct">拥有源注册内存的 RDMA 队列对。</param>
    /// <param name="cancellationToken">取消带宽等待、注册或文件写入。</param>
    /// <returns>服务端确认的实际写入长度。</returns>
    private async ValueTask<int> WriteRdmaAsync(ReadOnlyMemory<byte> buffer, long offset, bool writeThrough,
        SmbConnection connection, SmbDirectConnection direct, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        byte[] source = buffer.ToArray();
        await Share.Client.QosState.LimitUploadAsync(source.Length, cancellationToken).ConfigureAwait(false);
        SmbRdmaMemoryRegistration registration = await direct.RegisterBufferAsync(source, SmbRdmaMemoryAccess.RemoteRead, cancellationToken).ConfigureAwait(false);
        bool requestStarted = false;
        int count = 0;
        try
        {
            // 异常处理先结束固定通道，最后再注销内存，不能让隐式释放先于硬件栅栏。
            byte[] descriptors = EncodeRdmaDescriptors(registration);
            byte[] body = new byte[48 + descriptors.Length];
            Wire.Put16(body, 0, 49);
            Wire.PutI64(body, 8, offset);
            Id.Write(body, 16);
            // V1 写入的数据长度放在 RemainingBytes；Length 和 DataOffset 必须为零。
            Wire.Put32(body, 32, 1);
            Wire.Put32(body, 36, (uint)source.Length);
            Wire.Put16(body, 40, 112);
            Wire.Put16(body, 42, (ushort)descriptors.Length);
            Wire.Put32(body, 44, writeThrough ? 1u : 0);
            descriptors.CopyTo(body, 48);
            cancellationToken.ThrowIfCancellationRequested();
            requestStarted = true;
            // 本次 WRITE 的内联 Length 为零，仍按逻辑数据长度保留 credit 预算。
            Response response = await connection.SendAsync(Command.Write, body, Share.TreeId, cancellationToken, source.Length).ConfigureAwait(false);
            response.EnsureSuccess();
            Wire.Structure(response.Packet, 17, 16);
            uint written = Wire.U32(response.Packet, 68);
            if (written == 0 || written > source.Length)
                throw new SmbProtocolException("Invalid RDMA WRITE completion count.");
            count = (int)written;
        }
        catch (Exception error) when (error is not SmbException)
        {
            if (requestStarted || error is not OperationCanceledException)
            {
                connection.Abort(error);
                await direct.DisposeAsync().ConfigureAwait(false);
            }
            throw;
        }
        finally
        {
            await DeregisterRdmaIoAsync(registration, connection, direct).ConfigureAwait(false);
        }
        Share.Client.QosState.Uploaded(count);
        return count;
    }

    /// <summary>编码数量受限的注册描述符数组，确保其长度能放入 SMB2 的 16 位通道信息长度字段。</summary>
    /// <param name="registration">覆盖整个数据范围的内存注册。</param>
    /// <returns>直接附加在 SMB 请求 Buffer 字段的描述符字节。</returns>
    private static byte[] EncodeRdmaDescriptors(SmbRdmaMemoryRegistration registration)
    {
        byte[] bytes = SmbRdmaBufferDescriptor.Encode(registration.Descriptors);
        return bytes.Length > ushort.MaxValue
            ? throw new SmbProtocolException("The RDMA descriptor array exceeds an SMB2 channel information field.")
            : bytes;
    }

    /// <summary>注销文件操作的注册内存；栅栏失败时关闭整个固定通道，避免继续使用不确定的注册状态。</summary>
    /// <param name="registration">需要注销的本次操作租约。</param>
    /// <param name="connection">拥有本次请求的 SMB 通道。</param>
    /// <param name="direct">需要结束设备访问的同一个 RDMA 连接。</param>
    private static async ValueTask DeregisterRdmaIoAsync(SmbRdmaMemoryRegistration registration, SmbConnection connection, SmbDirectConnection direct)
    {
        try
        {
            await registration.DisposeAsync().ConfigureAwait(false);
        }
        catch (Exception error)
        {
            connection.Abort(error);
            await direct.DisposeAsync().ConfigureAwait(false);
            throw;
        }
    }
}
