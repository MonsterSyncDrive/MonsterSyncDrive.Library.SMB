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
using System.Buffers.Binary;

namespace MonsterSyncDrive.Library.SMB.Protocol;

/// <summary>从对端接收并校验的 MS-SMBD 1.0 协商限制。</summary>
/// <param name="CreditsRequested">对端期望的 SEND 信用总数。</param>
/// <param name="CreditsGranted">授予本端点的初始 SEND 信用。</param>
/// <param name="MaximumReadWriteSize">逻辑直接放置的最大字节数。</param>
/// <param name="PreferredSendSize">对端首选的 SEND 字节数。</param>
/// <param name="MaximumReceiveSize">对端的 RECEIVE 最大字节数。</param>
/// <param name="MaximumFragmentedSize">对端的消息重组长度限制。</param>
internal readonly record struct SmbDirectNegotiation(ushort CreditsRequested, ushort CreditsGranted,
    int MaximumReadWriteSize, int PreferredSendSize, int MaximumReceiveSize, int MaximumFragmentedSize);
/// <summary>经过校验的 DATA_TRANSFER 消息头，以及租约保护的接收负载切片。</summary>
/// <param name="CreditsRequested">期望的 SEND 信用总数。</param>
/// <param name="CreditsGranted">本次增量授予的 SEND 信用。</param>
/// <param name="ResponseRequested">是否请求立即发送保活响应。</param>
/// <param name="RemainingLength">当前分片之后剩余的上层字节数。</param>
/// <param name="Payload">接收缓冲区租约内已经对齐的负载。</param>
internal readonly record struct SmbDirectData(ushort CreditsRequested, ushort CreditsGranted, bool ResponseRequested,
    uint RemainingLength, ReadOnlyMemory<byte> Payload);

/// <summary>边界明确、分配可见的 MS-SMBD 协议编解码。</summary>
internal static class SmbDirectWire
{
    /// <summary>MS-SMBD 1.0 协议版本号。</summary>
    internal const ushort Version = 0x100;
    /// <summary>没有上层负载时的消息头字节数。</summary>
    internal const int DataHeaderLength = 20;
    /// <summary>通常采用的 8 字节对齐数据偏移，包含四个零填充字节。</summary>
    internal const int PayloadOffset = 24;
    /// <summary>读取小端无符号 16 位协议字段。</summary>
    private static ushort U16(ReadOnlySpan<byte> b, int p)
    {
        return BinaryPrimitives.ReadUInt16LittleEndian(b[p..]);
    }

    /// <summary>读取小端无符号 32 位协议字段。</summary>
    private static uint U32(ReadOnlySpan<byte> b, int p)
    {
        return BinaryPrimitives.ReadUInt32LittleEndian(b[p..]);
    }

    /// <summary>写入小端无符号 16 位协议字段。</summary>
    private static void W16(Span<byte> b, int p, ushort v)
    {
        BinaryPrimitives.WriteUInt16LittleEndian(b[p..], v);
    }

    /// <summary>写入小端无符号 32 位协议字段。</summary>
    private static void W32(Span<byte> b, int p, uint v)
    {
        BinaryPrimitives.WriteUInt32LittleEndian(b[p..], v);
    }

    /// <summary>编码初始的 20 字节 MS-SMBD 协商请求。</summary>
    internal static byte[] NegotiateRequest(SmbDirectOptions options)
    {
        byte[] packet = new byte[20];
        W16(packet, 0, Version);
        W16(packet, 2, Version);
        W16(packet, 6, options.SendCreditTarget);
        W32(packet, 8, (uint)options.PreferredSendSize);
        W32(packet, 12, (uint)options.MaximumReceiveSize);
        W32(packet, 16, (uint)options.MaximumFragmentedReceiveSize);
        return packet;
    }

    /// <summary>根据已提供的接收资源校验 32 字节协商响应。</summary>
    internal static SmbDirectNegotiation NegotiateResponse(ReadOnlySpan<byte> packet, SmbDirectOptions offered)
    {
        if (packet.Length < 32)
            throw new SmbProtocolException("Truncated SMB Direct negotiation response.");
        if (U16(packet, 4) != Version || U16(packet, 0) > Version || U16(packet, 2) < Version ||
            U16(packet, 8) == 0 || U16(packet, 10) == 0 || U32(packet, 12) != 0 ||
            U32(packet, 24) < 128 || U32(packet, 28) < 131072 ||
            U32(packet, 20) > offered.MaximumReceiveSize)
            throw new SmbProtocolException("The peer rejected or returned invalid SMB Direct negotiation parameters.");
        for (int i = 16; i < 32; i += 4)
            if (U32(packet, i) > int.MaxValue)
                throw new SmbProtocolException("An SMB Direct limit exceeds supported bounds.");
        return new(U16(packet, 8), U16(packet, 10), (int)U32(packet, 16), (int)U32(packet, 20), (int)U32(packet, 24), (int)U32(packet, 28));
    }

    /// <summary>编码 DATA_TRANSFER 帧，不添加 TCP 或 NetBIOS 前缀。</summary>
    internal static byte[] Data(ReadOnlySpan<byte> payload, uint remaining, ushort requested, ushort granted, bool responseRequested)
    {
        if (requested == 0)
            throw new ArgumentOutOfRangeException(nameof(requested));
        byte[] packet = new byte[(payload.IsEmpty ? DataHeaderLength : PayloadOffset) + payload.Length];
        W16(packet, 0, requested);
        W16(packet, 2, granted);
        W16(packet, 4, responseRequested ? (ushort)1 : (ushort)0);
        W32(packet, 8, remaining);
        if (!payload.IsEmpty)
        {
            W32(packet, 12, PayloadOffset);
            W32(packet, 16, (uint)payload.Length);
            payload.CopyTo(packet.AsSpan(PayloadOffset));
        }
        return packet;
    }

    /// <summary>提供负载字节前，校验全部不可信偏移、对齐、标志和总长度。</summary>
    internal static SmbDirectData ParseData(ReadOnlyMemory<byte> packet, int maximumReceiveSize, int maximumFragmentedSize)
    {
        if (packet.Length < DataHeaderLength || packet.Length > maximumReceiveSize)
            throw new SmbProtocolException("Invalid SMB Direct data message length.");
        ReadOnlySpan<byte> span = packet.Span;
        uint offset = U32(span, 12);
        uint length = U32(span, 16);
        uint remaining = U32(span, 8);
        return U16(span, 0) == 0 || (U16(span, 4) & ~1) != 0 || (offset & 7) != 0 ||
            offset > packet.Length || length > packet.Length - offset ||
            (length == 0 && (offset != 0 || remaining != 0)) || (length != 0 && offset < PayloadOffset) ||
            length > maximumFragmentedSize || remaining > maximumFragmentedSize - length
            ? throw new SmbProtocolException("Invalid SMB Direct data message fields.")
            : new(U16(span, 0), U16(span, 2), U16(span, 4) == 1, remaining, packet.Slice((int)offset, (int)length));
    }
}