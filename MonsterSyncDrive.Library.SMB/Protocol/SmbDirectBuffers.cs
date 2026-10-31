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

namespace MonsterSyncDrive.SMB;

/// <summary>MS-SMBD 2.2.3.1 定义的 16 字节 SMB_DIRECT_BUFFER_DESCRIPTOR_V1。</summary>
/// <param name="Offset">提供程序定义的远程起始地址，保留主机数值表示。</param>
/// <param name="Token">提供程序返回的不透明远程导向令牌。</param>
/// <param name="Length">已注册片段的非零字节数。</param>
public readonly record struct SmbRdmaBufferDescriptor(ulong Offset, uint Token, uint Length)
{
    /// <summary>固定的协议长度：8 字节偏移，后接两个 4 字节字段。</summary>
    public const int EncodedSize = 16;

    /// <summary>按 MS-SMBD 的小端字段顺序编码描述符。</summary>
    /// <param name="destination">至少 16 字节的目标跨度。</param>
    public void Write(Span<byte> destination)
    {
        if (destination.Length < EncodedSize) throw new ArgumentException("A buffer descriptor needs 16 bytes.", nameof(destination));
        if (Length == 0 || Offset > ulong.MaxValue - Length) throw new ArgumentException("Invalid RDMA buffer range.");
        BinaryPrimitives.WriteUInt64LittleEndian(destination, Offset);
        BinaryPrimitives.WriteUInt32LittleEndian(destination[8..], Token);
        BinaryPrimitives.WriteUInt32LittleEndian(destination[12..], Length);
    }

    /// <summary>解析描述符，并拒绝溢出或空的远程范围。</summary>
    /// <param name="source">至少包含一个编码描述符的数据。</param>
    /// <returns>经过校验的描述符。</returns>
    public static SmbRdmaBufferDescriptor Parse(ReadOnlySpan<byte> source)
    {
        if (source.Length < EncodedSize) throw new SmbProtocolException("Truncated SMB Direct buffer descriptor.");
        var result = new SmbRdmaBufferDescriptor(BinaryPrimitives.ReadUInt64LittleEndian(source),
            BinaryPrimitives.ReadUInt32LittleEndian(source[8..]), BinaryPrimitives.ReadUInt32LittleEndian(source[12..]));
        if (result.Length == 0 || result.Offset > ulong.MaxValue - result.Length)
            throw new SmbProtocolException("Invalid SMB Direct buffer descriptor range.");
        return result;
    }

    /// <summary>在数量限制内编码描述符数组，不依赖运行时序列化或平台专有类型。</summary>
    public static byte[] Encode(IReadOnlyList<SmbRdmaBufferDescriptor> descriptors)
    {
        ArgumentNullException.ThrowIfNull(descriptors);
        if (descriptors.Count is < 1 or > 4096) throw new ArgumentOutOfRangeException(nameof(descriptors));
        var bytes = new byte[checked(descriptors.Count * EncodedSize)];
        for (var i = 0; i < descriptors.Count; i++) descriptors[i].Write(bytes.AsSpan(i * EncodedSize));
        return bytes;
    }

    /// <summary>解码完整数组，拒绝截断的描述符或过多的片段。</summary>
    public static IReadOnlyList<SmbRdmaBufferDescriptor> Decode(ReadOnlySpan<byte> source)
    {
        if (source.Length == 0 || source.Length % EncodedSize != 0 || source.Length / EncodedSize > 4096)
            throw new SmbProtocolException("Invalid SMB Direct descriptor array length.");
        var result = new SmbRdmaBufferDescriptor[source.Length / EncodedSize];
        for (var i = 0; i < result.Length; i++) result[i] = Parse(source[(i * EncodedSize)..]);
        return result;
    }

    /// <summary>选取可以跨越已注册片段的子范围，不改变远程令牌。</summary>
    public static IReadOnlyList<SmbRdmaBufferDescriptor> Slice(IReadOnlyList<SmbRdmaBufferDescriptor> descriptors, long offset, int length)
    {
        ArgumentNullException.ThrowIfNull(descriptors);
        ArgumentOutOfRangeException.ThrowIfNegative(offset);
        ArgumentOutOfRangeException.ThrowIfNegative(length);
        if (descriptors.Count is < 1 or > 4096) throw new ArgumentOutOfRangeException(nameof(descriptors));
        long total = 0;
        foreach (var descriptor in descriptors)
        {
            if (descriptor.Length == 0 || descriptor.Offset > ulong.MaxValue - descriptor.Length)
                throw new ArgumentException("Invalid registered range.", nameof(descriptors));
            total = checked(total + descriptor.Length);
        }
        if (offset > total || length > total - offset) throw new ArgumentOutOfRangeException(nameof(length));
        var result = new List<SmbRdmaBufferDescriptor>();
        var remaining = length;
        foreach (var descriptor in descriptors)
        {
            if (remaining == 0) break;
            if (offset >= descriptor.Length) { offset -= descriptor.Length; continue; }
            var count = (uint)Math.Min(remaining, descriptor.Length - offset);
            result.Add(new SmbRdmaBufferDescriptor(checked(descriptor.Offset + (ulong)offset), descriptor.Token, count));
            remaining -= (int)count;
            offset = 0;
        }
        return result;
    }
}