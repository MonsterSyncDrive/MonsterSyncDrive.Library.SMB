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
using System.Numerics;
using System.Security.Cryptography;

namespace MonsterSyncDrive.SMB.Security;

/// <summary>实现 RFC 1320 MD4，仅用于 NTLMv2 要求的密码单向散列函数。</summary>
/// <remarks>不将 MD4 暴露为通用完整性算法，也不使用它保护 SMB 消息。</remarks>
internal static class Md4
{
    /// <summary>计算输入字节的哈希，并清除临时填充消息和字调度缓冲区。</summary>
    /// <param name="data">待散列字节；NTLM 传入采用 UTF-16LE 编码的密码。</param>
    /// <returns>按小端状态顺序排列的 16 字节 MD4 摘要。</returns>
    internal static byte[] Hash(ReadOnlySpan<byte> data)
    {
        // RFC 1320 先填充到长度模 64 等于 56，再追加小端 UInt64 编码的原始位数。
        var paddedLength = checked((data.Length + 72) / 64 * 64);
        var padded = new byte[paddedLength];
        data.CopyTo(padded);
        padded[data.Length] = 0x80;
        BinaryPrimitives.WriteUInt64LittleEndian(padded.AsSpan(paddedLength - 8), (ulong)data.Length * 8);
        uint a = 0x67452301, b = 0xEFCDAB89, c = 0x98BADCFE, d = 0x10325476;
        Span<uint> words = stackalloc uint[16];
        // 压缩过程中的加法必须按 2 的 32 次方回绕；启用溢出检查会改变算法结果。
        unchecked
        {
            for (var block = 0; block < padded.Length; block += 64)
            {
                for (var i = 0; i < 16; i++)
                    words[i] = BinaryPrimitives.ReadUInt32LittleEndian(padded.AsSpan(block + i * 4));
                var aa = a; var bb = b; var cc = c; var dd = d;
                for (var i = 0; i < 48; i++)
                {
                    var round = i / 16;
                    var j = i % 16;
                    // 三轮分别按顺序、按列和按位反转索引的顺序遍历同一个数据块。
                    var index = round switch { 0 => j, 1 => (j % 4) * 4 + j / 4, _ => Round3Index(j) };
                    var rotation = round switch
                    {
                        0 => (j % 4) switch { 0 => 3, 1 => 7, 2 => 11, _ => 19 },
                        1 => (j % 4) switch { 0 => 3, 1 => 5, 2 => 9, _ => 13 },
                        _ => (j % 4) switch { 0 => 3, 1 => 9, 2 => 11, _ => 15 }
                    };
                    var f = round switch { 0 => (b & c) | (~b & d), 1 => (b & c) | (b & d) | (c & d), _ => b ^ c ^ d };
                    var constant = round switch { 0 => 0u, 1 => 0x5A827999u, _ => 0x6ED9EBA1u };
                    var value = BitOperations.RotateLeft(a + f + words[index] + constant, rotation);
                    a = d; d = c; c = b; b = value;
                }
                a += aa; b += bb; c += cc; d += dd;
            }
        }
        var result = new byte[16];
        BinaryPrimitives.WriteUInt32LittleEndian(result, a);
        BinaryPrimitives.WriteUInt32LittleEndian(result.AsSpan(4), b);
        BinaryPrimitives.WriteUInt32LittleEndian(result.AsSpan(8), c);
        BinaryPrimitives.WriteUInt32LittleEndian(result.AsSpan(12), d);
        CryptographicOperations.ZeroMemory(padded);
        CryptographicOperations.ZeroMemory(System.Runtime.InteropServices.MemoryMarshal.AsBytes(words));
        return result;
    }

    /// <summary>反转索引的低四位，得到 MD4 第三轮的输入字排列。</summary>
    /// <param name="j">本轮内从零到十五的操作索引。</param>
    /// <returns>对应的输入字索引。</returns>
    private static int Round3Index(int j) =>
        ((j & 1) << 3) | ((j & 2) << 1) | ((j & 4) >> 1) | ((j & 8) >> 3);
}