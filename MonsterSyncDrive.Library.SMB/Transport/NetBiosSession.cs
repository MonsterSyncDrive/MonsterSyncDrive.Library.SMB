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
using System.Text;

namespace MonsterSyncDrive.SMB.Transport;

/// <summary>编码 RFC 1002 名称，并在交换 SMB 消息之前建立会话服务连接。</summary>
internal static class NetBiosSession
{
    /// <summary>根据 Latin-1 基础名称、服务后缀和作用域生成第一级编码名称。</summary>
    /// <param name="name">以单字节字符表示的基础名称，长度为 1 至 15 个字节。</param>
    /// <param name="suffix">用于标识服务的第十六个名称字节。</param>
    /// <param name="scope">由 DNS 标签组成的作用域；空字符串表示不带作用域。</param>
    /// <returns>带长度前缀的半字节编码名称及以零结尾的作用域标签。</returns>
    internal static byte[] EncodeName(string name, byte suffix, string scope)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(name);
        ArgumentNullException.ThrowIfNull(scope);
        name = string.Create(name.Length, name, (destination, value) =>
        {
            for (var i = 0; i < value.Length; i++) destination[i] = value[i] is >= 'a' and <= 'z' ? (char)(value[i] - 32) : value[i];
        });
        if (name.Length > 15 || name.Any(c => c is < ' ' or > '\u00FF'))
            throw new ArgumentException("A NetBIOS base name must contain 1..15 single-byte characters.", nameof(name));
        Span<byte> bytes = stackalloc byte[16];
        bytes.Fill(0x20); Encoding.Latin1.GetBytes(name, bytes); bytes[15] = suffix;
        return EncodeName(bytes, scope);
    }

    /// <summary>编码任意 16 字节 NetBIOS 名称，不改变大小写或 OEM 字节。</summary>
    /// <param name="bytes">恰好十六个名称字节，包含服务后缀。</param>
    /// <param name="scope">由 DNS 标签组成的可选作用域。</param>
    /// <returns>完整的 RFC 1002 名称表示。</returns>
    internal static byte[] EncodeName(ReadOnlySpan<byte> bytes, string scope)
    {
        ArgumentNullException.ThrowIfNull(scope);
        if (bytes.Length != 16) throw new ArgumentException("A raw NetBIOS name must contain exactly 16 octets.", nameof(bytes));
        var labels = scope.Length == 0 ? [] : scope.TrimEnd('.').Split('.');
        if (labels.Any(l => l.Length is < 1 or > 63 || l.Any(c => c is < '!' or > '~' || c is '.' or '\\' or '/')))
            throw new ArgumentException("A NetBIOS scope must contain ASCII DNS labels of 1..63 bytes.", nameof(scope));
        var length = 34 + labels.Sum(l => l.Length + 1);
        if (length > 255) throw new ArgumentException("The encoded NetBIOS name and scope exceed 255 bytes.", nameof(scope));
        var output = new byte[length]; output[0] = 32;
        for (var i = 0; i < 16; i++)
        {
            output[1 + i * 2] = (byte)('A' + (bytes[i] >> 4));
            output[2 + i * 2] = (byte)('A' + (bytes[i] & 15));
        }
        var position = 33;
        foreach (var label in labels)
        {
            output[position++] = (byte)label.Length;
            position += Encoding.ASCII.GetBytes(label, output.AsSpan(position));
        }
        return output;
    }

    /// <summary>返回重定向端点；请求的会话成功建立后返回 null。</summary>
    /// <param name="stream">刚建立连接的 IPv4 TCP 字节流。</param>
    /// <param name="options">已经验证的主叫名和被叫名配置。</param>
    /// <param name="cancellationToken">覆盖整个连接过程的截止时间及调用方取消令牌。</param>
    /// <returns>六字节 IPv4 重定向目标；收到成功响应后返回 null。</returns>
    /// <exception cref="SmbNetBiosException">服务器发送了拒绝响应；异常会保留其拒绝原因。</exception>
    /// <exception cref="SmbProtocolException">控制消息的类型、标志或长度无效。</exception>
    internal static async Task<IPEndPoint?> RequestAsync(Stream stream, SmbNetBiosOptions options, CancellationToken cancellationToken)
    {
        var called = options.CalledNameBytes is { } calledBytes ? EncodeName(calledBytes.Span, options.Scope) : EncodeName(options.CalledName, options.CalledNameSuffix, options.Scope);
        var calling = options.CallingNameBytes is { } callingBytes ? EncodeName(callingBytes.Span, options.Scope) : EncodeName(options.CallingName, options.CallingNameSuffix, options.Scope);
        var length = called.Length + calling.Length;
        var packet = new byte[4 + length];
        packet[0] = 0x81; packet[2] = (byte)(length >> 8); packet[3] = (byte)length;
        called.CopyTo(packet, 4); calling.CopyTo(packet, 4 + called.Length);
        await stream.WriteAsync(packet, cancellationToken).ConfigureAwait(false);
        var header = new byte[4];
        while (true)
        {
            await stream.ReadExactlyAsync(header, cancellationToken).ConfigureAwait(false);
            if ((header[1] & 0xFE) != 0) throw new SmbProtocolException("Invalid NetBIOS Session Service flags.");
            var responseLength = ((header[1] & 1) << 16) | (header[2] << 8) | header[3];
            // 严格验证控制消息长度之前，不按服务器提供的长度分配缓冲区。
            // 保活消息与会话请求共用整个连接过程的截止时间。
            switch (header[0])
            {
                case 0x85 when responseLength == 0: continue;
                case 0x82 when responseLength == 0: return null;
                case 0x83 when responseLength == 1:
                    var error = new byte[1];
                    await stream.ReadExactlyAsync(error, cancellationToken).ConfigureAwait(false);
                    throw new SmbNetBiosException(error[0]);
                case 0x84 when responseLength == 6:
                    var target = new byte[6];
                    await stream.ReadExactlyAsync(target, cancellationToken).ConfigureAwait(false);
                    var port = (target[4] << 8) | target[5];
                    if (port == 0) throw new SmbProtocolException("Invalid NetBIOS retarget port.");
                    return new IPEndPoint(new IPAddress(target.AsSpan(0, 4)), port);
                default: throw new SmbProtocolException("Invalid NetBIOS session establishment reply.");
            }
        }
    }
}