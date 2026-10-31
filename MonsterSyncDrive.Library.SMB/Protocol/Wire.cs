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
using System.Text;

namespace MonsterSyncDrive.Library.SMB.Protocol;


/// <summary>SMB2 头中的标准命令号，声明顺序与 0x0000 至 0x0012 一一对应。</summary>
internal enum Command : ushort
{

    /// <summary>协商协议、能力和算法。</summary>
    Negotiate,
    /// <summary>初次认证或绑定现有会话。</summary>
    SessionSetup,
    /// <summary>注销认证会话。</summary>
    Logoff,
    /// <summary>连接共享。</summary>
    TreeConnect,
    /// <summary>断开共享。</summary>
    TreeDisconnect,
    /// <summary>创建或打开文件、目录、管道。</summary>
    Create,
    /// <summary>关闭句柄。</summary>
    Close,

    /// <summary>请求服务器刷新数据。</summary>
    Flush,
    /// <summary>按偏移读取数据。</summary>
    Read,
    /// <summary>按偏移写入数据。</summary>
    Write,
    /// <summary>管理字节范围锁。</summary>
    Lock,
    /// <summary>执行 FSCTL 或设备控制请求。</summary>
    Ioctl,
    /// <summary>取消未完成请求。</summary>
    Cancel,
    /// <summary>探测连接。</summary>
    Echo,
    /// <summary>分页枚举目录。</summary>
    QueryDirectory,
    /// <summary>等待目录变化。</summary>
    ChangeNotify,
    /// <summary>查询文件、卷、安全或配额信息。</summary>
    QueryInfo,
    /// <summary>设置文件、卷、安全或配额信息。</summary>
    SetInfo,
    /// <summary>接收和确认传统 oplock 撤销。</summary>
    OplockBreak
}


/// <summary>集中实现受边界检查的小端序编码、UTF-16 解码和 SMB2 固定头校验。</summary>
internal static class Wire
{

    /// <summary>未压缩 SMB2 固定头长度 64 字节。</summary>
    internal const int HeaderSize = 64;

    /// <summary>SMB2 头的响应、异步格式和签名标志位。</summary>
    internal const uint ServerToClient = 1, AsyncCommand = 2, Signed = 8;

    /// <summary>严格的 UTF-16LE 编码器；不以替换字符掩盖畸形名称。</summary>
    internal static readonly Encoding Unicode = new UnicodeEncoding(false, false, true);

    /// <summary>从受检范围读取小端无符号 16 位字段。</summary>
    internal static ushort U16(ReadOnlySpan<byte> data, int offset)
    {
        return BinaryPrimitives.ReadUInt16LittleEndian(Slice(data, offset, 2));
    }

    /// <summary>从受检范围读取小端无符号 32 位字段。</summary>
    internal static uint U32(ReadOnlySpan<byte> data, int offset)
    {
        return BinaryPrimitives.ReadUInt32LittleEndian(Slice(data, offset, 4));
    }

    /// <summary>从受检范围读取小端无符号 64 位字段。</summary>
    internal static ulong U64(ReadOnlySpan<byte> data, int offset)
    {
        return BinaryPrimitives.ReadUInt64LittleEndian(Slice(data, offset, 8));
    }

    /// <summary>按原始二进制补码位模式读取小端有符号 64 位字段。</summary>
    internal static long I64(ReadOnlySpan<byte> data, int offset)
    {
        return unchecked((long)U64(data, offset));
    }

    /// <summary>将协议无符号长度转为托管索引，拒绝超过 Int32 的值。</summary>
    internal static int Int32(uint value)
    {
        return value <= int.MaxValue ? (int)value
        : throw new SmbProtocolException("An SMB size or offset exceeds the supported range.");
    }

    /// <summary>将无符号 16 位字段写为小端序。</summary>
    internal static void Put16(Span<byte> data, int offset, ushort value)
    {
        BinaryPrimitives.WriteUInt16LittleEndian(data[offset..], value);
    }

    /// <summary>将无符号 32 位字段写为小端序。</summary>
    internal static void Put32(Span<byte> data, int offset, uint value)
    {
        BinaryPrimitives.WriteUInt32LittleEndian(data[offset..], value);
    }

    /// <summary>将无符号 64 位字段写为小端序。</summary>
    internal static void Put64(Span<byte> data, int offset, ulong value)
    {
        BinaryPrimitives.WriteUInt64LittleEndian(data[offset..], value);
    }

    /// <summary>按小端序写入有符号 64 位字段。</summary>
    internal static void PutI64(Span<byte> data, int offset, long value)
    {
        Put64(data, offset, unchecked((ulong)value));
    }


    /// <summary>在切片之前同时校验起点和长度，避免整数相加溢出绕过范围判断。</summary>
    internal static ReadOnlySpan<byte> Slice(ReadOnlySpan<byte> data, int offset, int length)
    {
        return offset < 0 || length < 0 || offset > data.Length - length
            ? throw new SmbProtocolException("An SMB field points outside its packet.")
            : data.Slice(offset, length);
    }


    /// <summary>解析带绝对偏移和长度的协议缓冲区，并校验最小合法数据起点。</summary>
    internal static byte[] Buffer(ReadOnlySpan<byte> packet, int offset, uint length, int minimumOffset)
    {
        return length == 0
            ? []
            : offset < minimumOffset || length > int.MaxValue
            ? throw new SmbProtocolException("Invalid SMB buffer offset or length.")
            : Slice(packet, offset, (int)length).ToArray();
    }


    /// <summary>从指定字节范围严格解码偶数字节的 UTF-16LE 字符串。</summary>
    internal static string Text(ReadOnlySpan<byte> data, int offset, int length)
    {
        if ((length & 1) != 0)
            throw new SmbProtocolException("An SMB Unicode string has an odd byte length.");
        try
        {
            return Unicode.GetString(Slice(data, offset, length));
        }
        catch (DecoderFallbackException ex)
        {
            throw new SmbProtocolException("Invalid SMB Unicode string.", ex);
        }
    }


    /// <summary>将 FILETIME 转为时间，保留零和哨兵值为空，拒绝非法日期。</summary>
    internal static DateTimeOffset? Time(ReadOnlySpan<byte> data, int offset)
    {
        long value = I64(data, offset);
        if (value is 0 or -1)
            return null;
        try
        {
            return DateTimeOffset.FromFileTime(value);
        }
        catch (ArgumentOutOfRangeException ex)
        {
            throw new SmbProtocolException("Invalid SMB file timestamp.", ex);
        }
    }


    /// <summary>构造规范固定头并填写命令、credit、消息号、会话和共享树。</summary>
    internal static byte[] Header(Command command, ulong messageId, ulong sessionId, uint treeId, ushort charge, ushort credits, int bodyLength)
    {
        byte[] packet = new byte[checked(HeaderSize + bodyLength)];
        packet[0] = 0xFE;
        packet[1] = (byte)'S';
        packet[2] = (byte)'M';
        packet[3] = (byte)'B';
        Put16(packet, 4, HeaderSize);
        Put16(packet, 6, charge);
        Put16(packet, 12, (ushort)command);
        Put16(packet, 14, credits);
        Put64(packet, 24, messageId);
        Put32(packet, 32, 0xFEFF);
        Put32(packet, 36, treeId);
        Put64(packet, 40, sessionId);
        return packet;
    }


    /// <summary>确认 SMB2 标识、64 字节头、响应方向和不支持的 compound 链边界。</summary>
    internal static void ValidateHeader(ReadOnlySpan<byte> packet)
    {
        if (packet.Length < HeaderSize || !packet[..4].SequenceEqual(new byte[] { 0xFE, 0x53, 0x4D, 0x42 }) || U16(packet, 4) != HeaderSize)
            throw new SmbProtocolException("Invalid SMB2 header.");
        if ((U32(packet, 16) & ServerToClient) == 0 || U32(packet, 20) != 0)
            throw new SmbProtocolException("Unexpected SMB request or compound response.");
    }


    /// <summary>校验命令体固定 StructureSize 及最小消息长度。</summary>
    internal static void Structure(ReadOnlySpan<byte> packet, ushort expected, int minimumLength)
    {
        if (packet.Length < HeaderSize + minimumLength || U16(packet, HeaderSize) != expected)
            throw new SmbProtocolException($"Invalid SMB response structure (expected {expected}).");
    }


    /// <summary>将长度向上对齐到八字节边界，用于协商和创建上下文。</summary>
    internal static int Align8(int value)
    {
        return checked((value + 7) & ~7);
    }
}


/// <summary>收到的 SMB2 响应与原请求，供认证预哈希和错误传播。</summary>
/// <param name="Packet">经过承载、解密、解压缩和标识检查的响应。</param>
/// <param name="Request">原始发出请求。</param>
internal sealed record Response(byte[] Packet, byte[] Request)
{

    /// <summary>头部保留的 NTSTATUS。</summary>
    internal SmbStatus Status => (SmbStatus)Wire.U32(Packet, 8);

    /// <summary>头部会话号；初次认证可由服务器首次分配。</summary>
    internal ulong SessionId => Wire.U64(Packet, 40);

    /// <summary>普通同步头中的共享树号，异步头对应位置不表达共享树。</summary>
    internal uint TreeId => Wire.U32(Packet, 36);

    /// <summary>允许成功及明确列出的继续或分页状态；其他状态保留服务端错误载荷，并区分 SESSION_SETUP 的安全缓冲格式。</summary>
    internal void EnsureSuccess(params SmbStatus[] accepted)
    {
        if (Status == SmbStatus.Success || accepted.Contains(Status))
            return;
        byte[] data = Packet.Length >= 72 && Wire.U16(Packet, 12) == (ushort)Command.SessionSetup &&
            Wire.U16(Packet, 64) == 9 && Wire.U16(Packet, 68) >= 72 &&
            Wire.U16(Packet, 68) <= Packet.Length - Wire.U16(Packet, 70)
            ? Wire.Buffer(Packet, Wire.U16(Packet, 68), Wire.U16(Packet, 70), 72)
            : Packet.Length >= 72 && Wire.U16(Packet, 64) == 9
            ? Wire.Buffer(Packet, 72, Wire.U32(Packet, 68), 72)
            : Packet.Length >= 112 && Wire.U16(Packet, 12) == (ushort)Command.Ioctl && Wire.U16(Packet, 64) == 49
                ? Wire.Buffer(Packet, Wire.Int32(Wire.U32(Packet, 96)), Wire.U32(Packet, 100), 112) : [];
        throw new SmbException(Status, Wire.U16(Packet, 12), data);
    }
}