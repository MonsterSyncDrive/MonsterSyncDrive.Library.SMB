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
using System.Text;

namespace MonsterSyncDrive.Library.SMB;


/// <summary>标准文件信息的无反射编解码器，集中验证固定布局、长度链、UTF-16、ASCII 名称和整数边界。</summary>
internal static class SmbFileInformationCodec
{

    /// <summary>解码 40 字节基本信息并拒绝负时间戳；零时间按协议保留为空。</summary>
    /// <param name="data">已经从 SMB 响应提取的原始信息缓冲区。</param>
    /// <returns>四类时间和文件属性。</returns>
    internal static SmbBasicInformation Basic(ReadOnlySpan<byte> data)
    {
        _ = Wire.Slice(data, 0, 40);
        return new(Time(data, 0), Time(data, 8), Time(data, 16), Time(data, 24), (FileAttributes)Wire.U32(data, 32));
    }


    /// <summary>解码 24 字节标准信息，校验非负大小及严格的零或一布尔值。</summary>
    /// <param name="data">已经从 SMB 响应提取的原始信息缓冲区。</param>
    /// <returns>分配量、EOF、硬链接计数和状态。</returns>
    internal static SmbStandardInformation Standard(ReadOnlySpan<byte> data)
    {
        _ = Wire.Slice(data, 0, 24);
        return new(Nonnegative(data, 0), Nonnegative(data, 8), Wire.U32(data, 16), Boolean(data, 20), Boolean(data, 21));
    }


    /// <summary>按 FILE_ALL_INFORMATION 的嵌套布局解码全部字段，而不丢失访问、游标、模式和对齐信息。</summary>
    /// <param name="data">已经从 SMB 响应提取的原始信息缓冲区。</param>
    /// <returns>完整聚合信息模型。</returns>
    /// <remarks>固定部分为 100 字节；内嵌名称从偏移 96 的长度字段开始。</remarks>
    internal static SmbAllInformation All(ReadOnlySpan<byte> data)
    {
        _ = Wire.Slice(data, 0, 100);
        return new(Basic(data), Standard(data[40..]), Wire.U64(data, 64), Wire.U32(data, 72),
            (SmbAccessMask)Wire.U32(data, 76), Nonnegative(data, 80), (SmbFileMode)Wire.U32(data, 88),
            Alignment(data[92..]), Name(data[96..]));
    }


    /// <summary>校验设备对齐掩码为规范允许的零或 2 的幂减一值，最大 511。</summary>
    /// <param name="data">已经从 SMB 响应提取的原始信息缓冲区。</param>
    /// <returns>可换算为字节边界的对齐模型。</returns>
    internal static SmbAlignmentInformation Alignment(ReadOnlySpan<byte> data)
    {
        uint mask = Wire.U32(data, 0);
        return mask > 511 || (mask & (mask + 1)) != 0
            ? throw new SmbProtocolException("Invalid file buffer alignment requirement.")
            : new(mask);
    }


    /// <summary>解码长度前缀 UTF-16 名称，拒绝奇数字节、无效编码、越界和嵌入 NUL。</summary>
    /// <param name="data">已经从 SMB 响应提取的原始信息缓冲区。</param>
    /// <returns>完整名称字符串，允许规范化路径的分隔符。</returns>
    internal static string Name(ReadOnlySpan<byte> data)
    {
        string value = Wire.Text(data, 4, Wire.Int32(Wire.U32(data, 0)));
        return value.Contains('\0') ? throw new SmbProtocolException("A file information name contains NUL.") : value;
    }


    /// <summary>解码文件系统压缩信息，保留服务端格式编号和单元移位。</summary>
    /// <param name="data">已经从 SMB 响应提取的原始信息缓冲区。</param>
    /// <returns>压缩后大小及压缩参数。</returns>
    internal static SmbFileCompressionInformation Compression(ReadOnlySpan<byte> data)
    {
        _ = Wire.Slice(data, 0, 16);
        return new(Nonnegative(data, 0), Wire.U16(data, 8), data[10], data[11], data[12]);
    }


    /// <summary>解码 NETWORK_OPEN 信息；其属性偏移为 48，区别于 BASIC 信息的偏移 32。</summary>
    /// <param name="data">已经从 SMB 响应提取的原始信息缓冲区。</param>
    /// <returns>时间、属性、分配量和 EOF。</returns>
    internal static SmbNetworkOpenInformation NetworkOpen(ReadOnlySpan<byte> data)
    {
        _ = Wire.Slice(data, 0, 56);
        return new(new(Time(data, 0), Time(data, 8), Time(data, 16), Time(data, 24), (FileAttributes)Wire.U32(data, 48)),
            Nonnegative(data, 32), Nonnegative(data, 40));
    }


    /// <summary>解码 64 位卷序列号和两段 64 位组成的文件 ID，避免 Guid 字节序转换。</summary>
    /// <param name="data">已经从 SMB 响应提取的原始信息缓冲区。</param>
    /// <returns>原样保存的文件系统标识。</returns>
    internal static SmbFileIdentity Identity(ReadOnlySpan<byte> data)
    {
        _ = Wire.Slice(data, 0, 24);
        return new(Wire.U64(data, 0), new(Wire.U64(data, 8), Wire.U64(data, 16)));
    }


    /// <summary>验证并解码管道读取模式和完成模式两个枚举字段。</summary>
    /// <param name="data">已经从 SMB 响应提取的原始信息缓冲区。</param>
    /// <returns>管道模式。</returns>
    internal static SmbPipeInformation Pipe(ReadOnlySpan<byte> data)
    {
        SmbPipeReadMode read = (SmbPipeReadMode)Wire.U32(data, 0);
        SmbPipeCompletionMode completion = (SmbPipeCompletionMode)Wire.U32(data, 4);
        return !Enum.IsDefined(read) || !Enum.IsDefined(completion)
            ? throw new SmbProtocolException("Invalid named-pipe mode.")
            : new(read, completion);
    }


    /// <summary>解码 40 字节管道状态，检查类型、方向、连接状态和端类型均为已定义值。</summary>
    /// <param name="data">已经从 SMB 响应提取的原始信息缓冲区。</param>
    /// <returns>管道实例、配额、数据量和状态。</returns>
    internal static SmbPipeLocalInformation PipeLocal(ReadOnlySpan<byte> data)
    {
        _ = Wire.Slice(data, 0, 40);
        SmbPipeType type = (SmbPipeType)Wire.U32(data, 0);
        SmbPipeConfiguration configuration = (SmbPipeConfiguration)Wire.U32(data, 4);
        SmbPipeState state = (SmbPipeState)Wire.U32(data, 32);
        SmbPipeEnd end = (SmbPipeEnd)Wire.U32(data, 36);
        return !Enum.IsDefined(type) || !Enum.IsDefined(configuration) || !Enum.IsDefined(state) || !Enum.IsDefined(end)
            ? throw new SmbProtocolException("Invalid named-pipe local information.")
            : new(type, configuration, Wire.U32(data, 8), Wire.U32(data, 12), Wire.U32(data, 16),
            Wire.U32(data, 20), Wire.U32(data, 24), Wire.U32(data, 28), state, end);
    }


    /// <summary>保留管道收集时长的有符号 100 纳秒表示，并读取字节阈值。</summary>
    /// <param name="data">已经从 SMB 响应提取的原始信息缓冲区。</param>
    /// <returns>远程管道收集参数。</returns>
    internal static SmbPipeRemoteInformation PipeRemote(ReadOnlySpan<byte> data)
    {
        _ = Wire.Slice(data, 0, 12);
        return new(TimeSpan.FromTicks(Wire.I64(data, 0)), Wire.U32(data, 8));
    }


    /// <summary>解析 4 字节对齐的 EA 链，验证标志、ASCII 名称、NUL、重复名称及值长度。</summary>
    /// <param name="data">已经从 SMB 响应提取的原始信息缓冲区。</param>
    /// <returns>具有独立值副本的 EA 集合。</returns>
    /// <remarks>每个非末尾 NextEntryOffset 必须跨过当前名称和值，不能重叠或指向缓冲区外。</remarks>
    internal static IReadOnlyList<SmbExtendedAttribute> ExtendedAttributes(ReadOnlySpan<byte> data)
    {
        List<SmbExtendedAttribute> result = new();
        HashSet<string> names = new(StringComparer.OrdinalIgnoreCase);
        int position = 0;
        while (position < data.Length)
        {
            var remaining = data[position..];
            _ = Wire.Slice(remaining, 0, 8);
            uint next = Wire.U32(remaining, 0);
            int size = checked(9 + remaining[5] + Wire.U16(remaining, 6));
            // 先按本条目的 NextEntryOffset 收窄切片，禁止名称或值借用下一条目的字节。
            var entry = BoundEntry(remaining, next, size, 4);
            if (entry[4] is not (0 or 0x80) || entry[8 + entry[5]] != 0)
                throw new SmbProtocolException("Invalid extended-attribute flags or name terminator.");
            var rawName = entry.Slice(8, entry[5]);
            if (rawName.ContainsAnyInRange((byte)128, byte.MaxValue))
                throw new SmbProtocolException("An extended-attribute name is not ASCII.");
            string name = Encoding.ASCII.GetString(rawName);
            try
            {
                ValidateEaName(name);
            }
            catch (ArgumentException ex)
            {
                throw new SmbProtocolException("Invalid extended-attribute name.", ex);
            }
            if (!names.Add(name))
                throw new SmbProtocolException("Duplicate extended-attribute name.");
            result.Add(new(name, entry.Slice(9 + entry[5], Wire.U16(entry, 6)).ToArray(), entry[4] != 0));
            if (next == 0)
                break;
            position = checked(position + (int)next);
        }
        return result;
    }

    // BUFFER_OVERFLOW 响应允许合法地截断最后一个 EA 条目的变长部分。

    /// <summary>区分 BUFFER_OVERFLOW 中合法的末尾截断与非法的链偏移，供有界扩容重试使用。</summary>
    /// <param name="data">已经从 SMB 响应提取的原始信息缓冲区。</param>
    /// <returns>尾部不足以容纳声明的固定头、名称或值时为真。</returns>
    /// <remarks>该方法不把完整但内容非法的记录视作需要扩容，完整内容仍由严格解析器验证。</remarks>
    internal static bool ContainsTruncatedEa(ReadOnlySpan<byte> data)
    {
        int offset = 0;
        while (offset < data.Length)
        {
            var remaining = data[offset..];
            if (remaining.Length < 8)
                return true;
            int minimum = 9 + remaining[5] + Wire.U16(remaining, 6);
            if (remaining.Length < minimum)
                return true;
            uint next = Wire.U32(remaining, 0);
            if (next == 0)
                return false;
            if (next % 4 != 0 || next < minimum)
                throw new SmbProtocolException("Invalid EA chain offset.");
            if (next >= remaining.Length)
                throw new SmbProtocolException("Invalid EA chain offset.");
            offset = checked(offset + (int)next);
        }
        return false;
    }


    /// <summary>编码用于设置或删除的 EA 链，在分配内存前检查数量、事务总量、名称唯一性和 ushort 值上界。</summary>
    /// <param name="attributes">至少一个要修改的 EA；空值表示删除名称。</param>
    /// <param name="maximumLength">允许的总事务输入字节数。</param>
    /// <returns>含正确 NextEntryOffset、ASCII NUL 与值长度的请求数据。</returns>
    internal static byte[] EncodeExtendedAttributes(IReadOnlyList<SmbExtendedAttribute> attributes, int maximumLength)
    {
        ArgumentNullException.ThrowIfNull(attributes);
        if (attributes.Count == 0)
            throw new ArgumentException("At least one extended attribute is required.", nameof(attributes));
        if (attributes.Count > maximumLength / 10)
            throw new ArgumentOutOfRangeException(nameof(attributes), "The EA set exceeds the transaction capacity.");
        HashSet<string> names = new(StringComparer.OrdinalIgnoreCase);
        List<byte[]> encoded = new(attributes.Count);
        int total = 0;
        for (int index = 0; index < attributes.Count; index++)
        {
            var attribute = attributes[index] ?? throw new ArgumentException("An EA must not be null.", nameof(attributes));
            ValidateEaName(attribute.Name);
            if (!names.Add(attribute.Name))
                throw new ArgumentException("Duplicate extended-attribute name.", nameof(attributes));
            if (attribute.Value.Length > ushort.MaxValue)
                throw new ArgumentOutOfRangeException(nameof(attributes), "An EA value cannot exceed 65535 bytes.");
            byte[] name = Encoding.ASCII.GetBytes(attribute.Name);
            int size = 9 + name.Length + attribute.Value.Length;
            int aligned = index == attributes.Count - 1 ? size : (size + 3) & ~3;
            if (aligned > maximumLength - total)
                throw new ArgumentOutOfRangeException(nameof(attributes), "The EA set exceeds the negotiated transaction capacity.");
            byte[] entry = new byte[aligned];
            if (index != attributes.Count - 1)
                Wire.Put32(entry, 0, (uint)aligned);
            entry[4] = attribute.Required ? (byte)0x80 : (byte)0;
            entry[5] = (byte)name.Length;
            Wire.Put16(entry, 6, (ushort)attribute.Value.Length);
            name.CopyTo(entry, 8);
            attribute.Value.Span.CopyTo(entry.AsSpan(9 + name.Length));
            encoded.Add(entry);
            total += aligned;
        }
        byte[] result = new byte[total];
        int position = 0;
        foreach (byte[] entry in encoded)
        {
            entry.CopyTo(result, position);
            position += entry.Length;
        }
        return result;
    }


    /// <summary>编码 FILE_GET_EA_INFORMATION 名称筛选链，保持 ASCII 终止符与 4 字节记录对齐。</summary>
    /// <param name="names">名称不重复的 ASCII 筛选列表。</param>
    /// <param name="maximumLength">名称筛选的最大事务字节数。</param>
    /// <returns>空列表返回空缓冲区，否则返回完整筛选结构。</returns>
    internal static byte[] EncodeEaNames(IReadOnlyList<string> names, int maximumLength = 65536)
    {
        ArgumentNullException.ThrowIfNull(names);
        if (names.Count == 0)
            return [];
        if (names.Count > maximumLength / 7)
            throw new ArgumentOutOfRangeException(nameof(names), "The EA name filter exceeds the transaction capacity.");
        HashSet<string> seen = new(StringComparer.OrdinalIgnoreCase);
        using MemoryStream stream = new();
        for (int index = 0; index < names.Count; index++)
        {
            ValidateEaName(names[index]);
            if (!seen.Add(names[index]))
                throw new ArgumentException("Duplicate EA filter name.", nameof(names));
            byte[] name = Encoding.ASCII.GetBytes(names[index]);
            int size = 6 + name.Length;
            int aligned = index == names.Count - 1 ? size : (size + 3) & ~3;
            if (aligned > maximumLength - stream.Length)
                throw new ArgumentOutOfRangeException(nameof(names), "The EA name filter exceeds the transaction capacity.");
            byte[] entry = new byte[aligned];
            if (index != names.Count - 1)
                Wire.Put32(entry, 0, (uint)aligned);
            entry[4] = (byte)name.Length;
            name.CopyTo(entry, 5);
            stream.Write(entry);
        }
        return stream.ToArray();
    }


    /// <summary>按选定的目录格式解析条目链，保留该格式实际携带的元数据、短名和 64/128 位标识。</summary>
    /// <param name="data">已经从 SMB 响应提取的原始信息缓冲区。</param>
    /// <param name="informationClass">决定固定头偏移的标准 QUERY_DIRECTORY 信息类。</param>
    /// <returns>统一目录条目集合。</returns>
    /// <remarks>每个名称都只在本条目的边界内解码，防止利用后续条目字节补齐伪造的字符串。</remarks>
    internal static IReadOnlyList<SmbDirectoryInformationEntry> Directory(ReadOnlySpan<byte> data, SmbDirectoryInformationClass informationClass)
    {
        var (Header, Ea, Reparse, ShortName, Id64, Id128) = DirectoryLayout(informationClass);
        List<SmbDirectoryInformationEntry> entries = new();
        int position = 0;
        while (position < data.Length)
        {
            var remaining = data[position..];
            _ = Wire.Slice(remaining, 0, Header);
            uint next = Wire.U32(remaining, 0);
            int nameLength = Wire.Int32(Wire.U32(remaining, informationClass == SmbDirectoryInformationClass.Names ? 8 : 60));
            if (nameLength > int.MaxValue - Header)
                throw new SmbProtocolException("Oversized directory name.");
            var entry = BoundEntry(remaining, next, Header + nameLength, 8);
            string name = Wire.Text(entry, Header, nameLength);
            ValidateDirectoryName(name);
            if (informationClass == SmbDirectoryInformationClass.Names)
            {
                entries.Add(new(name, Wire.U32(entry, 4), null, null, null, null, null, null, null, null, null, null, null, null));
            }
            else
            {
                string? shortName = null;
                if (ShortName >= 0)
                {
                    byte shortLength = entry[ShortName];
                    if (shortLength > 24 || (shortLength & 1) != 0)
                        throw new SmbProtocolException("Invalid short-name length.");
                    shortName = Wire.Text(entry, ShortName + 2, shortLength);
                    if (shortName.Length != 0)
                        ValidateDirectoryName(shortName);
                }
                FileAttributes attributes = (FileAttributes)Wire.U32(entry, 56);
                SmbFileId128? id128 = Id128 < 0 ? null : new SmbFileId128(Wire.U64(entry, Id128), Wire.U64(entry, Id128 + 8));
                entries.Add(new(name, Wire.U32(entry, 4), Nonnegative(entry, 40), Nonnegative(entry, 48), attributes,
                    Time(entry, 8), Time(entry, 16), Time(entry, 24), Time(entry, 32),
                    Ea < 0 ? null : Wire.U32(entry, Ea),
                    Reparse < 0 || (attributes & FileAttributes.ReparsePoint) == 0 ? null : Wire.U32(entry, Reparse),
                    shortName, Id64 < 0 ? null : Wire.U64(entry, Id64), id128));
            }
            if (next == 0)
                break;
            position = checked(position + (int)next);
        }
        return entries;
    }


    /// <summary>返回 11 种目录格式的固定头大小及可选字段偏移，缺失字段使用负一。</summary>
    /// <param name="value">已定义的远程目录格式。</param>
    /// <returns>固定头、EA、标签、短名长度、64 位 ID 和 128 位 ID 的偏移。</returns>
    internal static (int Header, int Ea, int Reparse, int ShortName, int Id64, int Id128) DirectoryLayout(SmbDirectoryInformationClass value)
    {
        return value switch
        {
            SmbDirectoryInformationClass.Directory => (64, -1, -1, -1, -1, -1),
            SmbDirectoryInformationClass.FullDirectory => (68, 64, -1, -1, -1, -1),
            SmbDirectoryInformationClass.BothDirectory => (94, 64, -1, 68, -1, -1),
            SmbDirectoryInformationClass.Names => (12, -1, -1, -1, -1, -1),
            // 旧 IdBoth 格式在 24 字节短名后补齐至偏移 96，再放置 64 位 ID。
            SmbDirectoryInformationClass.IdBothDirectory => (104, 64, -1, 68, 96, -1),
            SmbDirectoryInformationClass.IdFullDirectory => (80, 64, -1, -1, 72, -1),
            SmbDirectoryInformationClass.IdExtdDirectory => (88, 64, 68, -1, -1, 72),
            SmbDirectoryInformationClass.Id64ExtdDirectory => (80, 64, 68, -1, 72, -1),
            SmbDirectoryInformationClass.Id64ExtdBothDirectory => (106, 64, 68, 80, 72, -1),
            SmbDirectoryInformationClass.IdAllExtdDirectory => (96, 64, 68, -1, 72, 80),
            // AllExtdBoth 顺序为基本字段、标签、64 位 ID、128 位 ID、短名头和短名；名称紧接于 122。
            SmbDirectoryInformationClass.IdAllExtdBothDirectory => (122, 64, 68, 96, 72, 80),
            _ => throw new ArgumentOutOfRangeException(nameof(value))
        };
    }


    /// <summary>编码网络扩展重命名结构，RootDirectory 固定为零，并保留结构最小 24 字节的填充。</summary>
    /// <param name="destination">非空的共享相对目标路径。</param>
    /// <param name="flags">不含未知位的扩展重命名标志。</param>
    /// <returns>FILE_RENAME_INFORMATION_EX 请求字节。</returns>
    internal static byte[] EncodeRename(string destination, SmbRenameFlags flags)
    {
        if (((uint)flags & ~0x1FFu) != 0)
            throw new ArgumentOutOfRangeException(nameof(flags));
        string normalized = SmbPath.Normalize(destination);
        if (normalized.Length == 0)
            throw new ArgumentException("A destination filename is required.", nameof(destination));
        byte[] name = Wire.Unicode.GetBytes(normalized);
        byte[] result = new byte[Math.Max(24, 20 + name.Length)];
        Wire.Put32(result, 0, (uint)flags);
        Wire.Put32(result, 16, (uint)name.Length);
        name.CopyTo(result, 20);
        return result;
    }


    /// <summary>编码 FILE_SHORT_NAME_INFORMATION，限制 UTF-16 长度并禁止路径分隔符。</summary>
    /// <param name="shortName">最长 12 个 UTF-16 单元的名称；空字符串请求移除短名。</param>
    /// <returns>长度前缀和 UTF-16 名称。</returns>
    internal static byte[] EncodeShortName(string shortName)
    {
        ArgumentNullException.ThrowIfNull(shortName);
        if (shortName.Length != 0)
        {
            try
            {
                ValidateDirectoryName(shortName);
            }
            catch (SmbProtocolException ex)
            {
                throw new ArgumentException("A short name must be a single file name.", nameof(shortName), ex);
            }
        }
        byte[] name = Wire.Unicode.GetBytes(shortName);
        if (name.Length > 24)
            throw new ArgumentException("A short name may contain at most 12 UTF-16 code units.", nameof(shortName));
        byte[] result = new byte[4 + name.Length];
        Wire.Put32(result, 0, (uint)name.Length);
        name.CopyTo(result, 4);
        return result;
    }


    /// <summary>检查 EA 名称的 1 至 254 字符 ASCII 范围及规范禁止字符，避免编码时静默替换非 ASCII 字符。</summary>
    /// <param name="name">要查询或设置的 EA 名称。</param>
    internal static void ValidateEaName(string name)
    {
        ArgumentNullException.ThrowIfNull(name);
        if (name.Length is < 1 or > 254 || name.Any(character => character is < ' ' or > '\x7F' || "\\/:*?\"<>|,+=[];".Contains(character)))
            throw new ArgumentException("An EA name must be 1 to 254 permitted ASCII characters.", nameof(name));
    }


    /// <summary>验证带 NextEntryOffset 的单个记录并收窄其可访问范围。</summary>
    /// <param name="remaining">从当前记录起到响应末尾的剩余数据。</param>
    /// <param name="next">相对本条目起点的下一条偏移；零表示末尾。</param>
    /// <param name="minimum">本条目固定字段加已声明变长字段所需的最少字节数。</param>
    /// <param name="alignment">非末尾记录所要求的 4 或 8 字节对齐。</param>
    /// <returns>限于当前记录的切片；末尾记录可包含忽略的填充。</returns>
    private static ReadOnlySpan<byte> BoundEntry(ReadOnlySpan<byte> remaining, uint next, int minimum, int alignment)
    {
        return minimum < 0 || remaining.Length < minimum ||
            (next != 0 && (next % alignment != 0 || next < minimum || next >= remaining.Length))
            ? throw new SmbProtocolException("Invalid or truncated information entry chain.")
            : next == 0 ? remaining : remaining[..(int)next];
    }


    /// <summary>拒绝空目录名称、路径分隔符、数据流分隔符与 NUL；点目录名称仍合法。</summary>
    /// <param name="name">服务器报告的单级目录条目名称。</param>
    private static void ValidateDirectoryName(string name)
    {
        if (name.Length == 0 || name.IndexOfAny(['\\', '/', '\0', ':']) >= 0)
            throw new SmbProtocolException("Invalid directory information name.");
    }


    /// <summary>读取查询结果中的非负 FILETIME，验证日期范围并把零转换为空。</summary>
    /// <param name="data">已经从 SMB 响应提取的原始信息缓冲区。</param>
    /// <param name="offset">8 字节时间字段的偏移。</param>
    /// <returns>UTC 文件时间或空值。</returns>
    private static DateTimeOffset? Time(ReadOnlySpan<byte> data, int offset)
    {
        return Wire.I64(data, offset) < 0 ? throw new SmbProtocolException("Negative file information timestamp.") : Wire.Time(data, offset);
    }


    /// <summary>读取文件长度、分配量或位置，并拒绝负值。</summary>
    /// <param name="data">已经从 SMB 响应提取的原始信息缓冲区。</param>
    /// <param name="offset">8 字节有符号字段的偏移。</param>
    /// <returns>已验证的非负数值。</returns>
    private static long Nonnegative(ReadOnlySpan<byte> data, int offset)
    {
        long value = Wire.I64(data, offset);
        return value >= 0 ? value : throw new SmbProtocolException("Negative file information size or position.");
    }


    /// <summary>读取协议布尔字段，仅接受字节零和一。</summary>
    /// <param name="data">已经从 SMB 响应提取的原始信息缓冲区。</param>
    /// <param name="offset">布尔字节偏移。</param>
    /// <returns>对应的布尔值。</returns>
    private static bool Boolean(ReadOnlySpan<byte> data, int offset)
    {
        return Wire.Slice(data, offset, 1)[0] switch
        {
            0 => false,
            1 => true,
            _ => throw new SmbProtocolException("Invalid file information Boolean.")
        };
    }
}