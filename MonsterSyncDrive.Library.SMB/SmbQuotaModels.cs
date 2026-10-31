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
using System.Globalization;
using System.Text;
using MonsterSyncDrive.SMB.Protocol;

namespace MonsterSyncDrive.SMB;

/// <summary>不依赖 Windows 身份 API 的不可变安全标识符，支持 SID 文本和网络二进制格式。</summary>
public sealed class SmbSecurityIdentifier : IEquatable<SmbSecurityIdentifier>
{
    /// <summary>私有的规范化 SID 副本；标识符授权机构采用大端，子授权值采用小端。</summary>
    private readonly byte[] binary;
    /// <summary>SID 版本；本实现仅接受协议定义的版本 1。</summary>
    public byte Revision => binary[0];
    /// <summary>六字节标识符授权机构的无符号数值。</summary>
    public ulong IdentifierAuthority { get; }
    /// <summary>只读的 32 位子授权值序列，最多 15 项。</summary>
    public IReadOnlyList<uint> SubAuthorities { get; }
    /// <summary>完整二进制 SID 的字节长度，等于 8 加上四倍的子授权数量。</summary>
    public int BinaryLength => binary.Length;
    /// <summary>供内部编码器读取的私有二进制视图；公共调用方只能取得复制后的数组。</summary>
    internal ReadOnlySpan<byte> Binary => binary;

    /// <summary>从授权机构和子授权值构造 SID，并复制调用者传入的数组。</summary>
    /// <param name="identifierAuthority">不超过 48 位的无符号授权机构值。</param>
    /// <param name="subAuthorities">最多 15 个无符号子授权值。</param>
    /// <exception cref="ArgumentNullException">子授权数组为空引用。</exception>
    /// <exception cref="ArgumentOutOfRangeException">授权机构超过 48 位，或子授权项超过 15 个。</exception>
    public SmbSecurityIdentifier(ulong identifierAuthority, params uint[] subAuthorities)
    {
        ArgumentNullException.ThrowIfNull(subAuthorities);
        if (identifierAuthority > 0xFFFFFFFFFFFFUL || subAuthorities.Length > 15)
            throw new ArgumentOutOfRangeException(nameof(identifierAuthority));
        var sub = subAuthorities.ToArray();
        binary = new byte[8 + sub.Length * 4];
        binary[0] = 1; binary[1] = (byte)sub.Length;
        // SID 的授权机构与其余多字节字段字节序不同，不能整体按普通 SMB 小端字段编码。
        for (var index = 0; index < 6; index++) binary[7 - index] = (byte)(identifierAuthority >> (index * 8));
        for (var index = 0; index < sub.Length; index++) BinaryPrimitives.WriteUInt32LittleEndian(binary.AsSpan(8 + index * 4), sub[index]);
        IdentifierAuthority = identifierAuthority;
        SubAuthorities = Array.AsReadOnly(sub);
    }

    /// <summary>从完整二进制 SID 构造不可变对象；拒绝截断记录、额外尾随字节和未知版本。</summary>
    /// <param name="binary">恰好包含一个 SID 的二进制数据。</param>
    /// <returns>拥有独立数据副本的标识符。</returns>
    /// <exception cref="ArgumentException">版本、子授权数量或总长度不合法。</exception>
    public static SmbSecurityIdentifier FromBinary(ReadOnlySpan<byte> binary)
    {
        if (binary.Length < 8 || binary[0] != 1 || binary[1] > 15 || binary.Length != 8 + binary[1] * 4)
            throw new ArgumentException("A complete revision-1 SID with at most 15 sub-authorities is required.", nameof(binary));
        ulong authority = 0;
        for (var index = 2; index < 8; index++) authority = (authority << 8) | binary[index];
        var sub = new uint[binary[1]];
        for (var index = 0; index < sub.Length; index++) sub[index] = BinaryPrimitives.ReadUInt32LittleEndian(binary[(8 + index * 4)..]);
        return new(authority, sub);
    }

    /// <summary>解析 S-1-authority-subauthority 形式的 SID；授权机构也可使用 0x 十六进制形式。</summary>
    /// <param name="value">不含前后空白的 SID 文本。</param>
    /// <returns>与文本具有相同标识符值的不可变对象。</returns>
    /// <exception cref="ArgumentNullException">文本为空引用。</exception>
    /// <exception cref="FormatException">版本、格式或任一数值超出 SID 允许范围。</exception>
    public static SmbSecurityIdentifier Parse(string value)
    {
        ArgumentNullException.ThrowIfNull(value);
        var parts = value.Split('-');
        if (parts.Length is < 3 or > 18 || !parts[0].Equals("S", StringComparison.OrdinalIgnoreCase) || parts[1] != "1")
            throw new FormatException("A SID must have the form S-1-authority-subauthority...");
        var authorityPart = parts[2];
        var hex = authorityPart.StartsWith("0x", StringComparison.OrdinalIgnoreCase);
        if (!ulong.TryParse(hex ? authorityPart.AsSpan(2) : authorityPart.AsSpan(), hex ? NumberStyles.AllowHexSpecifier : NumberStyles.None,
            CultureInfo.InvariantCulture, out var authority) || authority > 0xFFFFFFFFFFFFUL)
            throw new FormatException("The SID authority must be a 48-bit unsigned integer.");
        var sub = new uint[parts.Length - 3];
        for (var index = 0; index < sub.Length; index++)
            if (!uint.TryParse(parts[index + 3], NumberStyles.None, CultureInfo.InvariantCulture, out sub[index]))
                throw new FormatException("A SID sub-authority must be a 32-bit unsigned integer.");
        return new(authority, sub);
    }

    /// <summary>尝试解析 SID 文本；格式错误或空引用返回 false，不创建部分有效的 SID。</summary>
    /// <param name="value">待解析的文本。</param>
    /// <param name="sid">成功时为解析结果，失败时为 null。</param>
    /// <returns>文本能被完整解析时返回 true。</returns>
    public static bool TryParse(string? value, out SmbSecurityIdentifier? sid)
    {
        sid = null;
        if (value is null) return false;
        try { sid = Parse(value); return true; }
        catch (FormatException) { return false; }
    }

    /// <summary>复制并返回完整二进制 SID，修改返回数组不会改变本对象。</summary>
    /// <returns>符合 MS-DTYP SID 布局的独立数组。</returns>
    public byte[] ToArray() => binary.ToArray();
    /// <summary>按规范化二进制值比较两个 SID。</summary>
    /// <param name="other">另一个 SID，允许为 null。</param>
    /// <returns>两个非空标识符的全部字节相同时返回 true。</returns>
    public bool Equals(SmbSecurityIdentifier? other) => other is not null && binary.AsSpan().SequenceEqual(other.binary);
    /// <summary>判断对象是否为具有相同 SID 二进制值的标识符。</summary>
    /// <param name="obj">待比较对象。</param>
    /// <returns>对象类型和值均匹配时返回 true。</returns>
    public override bool Equals(object? obj) => obj is SmbSecurityIdentifier other && Equals(other);
    /// <summary>基于 SID 字节生成与值相等规则一致的进程内哈希。</summary>
    /// <returns>可用于字典或集合的哈希值，不作为稳定持久化标识。</returns>
    public override int GetHashCode()
    {
        var hash = new HashCode();
        foreach (var value in binary) hash.Add(value);
        return hash.ToHashCode();
    }
    /// <summary>生成可再次解析的十进制规范 SID 文本。</summary>
    /// <returns>S-1-authority-subauthority 形式的字符串。</returns>
    public override string ToString()
    {
        var text = new StringBuilder("S-1-");
        text.Append(IdentifierAuthority.ToString(CultureInfo.InvariantCulture));
        foreach (var sub in SubAuthorities) text.Append('-').Append(sub.ToString(CultureInfo.InvariantCulture));
        return text.ToString();
    }
}

/// <summary>MS-FSCC 为每用户配额定义的特殊有符号取值。</summary>
public static class SmbQuotaValues
{
    /// <summary>没有配额限制或警告阈值，对应网络值 -1。</summary>
    public const long Unlimited = -1;
    /// <summary>QuotaLimit 的 -2 值表示删除整个配额项，绝不表示保留原值。</summary>
    public const long DeleteEntry = -2;
}

/// <summary>服务器返回的一项用户配额及其使用量。</summary>
/// <param name="SecurityIdentifier">配额所属用户的不可变 SID。</param>
/// <param name="ChangeTime">服务器报告的配额修改时间，零时间表示为 null。</param>
/// <param name="UsedBytes">服务器报告的已使用字节数，不得为负。</param>
/// <param name="WarningThreshold">警告字节阈值；-1 表示没有阈值。</param>
/// <param name="Limit">用户配额上限；-1 表示无限制，查询结果不使用删除标记。</param>
public sealed record SmbQuotaEntry(SmbSecurityIdentifier SecurityIdentifier, DateTimeOffset? ChangeTime,
    long UsedBytes, long WarningThreshold, long Limit)
{
    /// <summary>此用户是否没有字节配额上限。</summary>
    public bool IsUnlimited => Limit == SmbQuotaValues.Unlimited;
}

/// <summary>一次明确指定警告阈值和上限的用户配额修改；保留单个字段请使用可空参数更新接口。</summary>
/// <param name="SecurityIdentifier">需要修改配额的用户 SID。</param>
/// <param name="WarningThreshold">新的非负警告阈值，或表示无阈值的 -1。</param>
/// <param name="Limit">新的非负上限、表示无限制的 -1，或表示删除整个配额项的 -2。</param>
public sealed record SmbQuotaChange(SmbSecurityIdentifier SecurityIdentifier, long WarningThreshold, long Limit)
{
    /// <summary>构造显式删除用户配额的修改，不把 -2 暴露为“保持不变”操作。</summary>
    /// <param name="sid">需要删除配额项的用户 SID。</param>
    /// <returns>上限为删除标记、警告阈值为零的修改请求。</returns>
    public static SmbQuotaChange Delete(SmbSecurityIdentifier sid) => new(sid, 0, SmbQuotaValues.DeleteEntry);
}

/// <summary>一页 SMB2_QUERY_QUOTA_INFO 查询的选择、游标及输出大小设置。</summary>
public sealed record SmbQuotaQuery
{
    /// <summary>是否要求服务器至多返回一个配额项。</summary>
    public bool ReturnSingle { get; init; }
    /// <summary>未指定 SID 列表或起点时，是否重置此打开句柄的配额枚举游标。</summary>
    public bool RestartScan { get; init; } = true;
    /// <summary>只查询这些互不重复的 SID；不能同时设置起点，也不接受空选择列表。</summary>
    public IReadOnlyList<SmbSecurityIdentifier>? SecurityIdentifiers { get; init; }
    /// <summary>从此 SID 之后继续查询；具体定位遵循服务器对起点的协议行为。</summary>
    public SmbSecurityIdentifier? StartAfter { get; init; }
    /// <summary>本页最多接受的数据字节数，须容纳至少一项且不超过协商的事务上限。</summary>
    public int MaximumOutput { get; init; } = 65536;
}

/// <summary>一次配额查询返回的只读条目及枚举状态。</summary>
/// <param name="Entries">本页已经完整解析的条目；结束响应返回空集合。</param>
/// <param name="EndOfEnumeration">服务器明确返回没有更多条目或没有匹配项。</param>
/// <param name="BufferOverflow">服务器报告本页输出不足，调用方仍需继续查询。</param>
public sealed record SmbQuotaPage(IReadOnlyList<SmbQuotaEntry> Entries, bool EndOfEnumeration, bool BufferOverflow);

/// <summary>服务器报告的卷配额跟踪、强制执行、日志及重建状态。</summary>
[Flags]
public enum SmbVolumeQuotaFlags : uint
{
    /// <summary>未设置已知配额控制标志。</summary>
    None = 0,
    /// <summary>仅跟踪用量；与 Enforce 同时存在时，本标志优先且不执行限制。</summary>
    Track = 1,
    /// <summary>服务器执行配额限制；没有 Track 标志时才按强制状态解释。</summary>
    Enforce = 2,
    /// <summary>禁用卷内容索引。</summary>
    ContentIndexDisabled = 8,
    /// <summary>用户超过警告阈值时记录事件。</summary>
    LogQuotaThreshold = 0x10,
    /// <summary>用户超过配额上限时记录事件。</summary>
    LogQuotaLimit = 0x20,
    /// <summary>卷空闲空间低于阈值时记录事件。</summary>
    LogVolumeThreshold = 0x40,
    /// <summary>卷空闲空间超过限制条件时记录事件。</summary>
    LogVolumeLimit = 0x80,
    /// <summary>服务器的配额信息尚不完整或存在损坏。</summary>
    Incomplete = 0x100,
    /// <summary>服务器正在重建配额信息。</summary>
    Rebuilding = 0x200
}

/// <summary>允许远程设置的卷配额标志；不包含只能由服务器管理的跟踪、强制执行和重建状态。</summary>
[Flags]
public enum SmbVolumeQuotaSettingsFlags : uint
{
    /// <summary>不启用已知的索引或日志设置。</summary>
    None = 0,
    /// <summary>请求禁用卷内容索引。</summary>
    ContentIndexDisabled = 8,
    /// <summary>请求记录用户超过配额警告阈值的事件。</summary>
    LogQuotaThreshold = 0x10,
    /// <summary>请求记录用户超过配额上限的事件。</summary>
    LogQuotaLimit = 0x20,
    /// <summary>请求记录卷空闲空间阈值事件。</summary>
    LogVolumeThreshold = 0x40,
    /// <summary>请求记录卷空闲空间限制事件。</summary>
    LogVolumeLimit = 0x80
}

/// <summary>服务器通过 FileFsControlInformation 报告的默认用户配额和控制状态。</summary>
/// <param name="DefaultWarningThreshold">默认警告字节数；ulong.MaxValue 表示无默认阈值。</param>
/// <param name="DefaultLimit">默认配额字节数；ulong.MaxValue 表示无默认上限。</param>
/// <param name="Flags">包含只读服务器状态及可写日志设置的原始标志。</param>
public sealed record SmbVolumeQuotaControl(ulong DefaultWarningThreshold, ulong DefaultLimit, SmbVolumeQuotaFlags Flags)
{
    /// <summary>服务器是否没有设置默认用户配额上限。</summary>
    public bool HasUnlimitedDefault => DefaultLimit == ulong.MaxValue;
    /// <summary>服务器是否正在跟踪用量，包括仅跟踪和强制执行两种模式。</summary>
    public bool IsTracking => (Flags & (SmbVolumeQuotaFlags.Track | SmbVolumeQuotaFlags.Enforce)) != 0;
    /// <summary>是否仅设置强制执行标志；协议规定 Track 和 Enforce 同时存在时 Track 优先。</summary>
    public bool IsEnforced => (Flags & SmbVolumeQuotaFlags.Enforce) != 0 && (Flags & SmbVolumeQuotaFlags.Track) == 0;
}

/// <summary>可通过远程文件系统信息接口设置的默认配额和日志配置，不用于启用配额执行。</summary>
public sealed record SmbVolumeQuotaSettings
{
    /// <summary>新的默认用户警告字节数；ulong.MaxValue 表示无默认警告阈值。</summary>
    public ulong DefaultWarningThreshold { get; init; } = ulong.MaxValue;
    /// <summary>新的默认用户配额上限；ulong.MaxValue 表示无限制。</summary>
    public ulong DefaultLimit { get; init; } = ulong.MaxValue;
    /// <summary>新的可写索引及日志标志，不接受跟踪、执行或重建状态位。</summary>
    public SmbVolumeQuotaSettingsFlags Flags { get; init; }
}

/// <summary>实现 SID 选择、八字节对齐配额链和固定卷控制记录的边界检查与编解码。</summary>
internal static class SmbQuotaCodec
{
    /// <summary>编码 SMB2_QUERY_QUOTA_INFO，互斥处理明确 SID 列表和起始 SID。</summary>
    /// <param name="query">需要编码的选择和游标设置。</param>
    /// <param name="maximumInput">本次协商允许的最大输入数据长度。</param>
    /// <returns>含 16 字节头及 SID 缓冲区的完整查询输入。</returns>
    /// <exception cref="ArgumentException">选择重复、为空、与起点冲突或超过输入上限。</exception>
    internal static byte[] BuildQuery(SmbQuotaQuery query, int maximumInput)
    {
        ArgumentNullException.ThrowIfNull(query);
        var sids = query.SecurityIdentifiers?.ToArray();
        if (sids is not null && (sids.Length == 0 || query.StartAfter is not null))
            throw new ArgumentException("Supply either a nonempty SID list or a start SID.", nameof(query));
        if (sids is not null && (sids.Any(sid => sid is null) || sids.Distinct().Count() != sids.Length))
            throw new ArgumentException("SID selections must contain distinct non-null SIDs.", nameof(query));
        // 明确 SID 列表使用 FILE_GET_QUOTA_INFORMATION 的四字节链对齐，
        // 与查询结果 FILE_QUOTA_INFORMATION 的八字节链对齐不同。
        var length = 16;
        if (sids is not null)
            for (var index = 0; index < sids.Length; index++)
                length = checked(length + (index + 1 == sids.Length ? 8 + sids[index].BinaryLength : Align4(8 + sids[index].BinaryLength)));
        else if (query.StartAfter is not null) length = checked(length + query.StartAfter.BinaryLength);
        if (length > maximumInput)
            throw new ArgumentException("The quota selection exceeds the negotiated input size. Use GetQuotasAsync for batching.", nameof(query));
        var data = new byte[length];
        data[0] = query.ReturnSingle ? (byte)1 : (byte)0;
        data[1] = query.RestartScan ? (byte)1 : (byte)0;
        if (sids is not null)
        {
            Wire.Put32(data, 4, (uint)(length - 16));
            var position = 16;
            for (var index = 0; index < sids.Length; index++)
            {
                var size = 8 + sids[index].BinaryLength;
                var next = index + 1 == sids.Length ? 0 : Align4(size);
                Wire.Put32(data, position, (uint)next);
                Wire.Put32(data, position + 4, (uint)sids[index].BinaryLength);
                sids[index].Binary.CopyTo(data.AsSpan(position + 8));
                position += next == 0 ? size : next;
            }
        }
        else if (query.StartAfter is not null)
        {
            // StartSidOffset 从 SidBuffer 开头计数，而不是从 SMB 头或这 16 字节头计数；零即紧邻头之后。
            Wire.Put32(data, 8, (uint)query.StartAfter.BinaryLength);
            query.StartAfter.Binary.CopyTo(data.AsSpan(16));
        }
        return data;
    }

    /// <summary>解码八字节对齐的 FILE_QUOTA_INFORMATION 链，并检查 SID、长度、时间和配额哨兵值。</summary>
    /// <param name="data">一个查询响应返回的完整配额数据区。</param>
    /// <returns>不可修改的完整条目集合，不接受半条截断记录。</returns>
    /// <exception cref="SmbProtocolException">链偏移无效、SID 重复、记录截断或字段值非法。</exception>
    internal static IReadOnlyList<SmbQuotaEntry> ParseEntries(ReadOnlySpan<byte> data)
    {
        var entries = new List<SmbQuotaEntry>();
        var seen = new HashSet<SmbSecurityIdentifier>();
        var position = 0;
        while (position < data.Length)
        {
            var entry = data[position..];
            Wire.Slice(entry, 0, 40);
            var next = Wire.U32(entry, 0);
            var sidLength = Wire.U32(entry, 4);
            // next 是相对当前条目的偏移；必须覆盖本条 SID 且严格前进，避免重叠、越界或循环。
            if (sidLength is < 8 or > 68 || sidLength > entry.Length - 40 ||
                (next != 0 && (next % 8 != 0 || next < 40 + sidLength || next >= entry.Length)))
                throw new SmbProtocolException("Invalid quota entry length or linked offset.");
            SmbSecurityIdentifier sid;
            try { sid = SmbSecurityIdentifier.FromBinary(entry.Slice(40, (int)sidLength)); }
            catch (ArgumentException error) { throw new SmbProtocolException("Invalid quota SID.", error); }
            var changeTime = Wire.I64(entry, 8);
            var used = Wire.I64(entry, 16);
            var threshold = Wire.I64(entry, 24);
            var limit = Wire.I64(entry, 32);
            // 查询结果只允许 -1 表示无限制；-2 仅可出现在设置请求的 QuotaLimit 中，不能当成查询值。
            if (changeTime < 0 || used < 0 || threshold < SmbQuotaValues.Unlimited || limit < SmbQuotaValues.Unlimited || !seen.Add(sid))
                throw new SmbProtocolException("Invalid or duplicate quota entry.");
            entries.Add(new(sid, Wire.Time(entry, 8), used, threshold, limit));
            if (next == 0)
            {
                if (entry.Length - 40 - sidLength > 7)
                    throw new SmbProtocolException("Unexpected trailing quota information.");
                break;
            }
            position += (int)next;
        }
        return entries.AsReadOnly();
    }

    /// <summary>编码显式用户配额修改链，时间和用量字段置零，由服务器忽略或自行维护。</summary>
    /// <param name="changes">包含互不重复 SID 的修改集合。</param>
    /// <param name="maximumInput">允许的最大输入数据长度；过大时不执行隐式的部分批量修改。</param>
    /// <returns>可直接用于 SMB2 SET_INFO 配额类型的数据区。</returns>
    /// <exception cref="ArgumentException">集合为空、SID 重复、配额值无效或整个批次超过上限。</exception>
    internal static byte[] EncodeChanges(IReadOnlyList<SmbQuotaChange> changes, int maximumInput)
    {
        ArgumentNullException.ThrowIfNull(changes);
        if (changes.Count == 0) throw new ArgumentException("At least one quota change is required.", nameof(changes));
        var items = changes.ToArray();
        var seen = new HashSet<SmbSecurityIdentifier>();
        var length = 0;
        for (var index = 0; index < items.Length; index++)
        {
            var item = items[index];
            ArgumentNullException.ThrowIfNull(item);
            ArgumentNullException.ThrowIfNull(item.SecurityIdentifier);
            if (item.WarningThreshold < SmbQuotaValues.Unlimited || item.Limit < SmbQuotaValues.DeleteEntry || !seen.Add(item.SecurityIdentifier))
                throw new ArgumentException("Quota changes require valid limits and distinct SIDs.", nameof(changes));
            length = checked(length + (index + 1 == items.Length ? 40 + item.SecurityIdentifier.BinaryLength : Wire.Align8(40 + item.SecurityIdentifier.BinaryLength)));
        }
        if (length > maximumInput) throw new ArgumentException("Quota changes exceed the negotiated input size; submit smaller explicit batches.", nameof(changes));
        // 先完整校验整个批次，再分配及编码；避免发现后续无效项前已经发出一部分远端设置。
        var data = new byte[length];
        var position = 0;
        for (var index = 0; index < items.Length; index++)
        {
            var item = items[index];
            var size = 40 + item.SecurityIdentifier.BinaryLength;
            var next = index + 1 == items.Length ? 0 : Wire.Align8(size);
            Wire.Put32(data, position, (uint)next);
            Wire.Put32(data, position + 4, (uint)item.SecurityIdentifier.BinaryLength);
            Wire.PutI64(data, position + 24, item.WarningThreshold);
            Wire.PutI64(data, position + 32, item.Limit);
            item.SecurityIdentifier.Binary.CopyTo(data.AsSpan(position + 40));
            position += next == 0 ? size : next;
        }
        return data;
    }

    /// <summary>解码固定 48 字节卷配额控制记录，保留服务器报告的未知状态位。</summary>
    /// <param name="data">FileFsControlInformation 数据区。</param>
    /// <returns>默认配额值及服务器控制标志。</returns>
    /// <exception cref="SmbProtocolException">记录不足固定长度。</exception>
    internal static SmbVolumeQuotaControl ParseVolumeControl(ReadOnlySpan<byte> data)
    {
        Wire.Slice(data, 0, 48);
        return new(Wire.U64(data, 24), Wire.U64(data, 32), (SmbVolumeQuotaFlags)Wire.U32(data, 40));
    }

    /// <summary>编码可远程设置的卷默认配额和日志项，所有保留、已废弃及只读状态字段置零。</summary>
    /// <param name="settings">只包含可写设置的配置对象。</param>
    /// <returns>固定 48 字节控制记录。</returns>
    /// <exception cref="ArgumentException">调用者通过数值强转传入不允许设置的标志位。</exception>
    internal static byte[] EncodeVolumeSettings(SmbVolumeQuotaSettings settings)
    {
        ArgumentNullException.ThrowIfNull(settings);
        if (((uint)settings.Flags & ~0xF8u) != 0)
            throw new ArgumentException("Only logging and content-index settings are remotely writable. Quota enforcement status is server-controlled.", nameof(settings));
        // 前 24 字节的旧内容索引阈值按规范置零；TRACK/ENFORCE/重建位不能通过此结构远程启用。
        var data = new byte[48];
        Wire.Put64(data, 24, settings.DefaultWarningThreshold);
        Wire.Put64(data, 32, settings.DefaultLimit);
        Wire.Put32(data, 40, (uint)settings.Flags);
        return data;
    }

    /// <summary>按配额 SID 选择链要求把长度向上对齐到四字节边界，并保留整数溢出检查。</summary>
    /// <param name="value">待对齐的非负记录字节数。</param>
    /// <returns>大于等于原值的最近四字节倍数。</returns>
    private static int Align4(int value) => checked((value + 3) & ~3);
}