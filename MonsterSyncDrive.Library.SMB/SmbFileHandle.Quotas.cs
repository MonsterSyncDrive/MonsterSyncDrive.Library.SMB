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
using System.Runtime.CompilerServices;

namespace MonsterSyncDrive.Library.SMB;

/// <summary>用户配额专用索引句柄的查询及修改，以及普通卷句柄可用的默认配额控制操作。</summary>
public sealed partial class SmbFileHandle
{
    /// <summary>当前句柄是否是通过 OpenQuotaControlAsync 打开的专用用户配额控制句柄。</summary>
    public bool IsQuotaControlHandle
    {
        get; private set;
    }
    /// <summary>专用配额句柄是否在打开时显式请求了写数据权限；服务器仍可能拒绝管理操作。</summary>
    public bool IsQuotaControlWritable => IsQuotaControlHandle && (OpenOptions.Access & SmbAccessMask.WriteData) != 0;
    /// <summary>保护此打开句柄的服务器配额枚举游标；整个异步枚举期间持有该门。</summary>
    private readonly SemaphoreSlim quotaGate = new(1, 1);
    /// <summary>服务器明确表示配额枚举没有更多条目的 NTSTATUS 值。</summary>
    private const SmbStatus QuotaNoMoreEntries = (SmbStatus)0x8000001A;

    /// <summary>查询一页用户配额；连续枚举状态属于当前已打开的配额控制句柄。</summary>
    /// <param name="query">SID 选择、是否重启以及输出上限；省略时从头查询全部配额。</param>
    /// <param name="cancellationToken">取消等待配额锁或网络请求的令牌。</param>
    /// <returns>完整解析的配额页及服务器结束标志。</returns>
    /// <exception cref="InvalidOperationException">句柄不是通过专用配额打开接口建立的控制句柄。</exception>
    /// <exception cref="ArgumentException">查询选择或输出上限无效。</exception>
    /// <exception cref="SmbException">服务器不支持配额、拒绝访问或报告其他错误。</exception>
    public async Task<SmbQuotaPage> GetQuotaPageAsync(SmbQuotaQuery? query = null, CancellationToken cancellationToken = default)
    {
        EnsureQuotaControlHandle();
        query = SnapshotQuotaQuery(query ?? new());
        await quotaGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            return await GetQuotaPageCoreAsync(query, cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            _ = quotaGate.Release();
        }
    }

    /// <summary>
    /// 通过专用配额控制句柄逐页枚举用户配额，在枚举释放前独占此句柄的配额游标。
    /// </summary>
    /// <param name="maximumOutput">每页最多接受的字节数。</param>
    /// <param name="startAfter">可选的起始 SID；后续页面使用服务器句柄上的连续游标。</param>
    /// <param name="maximumEntries">允许返回的最大条目数，防止异常服务器导致无界扫描。</param>
    /// <param name="cancellationToken">取消枚举及等待的令牌。</param>
    /// <returns>按服务器枚举顺序产生的配额条目。</returns>
    /// <remarks>同一句柄上的其他配额调用会等待此枚举结束或释放；请及时释放异步枚举器。</remarks>
    /// <exception cref="SmbProtocolException">服务器重复返回 SID、无法前进或超过调用者条目上限。</exception>
    public async IAsyncEnumerable<SmbQuotaEntry> EnumerateQuotasAsync(int maximumOutput = 65536,
        SmbSecurityIdentifier? startAfter = null, int maximumEntries = 1_000_000,
        [EnumeratorCancellation] CancellationToken cancellationToken = default)
    {
        EnsureQuotaControlHandle();
        if (maximumEntries < 1)
            throw new ArgumentOutOfRangeException(nameof(maximumEntries));
        SmbQuotaQuery query = SnapshotQuotaQuery(new()
        {
            MaximumOutput = maximumOutput,
            StartAfter = startAfter
        });
        await quotaGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            HashSet<SmbSecurityIdentifier> seen = new();
            while (true)
            {
                SmbQuotaPage page = await GetQuotaPageCoreAsync(query, cancellationToken).ConfigureAwait(false);
                if (page.EndOfEnumeration)
                    yield break;
                foreach (SmbQuotaEntry entry in page.Entries)
                {
                    yield return !seen.Add(entry.SecurityIdentifier)
                        ? throw new SmbProtocolException("Quota enumeration did not make progress or repeated a SID.")
                        : seen.Count > maximumEntries ? throw new SmbProtocolException("Quota enumeration exceeded the caller's entry limit.") : entry;
                }
                // 起始 SID 只用于首个请求；继续发送同一 StartAfter 会反复定位，不能代替服务器游标续页。
                query = query with
                {
                    RestartScan = false,
                    StartAfter = null
                };
            }
        }
        finally
        {
            _ = quotaGate.Release();
        }
    }

    /// <summary>查询一个 SID 的配额，保留服务器为未知 SID 返回的全零记录。</summary>
    /// <param name="sid">需要查询的用户 SID。</param>
    /// <param name="cancellationToken">取消查询的令牌。</param>
    /// <returns>服务器返回的条目；服务器明确没有匹配项时为 null。</returns>
    /// <exception cref="ArgumentNullException">SID 为空引用。</exception>
    /// <exception cref="SmbProtocolException">服务器返回选择之外的 SID 或多于一个条目。</exception>
    public async Task<SmbQuotaEntry?> GetQuotaAsync(SmbSecurityIdentifier sid, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(sid);
        SmbQuotaPage page = await GetQuotaPageAsync(new()
        {
            SecurityIdentifiers = [sid],
            ReturnSingle = true
        }, cancellationToken).ConfigureAwait(false);
        return page.Entries.Count == 0 ? null : page.Entries[0];
    }

    /// <summary>批量查询明确的 SID 集合，按输入大小分批并从剩余集合中移除已返回的 SID。</summary>
    /// <param name="securityIdentifiers">互不重复且非空的 SID；空集合直接返回空结果。</param>
    /// <param name="maximumOutput">每次网络查询的输出上限。</param>
    /// <param name="cancellationToken">取消等待和网络查询的令牌。</param>
    /// <returns>按调用方 SID 输入顺序排列的完整结果。</returns>
    /// <exception cref="ArgumentException">包含空 SID、重复 SID 或无效的输出大小。</exception>
    /// <exception cref="SmbProtocolException">服务器返回意外 SID 或明确选择无法继续取得结果。</exception>
    public async Task<IReadOnlyList<SmbQuotaEntry>> GetQuotasAsync(IReadOnlyList<SmbSecurityIdentifier> securityIdentifiers,
        int maximumOutput = 65536, CancellationToken cancellationToken = default)
    {
        EnsureQuotaControlHandle();
        ArgumentNullException.ThrowIfNull(securityIdentifiers);
        SmbSecurityIdentifier[] selected = securityIdentifiers.ToArray();
        if (selected.Length == 0)
            return Array.Empty<SmbQuotaEntry>();
        if (selected.Any(sid => sid is null) || selected.Distinct().Count() != selected.Length)
            throw new ArgumentException("Quota selections require distinct non-null SIDs.", nameof(securityIdentifiers));
        _ = SnapshotQuotaQuery(new()
        {
            MaximumOutput = maximumOutput
        });
        await quotaGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            // SID 列表查询不依赖枚举游标。每次只发送尚未返回的选择，避免小输出缓冲反复返回第一页。
            Dictionary<SmbSecurityIdentifier, SmbQuotaEntry> results = new();
            List<SmbSecurityIdentifier> remaining = selected.ToList();
            while (remaining.Count != 0)
            {
                List<SmbSecurityIdentifier> batch = new();
                var size = 16;
                foreach (SmbSecurityIdentifier? sid in remaining)
                {
                    if (size + 8 + sid.BinaryLength > TransactionSize)
                        break;
                    batch.Add(sid);
                    size += 8 + sid.BinaryLength;
                }
                SmbQuotaPage page = await GetQuotaPageCoreAsync(new()
                {
                    MaximumOutput = maximumOutput,
                    SecurityIdentifiers = batch
                }, cancellationToken).ConfigureAwait(false);
                if (page.EndOfEnumeration || page.Entries.Count == 0)
                    throw new SmbProtocolException("The server did not return quota data for an explicit SID selection.");
                foreach (SmbQuotaEntry entry in page.Entries)
                {
                    if (!remaining.Remove(entry.SecurityIdentifier) || !results.TryAdd(entry.SecurityIdentifier, entry))
                        throw new SmbProtocolException("The server returned an unexpected quota SID.");
                }
            }
            return Array.AsReadOnly(selected.Select(sid => results[sid]).ToArray());
        }
        finally
        {
            _ = quotaGate.Release();
        }
    }

    /// <summary>在一个 SET_INFO 请求中设置明确的用户配额值，需要服务器授予配额管理权限。</summary>
    /// <param name="changes">完整修改批次；超出事务上限时失败，不隐式部分提交。</param>
    /// <param name="cancellationToken">取消等待和请求的令牌；不回滚服务器已经执行的修改。</param>
    /// <returns>服务器确认设置完成的任务。</returns>
    /// <exception cref="InvalidOperationException">句柄不是显式可写的配额控制句柄。</exception>
    /// <exception cref="ArgumentException">修改项、SID、阈值或批次大小无效。</exception>
    /// <exception cref="SmbException">服务器不支持配额或拒绝修改。</exception>
    public async Task SetQuotasAsync(IReadOnlyList<SmbQuotaChange> changes, CancellationToken cancellationToken = default)
    {
        EnsureQuotaControlHandle(writable: true);
        var data = SmbQuotaCodec.EncodeChanges(changes, TransactionSize);
        await quotaGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            await SetInfoAsync(SmbInfoType.Quota, 0, data, cancellationToken: cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            _ = quotaGate.Release();
        }
    }

    /// <summary>
    /// 先查询再设置配额，将 null 参数解释为保留当前报告值；该流程不与其他客户端的修改原子协调。
    /// </summary>
    /// <param name="sid">需要更新配额的用户 SID。</param>
    /// <param name="warningThreshold">新的非负警告阈值或 -1；null 表示读取并保留当前值。</param>
    /// <param name="limit">新的非负上限或 -1；null 表示保留当前值，不接受删除标记 -2。</param>
    /// <param name="cancellationToken">取消查询、等待或设置的令牌。</param>
    /// <returns>完成查询和后续设置的任务。</returns>
    /// <exception cref="ArgumentException">两个可选参数均未指定。</exception>
    /// <exception cref="ArgumentOutOfRangeException">阈值或上限小于 -1。</exception>
    public async Task UpdateQuotaAsync(SmbSecurityIdentifier sid, long? warningThreshold = null, long? limit = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(sid);
        if (warningThreshold is null && limit is null)
            throw new ArgumentException("Specify a warning threshold or quota limit.");
        if (warningThreshold < SmbQuotaValues.Unlimited || limit < SmbQuotaValues.Unlimited)
            throw new ArgumentOutOfRangeException(nameof(limit));
        EnsureQuotaControlHandle(writable: true);
        await quotaGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            SmbQuotaPage page = await GetQuotaPageCoreAsync(new()
            {
                SecurityIdentifiers = [sid],
                ReturnSingle = true
            }, cancellationToken).ConfigureAwait(false);
            // 协议没有“保持不变”的写入哨兵；尤其 -2 表示删除，不能用它代替 null。
            SmbQuotaEntry? current = page.Entries.FirstOrDefault();
            SmbQuotaChange change = new(sid, warningThreshold ?? current?.WarningThreshold ?? SmbQuotaValues.Unlimited,
                limit ?? current?.Limit ?? SmbQuotaValues.Unlimited);
            var data = SmbQuotaCodec.EncodeChanges([change], TransactionSize);
            await SetInfoAsync(SmbInfoType.Quota, 0, data, cancellationToken: cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            _ = quotaGate.Release();
        }
    }

    /// <summary>使用 QuotaLimit=-2 显式删除用户配额项，不等同于将上限改为无限制。</summary>
    /// <param name="sid">需要删除配额项的用户 SID。</param>
    /// <param name="cancellationToken">取消等待或设置的令牌。</param>
    /// <returns>服务器确认删除配额设置的任务。</returns>
    /// <exception cref="SmbException">服务器拒绝配额管理操作。</exception>
    public Task DeleteQuotaAsync(SmbSecurityIdentifier sid, CancellationToken cancellationToken = default)
    {
        return SetQuotasAsync([SmbQuotaChange.Delete(sid)], cancellationToken);
    }

    /// <summary>查询当前句柄所在卷的默认用户配额、日志配置和配额执行状态。</summary>
    /// <param name="cancellationToken">取消信息查询的令牌。</param>
    /// <returns>服务器报告的卷配额控制信息，包含只能由服务器管理的状态位。</returns>
    /// <exception cref="SmbException">卷不支持该信息类或服务器拒绝访问。</exception>
    public async Task<SmbVolumeQuotaControl> GetVolumeQuotaControlAsync(CancellationToken cancellationToken = default)
    {
        var data = await QueryInfoAsync(SmbInfoType.FileSystem, 6, maximumOutput: 48,
            cancellationToken: cancellationToken).ConfigureAwait(false);
        return SmbQuotaCodec.ParseVolumeControl(data);
    }

    /// <summary>
    /// 设置可远程写入的默认用户配额和日志配置，并重新查询服务器实际报告的状态。
    /// </summary>
    /// <param name="settings">新的默认警告阈值、上限及可写标志。</param>
    /// <param name="cancellationToken">取消设置或重新查询的令牌。</param>
    /// <returns>设置后的服务器报告值，不推定服务器接受了所有可选设置。</returns>
    /// <remarks>跟踪、强制执行和重建状态由服务器控制，不能使用此结构启用；取消后修改可能已执行。</remarks>
    /// <exception cref="ArgumentException">设置含只读或未知标志。</exception>
    /// <exception cref="SmbException">服务器拒绝管理权限、设置或后续查询。</exception>
    public async Task<SmbVolumeQuotaControl> SetVolumeQuotaControlAsync(SmbVolumeQuotaSettings settings,
        CancellationToken cancellationToken = default)
    {
        var data = SmbQuotaCodec.EncodeVolumeSettings(settings);
        await SetInfoAsync(SmbInfoType.FileSystem, 6, data, cancellationToken: cancellationToken).ConfigureAwait(false);
        return await GetVolumeQuotaControlAsync(cancellationToken).ConfigureAwait(false);
    }

    /// <summary>校验查询大小并复制 SID 选择数组，使调用方后续修改不改变等待中的请求。</summary>
    /// <param name="query">需要验证和快照的查询配置。</param>
    /// <returns>拥有独立 SID 选择列表的配置。</returns>
    /// <exception cref="ArgumentException">输出不能容纳条目、超过事务上限或选择无效。</exception>
    private SmbQuotaQuery SnapshotQuotaQuery(SmbQuotaQuery query)
    {
        if (query.MaximumOutput < 48 || query.MaximumOutput > TransactionSize)
            throw new ArgumentOutOfRangeException(nameof(query), "Quota output must fit the negotiated transaction and contain an entry.");
        SmbQuotaQuery result = query with
        {
            SecurityIdentifiers = query.SecurityIdentifiers?.ToArray()
        };
        _ = SmbQuotaCodec.BuildQuery(result, TransactionSize);
        return result;
    }

    /// <summary>在调用方持有配额门时编码和发送 QUERY_INFO，并解码结束状态或完整配额记录链。</summary>
    /// <param name="query">已快照且大小有效的查询配置。</param>
    /// <param name="cancellationToken">取消本次网络请求的令牌。</param>
    /// <returns>经过 SID 选择、数量和缓冲边界校验的一页结果。</returns>
    /// <exception cref="InvalidOperationException">句柄不是用户配额专用控制句柄。</exception>
    /// <exception cref="SmbProtocolException">成功回复为空、超长，或包含错误数量和 SID。</exception>
    private async Task<SmbQuotaPage> GetQuotaPageCoreAsync(SmbQuotaQuery query, CancellationToken cancellationToken)
    {
        EnsureQuotaControlHandle();
        var input = SmbQuotaCodec.BuildQuery(query, TransactionSize);
        var body = new byte[40 + input.Length];
        Wire.Put16(body, 0, 41);
        body[2] = (byte)SmbInfoType.Quota;
        Wire.Put32(body, 4, (uint)query.MaximumOutput);
        Wire.Put16(body, 8, 104);
        Wire.Put32(body, 12, (uint)input.Length);
        Id.Write(body, 24);
        input.CopyTo(body, 40);
        Response response = await Share.SendAsync(Command.QueryInfo, body, cancellationToken, query.MaximumOutput).ConfigureAwait(false);
        // NO_MORE_ENTRIES/NO_SUCH_FILE 是明确的结束信号；SUCCESS 下空输出并不等价，应作为协议错误。
        response.EnsureSuccess(QuotaNoMoreEntries, SmbStatus.NoSuchFile, SmbStatus.BufferOverflow);
        if (response.Status is QuotaNoMoreEntries or SmbStatus.NoSuchFile)
            return new(Array.Empty<SmbQuotaEntry>(), true, false);
        Wire.Structure(response.Packet, 9, 8);
        var length = Wire.U32(response.Packet, 68);
        if (length == 0 || length > query.MaximumOutput)
            throw new SmbProtocolException("The quota response was empty or exceeded the requested size.");
        var data = Wire.Buffer(response.Packet, Wire.U16(response.Packet, 66), length, 72);
        IReadOnlyList<SmbQuotaEntry> entries = SmbQuotaCodec.ParseEntries(data);
        return entries.Count == 0 || (query.ReturnSingle && entries.Count > 1)
            ? throw new SmbProtocolException("The server returned an invalid number of quota entries.")
            : query.SecurityIdentifiers is { } selection && entries.Any(entry => !selection.Contains(entry.SecurityIdentifier))
            ? throw new SmbProtocolException("The server returned a quota SID outside the selection.")
            : new(entries, false, response.Status == SmbStatus.BufferOverflow);
    }

    /// <summary>在统一 CREATE 流程尚未向调用方发布句柄时，将其标记为保留配额索引用途。</summary>
    internal void InitializeQuotaControlHandle()
    {
        IsQuotaControlHandle = true;
    }

    /// <summary>在任何用户配额网络请求之前校验句柄用途以及显式写入授权请求。</summary>
    /// <param name="writable">是否要求调用者在打开专用句柄时选择可写模式。</param>
    /// <exception cref="InvalidOperationException">使用普通文件、普通目录或只读配额句柄执行不允许的操作。</exception>
    private void EnsureQuotaControlHandle(bool writable = false)
    {
        ThrowIfClosed();
        if (!IsQuotaControlHandle)
            throw new InvalidOperationException("Open the reserved quota control stream with SmbShare.OpenQuotaControlAsync before querying user quotas.");
        if (writable && !IsQuotaControlWritable)
            throw new InvalidOperationException("Quota changes require a quota control handle opened with writable=true.");
    }
}
