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
using MonsterSyncDrive.SMB.Protocol;

namespace MonsterSyncDrive.SMB;

/// <summary>远端文件句柄的分配信息查询、分配设置和结果核对操作。</summary>
public sealed partial class SmbFileHandle
{
    /// <summary>重新查询服务器的分配量和 EOF，不使用打开时的长度快照。</summary>
    /// <param name="cancellationToken">取消本次信息查询的令牌。</param>
    /// <returns>服务器当前报告的标准分配信息。</returns>
    /// <exception cref="SmbException">服务器拒绝查询或不支持该信息类。</exception>
    /// <exception cref="SmbProtocolException">服务器返回的记录截断或含无效字段。</exception>
    public async Task<SmbFileAllocationInfo> GetAllocationInfoAsync(CancellationToken cancellationToken = default)
    {
        var data = await QueryInfoAsync(SmbInfoType.File, 5, maximumOutput: 24,
            cancellationToken: cancellationToken).ConfigureAwait(false);
        return ParseAllocationInfo(data);
    }

    /// <summary>解码 FileStandardInformation 的固定部分，拒绝负数长度和非法布尔状态。</summary>
    /// <param name="data">至少包含 24 字节的标准文件信息数据。</param>
    /// <returns>分配量、逻辑长度、链接数量和目录状态。</returns>
    /// <exception cref="SmbProtocolException">记录不足 24 字节或字段值违反协议约束。</exception>
    internal static SmbFileAllocationInfo ParseAllocationInfo(ReadOnlySpan<byte> data)
    {
        Wire.Slice(data, 0, 24);
        var allocation = Wire.I64(data, 0);
        var eof = Wire.I64(data, 8);
        if (allocation < 0 || eof < 0 || data[20] > 1 || data[21] > 1)
            throw new SmbProtocolException("The server returned invalid standard file allocation information.");
        return new(allocation, eof, Wire.U32(data, 16), data[20] != 0, data[21] != 0);
    }

    /// <summary>
    /// 设置 FileAllocationInformation，并在确认后查询服务器报告的分配量和逻辑长度。
    /// </summary>
    /// <param name="requestedSize">请求分配的非负字节数；小于 EOF 时可能截断现有数据。</param>
    /// <param name="requireReportedAllocation">为 true 时要求重新报告的分配量达到请求值，否则抛出异常。</param>
    /// <param name="cancellationToken">取消查询或设置的令牌；取消不回滚已执行的设置。</param>
    /// <returns>请求值及前后两次观察值；并发访问可能影响观察结果。</returns>
    /// <remarks>服务器确认仅表示接受请求；本方法不证明底层介质已实际预留磁盘块。</remarks>
    /// <exception cref="ArgumentOutOfRangeException">请求量为负数。</exception>
    /// <exception cref="IOException">要求核对分配量但服务器报告量不足；此时请求可能已经执行。</exception>
    /// <exception cref="SmbException">服务器拒绝查询或分配设置。</exception>
    public async Task<SmbAllocationResult> AllocateAsync(long requestedSize, bool requireReportedAllocation = false,
        CancellationToken cancellationToken = default)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(requestedSize);
        // “查询、设置、查询”是三个独立远端操作。保留两次观察值，不能把成功确认改写成物理预留保证。
        var before = await GetAllocationInfoAsync(cancellationToken).ConfigureAwait(false);
        await SetAllocationSizeAsync(requestedSize, cancellationToken).ConfigureAwait(false);
        var after = await GetAllocationInfoAsync(cancellationToken).ConfigureAwait(false);
        var result = new SmbAllocationResult(requestedSize, before, after);
        if (requireReportedAllocation && !result.ReportedAllocationMeetsRequest)
            throw new IOException($"The server acknowledged an allocation of {requestedSize} bytes but reports {after.AllocationSize} bytes. " +
                "The allocation request has already executed; physical reservation is not confirmed.");
        return result;
    }

    /// <summary>
    /// 仅在报告的分配量不足时请求增长，并使用观察到的 EOF 作为请求下限。
    /// </summary>
    /// <param name="minimumSize">希望服务器至少报告的非负分配字节数。</param>
    /// <param name="requireReportedAllocation">是否把重新报告量不足视为错误。</param>
    /// <param name="cancellationToken">取消本次操作的令牌。</param>
    /// <returns>所需下限和操作前后的观察结果；无需增长时前后结果相同。</returns>
    /// <remarks>调用者须排除并发写入，才能保证查询之后新增的数据不被另一分配请求影响。</remarks>
    /// <exception cref="ArgumentOutOfRangeException">最小分配量为负数。</exception>
    /// <exception cref="IOException">设置已确认，但核对得到的报告量仍未达到要求。</exception>
    public async Task<SmbAllocationResult> EnsureAllocationAsync(long minimumSize, bool requireReportedAllocation = false,
        CancellationToken cancellationToken = default)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(minimumSize);
        var before = await GetAllocationInfoAsync(cancellationToken).ConfigureAwait(false);
        if (before.AllocationSize >= minimumSize)
            return new(minimumSize, before, before);
        // 稀疏文件的 AllocationSize 可以小于 EOF；直接传入 minimumSize 可能意外截断逻辑数据。
        var requested = Math.Max(minimumSize, before.EndOfFile);
        await SetAllocationSizeAsync(requested, cancellationToken).ConfigureAwait(false);
        var after = await GetAllocationInfoAsync(cancellationToken).ConfigureAwait(false);
        var result = new SmbAllocationResult(minimumSize, before, after);
        if (requireReportedAllocation && !result.ReportedAllocationMeetsRequest)
            throw new IOException($"The server reports {after.AllocationSize} allocated bytes after requesting at least {minimumSize}. " +
                "The allocation request has already executed; physical reservation is not confirmed.");
        return result;
    }
}