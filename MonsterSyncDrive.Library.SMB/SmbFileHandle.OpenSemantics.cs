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

/// <summary>远端文件句柄的扇区几何查询和无缓冲 I/O 对齐校验。</summary>
public sealed partial class SmbFileHandle
{
    /// <summary>串行化首次逻辑扇区查询，避免并发读写重复探测几何信息。</summary>
    private readonly SemaphoreSlim unbufferedGeometryGate = new(1, 1);
    /// <summary>本句柄已确认的逻辑扇区字节数；零表示尚未成功查询。</summary>
    private uint unbufferedLogicalSectorSize;

    /// <summary>查询句柄所在卷的逻辑、物理扇区大小和对齐标志。</summary>
    /// <param name="cancellationToken">取消查询的令牌。</param>
    /// <returns>服务器报告的完整扇区几何信息。</returns>
    /// <exception cref="SmbException">服务器拒绝查询或不支持 FileFsSectorSizeInformation。</exception>
    /// <exception cref="SmbProtocolException">服务器返回的几何记录无效。</exception>
    public async Task<SmbSectorSizeInformation> GetSectorSizeInformationAsync(CancellationToken cancellationToken = default)
    {
        var data = await QueryInfoAsync(SmbInfoType.FileSystem, 11, maximumOutput: 28,
            cancellationToken: cancellationToken).ConfigureAwait(false);
        return SmbSectorSizeInformation.Parse(data);
    }

    /// <summary>按需查询逻辑扇区大小，并在发送数据请求前校验远端无缓冲 I/O 的偏移和长度。</summary>
    /// <param name="offset">即将发送的文件字节偏移。</param>
    /// <param name="count">即将发送的单次读写数据字节数，或完整写入的预检长度。</param>
    /// <param name="cancellationToken">取消首次几何查询或等待查询锁的令牌。</param>
    /// <exception cref="InvalidOperationException">无缓冲数据操作用于非磁盘共享。</exception>
    /// <exception cref="ArgumentException">偏移或数据长度不满足逻辑扇区对齐。</exception>
    /// <remarks>本地托管缓冲区地址不会传入 SMB 请求，因此无需验证本地原生地址对齐。</remarks>
    private async Task ValidateUnbufferedIoAsync(long offset, int count, CancellationToken cancellationToken)
    {
        if ((OpenOptions.CreateOptions & SmbCreateOptions.NoIntermediateBuffering) == 0 || count == 0)
            return;
        if (!share.IsDiskShare)
            throw new InvalidOperationException("Unbuffered file I/O requires a disk share.");
        var sectorSize = Volatile.Read(ref unbufferedLogicalSectorSize);
        if (sectorSize == 0)
        {
            await unbufferedGeometryGate.WaitAsync(cancellationToken).ConfigureAwait(false);
            try
            {
                sectorSize = unbufferedLogicalSectorSize;
                if (sectorSize == 0)
                {
                    // 只有明确的不支持信息类错误才回退；权限、网络和取消错误必须继续向调用方报告。
                    try { sectorSize = (await GetSectorSizeInformationAsync(cancellationToken).ConfigureAwait(false)).LogicalBytesPerSector; }
                    catch (SmbException error) when (error.Status is SmbStatus.NotSupported or SmbStatus.InvalidDeviceRequest ||
                        (uint)error.Status == 0xC0000003)
                    {
                        var data = await QueryInfoAsync(SmbInfoType.FileSystem, 7, maximumOutput: 32,
                            cancellationToken: cancellationToken).ConfigureAwait(false);
                        Wire.Slice(data, 0, 32);
                        sectorSize = Wire.U32(data, 28);
                        if (!SmbSectorSizeInformation.IsSectorSize(sectorSize))
                            throw new SmbProtocolException("The server returned an invalid logical sector size.");
                    }
                    // 只缓存成功结果，取消或错误不会使此句柄永久记住一个失败的初始化任务。
                    Volatile.Write(ref unbufferedLogicalSectorSize, sectorSize);
                }
            }
            finally { unbufferedGeometryGate.Release(); }
        }
        ValidateUnbufferedAlignment(offset, count, sectorSize);
    }

    /// <summary>校验远端无缓冲请求是否使用逻辑扇区倍数的偏移和长度。</summary>
    /// <param name="offset">非负文件字节偏移。</param>
    /// <param name="count">非负数据长度。</param>
    /// <param name="logicalSectorSize">已验证为正二次幂的逻辑扇区大小。</param>
    /// <exception cref="ArgumentOutOfRangeException">逻辑扇区大小不是受支持的有效值。</exception>
    /// <exception cref="ArgumentException">偏移或长度为负数，或不是逻辑扇区的整倍数。</exception>
    internal static void ValidateUnbufferedAlignment(long offset, int count, uint logicalSectorSize)
    {
        if (!SmbSectorSizeInformation.IsSectorSize(logicalSectorSize))
            throw new ArgumentOutOfRangeException(nameof(logicalSectorSize));
        if (offset < 0 || offset % logicalSectorSize != 0)
            throw new ArgumentException($"An unbuffered offset must be a multiple of {logicalSectorSize} bytes.", nameof(offset));
        if (count < 0 || count % logicalSectorSize != 0)
            throw new ArgumentException($"An unbuffered transfer length must be a multiple of {logicalSectorSize} bytes.", nameof(count));
    }
}