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

/// <summary>服务器通过 FileStandardInformation 报告的分配量、逻辑长度及句柄状态。</summary>
/// <param name="AllocationSize">服务器报告的分配字节数，不必等于物理设备实际预留空间。</param>
/// <param name="EndOfFile">文件当前逻辑长度，单位为字节。</param>
/// <param name="LinkCount">指向文件的硬链接数量。</param>
/// <param name="DeletePending">是否已设置待删除状态。</param>
/// <param name="IsDirectory">该对象是否为目录。</param>
public sealed record SmbFileAllocationInfo(long AllocationSize, long EndOfFile, uint LinkCount,
    bool DeletePending, bool IsDirectory);

/// <summary>一次分配请求前后的服务器观察结果；不承诺底层磁盘块已经实际预留。</summary>
/// <param name="RequestedSize">调用者要求的最小分配字节数。</param>
/// <param name="Before">请求发送前查询到的分配和 EOF。</param>
/// <param name="After">请求确认后重新查询到的分配和 EOF。</param>
public sealed record SmbAllocationResult(long RequestedSize, SmbFileAllocationInfo Before, SmbFileAllocationInfo After)
{
    /// <summary>服务器重新报告的分配量是否至少达到请求量；仍不是物理预留的证明。</summary>
    public bool ReportedAllocationMeetsRequest => After.AllocationSize >= RequestedSize;
    /// <summary>前后两次查询的逻辑文件长度是否不同；并发写入也可能造成变化。</summary>
    public bool EndOfFileChanged => Before.EndOfFile != After.EndOfFile;
}

/// <summary>FileFsSectorSizeInformation 返回的设备对齐和介质能力标志。</summary>
[Flags]
public enum SmbSectorSizeFlags : uint
{
    /// <summary>服务器未报告已知标志。</summary>
    None = 0,
    /// <summary>设备的首个物理扇区与首个逻辑扇区对齐。</summary>
    AlignedDevice = 1,
    /// <summary>分区边界与设备物理扇区边界对齐。</summary>
    PartitionAlignedOnDevice = 2,
    /// <summary>设备报告没有机械寻道开销。</summary>
    NoSeekPenalty = 4,
    /// <summary>设备支持 TRIM 或对应的空间回收操作。</summary>
    TrimEnabled = 8
}

/// <summary>文件服务器报告的扇区几何信息；未知的对齐偏移表示为 null。</summary>
/// <param name="LogicalBytesPerSector">逻辑寻址单位，也是远端无缓冲偏移和长度的对齐单位。</param>
/// <param name="PhysicalBytesPerSectorForAtomicity">设备报告的原子写物理扇区大小；零值按原始报告保留。</param>
/// <param name="PhysicalBytesPerSectorForPerformance">设备建议的性能物理扇区大小。</param>
/// <param name="FileSystemEffectivePhysicalBytesPerSectorForAtomicity">文件系统实际使用的原子对齐单位。</param>
/// <param name="Flags">设备和分区的对齐及能力标志。</param>
/// <param name="ByteOffsetForSectorAlignment">逻辑起点在首个物理扇区内的偏移；未知时为 null。</param>
/// <param name="ByteOffsetForPartitionAlignment">分区相对物理扇区的偏移；未知时为 null。</param>
public sealed record SmbSectorSizeInformation(uint LogicalBytesPerSector, uint PhysicalBytesPerSectorForAtomicity,
    uint PhysicalBytesPerSectorForPerformance, uint FileSystemEffectivePhysicalBytesPerSectorForAtomicity,
    SmbSectorSizeFlags Flags, uint? ByteOffsetForSectorAlignment, uint? ByteOffsetForPartitionAlignment)
{
    /// <summary>解码固定 28 字节扇区记录，并校验可用大小和物理偏移的边界。</summary>
    /// <param name="data">FileFsSectorSizeInformation 响应的数据区。</param>
    /// <returns>保留未知标志及未知对齐偏移的几何模型。</returns>
    /// <exception cref="SmbProtocolException">记录截断、扇区大小无效或偏移越过物理扇区。</exception>
    internal static SmbSectorSizeInformation Parse(ReadOnlySpan<byte> data)
    {
        Wire.Slice(data, 0, 28);
        var logical = Wire.U32(data, 0);
        var atomic = Wire.U32(data, 4);
        var performance = Wire.U32(data, 8);
        var effective = Wire.U32(data, 12);
        if (!IsSectorSize(logical) || (atomic != 0 && (!IsSectorSize(atomic) || atomic < logical)) ||
            (performance != 0 && (!IsSectorSize(performance) || performance < logical)) ||
            (effective != 0 && (!IsSectorSize(effective) || effective < logical)))
            throw new SmbProtocolException("The server returned invalid sector geometry.");
        // 0xFFFFFFFF 是协议的未知偏移值，不可作为普通偏移参与对齐计算。
        var sectorOffset = Wire.U32(data, 20);
        var partitionOffset = Wire.U32(data, 24);
        if (atomic != 0 && sectorOffset != uint.MaxValue && sectorOffset >= atomic)
            throw new SmbProtocolException("The sector alignment offset is outside its physical sector.");
        return new(logical, atomic, performance, effective, (SmbSectorSizeFlags)Wire.U32(data, 16),
            sectorOffset == uint.MaxValue ? null : sectorOffset, partitionOffset == uint.MaxValue ? null : partitionOffset);
    }

    /// <summary>判断数值能否作为本实现支持的正数、二次幂扇区大小。</summary>
    /// <param name="value">服务器报告或调用者指定的字节数。</param>
    /// <returns>数值非零、可表示为正 int 且为二次幂时返回 true。</returns>
    internal static bool IsSectorSize(uint value) => value != 0 && value <= int.MaxValue && (value & (value - 1)) == 0;
}