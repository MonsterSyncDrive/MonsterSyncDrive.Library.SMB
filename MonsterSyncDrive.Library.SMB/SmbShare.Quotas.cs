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
namespace MonsterSyncDrive.SMB;

/// <summary>通过固定的文件系统配额索引控制流建立用户配额操作句柄。</summary>
public sealed partial class SmbShare
{
    /// <summary>Windows NTFS 与 Samba 配额接口使用的共享根相对保留索引流路径。</summary>
    internal const string QuotaControlPath = @"$Extend\$Quota:$Q:$INDEX_ALLOCATION";

    /// <summary>打开用户配额专用控制句柄，默认只读，不修改任何配额条目或卷默认设置。</summary>
    /// <param name="writable">显式请求用户配额管理所需的写数据访问；默认 false。</param>
    /// <param name="cancellationToken">取消打开特殊索引流的令牌。</param>
    /// <returns>可用于用户配额查询的专用句柄；writable=true 时可执行配额修改，仍受服务器授权。</returns>
    /// <remarks>
    /// 普通文件或目录句柄不能代替配额控制句柄。Windows 通常要求共享映射到卷根；
    /// Samba 需要启用对应的 quota fake-file 支持。接口保留服务器原始路径和权限错误，
    /// 不自动尝试管理共享、创建索引、修改配额或绕过普通路径校验。
    /// </remarks>
    /// <exception cref="NotSupportedException">当前共享不是磁盘共享。</exception>
    /// <exception cref="SmbException">控制流不存在、配额能力未提供或服务器拒绝访问。</exception>
    public Task<SmbFileHandle> OpenQuotaControlAsync(bool writable = false, CancellationToken cancellationToken = default)
    {
        ThrowIfDisposed();
        if (!IsDiskShare) throw new NotSupportedException("User quota control requires a disk share.");
        var access = SmbAccessMask.ReadData | SmbAccessMask.ReadAttributes | SmbAccessMask.ReadControl | SmbAccessMask.Synchronize;
        if (writable) access |= SmbAccessMask.WriteData;
        return OpenFileCoreAsync(QuotaControlPath, new SmbOpenOptions
        {
            Access = access,
            ShareAccess = SmbShareAccess.Read | SmbShareAccess.Write,
            Disposition = SmbCreateDisposition.Open,
            CreateOptions = SmbCreateOptions.None,
            Attributes = FileAttributes.Normal
        }, quotaControl: true, cancellationToken);
    }
}