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

/// <summary>向服务器说明文件访问模式的缓存提示，不改变按偏移读写的语义。</summary>
public enum SmbAccessPattern
{
    /// <summary>不声明顺序或随机访问偏好，由服务器选择缓存策略。</summary>
    Normal,
    /// <summary>声明顺序访问偏好，发送 FILE_SEQUENTIAL_ONLY。</summary>
    Sequential,
    /// <summary>声明随机访问偏好，发送 FILE_RANDOM_ACCESS。</summary>
    Random
}

/// <summary>本次打开是否允许服务器使用常规文件数据缓冲。</summary>
public enum SmbBufferingMode
{
    /// <summary>允许服务器使用文件系统缓冲。</summary>
    Buffered,
    /// <summary>请求服务器无缓冲访问，文件偏移和数据长度须满足逻辑扇区对齐。</summary>
    Unbuffered
}

/// <summary>构造跨平台的文件访问、缓冲及备份意图选项，并校验彼此冲突的标志。</summary>
public static class SmbOpenSemantics
{
    /// <summary>构造读取普通文件的打开选项；不会请求系统安全或备份特权。</summary>
    /// <param name="pattern">向服务器提供的访问模式提示。</param>
    /// <param name="buffering">服务器缓冲模式。</param>
    /// <param name="backupIntent">是否请求服务器按备份意图执行访问检查；服务器仍需授予相应权限。</param>
    /// <param name="sharing">允许其他打开共享的读、写、删除操作。</param>
    /// <returns>可传给共享打开接口的不可变选项。</returns>
    /// <exception cref="ArgumentOutOfRangeException">访问模式或缓冲模式不是已定义值。</exception>
    public static SmbOpenOptions ForRead(SmbAccessPattern pattern = SmbAccessPattern.Normal,
        SmbBufferingMode buffering = SmbBufferingMode.Buffered, bool backupIntent = false,
        SmbShareAccess sharing = SmbShareAccess.All)
        => Apply(new SmbOpenOptions
        {
            Access = SmbAccessMask.GenericRead | SmbAccessMask.Synchronize,
            ShareAccess = sharing
        }, pattern, buffering, backupIntent);

    /// <summary>构造写入普通文件的选项，并允许读取文件属性以核对写入结果。</summary>
    /// <param name="disposition">文件不存在或已存在时采用的创建、打开或覆盖策略。</param>
    /// <param name="pattern">向服务器提供的访问模式提示。</param>
    /// <param name="buffering">服务器缓冲模式。</param>
    /// <param name="backupIntent">是否请求备份或恢复意图访问检查，不自动获取服务器权限。</param>
    /// <param name="sharing">允许其他打开共享的操作。</param>
    /// <returns>包含通用写、读取属性和同步访问权限的打开选项。</returns>
    /// <exception cref="ArgumentOutOfRangeException">访问模式或缓冲模式无效。</exception>
    public static SmbOpenOptions ForWrite(SmbCreateDisposition disposition = SmbCreateDisposition.OpenIf,
        SmbAccessPattern pattern = SmbAccessPattern.Normal, SmbBufferingMode buffering = SmbBufferingMode.Buffered,
        bool backupIntent = false, SmbShareAccess sharing = SmbShareAccess.All)
        => Apply(new SmbOpenOptions
        {
            Access = SmbAccessMask.GenericWrite | SmbAccessMask.ReadAttributes | SmbAccessMask.Synchronize,
            Disposition = disposition,
            ShareAccess = sharing
        }, pattern, buffering, backupIntent);

    /// <summary>
    /// 在现有选项上替换访问提示、缓冲和备份意图，保留处置方式、共享权限及其他创建标志。
    /// </summary>
    /// <param name="options">需要派生新选项的源对象；源对象不会被修改。</param>
    /// <param name="pattern">新的顺序或随机访问提示。</param>
    /// <param name="buffering">新的服务器缓冲模式。</param>
    /// <param name="backupIntent">是否发送备份意图标志；不绕过服务器授权。</param>
    /// <returns>已校验的新打开选项。</returns>
    /// <exception cref="ArgumentNullException"><paramref name="options"/> 为空。</exception>
    /// <exception cref="ArgumentOutOfRangeException">访问模式或缓冲模式无效。</exception>
    /// <exception cref="ArgumentException">选项显式同时请求无缓冲和追加数据访问。</exception>
    public static SmbOpenOptions Apply(SmbOpenOptions options, SmbAccessPattern pattern,
        SmbBufferingMode buffering = SmbBufferingMode.Buffered, bool backupIntent = false)
    {
        ArgumentNullException.ThrowIfNull(options);
        if (!Enum.IsDefined(pattern) || !Enum.IsDefined(buffering))
            throw new ArgumentOutOfRangeException(nameof(pattern));
        // 先移除这一组提示，再按本次参数重建；否则重复 Apply 会意外保留上次访问模式。
        var flags = options.CreateOptions & ~(SmbCreateOptions.SequentialOnly | SmbCreateOptions.RandomAccess |
            SmbCreateOptions.NoIntermediateBuffering | SmbCreateOptions.OpenForBackupIntent);
        flags |= pattern switch
        {
            SmbAccessPattern.Sequential => SmbCreateOptions.SequentialOnly,
            SmbAccessPattern.Random => SmbCreateOptions.RandomAccess,
            _ => 0
        };
        if (buffering == SmbBufferingMode.Unbuffered) flags |= SmbCreateOptions.NoIntermediateBuffering;
        if (backupIntent) flags |= SmbCreateOptions.OpenForBackupIntent;
        var result = options with { CreateOptions = flags };
        Validate(result);
        return result;
    }

    /// <summary>在发送 CREATE 之前拒绝互斥的访问模式及无缓冲追加权限组合。</summary>
    /// <param name="options">即将编码到 CREATE 请求中的打开选项。</param>
    /// <exception cref="ArgumentException">顺序和随机提示同时存在，或无缓冲请求带显式追加数据权限。</exception>
    internal static void Validate(SmbOpenOptions options)
    {
        if ((options.CreateOptions & (SmbCreateOptions.SequentialOnly | SmbCreateOptions.RandomAccess)) ==
            (SmbCreateOptions.SequentialOnly | SmbCreateOptions.RandomAccess))
            throw new ArgumentException("Sequential and random access hints are mutually exclusive.", nameof(options));
        if ((options.CreateOptions & SmbCreateOptions.NoIntermediateBuffering) != 0 &&
            (options.Access & SmbAccessMask.AppendData) != 0)
            throw new ArgumentException("Unbuffered opens cannot request explicit AppendData access.", nameof(options));
    }
}