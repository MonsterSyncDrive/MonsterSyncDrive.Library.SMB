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
namespace MonsterSyncDrive.Library.SMB;

/// <summary>在所有操作系统上按共享相对路径解析 SMB 名称，统一使用反斜杠，不依赖本地路径规则。</summary>
public static class SmbPath
{
    /// <summary>统一分隔符并校验共享内路径，拒绝 UNC 前缀、目录跳转、通配符及无效的数据流形式。</summary>
    /// <param name="path">共享内文件或目录路径；空字符串表示共享根。</param>
    /// <returns>移除空分隔段、使用反斜杠的共享相对路径。</returns>
    /// <remarks>冒号仅按末级名称的备用数据流语法解释，不按本地操作系统的盘符语义解析。</remarks>
    /// <exception cref="ArgumentNullException">路径为空引用。</exception>
    /// <exception cref="ArgumentException">路径包含不允许的导航、字符或数据流格式。</exception>
    /// <exception cref="PathTooLongException">规范化后的 UTF-16 路径长度超过 32760 个字符。</exception>
    public static string Normalize(string path)
    {
        ArgumentNullException.ThrowIfNull(path);
        if (path.Contains('\0') || path.StartsWith(@"\\", StringComparison.Ordinal) ||
            path.StartsWith("//", StringComparison.Ordinal))
            throw new ArgumentException("Use a share-relative path without NUL, UNC prefix or drive name.", nameof(path));
        string[] parts = path.Replace('/', '\\').Split('\\', StringSplitOptions.RemoveEmptyEntries);
        for (int i = 0; i < parts.Length; i++)
        {
            string part = parts[i];
            if (part is "." or ".." || part.IndexOfAny(['*', '?', '"', '<', '>', '|']) >= 0)
                throw new ArgumentException("Relative navigation and wildcards are not valid file paths.", nameof(path));
            // 只有末级文件名允许 ADS；中间目录不能携带流名，流类型也只接受 $DATA。
            if (part.Contains(':'))
            {
                string[] streamParts = part.Split(':');
                if (i != parts.Length - 1 || streamParts.Length is < 2 or > 3 ||
                    streamParts[0].Length == 0 || streamParts[0] is "." or ".." ||
                    (streamParts.Length == 2 && streamParts[1].Length == 0) ||
                    (streamParts.Length == 3 && !streamParts[2].Equals("$DATA", StringComparison.OrdinalIgnoreCase)))
                    throw new ArgumentException("Invalid drive or alternate data stream path.", nameof(path));
            }
        }
        string normalized = string.Join('\\', parts);
        return normalized.Length > 32760 ? throw new PathTooLongException() : normalized;
    }

    /// <summary>为一个普通共享内文件路径构造 :stream:$DATA 备用数据流路径。</summary>
    /// <param name="path">非根目录、尚未包含数据流部分的文件路径。</param>
    /// <param name="streamName">单个非空数据流名称，不能包含分隔符、冒号或 NUL。</param>
    /// <returns>完整且经过规范化的数据流路径。</returns>
    /// <exception cref="ArgumentException">文件路径或流名称不满足备用数据流命名要求。</exception>
    public static string WithStream(string path, string streamName)
    {
        string normalized = Normalize(path);
        ArgumentException.ThrowIfNullOrWhiteSpace(streamName);
        return normalized.Length == 0 || normalized.Contains(':') || streamName.IndexOfAny(['\\', '/', ':', '\0']) >= 0
            ? throw new ArgumentException("Use a file path and a single alternate stream name.")
            : Normalize(normalized + ":" + streamName + ":$DATA");
    }

    /// <summary>按 SMB 共享内规则合并目录和子路径，两部分均经过独立路径校验。</summary>
    /// <param name="directory">共享内目录，空字符串表示根。</param>
    /// <param name="name">共享内子名称或子路径，不接受 UNC 和相对跳转。</param>
    /// <returns>使用反斜杠的规范化组合路径。</returns>
    /// <exception cref="ArgumentException">任一部分不符合共享内路径规则。</exception>
    public static string Combine(string directory, string name)
    {
        string normalizedDirectory = Normalize(directory);
        string normalizedName = Normalize(name);
        return Normalize(normalizedDirectory.Length == 0 ? normalizedName : normalizedDirectory + "\\" + normalizedName);
    }

    /// <summary>验证单个共享名称，不接受路径、流名、NUL 或点导航名称。</summary>
    /// <param name="share">服务器上的单个非空共享名称。</param>
    /// <returns>原始共享名称，不改变大小写或 Unicode 字符。</returns>
    /// <exception cref="ArgumentException">共享名为空白或包含路径及流分隔符。</exception>
    internal static string ValidateShare(string share)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(share);
        return share.IndexOfAny(['\\', '/', '\0', ':']) >= 0 || share is "." or ".."
            ? throw new ArgumentException("Specify a single share name.", nameof(share))
            : share;
    }
}