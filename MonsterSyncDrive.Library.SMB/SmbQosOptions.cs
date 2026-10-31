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


/// <summary>应用请求的相对优先级；加权轮转保证低优先级不会被无限饿死。</summary>
public enum SmbRequestPriority
{
    /// <summary>后台同步等可延迟操作。</summary>
    Background,
    /// <summary>低优先级文件操作。</summary>
    Low,
    /// <summary>默认优先级。</summary>
    Normal,
    /// <summary>优先处理的交互操作；不是操作系统实时调度。</summary>
    High
}

/// <summary>一个逻辑客户端所有通道共享的应用数据速率和并发调度配置。</summary>
public sealed record SmbQosOptions
{
    /// <summary>上传文件数据的字节每秒速率；零表示无限制，不计算协议头和控制消息。</summary>
    public long UploadBytesPerSecond
    {
        get; init;
    }

    /// <summary>交付给应用的文件读取数据速率，单位字节每秒；零表示无限制，控制消息不受此限。</summary>
    public long DownloadBytesPerSecond
    {
        get; init;
    }
    /// <summary>每个方向的初始突发额度，最多采用配置速率的一秒数据量。</summary>
    public int BurstBytes { get; init; } = 65536;
    /// <summary>等待响应的普通请求并发上限；零表示不限制，长通知和必要控制消息不占此预算。</summary>
    public int MaximumConcurrentRequests
    {
        get; init;
    }

    /// <summary>并发请求预算耗尽后最多排队的普通请求数，超出时在发送前明确失败。</summary>
    public int MaximumQueuedRequests { get; init; } = 4096;

    /// <summary>没有异步优先级作用域时采用的请求级别。</summary>
    public SmbRequestPriority DefaultPriority { get; init; } = SmbRequestPriority.Normal;


    /// <summary>验证非负速率、正突发额度、队列和并发上限，返回独立策略记录。</summary>
    internal SmbQosOptions Snapshot()
    {
        return UploadBytesPerSecond < 0 || DownloadBytesPerSecond < 0 || BurstBytes < 1 ||
            MaximumConcurrentRequests is < 0 or > 65535 || MaximumQueuedRequests < 1 || !Enum.IsDefined(DefaultPriority)
            ? throw new ArgumentException("Invalid SMB QoS rates or scheduling limits.")
            : (this with
            {
            });
    }
}


/// <summary>同一逻辑客户端所有通道的应用数据和调度统计。</summary>
/// <param name="UploadedFileBytes">服务器实际确认写入的文件字节数。</param>
/// <param name="DownloadedFileBytes">已向读取调用交付的文件字节数。</param>
/// <param name="ActiveRequests">当前占用普通请求并发预算的数量。</param>
/// <param name="QueuedRequests">等待普通请求预算的数量。</param>
public sealed record SmbQosStatistics(long UploadedFileBytes, long DownloadedFileBytes,
    int ActiveRequests, int QueuedRequests);

/// <summary>为当前异步调用链设置 SMB 请求优先级，释放时恢复父作用域。</summary>
public sealed class SmbQosScope : IDisposable
{

    /// <summary>AsyncLocal 保存当前异步控制流的优先级栈，不使用跨任务全局优先级。</summary>
    private static readonly AsyncLocal<SmbQosScope?> Current = new();

    /// <summary>进入本作用域前的优先级节点，释放时恢复。</summary>
    private readonly SmbQosScope? previous;

    /// <summary>此作用域指定的请求级别。</summary>
    private readonly SmbRequestPriority priority;

    /// <summary>保存父作用域并推入经过校验的优先级。</summary>
    /// <param name="value">当前异步调用链采用的优先级。</param>
    private SmbQosScope(SmbRequestPriority value)
    {
        if (!Enum.IsDefined(value))
            throw new ArgumentOutOfRangeException(nameof(value));
        priority = value;
        previous = Current.Value;
        Current.Value = this;
    }

    /// <summary>为当前异步调用链创建优先级作用域；应以 using 按栈顺序释放。</summary>
    /// <param name="priority">作用域内新建 SMB 请求采用的优先级。</param>
    public static SmbQosScope Begin(SmbRequestPriority priority)
    {
        return new(priority);
    }

    /// <summary>读取当前异步优先级，没有作用域时返回策略默认值。</summary>
    /// <param name="fallback">默认请求级别。</param>
    internal static SmbRequestPriority PriorityOr(SmbRequestPriority fallback)
    {
        return Current.Value?.priority ?? fallback;
    }

    /// <summary>恢复父作用域；拒绝跨控制流或乱序释放造成的优先级污染。</summary>
    public void Dispose()
    {
        if (ReferenceEquals(Current.Value, this))
            Current.Value = previous;
        else if (!ReferenceEquals(Current.Value, previous))
            throw new InvalidOperationException("SMB priority scopes must be disposed in order in their owning control flow.");
    }
}