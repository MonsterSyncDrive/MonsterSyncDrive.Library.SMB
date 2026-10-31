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
namespace MonsterSyncDrive.Library.SMB.Protocol;


/// <summary>一个逻辑客户端的应用数据限速、加权并发调度及统计；所有绑定通道共享实例。</summary>
internal sealed class SmbQosState
{

    /// <summary>创建时验证的速率和调度快照。</summary>
    private readonly SmbQosOptions options;

    /// <summary>只约束文件上传数据的独立限速门。</summary>
    private readonly DataRateGate upload;

    /// <summary>只约束交付给应用的文件下载数据，避免阻塞协议接收循环。</summary>
    private readonly DataRateGate download;

    /// <summary>保护并发预算、轮转游标和请求队列。</summary>
    private readonly object sync = new();

    /// <summary>按 Background、Low、Normal、High 划分的 FIFO 等待队列。</summary>
    private readonly LinkedList<Waiter>[] queues = [new(), new(), new(), new()];
    // 加权轮转为各级保留机会，持续到来的高优先级请求也不能无限期饿死后台队列。

    /// <summary>高、普通、低、后台按 8:4:2:1 轮转，忙碌的高优先级不能永久饿死后台。</summary>
    private static readonly int[] Schedule = [3, 3, 3, 3, 3, 3, 3, 3, 2, 2, 2, 2, 1, 1, 0];

    /// <summary>轮转位置、已占用的并发槽和排队总数，均由 sync 保护。</summary>
    private int cursor, active, queued;

    /// <summary>已确认上传和已交付下载的文件字节累计值。</summary>
    private long uploaded, downloaded;


    /// <summary>为一个逻辑会话创建共享限速和调度状态。</summary>
    /// <param name="options">经过校验的 QoS 策略。</param>
    /// <param name="timeProvider">可替换的单调时钟；默认使用系统时间提供程序。</param>
    internal SmbQosState(SmbQosOptions options, TimeProvider? timeProvider = null)
    {
        this.options = options.Snapshot();
        upload = new(options.UploadBytesPerSecond, options.BurstBytes, timeProvider ?? TimeProvider.System);
        download = new(options.DownloadBytesPerSecond, options.BurstBytes, timeProvider ?? TimeProvider.System);
    }


    /// <summary>在文件写请求发送前等待上传预算，取消时释放限速门。</summary>
    internal ValueTask LimitUploadAsync(int bytes, CancellationToken cancellationToken)
    {
        return upload.WaitAsync(bytes, cancellationToken);
    }

    /// <summary>在响应已校验之后、文件数据交付之前等待下载预算。</summary>
    internal ValueTask LimitDownloadAsync(int bytes, CancellationToken cancellationToken)
    {
        return download.WaitAsync(bytes, cancellationToken);
    }

    /// <summary>仅累计服务端实际确认的写入数据，短写不按请求长度虚计。</summary>
    internal void Uploaded(int bytes)
    {
        _ = Interlocked.Add(ref uploaded, bytes);
    }

    /// <summary>累计实际交付的文件数据字节数，EOF 和头部不计。</summary>
    internal void Downloaded(int bytes)
    {
        _ = Interlocked.Add(ref downloaded, bytes);
    }

    /// <summary>在锁内获取一致的活动、排队数量，并以原子读取获取字节累计值。</summary>
    internal SmbQosStatistics Snapshot()
    {
        lock (sync)
            return new(Interlocked.Read(ref uploaded), Interlocked.Read(ref downloaded), active, queued);
    }


    /// <summary>按异步优先级获取普通请求并发租约；队列满时在发送前失败。</summary>
    internal ValueTask<IDisposable> AcquireAsync(CancellationToken token)
    {
        token.ThrowIfCancellationRequested();
        if (options.MaximumConcurrentRequests == 0)
            return ValueTask.FromResult<IDisposable>(NoLease.Instance);
        lock (sync)
        {
            if (active < options.MaximumConcurrentRequests && queued == 0)
            {
                active++;
                return ValueTask.FromResult<IDisposable>(new Lease(this));
            }
            if (queued >= options.MaximumQueuedRequests)
                throw new InvalidOperationException("The SMB QoS request queue is full.");
            int priority = (int)SmbQosScope.PriorityOr(options.DefaultPriority);
            Waiter waiter = new(this, priority, token);
            waiter.Node = queues[priority].AddLast(waiter);
            queued++;
            return AwaitAsync(waiter, token);
        }
    }


    /// <summary>注册队列取消并异步等待租约，退出时释放令牌注册，避免在锁中等待回调。</summary>
    private static async ValueTask<IDisposable> AwaitAsync(Waiter waiter, CancellationToken token)
    {
        using var registration = token.UnsafeRegister(static state =>
        {
            Waiter value = (Waiter)state!;
            value.Owner.Cancel(value);
        }, waiter);
        return await waiter.Completion.Task.ConfigureAwait(false);
    }


    /// <summary>只移除尚未授予租约的等待节点；已获租约的请求由持有者释放。</summary>
    private void Cancel(Waiter waiter)
    {
        lock (sync)
        {
            if (waiter.Node is null)
                return;
            queues[waiter.Priority].Remove(waiter.Node);
            waiter.Node = null;
            queued--;
            _ = waiter.Completion.TrySetCanceled(waiter.Token);
        }
    }


    /// <summary>归还一个并发槽并按加权 FIFO 选择下个请求，完成任务时不执行同步调用方代码。</summary>
    private void Release()
    {
        lock (sync)
        {
            active--;
            while (active < options.MaximumConcurrentRequests && queued != 0)
            {
                for (int i = 0; i < Schedule.Length; i++)
                {
                    int index = Schedule[cursor];
                    cursor = (cursor + 1) % Schedule.Length;
                    if (queues[index].First is not { } node)
                        continue;
                    var waiter = node.Value;
                    queues[index].Remove(node);
                    waiter.Node = null;
                    queued--;
                    active++;
                    _ = waiter.Completion.TrySetResult(new Lease(this));
                    break;
                }
            }
        }
    }


    /// <summary>排队请求及其取消、优先级和链表节点。</summary>
    /// <param name="owner">所属客户端调度器。</param>
    /// <param name="priority">固定为入队时的优先级。</param>
    /// <param name="token">该排队请求的取消令牌。</param>
    private sealed class Waiter(SmbQosState owner, int priority, CancellationToken token)
    {

        /// <summary>负责队列修改的调度器。</summary>
        internal readonly SmbQosState Owner = owner;

        /// <summary>入队时固定的队列索引。</summary>
        internal readonly int Priority = priority;

        /// <summary>取消异常关联的原始令牌。</summary>
        internal readonly CancellationToken Token = token;

        /// <summary>队列节点；授予或取消后置空，防止重复移除。</summary>
        internal LinkedListNode<Waiter>? Node;

        /// <summary>异步交付唯一并发槽租约的任务。</summary>
        internal readonly TaskCompletionSource<IDisposable> Completion = new(TaskCreationOptions.RunContinuationsAsynchronously);
    }

    /// <summary>普通请求持有的幂等并发槽租约。</summary>
    /// <param name="owner">租约归还的调度器。</param>
    private sealed class Lease(SmbQosState owner) : IDisposable
    {

        /// <summary>尚未归还的所属调度器，Interlocked.Exchange 保证仅归还一次。</summary>
        private SmbQosState? value = owner;

        /// <summary>只归还一次并发预算，允许异常路径重复释放。</summary>
        public void Dispose()
        {
            Interlocked.Exchange(ref value, null)?.Release();
        }
    }

    /// <summary>不启用并发限制时使用的无分配空租约。</summary>
    private sealed class NoLease : IDisposable
    {

        /// <summary>所有不限流请求共享的不可变空租约。</summary>
        internal static readonly NoLease Instance = new();

        /// <summary>空租约不修改调度状态。</summary>
        public void Dispose()
        {
        }
    }


    /// <summary>基于单调时钟的有界突发数据门，串行计算等待以避免多个并发写分别获得完整速率。</summary>
    /// <param name="rate">字节每秒，零表示无限制。</param>
    /// <param name="burstBytes">初始突发字节上限，最多一秒预算。</param>
    /// <param name="time">用于测量真实等待时间的单调时钟。</param>
    private sealed class DataRateGate(long rate, int burstBytes, TimeProvider time)
    {

        /// <summary>同一方向的等待计算互斥门；取消会在 finally 归还。</summary>
        private readonly SemaphoreSlim gate = new(1, 1);

        /// <summary>突发预算上限，不超过一个速率周期的数据量。</summary>
        private readonly double capacity = Math.Min(rate, burstBytes);

        /// <summary>当前剩余突发预算，扣除和补充均在方向门内进行。</summary>
        private double tokens = Math.Min(rate, burstBytes);

        /// <summary>上次结算的单调时间戳。</summary>
        private long last = time.GetTimestamp();


        /// <summary>扣除突发额度，并按真实已等待时长补足剩余字节预算；长等待切片以保持可取消和计时器范围安全。</summary>
        internal async ValueTask WaitAsync(int count, CancellationToken token)
        {
            if (count < 0)
                throw new ArgumentOutOfRangeException(nameof(count));
            token.ThrowIfCancellationRequested();
            if (rate == 0 || count == 0)
                return;
            await gate.WaitAsync(token).ConfigureAwait(false);
            try
            {
                long now = time.GetTimestamp();
                double elapsed = Math.Max(0, time.GetElapsedTime(last, now).TotalSeconds);
                tokens = Math.Min(capacity, tokens + (elapsed * rate));
                last = now;
                if (count <= tokens)
                {
                    tokens -= count;
                    return;
                }
                double remaining = (count - tokens) / rate;
                tokens = 0;
                // 长等待按上限切片：既保持调用方取消响应，也避免底层计时器可表示范围溢出。
                while (remaining > 0)
                {
                    TimeSpan delay = TimeSpan.FromSeconds(Math.Min(remaining, 30));
                    long start = time.GetTimestamp();
                    await Task.Delay(delay, time, token).ConfigureAwait(false);
                    remaining -= Math.Max(0, time.GetElapsedTime(start, time.GetTimestamp()).TotalSeconds);
                }
                last = time.GetTimestamp();
            }
            finally
            {
                _ = gate.Release();
            }
        }
    }
}