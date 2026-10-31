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
using System.Threading.Channels;

namespace MonsterSyncDrive.Library.SMB;

/// <summary>跟踪传统机会锁授予状态，并串行处理同一打开句柄的缓存权限撤销。</summary>
public sealed partial class SmbFileHandle
{
    /// <summary>保护失效处理、级别发布及每个句柄的处理任务链。</summary>
    private readonly object oplockGate = new();
    /// <summary>在句柄或会话最后一条可用通道关闭时取消缓存处理程序。</summary>
    private readonly CancellationTokenSource oplockLifetime = new();
    /// <summary>向可选的应用程序观察者交付有限次的实际缓存降级通知。</summary>
    private readonly Channel<SmbOplockBreak> oplockNotifications = Channel.CreateUnbounded<SmbOplockBreak>(
        new UnboundedChannelOptions { AllowSynchronousContinuations = false });
    /// <summary>串行撤销处理任务链的尾部，始终在接收循环以外调度执行。</summary>
    private Task oplockProcessing = Task.CompletedTask;
    /// <summary>以原子方式发布的已授予协议级别，在失效时清零。</summary>
    private int oplockLevel;
    /// <summary>待处理协议通知数量，独立于应用程序观察者施加上限。</summary>
    private int queuedOplockBreaks;
    /// <summary>防止迟到的回调或确认响应恢复已经因关闭或传输失败而撤销的权限。</summary>
    private bool oplockInvalidated;
    /// <summary>会话完全失效后用于结束活动观察者的传输错误。</summary>
    private Exception? oplockInvalidationError;

    /// <summary>当前授予的级别；处理有效撤销时立即降低，关闭后返回 None。</summary>
    public SmbOplockLevel OplockLevel => IsClosed || !Share.Client.IsTransportAlive
        ? SmbOplockLevel.None : (SmbOplockLevel)Volatile.Read(ref oplockLevel);

    /// <summary>
    /// 等待下一条降级通知；由于本库不缓存文件数据，默认处理程序会立即确认。
    /// 需要自行缓存的应用程序必须在打开文件前配置 OplockBreakHandler。
    /// </summary>
    /// <param name="cancellationToken">只取消本次等待，不释放远程机会锁。</param>
    /// <returns>下一条通知；其 Completion 任务包含处理程序与必要的确认交换。</returns>
    /// <exception cref="ObjectDisposedException">文件或其所属共享已经释放。</exception>
    /// <exception cref="ChannelClosedException">可用通知到达之前，该打开句柄已关闭。</exception>
    public ValueTask<SmbOplockBreak> WaitForOplockBreakAsync(CancellationToken cancellationToken = default)
    {
        ThrowIfClosed();
        return oplockNotifications.Reader.ReadAsync(cancellationToken);
    }

    /// <summary>验证 CREATE 响应，并在注册句柄之前保存已授予级别。</summary>
    /// <param name="granted">CREATE 响应中的 OplockLevel 字节。</param>
    /// <exception cref="SmbProtocolException">对端授予了未知级别、租约级别或高于请求的级别。</exception>
    internal void InitializeOplock(byte granted)
    {
        SmbOplockLevel level = (SmbOplockLevel)granted;
        if (!SmbOplockProtocol.CanGrant(OpenOptions.RequestedOplockLevel, level))
            throw new SmbProtocolException("The server granted an invalid or unrequested oplock level.");
        lock (oplockGate)
            if (!oplockInvalidated)
                Volatile.Write(ref oplockLevel, (int)level);
    }

    /// <summary>将降级加入有界队列，不在协议读取线程上运行用户回调。</summary>
    /// <param name="requested">已经验证的服务器请求级别。</param>
    /// <exception cref="SmbProtocolException">对端向同一打开句柄发送了过量待处理通知。</exception>
    internal void QueueOplockBreak(SmbOplockLevel requested)
    {
        lock (oplockGate)
        {
            if (oplockInvalidated || IsClosed)
                return;
            // 传统机会锁只能降级有限次；即使对端持续发送通知，也必须限制待处理工作量。
            if (queuedOplockBreaks >= 8)
                throw new SmbProtocolException("Too many pending oplock break notifications for a file.");
            queuedOplockBreaks++;
            Task previous = oplockProcessing;
            // 用户代码自身可能发起 SMB 操作，因此不能在连接接收循环上执行，否则会阻塞响应处理。
            oplockProcessing = Task.Run(async () =>
            {
                try
                {
                    await previous.ConfigureAwait(false);
                    await ProcessOplockBreakAsync(requested).ConfigureAwait(false);
                }
                finally
                {
                    lock (oplockGate)
                        queuedOplockBreaks--;
                }
            });
        }
    }

    /// <summary>撤销本地权限，等待应用程序处理缓存，并校验必要的确认响应。</summary>
    /// <param name="requested">通知所要求的降级级别。</param>
    /// <returns>观察全部错误的任务；无法保持缓存一致性时使会话失败。</returns>
    /// <remarks>
    /// 从 Level-II 降级为 None 不发送确认；其他有效降级允许应用程序保留
    /// 请求级别或更低级别；即使回调忽略取消，也必须实施有限的处理期限。
    /// 本方法不阻塞连接接收线程，因此处理程序可以安全地发起 SMB IO。
    /// </remarks>
    private async Task ProcessOplockBreakAsync(SmbOplockLevel requested)
    {
        SmbOplockBreak notification;
        lock (oplockGate)
        {
            if (oplockInvalidated || IsClosed)
                return;
            // 持有 oplockGate 时不能调用公共属性读取器，因为它会检查通道状态。
            // 通道失败清理先获取 channelLock 再获取此锁，反向获取会造成锁顺序倒置。
            SmbOplockLevel previous = (SmbOplockLevel)Volatile.Read(ref oplockLevel);
            if (!SmbOplockProtocol.IsTransition(previous, requested))
                return; // 按 MS-SMB2 第 3.2.5.19.1 节忽略未知或不适用的转换。
            Volatile.Write(ref oplockLevel, (int)requested);
            notification = new SmbOplockBreak(this, previous, requested, previous != SmbOplockLevel.LevelII);
            _ = oplockNotifications.Writer.TryWrite(notification);
        }

        using CancellationTokenSource deadline = CancellationTokenSource.CreateLinkedTokenSource(oplockLifetime.Token);
        var timeout = Share.Client.Options.OperationTimeout;
        deadline.CancelAfter(timeout == Timeout.InfiniteTimeSpan ? TimeSpan.FromSeconds(60) : timeout);
        try
        {
            SmbOplockLevel accepted = requested;
            if (OpenOptions.OplockBreakHandler is { } handler)
                accepted = await handler(notification, deadline.Token).AsTask().WaitAsync(deadline.Token).ConfigureAwait(false);
            if (!SmbOplockProtocol.CanGrant(requested, accepted))
                throw new SmbProtocolException("An oplock break handler attempted to retain a stronger caching level.");
            deadline.Token.ThrowIfCancellationRequested();
            lock (oplockGate)
            {
                if (oplockInvalidated || IsClosed)
                    throw new OperationCanceledException(oplockLifetime.Token);
                Volatile.Write(ref oplockLevel, (int)accepted);
            }

            if (notification.RequiresAcknowledgement)
            {
                var response = await Share.SendAsync(Command.OplockBreak,
                    SmbOplockProtocol.Acknowledgement(Id, accepted), deadline.Token).ConfigureAwait(false);
                response.EnsureSuccess();
                Wire.Structure(response.Packet, 24, 24);
                SmbOplockLevel result = (SmbOplockLevel)response.Packet[66];
                if (response.Packet.Length != 88 || SmbFileId.Read(response.Packet, 72) != Id ||
                    !SmbOplockProtocol.CanGrant(accepted, result))
                    throw new SmbProtocolException("Invalid oplock acknowledgment response.");
                lock (oplockGate)
                    if (!oplockInvalidated && !IsClosed)
                        Volatile.Write(ref oplockLevel, (int)result);
            }
            notification.Complete();
        }
        catch (OperationCanceledException) when (oplockLifetime.IsCancellationRequested || IsClosed)
        {
            if (oplockInvalidationError is { } invalidation)
                notification.Fail(invalidation);
            else
                notification.Cancel(oplockLifetime.Token);
        }
        catch (Exception error)
        {
            Exception failure = error is OperationCanceledException
                ? new TimeoutException("An oplock break handler or acknowledgment timed out.", error)
                : error;
            Share.Client.Abort(new SmbProtocolException("The oplock downgrade could not be completed safely.", failure));
            notification.Fail(failure);
        }
    }

    /// <summary>一次性清除缓存权限并结束观察者，不等待应用程序代码。</summary>
    /// <param name="error">会话失败原因；正常关闭时为 null。</param>
    internal void InvalidateOplock(Exception? error = null)
    {
        lock (oplockGate)
        {
            if (oplockInvalidated)
                return;
            oplockInvalidated = true;
            oplockInvalidationError = error;
            Volatile.Write(ref oplockLevel, 0);
            _ = oplockNotifications.Writer.TryComplete(error);
        }
        // 取消处理程序属于应用程序代码，不能在 SMB 接收循环上执行。
        _ = CancelOplockLifetimeAsync();
    }

    /// <summary>观察异步取消过程，防止应用程序令牌回调抛出的异常中断清理。</summary>
    /// <returns>所有取消回调完成后结束的任务。</returns>
    private async Task CancelOplockLifetimeAsync()
    {
        try
        {
            await oplockLifetime.CancelAsync().ConfigureAwait(false);
        }
        catch (Exception) { /* 用户令牌回调不能阻止句柄或会话清理。 */ }
    }
}
