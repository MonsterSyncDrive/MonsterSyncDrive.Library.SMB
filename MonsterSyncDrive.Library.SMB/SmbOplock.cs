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

/// <summary>传统 SMB 机会锁；租约缓存属于另一套独立的协议功能。</summary>
public enum SmbOplockLevel : byte
{
    /// <summary>不授予机会锁缓存权限。</summary>
    None = 0,
    /// <summary>共享读取缓存；降级为 None 时不需要发送协议确认。</summary>
    LevelII = 1,
    /// <summary>独占读取和写入缓存权限。</summary>
    Exclusive = 8,
    /// <summary>独占缓存权限，并允许保留应用程序已经关闭的远程句柄。</summary>
    Batch = 9
}

/// <summary>
/// 服务器请求的机会锁降级通知；应用程序如需缓存数据，必须在打开文件之前
/// 通过打开选项设置处理程序，并在处理程序返回前完成缓存刷新或失效处理。
/// </summary>
public sealed class SmbOplockBreak
{
    /// <summary>发布处理完成信号，避免在协议处理线程上执行应用程序的后续代码。</summary>
    private readonly TaskCompletionSource completion = new(TaskCreationOptions.RunContinuationsAsynchronously);

    /// <summary>正在撤销已授予缓存权限的文件句柄。</summary>
    public SmbFileHandle File { get; }
    /// <summary>开始处理本条通知之前的已授予缓存级别。</summary>
    public SmbOplockLevel PreviousLevel { get; }
    /// <summary>服务器当前允许客户端保留的最高缓存级别。</summary>
    public SmbOplockLevel RequestedLevel { get; }
    /// <summary>该降级是否需要发送 SMB2 OPLOCK_BREAK 确认。</summary>
    public bool RequiresAcknowledgement { get; }
    /// <summary>向应用程序交付降级通知时记录的本地 UTC 时间。</summary>
    public DateTimeOffset ReceivedAt { get; }
    /// <summary>处理程序与必要的服务器确认均完成后结束的任务。</summary>
    public Task Completion => completion.Task;

    /// <summary>创建不可变的通知对象及可独立观察的完成信号。</summary>
    /// <param name="file">受影响的远程打开句柄。</param>
    /// <param name="previous">此前已授予的缓存级别。</param>
    /// <param name="requested">服务器请求的降级级别。</param>
    /// <param name="requiresAcknowledgement">协议是否要求发送确认。</param>
    internal SmbOplockBreak(SmbFileHandle file, SmbOplockLevel previous, SmbOplockLevel requested, bool requiresAcknowledgement)
    {
        File = file;
        PreviousLevel = previous;
        RequestedLevel = requested;
        RequiresAcknowledgement = requiresAcknowledgement;
        ReceivedAt = DateTimeOffset.UtcNow;
        // 应用程序可以不等待 Completion；这里观察失败任务，避免回调错误变成未观察的任务异常。
        _ = completion.Task.ContinueWith(static task => _ = task.Exception,
            CancellationToken.None, TaskContinuationOptions.OnlyOnFaulted | TaskContinuationOptions.ExecuteSynchronously,
            TaskScheduler.Default);
    }

    /// <summary>将缓存失效处理及必要的服务器确认标记为已完成。</summary>
    internal void Complete() => completion.TrySetResult();
    /// <summary>向通知观察者发布缓存处理程序或协议处理的错误。</summary>
    /// <param name="error">导致无法安全完成处理的原始错误。</param>
    internal void Fail(Exception error) => completion.TrySetException(error);
    /// <summary>在处理期间文件句柄被关闭时取消该通知。</summary>
    /// <param name="cancellationToken">标识此次取消的句柄生命周期令牌。</param>
    internal void Cancel(CancellationToken cancellationToken) => completion.TrySetCanceled(cancellationToken);
}

/// <summary>编码传统机会锁消息，并按边界约束校验其线上结构。</summary>
internal static class SmbOplockProtocol
{
    /// <summary>检查服务器授予值或应用程序选择值是否未超过所提供的缓存级别。</summary>
    /// <param name="requested">请求或通知所允许的最高级别。</param>
    /// <param name="granted">服务器返回或应用程序选择的级别。</param>
    /// <returns>级别已知且缓存权限不高于允许值时返回 true。</returns>
    internal static bool CanGrant(SmbOplockLevel requested, SmbOplockLevel granted)
        => Enum.IsDefined(requested) && Enum.IsDefined(granted) && Rank(granted) <= Rank(requested);

    /// <summary>将不连续的协议字节值映射为可比较的缓存权限强度。</summary>
    /// <param name="level">传统机会锁级别。</param>
    /// <returns>取值为零到三的相对缓存权限强度。</returns>
    private static int Rank(SmbOplockLevel level) => level switch
    {
        SmbOplockLevel.None => 0,
        SmbOplockLevel.LevelII => 1,
        SmbOplockLevel.Exclusive => 2,
        SmbOplockLevel.Batch => 3,
        _ => throw new SmbProtocolException("An unsupported oplock level was received.")
    };

    /// <summary>在传输层完成身份与完整性验证后读取完整的传统机会锁主动通知。</summary>
    /// <param name="packet">解密后的 SMB2 消息头及长度恰为 24 字节的通知正文。</param>
    /// <returns>受影响的文件标识符和请求的降级级别。</returns>
    /// <exception cref="SmbProtocolException">消息头、长度、结构或降级级别无效。</exception>
    /// <remarks>
    /// 通知使用 MessageId -1 和 TreeId 零，不使用普通待完成请求的标识符。
    /// 会话和本地强制加密策略由接收连接校验；共享的强制加密要求在解析 FileId 后校验。
    /// MS-SMB2 第 3.2.5.1.3 节要求 MessageId=-1 的通知跳过普通签名处理，
    /// 此例外不改变普通响应的 Required 签名策略，也不豁免任何强制加密要求。
    /// </remarks>
    internal static (SmbFileId Id, SmbOplockLevel Level) ReadNotification(ReadOnlySpan<byte> packet)
    {
        Wire.ValidateHeader(packet);
        if (packet.Length != Wire.HeaderSize + 24 || Wire.U16(packet, 12) != 0x12 ||
            Wire.U64(packet, 24) != ulong.MaxValue || Wire.U32(packet, 36) != 0 ||
            Wire.U32(packet, 8) != 0 || (Wire.U32(packet, 16) & Wire.AsyncCommand) != 0)
            throw new SmbProtocolException("Invalid unsolicited SMB oplock break header.");
        Wire.Structure(packet, 24, 24);
        var level = (SmbOplockLevel)packet[66];
        if (level is not (SmbOplockLevel.None or SmbOplockLevel.LevelII or SmbOplockLevel.Exclusive))
            throw new SmbProtocolException("Invalid oplock break downgrade level.");
        return (SmbFileId.Read(packet, 72), level);
    }

    /// <summary>识别 MS-SMB2 第 3.2.5.19.1 节规定的状态转换。</summary>
    /// <param name="previous">当前已经授予的缓存级别。</param>
    /// <param name="requested">撤销通知中的级别。</param>
    /// <returns>仅有效降级返回 true；重复通知及权限升级请求被忽略。</returns>
    internal static bool IsTransition(SmbOplockLevel previous, SmbOplockLevel requested)
        => previous switch
        {
            SmbOplockLevel.LevelII => requested == SmbOplockLevel.None,
            SmbOplockLevel.Exclusive => requested is SmbOplockLevel.None or SmbOplockLevel.LevelII,
            SmbOplockLevel.Batch => requested is SmbOplockLevel.None or SmbOplockLevel.LevelII or SmbOplockLevel.Exclusive,
            _ => false
        };

    /// <summary>构造固定为 24 字节、保留字段清零的机会锁确认正文。</summary>
    /// <param name="id">受影响的远程打开句柄。</param>
    /// <param name="level">客户端在刷新或清空缓存后接受的级别。</param>
    /// <returns>需要附带实际树标识符和会话标识符发送的确认正文。</returns>
    /// <exception cref="ArgumentOutOfRangeException">提供了 Batch 或未知级别。</exception>
    internal static byte[] Acknowledgement(SmbFileId id, SmbOplockLevel level)
    {
        if (level is not (SmbOplockLevel.None or SmbOplockLevel.LevelII or SmbOplockLevel.Exclusive))
            throw new ArgumentOutOfRangeException(nameof(level));
        var body = new byte[24];
        Wire.Put16(body, 0, 24);
        body[2] = (byte)level;
        id.Write(body, 8);
        return body;
    }
}