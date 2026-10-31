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

/// <summary>在会话范围内分发主动机会锁撤销通知，并处理 CREATE 句柄注册竞争。</summary>
public sealed partial class SmbClient
{
    /// <summary>串行化句柄注册后的通知重放与常规通知分发。</summary>
    private readonly object oplockDispatchGate = new();
    /// <summary>有界保存等待 CREATE 注册的通知及其实际加密状态，防止重放时丢失共享的强制加密约束。</summary>
    private readonly List<(byte[] Packet, bool WasEncrypted)> deferredOplockBreaks = [];
    /// <summary>统计其返回 FileId 尚未注册的 CREATE 操作。</summary>
    private int pendingOplockOpens;

    /// <summary>在 CREATE 可能发送之前开启注册竞争保护窗口。</summary>
    internal void BeginOplockOpen()
    {
        lock (oplockDispatchGate) pendingOplockOpens++;
    }

    /// <summary>结束一个 CREATE 保护窗口；没有后续注册机会时丢弃未匹配通知。</summary>
    /// <remarks>SMB 规范要求忽略未知 FileId，不应对其确认或无限重试。</remarks>
    internal void EndOplockOpen()
    {
        lock (oplockDispatchGate)
        {
            if (--pendingOplockOpens == 0)
                deferredOplockBreaks.Clear();
        }
    }

    /// <summary>CREATE 的后续代码完成新句柄注册后，重放此前暂存的通知。</summary>
    /// <remarks>
    /// 服务器可以连续发送 CREATE 响应和首次撤销通知；接收循环可能在等待方
    /// 的后续代码执行之前收到通知，因此需要重放，避免丢失缓存降级请求。
    /// 通知中的 TreeId 为零，必须按 FileId 搜索所有共享使用对象。
    /// </remarks>
    internal void OplockHandleRegistered()
    {
        try
        {
            lock (oplockDispatchGate)
            {
                for (var i = 0; i < deferredOplockBreaks.Count;)
                {
                    var notification = deferredOplockBreaks[i];
                    if (TryDispatchOplockBreak(notification.Packet, notification.WasEncrypted))
                        deferredOplockBreaks.RemoveAt(i);
                    else
                        i++;
                }
            }
        }
        catch (SmbProtocolException error)
        {
            // 此路径运行在 CREATE 的后续代码中，而非接收循环；重放发现加密策略违规时也必须终止会话。
            Abort(error);
            throw;
        }
    }

    /// <summary>校验已经过连接认证的主动消息，分发消息或短暂等待未知句柄完成注册。</summary>
    /// <param name="packet">经过必要的解密并通过接收通道安全策略校验的消息。</param>
    /// <param name="wasEncrypted">消息是否通过 SMB TRANSFORM_HEADER 加密接收；与客户端的发送偏好分别记录。</param>
    /// <exception cref="SmbProtocolException">消息格式错误，或对端超过 CREATE 暂存队列上限。</exception>
    internal void DispatchOplockBreak(byte[] packet, bool wasEncrypted)
    {
        _ = SmbOplockProtocol.ReadNotification(packet);
        lock (oplockDispatchGate)
        {
            if (TryDispatchOplockBreak(packet, wasEncrypted) || pendingOplockOpens == 0)
                return;
            if (deferredOplockBreaks.Count >= 128)
                throw new SmbProtocolException("Too many oplock breaks waiting for CREATE registration.");
            deferredOplockBreaks.Add((packet, wasEncrypted));
        }
    }

    /// <summary>查找会话中的打开句柄，不假定通知属于接收通道的某个树连接。</summary>
    /// <param name="packet">已经验证的通知。</param>
    /// <param name="wasEncrypted">原始通知是否实际采用 SMB 消息加密。</param>
    /// <returns>已知句柄接收了该通知时返回 true，包括正在关闭的句柄。</returns>
    private bool TryDispatchOplockBreak(byte[] packet, bool wasEncrypted)
    {
        foreach (var share in shares.Keys)
            if (share.TryQueueOplockBreak(packet, wasEncrypted))
                return true;
        return false;
    }

    /// <summary>所有可用通道失败后，使全部本地缓存授予状态失效。</summary>
    /// <param name="error">需要传递给待完成通知观察者的失败原因。</param>
    /// <remarks>只要会话仍有其他可用通道，单条绑定通道失败就不应撤销所有缓存授予。</remarks>
    internal void InvalidateAllOplocks(Exception error)
    {
        lock (oplockDispatchGate) deferredOplockBreaks.Clear();
        foreach (var share in shares.Keys)
            share.InvalidateOplocks(error);
    }
}