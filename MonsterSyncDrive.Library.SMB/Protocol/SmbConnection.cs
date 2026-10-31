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
using MonsterSyncDrive.Library.SMB.Protocol.Compression;
using MonsterSyncDrive.Library.SMB.Security;
using MonsterSyncDrive.Library.SMB.Transport;
using System.Collections.Concurrent;

namespace MonsterSyncDrive.Library.SMB.Protocol;


/// <summary>一个 SMB 传输通道的消息号、credit、收发和密码学状态；多个通道可共享一个逻辑会话。</summary>
internal sealed class SmbConnection : IAsyncDisposable
{

    /// <summary>已分配消息号的请求状态，保存验证响应和异步取消所需的上下文。</summary>
    /// <param name="command">发出的命令。</param>
    /// <param name="treeId">请求所属共享树。</param>
    /// <param name="encrypted">该请求是否发送加密变换。</param>
    /// <param name="signed">该请求是否必须验证签名。</param>
    /// <param name="request">预认证哈希和错误分析需要的原始请求副本。</param>
    private sealed class Pending(Command command, uint treeId, bool encrypted, bool signed, byte[] request)
    {

        /// <summary>请求的命令号，用于拒绝同一消息号上的错误命令回复。</summary>
        internal readonly Command Command = command;

        /// <summary>原请求共享树，异步头不再直接携带此值。</summary>
        internal readonly uint TreeId = treeId;

        /// <summary>原请求是否加密，防止回复被降为明文。</summary>
        internal readonly bool Encrypted = encrypted;

        /// <summary>原请求是否要求签名验证。</summary>
        internal readonly bool Signed = signed;

        /// <summary>发出前的完整 SMB 消息，包含最终消息号和签名。</summary>
        internal readonly byte[] Request = request;

        /// <summary>调用方等待的唯一最终响应任务，异步继续运行调用方以免阻塞接收循环。</summary>
        internal readonly TaskCompletionSource<Response> Completion = new(TaskCreationOptions.RunContinuationsAsynchronously);

        /// <summary>服务端 STATUS_PENDING 赋予的异步标识，供最终回复与 CANCEL 校验。</summary>
        internal ulong? AsyncId;
    }


    /// <summary>已建立且完成传输握手的消息承载，不假设底层一定是 TCP 流。</summary>
    private readonly ISmbMessageTransport transport;

    /// <summary>建立本通道时复制验证的配置快照。</summary>
    private readonly SmbClientOptions options;

    /// <summary>整个通道的终止令牌，失败后取消排队发送和接收。</summary>
    private readonly CancellationTokenSource lifetime = new();

    /// <summary>串行化消息号分配、签名和帧发送，避免并发请求顺序与 credit 窗口不一致。</summary>
    private readonly SemaphoreSlim writer = new(1, 1);

    /// <summary>消息号到未完成请求的并发索引，支持乱序回复。</summary>
    private readonly ConcurrentDictionary<ulong, Pending> outstanding = new();

    /// <summary>保护 credit、消息号分配和 credit 变化信号的锁。</summary>
    private readonly object creditLock = new();

    /// <summary>预算变化时唤醒所有等待者的新一代信号。</summary>
    private TaskCompletionSource creditChanged = NewSignal();

    /// <summary>通道唯一接收循环；负责验证和分派，不执行用户缓存回调。</summary>
    private readonly Task receiveTask;

    /// <summary>当前可用于新请求的服务器 credit 预算。</summary>
    private int credits = 1;

    /// <summary>下一段 credit 窗口的起始消息号，按 charge 向前推进。</summary>
    private ulong nextMessageId;

    /// <summary>首次导致通道终止的异常，只允许一次发布。</summary>
    private Exception? failure;

    /// <summary>异步释放的原子幂等标志。</summary>
    private int disposed;

    /// <summary>当前认证阶段或已绑定通道的签名及会话加密上下文。</summary>
    private SmbCryptography? cryptography;

    /// <summary>此通道实际协商的协议版本。</summary>
    internal SmbDialect Dialect { get; set; } = SmbDialect.Smb202;

    /// <summary>服务器是否支持多 credit 数据事务。</summary>
    internal bool LargeMtu
    {
        get; set;
    }

    /// <summary>本通道所属的认证会话号；绑定通道共享此值。</summary>
    internal ulong SessionId
    {
        get; set;
    }

    /// <summary>普通请求是否使用消息签名，绑定 SESSION_SETUP 也受此保护。</summary>
    internal bool SignRequests
    {
        get; private set;
    }

    /// <summary>普通会话消息是否使用 SMB 加密，与底层 QUIC TLS 分开。</summary>
    internal bool EncryptSession
    {
        get; private set;
    }
    /// <summary>经过认证回复确认的服务器会话强制加密位；与客户端 WhenAvailable 发送偏好分别保存。</summary>
    internal bool ServerRequiresEncryption
    {
        get; set;
    }

    /// <summary>通道尚未释放且未发布终止错误。</summary>
    internal bool IsAlive => Volatile.Read(ref failure) is null && Volatile.Read(ref disposed) == 0;

    /// <summary>当前通道等待响应的请求数，用于多通道调度。</summary>
    internal int PendingRequestCount => outstanding.Count;

    /// <summary>本地帧限制和底层传输限制的较小值，包含 SMB 头。</summary>
    internal int MaximumMessageSize => Math.Min(options.MaximumPacketSize, transport.MaximumMessageSize);

    /// <summary>实际承载通道的传输类型。</summary>
    internal SmbTransportKind TransportKind => transport.Kind;
    /// <summary>本通道所拥有的 SMB Direct 连接；普通 TCP、NetBIOS、QUIC 通道返回空。</summary>
    internal SmbDirectConnection? DirectConnection => (transport as SmbDirectTransport)?.Connection;
    /// <summary>仅在已认证 SMB3 RDMA 通道且未要求签名、消息加密或压缩时允许明文数据直接放置。</summary>
    internal bool CanUseRdmaDirectPlacement => IsAlive && SessionId != 0 && Dialect >= SmbDialect.Smb300 &&
        DirectConnection is not null && !SignRequests && !EncryptSession && Compression is null;

    /// <summary>经双方协商的压缩引擎；为空时收到压缩报文即拒绝。</summary>
    internal SmbCompression? Compression
    {
        get; set;
    }

    /// <summary>逻辑客户端共享的并发请求预算；字节限速在文件句柄层执行。</summary>
    internal SmbQosState QosState
    {
        get; set;
    }

    /// <summary>已经通过通道校验的非请求响应通知；回调只能排队，不能阻塞接收。</summary>
    internal Action<byte[], bool>? OplockBreakReceived
    {
        get; set;
    }

    /// <summary>通道首次终止的通知，用于会话级存活判断和 oplock 失效。</summary>
    internal event Action<Exception>? Failed;
    /// <summary>读取逻辑会话共享的通道故障序号，在 SMB3 请求签名前写入 ChannelSequence。</summary>
    internal Func<ushort>? ChannelSequenceProvider
    {
        get; set;
    }


    /// <summary>接管消息传输并启动唯一接收循环。</summary>
    /// <param name="transport">已经完成 TCP、NetBIOS、QUIC 或 SMB Direct 握手的传输。</param>
    /// <param name="options">已验证的通道选项。</param>
    private SmbConnection(ISmbMessageTransport transport, SmbClientOptions options)
    {
        this.transport = transport;
        this.options = options;
        QosState = new SmbQosState(options.Qos);
        receiveTask = ReceiveLoopAsync();
    }


    /// <summary>通过统一工厂建立消息传输；构造失败时释放已建立的传输。</summary>
    /// <param name="options">包含超时和传输的配置快照。</param>
    /// <param name="cancellationToken">连接及传输握手取消令牌。</param>
    internal static async Task<SmbConnection> ConnectAsync(SmbClientOptions options, CancellationToken cancellationToken)
    {
        ISmbMessageTransport transport = await SmbTransportFactory.ConnectAsync(options.Host, options.Port, options.Transport,
            options.MaximumPacketSize, options.ConnectTimeout, cancellationToken).ConfigureAwait(false);
        try
        {
            return new SmbConnection(transport, options);
        }
        catch
        {
            await transport.DisposeAsync().ConfigureAwait(false);
            throw;
        }
    }


    /// <summary>切换认证阶段或绑定完成后的密钥和保护策略；密钥释放由当前拥有者安排。</summary>
    /// <param name="crypto">本通道使用的密码学上下文。</param>
    /// <param name="sign">是否签名。</param>
    /// <param name="encrypt">是否对常规请求使用 SMB 加密。</param>
    internal void Authenticate(SmbCryptography crypto, bool sign, bool encrypt)
    {
        cryptography = crypto;
        SignRequests = sign;
        EncryptSession = encrypt;
    }


    /// <summary>预留调度和 credit 预算，分配消息号，按签名、压缩、加密次序发送并等待校验后的最终回复。</summary>
    /// <param name="command">SMB2 命令号。</param>
    /// <param name="body">不包含 64 字节 SMB2 头的命令体。</param>
    /// <param name="treeId">共享树号，协商或会话命令可为零。</param>
    /// <param name="cancellationToken">调用方取消令牌。</param>
    /// <param name="maximumResponse">预计最大响应负载，供 credit 计费。</param>
    /// <param name="encrypt">该共享是否额外要求加密。</param>
    /// <param name="infiniteTimeout">是否由调用方取消而不采用普通操作超时。</param>
    internal async Task<Response> SendAsync(Command command, ReadOnlyMemory<byte> body, uint treeId,
        CancellationToken cancellationToken, int maximumResponse = 0, bool encrypt = false,
        bool infiniteTimeout = false)
    {
        ObjectDisposedException.ThrowIf(Volatile.Read(ref disposed) != 0, this);
        ThrowIfFailed();
        if (body.Length > MaximumMessageSize - 116)
            throw new ArgumentOutOfRangeException(nameof(body), "The request exceeds MaximumPacketSize.");
        int payloadSize = command == Command.Write && body.Length >= 8 ? (int)Wire.U32(body.Span, 4)
            : command == Command.Ioctl && body.Length >= 32 ? (int)Wire.U32(body.Span, 28)
            : command == Command.SetInfo && body.Length >= 8 ? (int)Wire.U32(body.Span, 4)
            : 0;
        int charge = LargeMtu && Dialect != SmbDialect.Smb202
            ? Math.Max(1, (Math.Max(payloadSize, maximumResponse) + 65535) / 65536) : 1;
        if (charge > ushort.MaxValue)
            throw new ArgumentOutOfRangeException(nameof(maximumResponse));
        using var timeout = new CancellationTokenSource();
        if (!infiniteTimeout && options.OperationTimeout != Timeout.InfiniteTimeSpan)
            timeout.CancelAfter(options.OperationTimeout);
        using var linked = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, timeout.Token, lifetime.Token);
        using IDisposable? scheduling = await AcquireSchedulingAsync(command, infiniteTimeout, linked.Token,
            cancellationToken, timeout.Token).ConfigureAwait(false);
        try
        {
            await ReserveAsync(charge, linked.Token).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (timeout.IsCancellationRequested && !cancellationToken.IsCancellationRequested)
        {
            throw new TimeoutException("Waiting for SMB credits timed out.");
        }
        bool binding = command == Command.SessionSetup && body.Length >= 3 && (body.Span[2] & 1) != 0;
        bool protectedCommand = command is not (Command.Negotiate or Command.SessionSetup) || binding;
        bool encrypted = protectedCommand && (EncryptSession || encrypt);
        bool signed = protectedCommand && SignRequests && !encrypted;
        ulong id = 0;
        Pending? pending = null;
        bool written = false;
        bool frameComplete = false;
        bool assignedId = false;
        try
        {
            await writer.WaitAsync(linked.Token).ConfigureAwait(false);
            try
            {
                linked.Token.ThrowIfCancellationRequested();
                ThrowIfFailed();
                byte[] packet = Wire.Header(command, 0, SessionId, treeId,
                    Dialect == SmbDialect.Smb202 ? (ushort)0 : (ushort)charge, 64, body.Length);
                if (Dialect >= SmbDialect.Smb300 && SessionId != 0)
                    Wire.Put16(packet, 8, ChannelSequenceProvider?.Invoke() ?? 0);
                body.Span.CopyTo(packet.AsSpan(64));
                // 绑定通道可采用不同传输。只对本通道实际协商压缩的 SMB 3.1.1 保留 READ 请求压缩标志；
                // 不能仅凭主通道配置就让 RDMA、旧版本或未协商压缩的连接发送此标志。
                if (command == Command.Read && body.Length >= 4 &&
                    (Dialect != SmbDialect.Smb311 || Compression is null || TransportKind == SmbTransportKind.Rdma))
                    packet[67] &= 0xFD;
                lock (creditLock)
                {
                    id = nextMessageId;
                    nextMessageId = checked(nextMessageId + (uint)charge);
                    assignedId = true;
                }
                Wire.Put64(packet, 24, id);
                if (signed)
                    cryptography!.Sign(packet);
                pending = new Pending(command, treeId, encrypted, signed, packet);
                if (!outstanding.TryAdd(id, pending))
                    throw new SmbProtocolException("An SMB message ID was reused.");
                byte[] payload = command is not (Command.Negotiate or Command.SessionSetup) && Compression is { } compressor
                    ? compressor.Compress(packet) : packet;
                if (encrypted)
                    payload = cryptography!.Encrypt(payload, SessionId);
                // 一旦开始写帧，取消或失败便不能把半帧留在仍可用的连接上；异常路径必须终止承载。
                written = true;
                await WriteFrameAsync(payload, linked.Token).ConfigureAwait(false);
                frameComplete = true;
            }
            finally
            {
                _ = writer.Release();
            }
            using CancellationTokenRegistration timeoutRegistration = timeout.Token.UnsafeRegister(_ =>
            {
                if (!pending!.Completion.Task.IsCompleted)
                    Abort(new TimeoutException("An SMB operation timed out."));
            }, null);
            using CancellationTokenRegistration cancellationRegistration = cancellationToken.UnsafeRegister(
                _ => Cancel(id, pending!, cancellationToken), null);
            return await pending!.Completion.Task.ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (timeout.IsCancellationRequested && !cancellationToken.IsCancellationRequested)
        {
            if (written)
                Abort(new TimeoutException("An SMB operation timed out."));
            throw new TimeoutException("An SMB operation timed out.");
        }
        catch (Exception ex)
        {
            if (written && (!frameComplete || ex is not (OperationCanceledException or SmbException)))
                Abort(ex);
            throw;
        }
        finally
        {
            if (!written)
            {
                if (assignedId)
                {
                    if (pending is not null)
                        _ = outstanding.TryRemove(id, out _);
                    Abort(new SmbProtocolException("An SMB message could not be sent."));
                }
                AddCredits(charge);
            }
        }
    }


    /// <summary>在发送前申请普通请求调度预算；控制消息和长等待不占槽，排队超时不会破坏健康连接。</summary>
    /// <param name="command">准备发送的命令。</param>
    /// <param name="infiniteTimeout">是否为通知或等待式锁等长等待。</param>
    /// <param name="linkedToken">组合了用户、超时和通道终止的令牌。</param>
    /// <param name="userToken">用于区分显式取消的用户令牌。</param>
    /// <param name="timeoutToken">本次操作的超时令牌。</param>
    private async ValueTask<IDisposable?> AcquireSchedulingAsync(Command command, bool infiniteTimeout,
        CancellationToken linkedToken, CancellationToken userToken, CancellationToken timeoutToken)
    {
        if (infiniteTimeout || command is Command.Negotiate or Command.SessionSetup or Command.Cancel or Command.OplockBreak)
            return null;
        try
        {
            return await QosState.AcquireAsync(linkedToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (timeoutToken.IsCancellationRequested && !userToken.IsCancellationRequested)
        {
            throw new TimeoutException("Waiting for SMB request scheduling timed out.");
        }
    }

    /// <summary>等待足够的 credit；在同一锁内扣减，唤醒后重新校验连接与取消状态。</summary>
    /// <param name="charge">本请求需要的 credit 数。</param>
    /// <param name="cancellationToken">等待预算的取消令牌。</param>
    private async Task ReserveAsync(int charge, CancellationToken cancellationToken)
    {
        while (true)
        {
            Task wait;
            lock (creditLock)
            {
                ThrowIfFailed();
                cancellationToken.ThrowIfCancellationRequested();
                if (credits >= charge)
                {
                    credits -= charge;
                    return;
                }
                wait = creditChanged.Task;
            }
            await wait.WaitAsync(cancellationToken).ConfigureAwait(false);
        }
    }


    /// <summary>归还或加入服务器授予的 credit 并发布新一代变化信号。</summary>
    /// <param name="count">新增预算数量。</param>
    private void AddCredits(int count)
    {
        lock (creditLock)
        {
            credits = checked(credits + count);
            TaskCompletionSource signal = creditChanged;
            creditChanged = NewSignal();
            _ = signal.TrySetResult();
        }
    }


    /// <summary>创建异步继续执行的通知任务，防止在 credit 锁中执行调用方代码。</summary>
    private static TaskCompletionSource NewSignal()
    {
        return new(TaskCreationOptions.RunContinuationsAsynchronously);
    }


    /// <summary>校验最终受保护消息长度，再交给承载层原子帧发送。</summary>
    /// <param name="payload">可能已压缩或加密的消息。</param>
    /// <param name="cancellationToken">发送取消令牌，部分发送失败会终止连接。</param>
    private async Task WriteFrameAsync(byte[] payload, CancellationToken cancellationToken)
    {
        if (payload.Length > MaximumMessageSize)
            throw new SmbProtocolException("An SMB frame exceeds the configured limit.");
        await transport.SendAsync(payload, cancellationToken).ConfigureAwait(false);
    }


    /// <summary>唯一接收循环：还原加密及压缩、验证头和完整性，分派异步状态、oplock 与乱序最终回复。</summary>
    private async Task ReceiveLoopAsync()
    {
        try
        {
            while (!lifetime.IsCancellationRequested)
            {
                byte[] packet = await transport.ReceiveAsync(lifetime.Token).ConfigureAwait(false);
                if (packet.Length < 4 || packet.Length > MaximumMessageSize)
                    throw new SmbProtocolException("Invalid or oversized SMB message.");
                bool encrypted = packet[0] == 0xFD;
                if (encrypted)
                    packet = (cryptography ?? throw new SmbProtocolException("Unexpected encrypted SMB message.")).Decrypt(packet, SessionId);
                if (SmbCompression.IsCompressed(packet))
                    packet = (Compression ?? throw new SmbProtocolException("Unnegotiated SMB compression.")).Decompress(packet, MaximumMessageSize);
                Wire.ValidateHeader(packet);
                ulong id = Wire.U64(packet, 24);
                if (Wire.U16(packet, 12) == (ushort)Command.OplockBreak && id == ulong.MaxValue)
                {
                    ulong session = Wire.U64(packet, 40);
                    if (cryptography is null || (session != 0 && session != SessionId) || Wire.U32(packet, 36) != 0 ||
                        (Wire.U32(packet, 16) & Wire.AsyncCommand) != 0 ||
                        ((options.Encryption == SmbEncryptionPolicy.Required || ServerRequiresEncryption) && !encrypted))
                        throw new SmbProtocolException($"Invalid or unprotected SMB oplock notification: " +
                            $"authenticated={cryptography is not null}, sessionMatches={session == 0 || session == SessionId}, " +
                            $"treeZero={Wire.U32(packet, 36) == 0}, async={(Wire.U32(packet, 16) & Wire.AsyncCommand) != 0}, " +
                            $"encrypted={encrypted}, signed={(Wire.U32(packet, 16) & Wire.Signed) != 0}, localEncryptionPreference={EncryptSession}.");
                    // MS-SMB2 3.2.5.1.3 要求对全 1 消息号的主动通知跳过常规签名处理。
                    // 这不影响普通请求响应的强制签名；上述会话校验以及会话、共享的加密要求仍须执行。
                    Wire.Structure(packet, 24, 24);
                    // 这里只排队缓存回调。若接收循环等待 ACK 完成，就无法读取该 ACK 的响应而产生死锁。
                    // 主动通知没有对应的原请求。WhenAvailable 的发送加密偏好不等于服务端要求；
                    // 关联共享的强制加密条件必须带着实际保护状态，在 FileId 解析或延迟注册后再检查。
                    OplockBreakReceived?.Invoke(packet, encrypted);
                    continue;
                }
                if (!outstanding.TryGetValue(id, out Pending? pending))
                    throw new SmbProtocolException("The server returned an unknown SMB message ID.");
                var status = (SmbStatus)Wire.U32(packet, 8);
                bool async = (Wire.U32(packet, 16) & Wire.AsyncCommand) != 0;
                if (Wire.U16(packet, 12) != (ushort)pending.Command ||
                    (pending.Command is not (Command.SessionSetup or Command.Negotiate) && Wire.U64(packet, 40) != SessionId) ||
                    (!async && pending.Command is not (Command.TreeConnect or Command.SessionSetup or Command.Negotiate) && Wire.U32(packet, 36) != pending.TreeId))
                    throw new SmbProtocolException("SMB response identifiers do not match their request.");
                if (pending.Encrypted && !encrypted)
                    throw new SmbProtocolException("The server returned plaintext for an encrypted SMB request.");
                if (!encrypted && status != SmbStatus.Pending && pending.Command is not (Command.SessionSetup or Command.Negotiate))
                    cryptography?.Verify(packet, pending.Signed);
                if (status == SmbStatus.Pending)
                {
                    if (!async)
                        throw new SmbProtocolException("STATUS_PENDING requires an asynchronous SMB header.");
                    lock (pending)
                    {
                        if (pending.AsyncId is not null)
                            throw new SmbProtocolException("Duplicate SMB interim response.");
                        pending.AsyncId = Wire.U64(packet, 32);
                    }
                    AddCredits(Wire.U16(packet, 14));
                    continue;
                }
                lock (pending)
                {
                    if (pending.AsyncId is { } expected && (!async || Wire.U64(packet, 32) != expected))
                        throw new SmbProtocolException("An SMB asynchronous response has an invalid ID.");
                }
                _ = outstanding.TryRemove(id, out _);
                AddCredits(Wire.U16(packet, 14));
                _ = pending.Completion.TrySetResult(new Response(packet, pending.Request));
            }
        }
        catch (Exception ex)
        {
            Abort(ex);
        }
    }


    /// <summary>立即使调用方看到取消，并异步发送协议 CANCEL；继续接收服务端最终回复以保持通道一致。</summary>
    /// <param name="id">被取消请求的消息号。</param>
    /// <param name="pending">原请求和异步标识。</param>
    /// <param name="cancellationToken">需要保留到取消异常中的令牌。</param>
    private void Cancel(ulong id, Pending pending, CancellationToken cancellationToken)
    {
        if (pending.Completion.TrySetCanceled(cancellationToken))
            _ = SendCancelAsync(id, pending);
    }


    /// <summary>在同一写锁下发送不消耗 credit 的 CANCEL，沿用原请求保护及异步标识，超出宽限期则终止连接。</summary>
    /// <param name="id">原请求消息号。</param>
    /// <param name="pending">原请求状态。</param>
    private async Task SendCancelAsync(ulong id, Pending pending)
    {
        try
        {
            await writer.WaitAsync(lifetime.Token).ConfigureAwait(false);
            try
            {
                if (!outstanding.ContainsKey(id))
                    return;
                byte[] packet = Wire.Header(Command.Cancel, id, SessionId, pending.TreeId, 0, 0, 4);
                if (Dialect >= SmbDialect.Smb300 && SessionId != 0)
                    Wire.Put16(packet, 8, ChannelSequenceProvider?.Invoke() ?? 0);
                Wire.Put16(packet, 64, 4);
                lock (pending)
                {
                    if (pending.AsyncId is { } asyncId)
                    {
                        Wire.Put32(packet, 16, Wire.AsyncCommand);
                        Wire.Put64(packet, 32, asyncId);
                    }
                }
                if (pending.Signed)
                    cryptography!.Sign(packet);
                await WriteFrameAsync(pending.Encrypted ? cryptography!.Encrypt(packet, SessionId) : packet, lifetime.Token).ConfigureAwait(false);
            }
            finally
            {
                _ = writer.Release();
            }
            TimeSpan grace = options.OperationTimeout == Timeout.InfiniteTimeSpan ? TimeSpan.FromSeconds(60) : options.OperationTimeout;
            await Task.Delay(grace, lifetime.Token).ConfigureAwait(false);
            if (outstanding.ContainsKey(id))
                Abort(new TimeoutException("The server did not complete a cancelled SMB operation."));
        }
        catch (OperationCanceledException) when (lifetime.IsCancellationRequested) { }
        catch (Exception ex)
        {
            Abort(ex);
        }
    }


    /// <summary>只发布首个通道错误，终止传输并使所有待处理请求失败，最后通知会话层。</summary>
    /// <param name="exception">终止原因，保留为后续 IO 异常的内部错误。</param>
    internal void Abort(Exception exception)
    {
        if (Interlocked.CompareExchange(ref failure, exception, null) is not null)
            return;
        lifetime.Cancel();
        transport.Abort();
        foreach (KeyValuePair<ulong, Pending> entry in outstanding)
            if (outstanding.TryRemove(entry.Key, out Pending? pending))
                _ = pending.Completion.TrySetException(exception);
        lock (creditLock)
        {
            _ = creditChanged.TrySetResult();
        }
        try
        {
            Failed?.Invoke(exception);
        }
        catch { /* 订阅者异常不能阻止剩余传输资源清理。 */ }
    }


    /// <summary>失败后的调用立即得到保留原始原因的 IO 异常，不在已破坏的通道上继续发送。</summary>
    private void ThrowIfFailed()
    {
        if (Volatile.Read(ref failure) is { } error)
            throw new IOException("The SMB connection is closed.", error);
    }


    /// <summary>幂等终止通道、等待接收结束、释放承载和当前密码学密钥。</summary>
    public async ValueTask DisposeAsync()
    {
        if (Interlocked.Exchange(ref disposed, 1) != 0)
            return;
        Abort(new ObjectDisposedException(nameof(SmbConnection)));
        await receiveTask.ConfigureAwait(false);
        await transport.DisposeAsync().ConfigureAwait(false);
        cryptography?.Dispose();
        // Abort 之后仍可能有请求在异常展开中使用写锁和生命周期令牌，不能提前销毁这些同步对象。
    }
}