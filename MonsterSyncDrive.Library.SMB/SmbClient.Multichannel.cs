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
using System.Net;
using MonsterSyncDrive.SMB.Protocol;
using MonsterSyncDrive.SMB.Security;

namespace MonsterSyncDrive.SMB;

/// <summary>同一认证会话的附加通道绑定、服务器接口发现和请求分配实现。</summary>
public sealed partial class SmbClient
{
    /// <summary>客户端本地通道身份、连接及其端点配置；不包含用户凭据。</summary>
    /// <param name="Id">在此客户端中单调递增的通道标识。</param>
    /// <param name="Connection">已认证并绑定的独立传输连接。</param>
    /// <param name="EndpointOptions">此通道的实际端点及不可变选项快照。</param>
    /// <param name="Primary">是否为创建会话的首个通道。</param>
    private sealed record Channel(int Id, SmbConnection Connection, SmbClientOptions EndpointOptions, bool Primary)
    {
        /// <summary>是否已将此连接的失效计入会话通道序号；由 channelLock 保护。</summary>
        internal bool DisconnectObserved;
    }
    /// <summary>保护通道列表及其快照；锁内不执行网络等待或 oplock 回调。</summary>
    private readonly object channelLock = new();
    /// <summary>当前会话的主通道和仍待清理的附加通道记录。</summary>
    private readonly List<Channel> channels = [];
    /// <summary>串行化附加通道的绑定、失败通道清理和客户端最终释放。</summary>
    private readonly SemaphoreSlim channelGate = new(1, 1);
    /// <summary>独立拥有的原会话密钥副本，主连接失效或释放后仍可签名后续绑定。</summary>
    private SmbCryptography? sessionCryptography;
    /// <summary>主连接协商的服务端安全模式，新通道必须匹配。</summary>
    private ushort serverSecurityMode;
    /// <summary>主连接协商的服务端能力位，新通道必须匹配。</summary>
    private uint serverCapabilities;
    /// <summary>分配附加通道标识的原子计数器。</summary>
    private int channelSequence;
    /// <summary>轮转分配请求及最少负载并列候选时使用的原子计数器。</summary>
    private int selectionSequence;
    /// <summary>会话网络断连代数；输出时按无符号十六位模运算回绕，与本地通道标识分别计数。</summary>
    private int sessionChannelSequence;

    /// <summary>服务器是否协商了 SMB3 多通道能力；客户端仍须显式启用该功能。</summary>
    public bool MultichannelSupported => ConnectionInfo is not null && ConnectionInfo.Dialect >= SmbDialect.Smb300 &&
        (serverCapabilities & 8) != 0;

    /// <summary>返回通道状态的不可变快照；该快照不会随随后的连接状态变化自动更新。</summary>
    public IReadOnlyList<SmbChannelInfo> Channels
    {
        get
        {
            lock (channelLock)
                return channels.Select(channel => new SmbChannelInfo(channel.Id,
                    channel.EndpointOptions.Transport.RemoteAddress?.ToString() ?? channel.EndpointOptions.Host,
                    channel.EndpointOptions.Port, channel.Primary, channel.Connection.IsAlive,
                    channel.Connection.PendingRequestCount)).ToArray();
        }
    }

    /// <summary>在通道列表锁保护下检查是否仍有可发送新请求的连接。</summary>
    private bool HasLiveChannel
    {
        get { lock (channelLock) return channels.Any(channel => channel.Connection.IsAlive); }
    }

    /// <summary>将主连接注册为零号通道并绑定通知及失败事件。</summary>
    /// <param name="primary">最初创建会话的连接。</param>
    /// <param name="options">主连接选项快照。</param>
    private void RegisterPrimaryChannel(SmbConnection primary, SmbClientOptions options)
    {
        lock (channelLock)
            channels.Add(new Channel(0, primary, options, true));
        ConfigureChannel(primary);
    }

    /// <summary>为主通道和附加通道配置同一套会话级 oplock 与故障分派。</summary>
    /// <param name="transport">待配置回调的连接。</param>
    private void ConfigureChannel(SmbConnection transport)
    {
        transport.ChannelSequenceProvider = ReadChannelSequence;
        transport.OplockBreakReceived = DispatchOplockBreak;
        transport.Failed += error => OnChannelFailed(transport, error);
    }

    /// <summary>仅在最后一个通道也失效时撤销会话的 oplock；不会重发失败请求。</summary>
    /// <param name="failed">触发失败事件的连接。</param>
    /// <param name="error">该连接的失败原因。</param>
    private void OnChannelFailed(SmbConnection failed, Exception error)
    {
        bool lostAll;
        lock (channelLock)
        {
            ObserveDisconnectedChannels();
            lostAll = !channels.Any(channel => channel.Connection.IsAlive);
        }
        // 不在通道锁内调用 oplock 分派器；其队列溢出可能反向调用 Abort，造成锁顺序倒置。
        if (lostAll)
            InvalidateAllOplocks(error);
    }

    /// <summary>在已持有 channelLock 时，将已登记通道的首次失效计入会话代数。</summary>
    private void ObserveDisconnectedChannels()
    {
        if (Volatile.Read(ref disposed) != 0)
            return; // 整个会话的主动释放不属于需要切换到替代通道的网络故障。
        var survives = channels.Any(channel => channel.Connection.IsAlive);
        foreach (var channel in channels)
        {
            if (channel.Connection.IsAlive || channel.DisconnectObserved)
                continue;
            channel.DisconnectObserved = true;
            if (survives && ConnectionInfo is not null && ConnectionInfo.Dialect >= SmbDialect.Smb300)
                sessionChannelSequence = unchecked(sessionChannelSequence + 1);
        }
    }

    /// <summary>读取即将编码到请求头的通道序号，并补记尚未派发失败事件的断连。</summary>
    /// <returns>符合协议的十六位会话通道序号；溢出按模 65536 回绕。</returns>
    private ushort ReadChannelSequence()
    {
        lock (channelLock)
        {
            // 连接先公布不可用状态，再通知会话。此处补记消除了其间发送新请求仍带旧序号的窗口。
            ObserveDisconnectedChannels();
            return unchecked((ushort)sessionChannelSequence);
        }
    }

    /// <summary>取得全部已登记连接的独立数组，供锁外终止和异步释放使用。</summary>
    /// <returns>读取时已登记的连接，包括尚未清理的失效连接。</returns>
    private SmbConnection[] SnapshotConnections()
    {
        lock (channelLock)
            return channels.Select(channel => channel.Connection).ToArray();
    }

    /// <summary>按策略为新请求选择存活通道，并对负载计数只采样一次以避免并发选择空集。</summary>
    /// <returns>一个当前存活的通道连接；发送前仍可能因网络故障失效。</returns>
    /// <exception cref="IOException">所有通道均已断开。</exception>
    private SmbConnection SelectChannel()
    {
        lock (channelLock)
        {
            var live = channels.Where(channel => channel.Connection.IsAlive).ToArray();
            if (live.Length == 0)
                throw new IOException("The SMB session has no live transport channels.");
            var ordinal = (uint)Interlocked.Increment(ref selectionSequence);
            if (Options.Multichannel.SelectionPolicy == SmbChannelSelectionPolicy.RoundRobin)
                return live[ordinal % (uint)live.Length].Connection;
            // 每个请求计数只读取一次。若先取最小值再重新读取，期间的并发完成可能使候选集为空。
            // 所有选择都基于同一批快照，确保最小值对应的候选至少存在一个。
            var samples = live.Select(channel => (Channel: channel, Pending: channel.Connection.PendingRequestCount)).ToArray();
            var minimum = samples.Min(sample => sample.Pending);
            var eligible = samples.Where(sample => sample.Pending == minimum).ToArray();
            return eligible[ordinal % (uint)eligible.Length].Channel.Connection;
        }
    }

    /// <summary>探测指定的绑定通道，探测请求不会自动转移到其他连接。</summary>
    /// <param name="channelId">Channels 快照中的本地通道标识。</param>
    /// <param name="cancellationToken">取消本次探测。</param>
    /// <exception cref="ArgumentOutOfRangeException">通道标识不存在。</exception>
    public async Task EchoChannelAsync(int channelId, CancellationToken cancellationToken = default)
    {
        ThrowIfDisposed();
        SmbConnection target;
        lock (channelLock)
            target = channels.FirstOrDefault(channel => channel.Id == channelId)?.Connection
                ?? throw new ArgumentOutOfRangeException(nameof(channelId));
        var response = await target.SendAsync(Command.Echo, new byte[] { 4, 0, 0, 0 }, 0, cancellationToken).ConfigureAwait(false);
        response.EnsureSuccess();
        Wire.Structure(response.Packet, 4, 4);
    }

    /// <summary>
    /// 将附加传输认证并绑定为当前会话的通道，所用凭据必须对应原会话的同一用户。
    /// 绑定失败不主动关闭已有通道；已经发送的数据操作不会因连接故障而被盲目重发。
    /// </summary>
    /// <param name="endpointOptions">目标连接配置；会话 GUID、版本和安全策略强制继承主会话。</param>
    /// <param name="credential">与原会话相同用户的凭据；仅在本次认证期间使用。</param>
    /// <param name="cancellationToken">取消连接和绑定过程。</param>
    /// <returns>已经完成签名验证并登记的通道快照。</returns>
    /// <exception cref="NotSupportedException">端点未启用多通道、使用来宾身份或只有不支持安全绑定的签名组合。</exception>
    /// <exception cref="SmbProtocolException">服务器身份、协商参数、会话标识或绑定签名不匹配。</exception>
    public async Task<SmbChannelInfo> AddChannelAsync(SmbClientOptions endpointOptions, SmbCredential credential,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(endpointOptions);
        ArgumentNullException.ThrowIfNull(credential);
        ThrowIfDisposed();
        if (!Options.Multichannel.Enabled || !MultichannelSupported)
            throw new NotSupportedException("Both the client and the SMB3 server must enable multichannel.");
        if (!HasLiveChannel)
            throw new IOException("An additional channel requires a surviving authenticated session; create a new client after every channel disconnects.");
        if (ConnectionInfo.IsGuest || ConnectionInfo.IsAnonymous || credential.IsAnonymous)
            throw new NotSupportedException("SMB guest and anonymous sessions cannot bind additional channels.");
        if (ConnectionInfo.SigningAlgorithm == SmbSigningAlgorithm.AesGmac)
            throw new NotSupportedException("GMAC channel binding is disabled because per-connection binding message IDs can reuse a session signing nonce. Select AES-CMAC for multichannel.");
        var validated = (endpointOptions with
        {
            ClientGuid = Options.ClientGuid,
            MinimumDialect = ConnectionInfo.Dialect,
            MaximumDialect = ConnectionInfo.Dialect,
            Signing = Options.Signing,
            Encryption = Options.Encryption,
            EncryptionCiphers = Options.EncryptionCiphers,
            SigningAlgorithms = Options.SigningAlgorithms,
            Multichannel = Options.Multichannel,
            Compression = Options.Compression
        }).Validate();
        await channelGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        SmbConnection? additional = null;
        try
        {
            ThrowIfDisposed();
            await ReapFailedChannelsAsync().ConfigureAwait(false);
            lock (channelLock)
                if (channels.Count(channel => channel.Connection.IsAlive) >= Options.Multichannel.MaximumChannels)
                    throw new InvalidOperationException("The configured SMB channel limit has been reached.");
            additional = await SmbConnection.ConnectAsync(validated, cancellationToken).ConfigureAwait(false);
            additional.QosState = connection.QosState;
            ConfigureChannel(additional);
            await EstablishSessionAsync(credential, cancellationToken, additional, validated).ConfigureAwait(false);
            if (!additional.IsAlive)
                throw new IOException("The additional SMB channel disconnected before it could be registered.");
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            var id = Interlocked.Increment(ref channelSequence);
            var channel = new Channel(id, additional, validated, false);
            lock (channelLock)
                channels.Add(channel);
            additional = null;
            return new SmbChannelInfo(id, validated.Transport.RemoteAddress?.ToString() ?? validated.Host,
                validated.Port, false, true, 0);
        }
        finally
        {
            if (additional is not null)
                await additional.DisposeAsync().ConfigureAwait(false);
            channelGate.Release();
        }
    }

    /// <summary>使用全部位为一的特殊 IOCTL 文件标识查询服务器网络接口。</summary>
    /// <param name="share">属于本客户端的有效树连接，磁盘共享或 IPC$ 均可。</param>
    /// <param name="cancellationToken">取消接口查询。</param>
    /// <returns>已完成链表、边界和地址族验证的接口列表。</returns>
    public async Task<IReadOnlyList<SmbNetworkInterfaceInfo>> QueryNetworkInterfacesAsync(SmbShare share,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(share);
        ThrowIfDisposed();
        share.ThrowIfDisposed();
        if (!ReferenceEquals(share.Client, this))
            throw new ArgumentException("The share belongs to another SMB session.", nameof(share));
        if (!MultichannelSupported)
            throw new NotSupportedException("The server did not negotiate SMB3 multichannel support.");
        var request = new byte[57];
        Wire.Put16(request, 0, 57);
        Wire.Put32(request, 4, 0x001401FC);
        request.AsSpan(8, 16).Fill(0xFF);
        Wire.Put32(request, 44, 65536);
        Wire.Put32(request, 48, 1);
        var response = await SendAsync(Command.Ioctl, request, share.TreeId, cancellationToken,
            65536, share.EncryptionRequired).ConfigureAwait(false);
        response.EnsureSuccess();
        Wire.Structure(response.Packet, 49, 48);
        if (Wire.U32(response.Packet, 68) != 0x001401FC ||
            !response.Packet.AsSpan(72, 16).SequenceEqual(new byte[] { 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255 }) ||
            Wire.U32(response.Packet, 100) > 65536)
            throw new SmbProtocolException("Invalid SMB network-interface response.");
        var data = Wire.Buffer(response.Packet, Wire.Int32(Wire.U32(response.Packet, 96)), Wire.U32(response.Packet, 100), 112);
        return ParseNetworkInterfaces(data);
    }

    /// <summary>解码 NETWORK_INTERFACE_INFO 链表，忽略规范保留的端口和服务器区域索引。</summary>
    /// <param name="data">IOCTL 返回的原始接口数组。</param>
    /// <returns>接口索引、速率、能力和无服务器区域索引的 IP 地址。</returns>
    /// <exception cref="SmbProtocolException">链表偏移、地址族、接口索引或重复条目无效。</exception>
    internal static IReadOnlyList<SmbNetworkInterfaceInfo> ParseNetworkInterfaces(ReadOnlySpan<byte> data)
    {
        var result = new List<SmbNetworkInterfaceInfo>();
        var seen = new HashSet<(uint Index, IPAddress Address)>();
        var offset = 0;
        while (offset < data.Length)
        {
            var entry = Wire.Slice(data, offset, 152);
            var next = Wire.U32(entry, 0);
            var index = Wire.U32(entry, 4);
            var capability = (SmbNetworkInterfaceCapabilities)Wire.U32(entry, 8);
            if (index == 0 || (next != 0 && (next < 152 || next % 8 != 0 || next >= data.Length - offset)))
                throw new SmbProtocolException("Invalid network-interface entry chain.");
            var socket = entry[24..];
            var family = Wire.U16(socket, 0);
            // 依照 MS-SMB2 2.2.32.5.1.1/2，Port、FlowInfo 和 ScopeId 均为接收时必须忽略的保留域。
            // 服务器接口上的区域索引不能当作本机连接 IPv6 链路本地地址时的区域索引。
            var address = family switch
            {
                2 => new IPAddress(socket.Slice(4, 4)),
                23 => new IPAddress(socket.Slice(8, 16)),
                _ => throw new SmbProtocolException("Unsupported address family in SMB network-interface data.")
            };
            if (!seen.Add((index, address)))
                throw new SmbProtocolException("Duplicate SMB network-interface address.");
            result.Add(new SmbNetworkInterfaceInfo(index, capability, Wire.U64(entry, 16), address));
            if (next == 0)
                return result;
            offset = checked(offset + (int)next);
        }
        return result;
    }

    /// <summary>发现服务器接口并绑定附加通道，优先选择支持 RSS 和速率较高的接口。</summary>
    /// <param name="credential">用于绑定同一认证用户的凭据，不持久保存在客户端中。</param>
    /// <param name="discoveryShare">可选现有树；为空时临时连接 IPC$ 并在完成后释放。</param>
    /// <param name="cancellationToken">取消发现和后续绑定。</param>
    /// <returns>本次成功新建的通道快照，不包含既有通道。</returns>
    public async Task<IReadOnlyList<SmbChannelInfo>> ConnectAdditionalChannelsAsync(SmbCredential credential,
        SmbShare? discoveryShare = null, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(credential);
        ThrowIfDisposed();
        if (!Options.Multichannel.Enabled || !MultichannelSupported)
            throw new NotSupportedException("Both endpoints must enable SMB3 multichannel.");
        var owned = discoveryShare is null;
        var share = discoveryShare ?? await ConnectShareAsync("IPC$", cancellationToken).ConfigureAwait(false);
        try
        {
            var interfaces = await QueryNetworkInterfacesAsync(share, cancellationToken).ConfigureAwait(false);
            var ordered = interfaces.OrderByDescending(item => (item.Capabilities & SmbNetworkInterfaceCapabilities.RssCapable) != 0)
                .ThenByDescending(item => item.LinkSpeed).ToArray();
            var added = new List<SmbChannelInfo>();
            foreach (var item in ordered)
            {
                var perInterface = (item.Capabilities & SmbNetworkInterfaceCapabilities.RssCapable) != 0
                    ? Options.Multichannel.MaximumChannels : 1;
                for (var attempt = 0; attempt < perInterface; attempt++)
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    if (Channels.Count(channel => channel.IsConnected) >= Options.Multichannel.MaximumChannels)
                        return added;
                    var options = Options with
                    {
                        Transport = Options.Transport with { RemoteAddress = item.Address }
                    };
                    added.Add(await AddChannelAsync(options, credential, cancellationToken).ConfigureAwait(false));
                }
            }
            return added;
        }
        finally
        {
            if (owned)
                await share.DisposeAsync().ConfigureAwait(false);
        }
    }

    /// <summary>在持有 channelGate 时移除并释放失败的附加通道，主通道记录保留作诊断。</summary>
    private async Task ReapFailedChannelsAsync()
    {
        SmbConnection[] failed;
        lock (channelLock)
        {
            ObserveDisconnectedChannels();
            failed = channels.Where(channel => !channel.Primary && !channel.Connection.IsAlive)
                .Select(channel => channel.Connection).ToArray();
            channels.RemoveAll(channel => !channel.Primary && !channel.Connection.IsAlive);
        }
        foreach (var dead in failed)
            await dead.DisposeAsync().ConfigureAwait(false);
    }

    /// <summary>等待正在绑定的通道退出后，释放全部连接，最后清除独立拥有的会话密钥。</summary>
    private async Task DisposeChannelsAsync()
    {
        await channelGate.WaitAsync().ConfigureAwait(false);
        try
        {
            foreach (var channel in SnapshotConnections())
                await channel.DisposeAsync().ConfigureAwait(false);
            sessionCryptography?.Dispose();
            sessionCryptography = null;
        }
        finally { channelGate.Release(); }
    }
}