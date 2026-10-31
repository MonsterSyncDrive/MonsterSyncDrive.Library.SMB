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
using MonsterSyncDrive.Library.SMB.Protocol.Compression;
using MonsterSyncDrive.Library.SMB.Security;
using System.Collections.Concurrent;
using System.Security.Cryptography;

namespace MonsterSyncDrive.Library.SMB;

/// <summary>已认证的 SMB2/SMB3 会话，可选使用多个绑定传输通道并发处理请求。</summary>
public sealed partial class SmbClient : IAsyncDisposable
{
    /// <summary>最初建立会话的连接；其会话标识在通道切换后仍供绑定请求引用。</summary>
    private readonly SmbConnection connection;
    /// <summary>同名共享复用的服务端 TreeConnect 状态及本地引用计数。</summary>
    /// <param name="id">服务器分配的树标识。</param>
    /// <param name="type">共享种类。</param>
    /// <param name="flags">共享标志。</param>
    /// <param name="capabilities">共享能力位。</param>
    /// <param name="maximumAccess">树连接返回的最大访问权限。</param>
    private sealed class TreeState(uint id, byte type, uint flags, uint capabilities, SmbAccessMask maximumAccess)
    {
        /// <summary>服务器端树标识。</summary>
        internal readonly uint Id = id;
        /// <summary>磁盘、管道或打印共享的协议类型。</summary>
        internal readonly byte Type = type;
        /// <summary>服务器返回的共享策略和加密标志。</summary>
        internal readonly uint Flags = flags;
        /// <summary>服务器返回的共享能力位。</summary>
        internal readonly uint Capabilities = capabilities;
        /// <summary>当前认证身份在此共享上的最大访问权限。</summary>
        internal readonly SmbAccessMask MaximumAccess = maximumAccess;
        /// <summary>尚未释放的本地共享使用对象数量；由 treeGate 保护。</summary>
        internal int References;
    }
    /// <summary>会话当前持有的共享使用对象，用于释放和无树标识的 oplock 通知分派。</summary>
    private readonly ConcurrentDictionary<SmbShare, byte> shares = new();
    /// <summary>共享名到服务器树状态的映射，由 treeGate 保护。</summary>
    private readonly Dictionary<string, TreeState> trees = new(StringComparer.OrdinalIgnoreCase);
    /// <summary>串行化树创建、引用计数变化及销毁，防止重复创建或提前断开。</summary>
    private readonly SemaphoreSlim treeGate = new(1, 1);
    /// <summary>确保旧版 SMB3 的安全协商验证只执行一次。</summary>
    private readonly SemaphoreSlim negotiateValidation = new(1, 1);
    /// <summary>为 VALIDATE_NEGOTIATE_INFO 保留的原始客户端协商参数。</summary>
    private byte[] validateNegotiateInput = [];
    /// <summary>VALIDATE_NEGOTIATE_INFO 回复必须逐字节匹配的服务器协商参数。</summary>
    private byte[] validateNegotiateExpected = [];
    /// <summary>是否已经成功执行或按规范接受了安全协商验证。</summary>
    private bool negotiateValidated;
    /// <summary>通过原子操作设置的释放标志，禁止在释放期间创建新资源。</summary>
    private int disposed;
    /// <summary>连接前复制和验证的客户端选项，所有通道复用其安全策略。</summary>
    internal SmbClientOptions Options
    {
        get;
    }
    /// <summary>实际协商结果；有多个通道时传输上限取所有已绑定通道的保守最小值。</summary>
    public SmbConnectionInfo ConnectionInfo { get; private set; } = null!;
    /// <summary>客户端未释放且至少有一个绑定通道仍然连接。</summary>
    public bool IsConnected => Volatile.Read(ref disposed) == 0 && HasLiveChannel;
    /// <summary>是否仍有可用于清理或发送的新请求通道，供内部释放流程使用。</summary>
    internal bool IsTransportAlive => HasLiveChannel;
    /// <summary>逻辑服务器身份；传输地址覆盖不会修改用于认证和 UNC 路径的此名称。</summary>
    public string Host => Options.Host;

    /// <summary>保存主连接并注册其生命周期和通知分派，但尚不执行网络认证。</summary>
    /// <param name="connection">已建立的传输连接。</param>
    /// <param name="options">已经验证的选项快照。</param>
    private SmbClient(SmbConnection connection, SmbClientOptions options)
    {
        this.connection = connection;
        Options = options;
        RegisterPrimaryChannel(connection, options);
    }

    /// <summary>建立传输、协商 SMB、完成认证，并按配置自动绑定附加通道。</summary>
    /// <param name="options">连接、传输、安全及多通道策略。</param>
    /// <param name="credential">本次认证所用凭据；本方法不将其保存在客户端字段中。</param>
    /// <param name="cancellationToken">取消连接或认证过程。</param>
    /// <returns>已认证且可使用的客户端；失败时释放本次创建的全部通道。</returns>
    public static async Task<SmbClient> ConnectAsync(SmbClientOptions options, SmbCredential credential,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(credential);
        SmbClientOptions validated = options.Validate();
        SmbConnection connection = await SmbConnection.ConnectAsync(validated, cancellationToken).ConfigureAwait(false);
        SmbClient client = new(connection, validated);
        try
        {
            await client.EstablishSessionAsync(credential, cancellationToken).ConfigureAwait(false);
            if (validated.Multichannel.Enabled && validated.Multichannel.AutoConnect && client.MultichannelSupported)
                _ = await client.ConnectAdditionalChannelsAsync(credential, cancellationToken: cancellationToken).ConfigureAwait(false);
            return client;
        }
        catch (Exception error)
        {
            client.Abort(error);
            await client.DisposeAsync().ConfigureAwait(false);
            throw;
        }
    }

    /// <summary>完成初次认证或签名的通道绑定，同时维护协商约束与预认证哈希。</summary>
    /// <param name="credential">用于本次 GSS/NTLM 交换的显式凭据。</param>
    /// <param name="cancellationToken">取消本次交换。</param>
    /// <param name="targetConnection">为空时创建主会话，否则将此连接绑定到已有会话。</param>
    /// <param name="endpointOptions">附加通道的实际端点和传输选项；逻辑身份仍使用 Host。</param>
    /// <remarks>绑定期间使用原会话签名密钥，完成后切换到新的通道签名密钥；会话加密密钥保持不变。</remarks>
    private async Task EstablishSessionAsync(SmbCredential credential, CancellationToken cancellationToken,
        SmbConnection? targetConnection = null, SmbClientOptions? endpointOptions = null)
    {
        SmbConnection connection = targetConnection ?? this.connection;
        var binding = targetConnection is not null;
        if (binding)
            connection.ServerRequiresEncryption = this.connection.ServerRequiresEncryption;
        SmbTransportKind transportKind = (endpointOptions ?? Options).Transport.Kind;
        SmbDialect[] dialects = binding ? [ConnectionInfo.Dialect] :
            new[] { SmbDialect.Smb202, SmbDialect.Smb210, SmbDialect.Smb300, SmbDialect.Smb302, SmbDialect.Smb311 }
            .Where(dialect => dialect >= Options.MinimumDialect && dialect <= Options.MaximumDialect).ToArray();
        dialects = dialects.Where(dialect => transportKind switch
        {
            SmbTransportKind.NetBios => dialect <= SmbDialect.Smb302,
            SmbTransportKind.Quic => dialect == SmbDialect.Smb311,
            SmbTransportKind.Rdma => dialect >= SmbDialect.Smb300,
            _ => true
        }).ToArray();
        if (dialects.Length == 0)
            throw new NotSupportedException("The configured dialect range cannot be used over this SMB transport.");
        List<Cipher> ciphers = new();
        if (AesGcm.IsSupported)
            ciphers.AddRange([Cipher.Aes128Gcm, Cipher.Aes256Gcm]);
        if (AesCcm.IsSupported)
            ciphers.AddRange([Cipher.Aes128Ccm, Cipher.Aes256Ccm]);
        if (Options.EncryptionCiphers is { } cipherOffer)
        {
            ciphers = cipherOffer.Select(cipher => (Cipher)cipher).Where(ciphers.Contains).ToList();
            if (ciphers.Count == 0 && dialects.Contains(SmbDialect.Smb311) && Options.Encryption != SmbEncryptionPolicy.Disabled)
                throw new PlatformNotSupportedException("The platform cannot use any of the requested SMB encryption ciphers.");
        }
        SigningAlgorithm[] signingAlgorithms = AesGcm.IsSupported
            ? new[] { SigningAlgorithm.AesCmac, SigningAlgorithm.AesGmac, SigningAlgorithm.HmacSha256 }
            : [SigningAlgorithm.AesCmac, SigningAlgorithm.HmacSha256];
        if (Options.SigningAlgorithms is { } signingOffer)
        {
            signingAlgorithms = signingOffer.Select(algorithm => (SigningAlgorithm)algorithm).ToArray();
            if (!AesGcm.IsSupported && signingAlgorithms.Contains(SigningAlgorithm.AesGmac))
                throw new PlatformNotSupportedException("AES-GMAC is unavailable on this platform.");
        }
        if (Options.Multichannel.Enabled)
        {
            // 绑定期间多个新连接共用原会话签名密钥，而每个连接的 MessageId 都重新计数。
            // 若此时使用 GMAC，不同认证消息可能复用同一密钥下的随机数，破坏认证安全。
            // 当前只提供不依赖随机数的签名算法，直到具备经验证且符合规范的绑定方案。
            signingAlgorithms = signingAlgorithms.Where(algorithm => algorithm != SigningAlgorithm.AesGmac).ToArray();
            if (signingAlgorithms.Length == 0)
                throw new NotSupportedException("SMB multichannel requires AES-CMAC or HMAC-SHA256 signing; GMAC-only binding would reuse session signing nonces.");
        }
        uint clientCapabilities = 4 | (AesCcm.IsSupported && transportKind != SmbTransportKind.NetBios ? 0x40u : 0);
        if (Options.Multichannel.Enabled)
            clientCapabilities |= 8;
        var compressionAllowed = transportKind != SmbTransportKind.Rdma;
        var request = BuildNegotiate(dialects, ciphers, signingAlgorithms, clientCapabilities, compressionAllowed);
        Response negotiate = await connection.SendAsync(Command.Negotiate, request, 0, cancellationToken).ConfigureAwait(false);
        negotiate.EnsureSuccess();
        Wire.Structure(negotiate.Packet, 65, 64);
        var packet = negotiate.Packet;
        SmbDialect dialect = (SmbDialect)Wire.U16(packet, 68);
        if (!dialects.Contains(dialect))
            throw new SmbProtocolException("The server selected a dialect that was not offered.");
        var securityMode = Wire.U16(packet, 66);
        if ((securityMode & ~3) != 0 || (securityMode & 1) == 0)
            throw new SmbProtocolException("The server does not support SMB signing.");
        var signingRequired = Options.Signing == SmbSigningMode.Required || (securityMode & 2) != 0;
        if (signingRequired && Options.Signing == SmbSigningMode.Disabled)
            throw new SmbProtocolException("The server requires signing, but signing is disabled by the client.");
        var capabilities = Wire.U32(packet, 88);
        if (binding)
        {
            if (new Guid(packet.AsSpan(72, 16)) != ConnectionInfo.ServerGuid || dialect != ConnectionInfo.Dialect ||
                securityMode != serverSecurityMode || capabilities != serverCapabilities)
                throw new SmbProtocolException("The additional channel does not identify the same SMB server and capabilities.");
        }
        else
        {
            serverSecurityMode = securityMode;
            serverCapabilities = capabilities;
        }
        if (!binding && dialect is SmbDialect.Smb300 or SmbDialect.Smb302)
        {
            validateNegotiateInput = new byte[24 + (dialects.Length * 2)];
            Wire.Put32(validateNegotiateInput, 0, clientCapabilities);
            _ = Options.ClientGuid.TryWriteBytes(validateNegotiateInput.AsSpan(4, 16));
            Wire.Put16(validateNegotiateInput, 20, (ushort)(Options.Signing == SmbSigningMode.Required ? 3 : 1));
            Wire.Put16(validateNegotiateInput, 22, (ushort)dialects.Length);
            for (var i = 0; i < dialects.Length; i++)
                Wire.Put16(validateNegotiateInput, 24 + (i * 2), (ushort)dialects[i]);
            validateNegotiateExpected = new byte[24];
            Wire.Put32(validateNegotiateExpected, 0, capabilities);
            packet.AsSpan(72, 16).CopyTo(validateNegotiateExpected.AsSpan(4));
            Wire.Put16(validateNegotiateExpected, 20, securityMode);
            Wire.Put16(validateNegotiateExpected, 22, (ushort)dialect);
        }
        var maxTransaction = ValidateMaximum(Wire.U32(packet, 92));
        var maxRead = ValidateMaximum(Wire.U32(packet, 96));
        var maxWrite = ValidateMaximum(Wire.U32(packet, 100));
        Cipher cipher = dialect >= SmbDialect.Smb300 && (capabilities & 0x40) != 0 ? Cipher.Aes128Ccm : Cipher.None;
        SigningAlgorithm algorithm = dialect >= SmbDialect.Smb300 ? SigningAlgorithm.AesCmac : SigningAlgorithm.HmacSha256;
        SmbCompression? compression = null;
        if (dialect == SmbDialect.Smb311)
            ParseContexts(packet, ciphers, signingAlgorithms, out cipher, out algorithm, out compression, compressionAllowed);
        if (transportKind == SmbTransportKind.NetBios)
            cipher = Cipher.None;
        connection.Compression = compression;
        if (binding && (algorithm != (SigningAlgorithm)ConnectionInfo.SigningAlgorithm ||
            cipher != (ConnectionInfo.EncryptionCipher is { } selectedCipher ? (Cipher)selectedCipher : Cipher.None)))
            throw new SmbProtocolException("The additional channel selected different SMB cryptographic algorithms.");
        var encryptionSupported = cipher != Cipher.None &&
            (cipher is Cipher.Aes128Ccm or Cipher.Aes256Ccm ? AesCcm.IsSupported : AesGcm.IsSupported);
        if (Options.Encryption == SmbEncryptionPolicy.Required && !encryptionSupported)
            throw new SmbProtocolException("The server and platform cannot satisfy the required SMB encryption policy.");
        connection.Dialect = dialect;
        connection.LargeMtu = dialect != SmbDialect.Smb202 && (capabilities & 4) != 0;
        var preauth = SmbCryptography.PreauthHash(new byte[64], negotiate.Request);
        preauth = SmbCryptography.PreauthHash(preauth, packet);
        SmbCryptography? bindingSigner = null;
        if (binding)
        {
            connection.SessionId = this.connection.SessionId;
            bindingSigner = (sessionCryptography ?? throw new SmbProtocolException("Missing SMB session signing context.")).CloneForBinding();
            connection.Authenticate(bindingSigner, true, false);
        }
        var ntlmNegotiate = NtlmV2.Negotiate();
        Response first = await connection.SendAsync(Command.SessionSetup, SessionSetup(Spnego.Initial(ntlmNegotiate), binding),
            0, cancellationToken).ConfigureAwait(false);
        if (binding)
            bindingSigner!.Verify(first.Packet, true);
        first.EnsureSuccess(SmbStatus.MoreProcessingRequired);
        if (first.Status != SmbStatus.MoreProcessingRequired || first.SessionId == 0)
            throw new SmbProtocolException("The server did not start an NTLM challenge exchange.");
        if (binding && first.SessionId != this.connection.SessionId)
            throw new SmbProtocolException("The server changed the session ID while binding a channel.");
        Wire.Structure(first.Packet, 9, 8);
        preauth = SmbCryptography.PreauthHash(preauth, first.Request);
        preauth = SmbCryptography.PreauthHash(preauth, first.Packet);
        connection.SessionId = first.SessionId;
        var challengeBlob = Wire.Buffer(first.Packet, Wire.U16(first.Packet, 68), Wire.U16(first.Packet, 70), 72);
        Spnego.Token challengeToken = Spnego.Parse(challengeBlob);
        var challenge = challengeToken.ResponseToken ?? throw new SmbProtocolException("The server did not return an NTLM challenge.");
        NtlmResult ntlm = NtlmV2.Authenticate(credential, Host, ntlmNegotiate, challenge);
        try
        {
            var micSent = challengeToken.NegotiationState == Spnego.State.RequestMic;
            var outgoingMic = micSent ? NtlmV2.MechanismListMic(ntlm.SessionKey, false) : [];
            Response final = await connection.SendAsync(Command.SessionSetup, SessionSetup(Spnego.Response(ntlm.AuthenticateMessage, outgoingMic), binding),
                0, cancellationToken).ConfigureAwait(false);
            for (var round = 0; ; round++)
            {
                final.EnsureSuccess(SmbStatus.MoreProcessingRequired);
                if (binding && final.Status != SmbStatus.Success)
                    bindingSigner!.Verify(final.Packet, true);
                Wire.Structure(final.Packet, 9, 8);
                if (final.SessionId != connection.SessionId)
                    throw new SmbProtocolException("The server changed the session ID during authentication.");
                preauth = SmbCryptography.PreauthHash(preauth, final.Request);
                var securityBlob = Wire.Buffer(final.Packet, Wire.U16(final.Packet, 68), Wire.U16(final.Packet, 70), 72);
                Spnego.Token token = securityBlob.Length == 0 ? new Spnego.Token(null, null, null) : Spnego.Parse(securityBlob);
                if (token.MechanismListMic is { } serverMic &&
                    !CryptographicOperations.FixedTimeEquals(serverMic, NtlmV2.MechanismListMic(ntlm.SessionKey, true)))
                    throw new SmbProtocolException("The SPNEGO server mechanism-list MIC is invalid.");
                if (final.Status == SmbStatus.Success)
                {
                    if (token.NegotiationState is Spnego.State.AcceptIncomplete or Spnego.State.RequestMic)
                        throw new SmbProtocolException("SMB authentication completed before SPNEGO negotiation.");
                    break;
                }
                if (round != 0 || micSent || credential.IsAnonymous || token.ResponseToken is { Length: > 0 })
                    throw new SmbProtocolException("The server requested an unsupported extra authentication exchange.");
                preauth = SmbCryptography.PreauthHash(preauth, final.Packet);
                micSent = true;
                final = await connection.SendAsync(Command.SessionSetup,
                    SessionSetup(Spnego.Response([], NtlmV2.MechanismListMic(ntlm.SessionKey, false), Spnego.State.AcceptCompleted), binding),
                    0, cancellationToken).ConfigureAwait(false);
            }
            var sessionFlags = Wire.U16(final.Packet, 66);
            if ((sessionFlags & ~7) != 0)
                throw new SmbProtocolException("Invalid SMB session flags.");
            var guest = (sessionFlags & 1) != 0;
            var anonymous = (sessionFlags & 2) != 0;
            if (binding && (guest || anonymous))
                throw new SmbProtocolException("A bound channel cannot change the authenticated SMB session to a guest or anonymous session.");
            if ((guest || anonymous) && (!Options.AllowGuest || signingRequired ||
                Options.Encryption == SmbEncryptionPolicy.Required))
                throw new SmbProtocolException("The server returned a guest/anonymous session incompatible with the client policy.");
            if (credential.IsAnonymous && !anonymous && !guest)
                throw new SmbProtocolException("An anonymous login unexpectedly returned an authenticated session.");
            var encrypt = !guest && !anonymous && Options.Encryption != SmbEncryptionPolicy.Disabled && encryptionSupported;
            if (binding)
                encrypt = ConnectionInfo.IsEncrypted; // 绑定回复不能更改已经建立的会话加密策略。
            else if ((sessionFlags & 4) != 0)
            {
                if (!encryptionSupported || Options.Encryption == SmbEncryptionPolicy.Disabled || guest || anonymous)
                    throw new SmbProtocolException("The server requires encryption that the client cannot use.");
                encrypt = true;
            }
            // 依照 MS-SMB2 3.2.5.3.1，成功的 SESSION_SETUP 回复不计入派生密钥所用的预认证上下文。
            SmbCryptography crypto = binding
                ? sessionCryptography!.CreateChannel(ntlm.SessionKey, dialect, cipher, algorithm, preauth)
                : new SmbCryptography(ntlm.SessionKey, dialect, cipher, algorithm, preauth);
            try
            {
                if (!guest && !anonymous)
                    crypto.Verify(final.Packet, binding || signingRequired);
                connection.Authenticate(crypto, !guest && !anonymous && Options.Signing != SmbSigningMode.Disabled, encrypt);
                connection.ServerRequiresEncryption = binding
                    ? this.connection.ServerRequiresEncryption : (sessionFlags & 4) != 0;
                if (!binding)
                    sessionCryptography = crypto.CloneForBinding();
            }
            catch
            {
                crypto.Dispose();
                throw;
            }
            ConnectionInfo = binding ? ConnectionInfo with
            {
                MaxReadSize = Math.Min(ConnectionInfo.MaxReadSize, maxRead),
                MaxWriteSize = Math.Min(ConnectionInfo.MaxWriteSize, maxWrite),
                MaxTransactionSize = Math.Min(ConnectionInfo.MaxTransactionSize, maxTransaction)
            } : new SmbConnectionInfo(dialect, new Guid(packet.AsSpan(72, 16)),
                maxRead, maxWrite, maxTransaction, signingRequired, encryptionSupported, guest, anonymous)
            {
                SigningAlgorithm = (SmbSigningAlgorithm)algorithm,
                EncryptionCipher = cipher == Cipher.None ? null : (SmbEncryptionCipher)cipher,
                IsEncrypted = encrypt,
                Transport = transportKind,
                CompressionAlgorithms = compression?.Algorithms.ToArray() ?? [],
                SupportsChainedCompression = compression?.SupportsChained ?? false
            };
        }
        finally
        {
            CryptographicOperations.ZeroMemory(ntlm.SessionKey);
            bindingSigner?.Dispose();
        }
    }

    /// <summary>验证服务器声明的传输上限，并限制在本客户端能够接收的帧边界以内。</summary>
    /// <param name="size">服务器给出的最大数据长度。</param>
    /// <returns>客户端能够使用的有效最大长度。</returns>
    private int ValidateMaximum(uint size)
    {
        return size < 65536
            ? throw new SmbProtocolException("The server advertised an invalid maximum SMB transfer size.")
            : checked((int)Math.Min(size, (uint)Options.MaximumPacketSize - 256));
    }

    /// <summary>按八字节对齐编码版本列表及明确支持的 SMB 3.1.1 协商上下文。</summary>
    /// <param name="dialects">当前传输允许的协议版本。</param>
    /// <param name="ciphers">当前平台可用并获策略允许的加密算法。</param>
    /// <param name="signingAlgorithms">获策略允许的签名算法。</param>
    /// <param name="capabilities">实际实现的客户端能力位。</param>
    /// <param name="compressionAllowed">此传输是否允许协商网络压缩；RDMA 按协议排除。</param>
    /// <returns>不含 SMB2 头的 NEGOTIATE 请求体。</returns>
    private byte[] BuildNegotiate(SmbDialect[] dialects, List<Cipher> ciphers, SigningAlgorithm[] signingAlgorithms, uint capabilities, bool compressionAllowed)
    {
        List<(ushort Type, byte[] Data)> contexts = new();
        if (dialects.Contains(SmbDialect.Smb311))
        {
            var preauth = new byte[38];
            Wire.Put16(preauth, 0, 1);
            Wire.Put16(preauth, 2, 32);
            Wire.Put16(preauth, 4, 1);
            RandomNumberGenerator.Fill(preauth.AsSpan(6));
            contexts.Add((1, preauth));
            if (ciphers.Count > 0)
            {
                var encryption = new byte[2 + (ciphers.Count * 2)];
                Wire.Put16(encryption, 0, (ushort)ciphers.Count);
                for (var i = 0; i < ciphers.Count; i++)
                    Wire.Put16(encryption, 2 + (i * 2), (ushort)ciphers[i]);
                contexts.Add((2, encryption));
            }
            var signing = new byte[2 + (signingAlgorithms.Length * 2)];
            Wire.Put16(signing, 0, (ushort)signingAlgorithms.Length);
            for (var i = 0; i < signingAlgorithms.Length; i++)
                Wire.Put16(signing, 2 + (i * 2), (ushort)signingAlgorithms[i]);
            contexts.Add((8, signing));
            contexts.Add((5, Wire.Unicode.GetBytes(Host)));
            if (Options.Compression.Enabled && compressionAllowed)
                contexts.Add((3, SmbCompression.BuildNegotiateContext(Options.Compression)));
        }
        var dialectEnd = 36 + (dialects.Length * 2);
        var contextStart = Wire.Align8(64 + dialectEnd) - 64;
        var bodyLength = contexts.Count == 0 ? dialectEnd : contextStart + contexts.Sum(context => Wire.Align8(8 + context.Data.Length));
        var body = new byte[bodyLength];
        Wire.Put16(body, 0, 36);
        Wire.Put16(body, 2, (ushort)dialects.Length);
        Wire.Put16(body, 4, (ushort)(Options.Signing == SmbSigningMode.Required ? 3 : 1));
        Wire.Put32(body, 8, dialects.Any(value => value >= SmbDialect.Smb300) ? capabilities : 0);
        _ = Options.ClientGuid.TryWriteBytes(body.AsSpan(12, 16));
        if (contexts.Count > 0)
        {
            Wire.Put32(body, 28, (uint)contextStart + 64);
            Wire.Put16(body, 32, (ushort)contexts.Count);
        }
        for (var i = 0; i < dialects.Length; i++)
            Wire.Put16(body, 36 + (i * 2), (ushort)dialects[i]);
        var offset = contextStart;
        foreach ((ushort type, byte[]? data) in contexts)
        {
            Wire.Put16(body, offset, type);
            Wire.Put16(body, offset + 2, (ushort)data.Length);
            data.CopyTo(body, offset + 8);
            offset += Wire.Align8(8 + data.Length);
        }
        return body;
    }

    /// <summary>严格解码服务器协商上下文，拒绝重复、越界和未提供的算法。</summary>
    /// <param name="packet">完整 NEGOTIATE 回复。</param>
    /// <param name="offeredCiphers">实际在请求中提供的加密算法。</param>
    /// <param name="offeredSigning">实际在请求中提供的签名算法。</param>
    /// <param name="cipher">服务器选择的加密算法，未选择时为 None。</param>
    /// <param name="algorithm">服务器选择的签名算法。</param>
    /// <param name="compression">双方同意的压缩器；没有共同算法时为空。</param>
    /// <param name="compressionAllowed">此通道传输是否允许压缩，防止对 RDMA 强行协商未提供的扩展。</param>
    private void ParseContexts(byte[] packet, List<Cipher> offeredCiphers, SigningAlgorithm[] offeredSigning,
        out Cipher cipher, out SigningAlgorithm algorithm, out SmbCompression? compression, bool compressionAllowed)
    {
        cipher = Cipher.None;
        algorithm = SigningAlgorithm.AesCmac;
        compression = null;
        var count = Wire.U16(packet, 70);
        var position = Wire.U32(packet, 124);
        HashSet<ushort> seen = new();
        if (count == 0 || position < 128 || position % 8 != 0)
            throw new SmbProtocolException("SMB 3.1.1 requires aligned negotiate contexts.");
        for (var i = 0; i < count; i++)
        {
            if (position > int.MaxValue)
                throw new SmbProtocolException("Invalid SMB negotiate context offset.");
            var offset = (int)position;
            var type = Wire.U16(packet, offset);
            var length = Wire.U16(packet, offset + 2);
            ReadOnlySpan<byte> data = Wire.Slice(packet, offset + 8, length);
            if (!seen.Add(type))
                throw new SmbProtocolException("Duplicate SMB negotiate context.");
            if (type == 1)
            {
                if (length < 6 || Wire.U16(data, 0) != 1 || Wire.U16(data, 4) != 1 || length != 6 + Wire.U16(data, 2))
                    throw new SmbProtocolException("The server did not select SHA-512 preauthentication integrity.");
            }
            else if (type == 2)
            {
                if (length != 4 || Wire.U16(data, 0) != 1 || !offeredCiphers.Contains((Cipher)Wire.U16(data, 2)))
                    throw new SmbProtocolException("The server selected an encryption cipher that was not offered.");
                cipher = (Cipher)Wire.U16(data, 2);
            }
            else if (type == 8)
            {
                if (length != 4 || Wire.U16(data, 0) != 1 || !offeredSigning.Contains((SigningAlgorithm)Wire.U16(data, 2)))
                    throw new SmbProtocolException("The server selected a signing algorithm that was not offered.");
                algorithm = (SigningAlgorithm)Wire.U16(data, 2);
            }
            else if (type == 3)
            {
                if (!Options.Compression.Enabled || !compressionAllowed)
                    throw new SmbProtocolException("The server returned an unsolicited SMB compression context.");
                compression = SmbCompression.Negotiate(Options.Compression, data);
            }
            position = checked((uint)Wire.Align8(offset + 8 + length));
        }
        if (!seen.Contains(1))
            throw new SmbProtocolException("Missing SMB 3.1.1 preauthentication context.");
    }

    /// <summary>编码认证令牌、签名要求和可选 BINDING 标志；PreviousSessionId 始终为零。</summary>
    /// <param name="securityToken">SPNEGO 安全令牌。</param>
    /// <param name="binding">是否绑定已有会话到附加连接。</param>
    /// <returns>SESSION_SETUP 请求体。</returns>
    private byte[] SessionSetup(byte[] securityToken, bool binding = false)
    {
        var body = new byte[24 + securityToken.Length];
        Wire.Put16(body, 0, 25);
        body[2] = binding ? (byte)1 : (byte)0;
        body[3] = (byte)(Options.Signing == SmbSigningMode.Required ? 2 : 1);
        Wire.Put16(body, 12, 88);
        Wire.Put16(body, 14, checked((ushort)securityToken.Length));
        securityToken.CopyTo(body, 24);
        return body;
    }

    /// <summary>连接指定共享，并返回拥有独立文件句柄生命周期的本地使用对象。</summary>
    /// <param name="shareName">共享名，不含服务器名或路径分隔符。</param>
    /// <param name="cancellationToken">取消共享连接或等待。</param>
    /// <returns>共享使用对象；同名对象复用远端树，最后一个释放时才断开。</returns>
    public async Task<SmbShare> ConnectShareAsync(string shareName, CancellationToken cancellationToken = default)
    {
        ThrowIfDisposed();
        _ = SmbPath.ValidateShare(shareName);
        await treeGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            ThrowIfDisposed();
            if (trees.TryGetValue(shareName, out TreeState? tree))
            {
                SmbShare lease = new(this, tree.Id, shareName, tree.Type, tree.Flags, tree.Capabilities, tree.MaximumAccess);
                tree.References++;
                _ = shares.TryAdd(lease, 0);
                return lease;
            }
            return await ConnectNewTreeAsync(shareName, cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            _ = treeGate.Release();
        }
    }

    /// <summary>创建服务器树连接，验证其加密要求和树标识唯一性后登记引用。</summary>
    /// <param name="shareName">已验证的共享名称。</param>
    /// <param name="cancellationToken">取消网络请求。</param>
    /// <returns>新树连接的第一个本地共享使用对象。</returns>
    private async Task<SmbShare> ConnectNewTreeAsync(string shareName, CancellationToken cancellationToken)
    {
        var path = Wire.Unicode.GetBytes(@"\\" + Host + "\\" + shareName);
        var body = new byte[8 + path.Length];
        Wire.Put16(body, 0, 9);
        Wire.Put16(body, 4, 72);
        Wire.Put16(body, 6, checked((ushort)path.Length));
        path.CopyTo(body, 8);
        Response response = await SendAsync(Command.TreeConnect, body, 0, cancellationToken).ConfigureAwait(false);
        response.EnsureSuccess();
        Wire.Structure(response.Packet, 16, 16);
        SmbShare share = new(this, response.TreeId, shareName, response.Packet[66],
            Wire.U32(response.Packet, 68), Wire.U32(response.Packet, 72), (SmbAccessMask)Wire.U32(response.Packet, 76));
        if (share.EncryptionRequired && (!ConnectionInfo.EncryptionSupported || Options.Encryption == SmbEncryptionPolicy.Disabled ||
            ConnectionInfo.IsGuest || ConnectionInfo.IsAnonymous))
        {
            connection.Abort(new SmbProtocolException("The share requires encryption incompatible with the client policy."));
            throw new SmbProtocolException("The share requires SMB encryption.");
        }
        if (trees.Values.Any(tree => tree.Id == response.TreeId))
        {
            connection.Abort(new SmbProtocolException("The server reused a live SMB tree ID."));
            throw new SmbProtocolException("The server reused a live SMB tree ID.");
        }
        try
        {
            await ValidateNegotiateAsync(share, cancellationToken).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            connection.Abort(ex);
            throw;
        }
        trees.Add(shareName, new TreeState(response.TreeId, share.ShareType, share.Flags, share.Capabilities, share.MaximumAccess)
        {
            References = 1
        });
        _ = shares.TryAdd(share, 0);
        return share;
    }

    /// <summary>对 SMB 3.0/3.0.2 执行一次经完整性保护的协商参数回读，检测降级。</summary>
    /// <param name="share">用于发出无文件句柄控制请求的树连接。</param>
    /// <param name="cancellationToken">取消验证过程。</param>
    private async Task ValidateNegotiateAsync(SmbShare share, CancellationToken cancellationToken)
    {
        if (validateNegotiateInput.Length == 0 || ConnectionInfo.IsGuest || ConnectionInfo.IsAnonymous)
            return;
        await negotiateValidation.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            if (negotiateValidated)
                return;
            var body = new byte[56 + validateNegotiateInput.Length];
            Wire.Put16(body, 0, 57);
            Wire.Put32(body, 4, 0x00140204); // 安全协商回读控制码 FSCTL_VALIDATE_NEGOTIATE_INFO。
            body.AsSpan(8, 16).Fill(0xFF);
            Wire.Put32(body, 24, 120);
            Wire.Put32(body, 28, (uint)validateNegotiateInput.Length);
            Wire.Put32(body, 44, 24);
            Wire.Put32(body, 48, 1);
            validateNegotiateInput.CopyTo(body, 56);
            Response response = await share.SendAsync(Command.Ioctl, body, cancellationToken, 24).ConfigureAwait(false);
            // MS-SMB2 允许较早的实现返回已经签名的 STATUS_NOT_SUPPORTED；仍须验证回复完整性。
            response.EnsureSuccess(SmbStatus.NotSupported);
            if (response.Status == SmbStatus.Success)
            {
                Wire.Structure(response.Packet, 49, 48);
                var output = Wire.Buffer(response.Packet, Wire.Int32(Wire.U32(response.Packet, 96)),
                    Wire.U32(response.Packet, 100), 112);
                if (Wire.U32(response.Packet, 68) != 0x00140204 || !output.AsSpan().SequenceEqual(validateNegotiateExpected))
                    throw new SmbProtocolException("SMB secure negotiate validation failed.");
            }
            negotiateValidated = true;
        }
        finally
        {
            _ = negotiateValidation.Release();
        }
    }

    /// <summary>通过 srvsvc 命名管道上的 RPC 枚举共享资源，自动处理分片和续页。</summary>
    /// <param name="cancellationToken">取消管道连接或 RPC 分页读取。</param>
    /// <returns>服务器允许当前身份枚举的共享名称、类型和备注。</returns>
    public async Task<IReadOnlyList<SmbShareInfo>> ListSharesAsync(CancellationToken cancellationToken = default)
    {
        ThrowIfDisposed();
        await using SmbShare ipc = await ConnectShareAsync("IPC$", cancellationToken).ConfigureAwait(false);
        await using SmbFileHandle pipe = await ipc.OpenFileAsync("srvsvc", new SmbOpenOptions
        {
            Access = SmbAccessMask.GenericRead | SmbAccessMask.GenericWrite,
            CreateOptions = SmbCreateOptions.NonDirectoryFile
        }, cancellationToken).ConfigureAwait(false);
        return await new Protocol.ShareEnumeration(pipe, Host).EnumerateAsync(cancellationToken).ConfigureAwait(false);
    }

    /// <summary>通过当前选择策略选择的通道发送 ECHO，验证该通道的请求往返。</summary>
    /// <param name="cancellationToken">取消此探测。</param>
    public async Task EchoAsync(CancellationToken cancellationToken = default)
    {
        ThrowIfDisposed();
        Response response = await SendAsync(Command.Echo, new byte[] { 4, 0, 0, 0 }, 0, cancellationToken).ConfigureAwait(false);
        response.EnsureSuccess();
        Wire.Structure(response.Packet, 4, 4);
    }

    /// <summary>选择一个当前可用通道发送新请求；失败后不自动重发可能已经执行的操作。</summary>
    /// <param name="command">SMB2 命令。</param>
    /// <param name="body">已编码请求体。</param>
    /// <param name="treeId">共享树标识或零。</param>
    /// <param name="cancellationToken">调用者的取消令牌。</param>
    /// <param name="maximumResponse">预计最大回复数据长度，用于 credit 计费。</param>
    /// <param name="encrypt">是否因共享策略额外要求加密。</param>
    /// <param name="infiniteTimeout">是否使用调用者取消来结束等待式操作。</param>
    /// <returns>与此请求标识匹配的回复。</returns>
    internal Task<Response> SendAsync(Command command, ReadOnlyMemory<byte> body, uint treeId,
        CancellationToken cancellationToken, int maximumResponse = 0, bool encrypt = false, bool infiniteTimeout = false)
    {
        return SelectChannel().SendAsync(command, body, treeId, cancellationToken, maximumResponse, encrypt, infiniteTimeout);
    }

    /// <summary>撤销本地共享引用，并在最后一个引用释放时断开服务器树。</summary>
    /// <param name="share">正在释放的共享使用对象。</param>
    internal async Task ReleaseShareAsync(SmbShare share)
    {
        await treeGate.WaitAsync().ConfigureAwait(false);
        try
        {
            _ = shares.TryRemove(share, out _);
            if (!trees.TryGetValue(share.Name, out TreeState? tree) || --tree.References != 0)
                return;
            _ = trees.Remove(share.Name);
            if (!HasLiveChannel)
                return;
            Response response = await SendAsync(Command.TreeDisconnect, new byte[] { 4, 0, 0, 0 },
                tree.Id, CancellationToken.None, encrypt: share.EncryptionRequired).ConfigureAwait(false);
            response.EnsureSuccess();
        }
        finally
        {
            _ = treeGate.Release();
        }
    }
    /// <summary>因会话级协议错误终止所有通道，使全部未完成请求收到同一失败原因。</summary>
    /// <param name="error">触发终止的原始异常。</param>
    internal void Abort(Exception error)
    {
        foreach (SmbConnection channel in SnapshotConnections())
            channel.Abort(error);
    }
    /// <summary>在释放已经开始时阻止创建新的会话资源。</summary>
    internal void ThrowIfDisposed()
    {
        ObjectDisposedException.ThrowIf(Volatile.Read(ref disposed) != 0, this);
    }

    /// <summary>关闭本地共享、注销会话并释放全部通道和保留的会话密钥；重复调用无效。</summary>
    public async ValueTask DisposeAsync()
    {
        if (Interlocked.Exchange(ref disposed, 1) != 0)
            return;
        try
        {
            // 先等待已经开始的树连接操作退出，再取得释放快照，避免漏掉随后登记的共享。
            await treeGate.WaitAsync().ConfigureAwait(false);
            _ = treeGate.Release();
            foreach (SmbShare share in shares.Keys)
                try
                {
                    await share.DisposeAsync().ConfigureAwait(false);
                }
                catch (Exception ex) when (ex is IOException or TimeoutException) { }
            if (HasLiveChannel)
            {
                Response response = await SendAsync(Command.Logoff, new byte[] { 4, 0, 0, 0 },
                    0, CancellationToken.None).ConfigureAwait(false);
                response.EnsureSuccess();
            }
        }
        catch (Exception ex) when (ex is IOException or TimeoutException) { }
        finally
        {
            await DisposeChannelsAsync().ConfigureAwait(false);
        }
    }
}