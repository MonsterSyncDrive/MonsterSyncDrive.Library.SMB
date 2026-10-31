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
using System.Security.Cryptography;
using MonsterSyncDrive.SMB.Protocol;

namespace MonsterSyncDrive.SMB.Security;

/// <summary>NTLM 认证令牌，以及供 SMB 签名和加密使用的导出会话密钥。</summary>
/// <param name="AuthenticateMessage">序列化后的 NTLM 类型 3 消息。</param>
/// <param name="SessionKey">保密的 16 字节会话密钥；调用者必须在派生密钥后将其清除。</param>
internal sealed record NtlmResult(byte[] AuthenticateMessage, byte[] SessionKey);

/// <summary>实现 SMB 身份认证需要的 NTLMv2 质询响应和消息完整性功能子集。</summary>
internal static class NtlmV2
{
    /// <summary>使用 NTLM 扩展会话签名及序号零，对所提供的 SPNEGO 机制列表签名。</summary>
    /// <param name="sessionKey">导出的 NTLM 会话密钥。</param>
    /// <param name="server">为 true 时使用服务器到客户端的签名方向；为 false 时使用客户端方向。</param>
    /// <returns>包含版本号、截断校验值和序号的 16 字节 NTLM 签名。</returns>
    // 按 MS-NLMP 第 3.4.4.2 和 3.4.5.2 节，本客户端有意不协商 KEY_EXCH。
    // SPNEGO 使用序号零和区分方向的 NTLM 密钥，对 DER 编码的机制列表签名。
    internal static byte[] MechanismListMic(ReadOnlySpan<byte> sessionKey, bool server)
    {
        using var keyHash = IncrementalHash.CreateHash(HashAlgorithmName.MD5);
        keyHash.AppendData(sessionKey);
        keyHash.AppendData(server
            ? "session key to server-to-client signing key magic constant\0"u8
            : "session key to client-to-server signing key magic constant\0"u8);
        var signingKey = keyHash.GetHashAndReset();
        try
        {
            var mechanisms = Spnego.MechanismList();
            var signedData = new byte[4 + mechanisms.Length];
            mechanisms.CopyTo(signedData, 4);
            var checksum = HMACMD5.HashData(signingKey, signedData);
            var signature = new byte[16];
            Wire.Put32(signature, 0, 1);
            checksum.AsSpan(0, 8).CopyTo(signature.AsSpan(4));
            CryptographicOperations.ZeroMemory(checksum);
            return signature;
        }
        finally { CryptographicOperations.ZeroMemory(signingKey); }
    }
    /// <summary>请求采用 UTF-16LE 编码的身份和目标信息字符串。</summary>
    private const uint Unicode = 1;
    /// <summary>请求 NTLM 消息签名能力。</summary>
    private const uint Sign = 0x10;
    /// <summary>声明扩展会话协商所需的 NTLM 消息封装加密能力。</summary>
    private const uint Seal = 0x20;
    /// <summary>标识 NTLM 身份认证。</summary>
    private const uint Ntlm = 0x200;
    /// <summary>标记显式匿名认证消息。</summary>
    private const uint Anonymous = 0x800;
    /// <summary>声明 NTLM 的始终签名能力。</summary>
    private const uint AlwaysSign = 0x8000;
    /// <summary>要求 NTLM 扩展会话安全机制，不采用 NTLMv1 会话格式。</summary>
    private const uint ExtendedSessionSecurity = 0x80000;
    /// <summary>请求服务器提供目标信息 AV 对。</summary>
    private const uint TargetInfo = 0x800000;
    /// <summary>包含可选的 NTLM 版本字段。</summary>
    private const uint Version = 0x2000000;
    /// <summary>声明支持 128 位 NTLM 会话密钥。</summary>
    private const uint Negotiate128 = 0x20000000;
    /// <summary>KEY_EXCH 标志；有意将其排除，使 MIC 签名无需 RC4 密钥交换。</summary>
    private const uint KeyExchange = 0x40000000;
    /// <summary>除 128 位协商外，也声明传统的 56 位密钥能力。</summary>
    private const uint Negotiate56 = 0x80000000;
    /// <summary>在 NTLM 协商消息中声明的受支持能力集合。</summary>
    private const uint ClientFlags = Unicode | Sign | Seal | Ntlm | AlwaysSign |
        ExtendedSessionSecurity | TargetInfo | Version | Negotiate128 | Negotiate56;

    /// <summary>创建带有客户端能力标志的 NTLM 类型 1 消息。</summary>
    /// <returns>固定消息头及可选版本字段，不嵌入密码或凭据数据。</returns>
    internal static byte[] Negotiate()
    {
        var message = new byte[40];
        "NTLMSSP\0"u8.CopyTo(message);
        Wire.Put32(message, 8, 1);
        Wire.Put32(message, 12, ClientFlags | 4);
        WriteVersion(message.AsSpan(32));
        return message;
    }

    /// <summary>校验类型 2 质询，并生成 NTLMv2 类型 3 响应及会话密钥。</summary>
    /// <param name="credential">显式指定的域身份或匿名凭据。</param>
    /// <param name="host">用于构造 cifs 服务目标的逻辑 SMB 服务器名称。</param>
    /// <param name="negotiate">此前发送的原始 NTLM 协商字节，用于计算 NTLM MIC。</param>
    /// <param name="challenge">服务器提供的原始质询字节。</param>
    /// <param name="clientChallenge">用于确定性测试的可选八字节随机数；未指定时安全生成。</param>
    /// <param name="timestamp">可选的 FILETIME；服务器提供有效时间戳时优先使用服务器值。</param>
    /// <returns>认证消息和导出密钥；派生过程中使用的临时密码哈希会被清除。</returns>
    /// <exception cref="SmbProtocolException">质询、能力交集、AV 字段或缓冲区边界无效。</exception>
    /// <exception cref="ArgumentException">显式提供的随机数长度不是八字节。</exception>
    internal static NtlmResult Authenticate(SmbCredential credential, string host,
        byte[] negotiate, ReadOnlySpan<byte> challenge, ReadOnlySpan<byte> clientChallenge = default,
        long? timestamp = null)
    {
        if (challenge.Length < 48 || !challenge[..8].SequenceEqual("NTLMSSP\0"u8) || Wire.U32(challenge, 8) != 2)
            throw new SmbProtocolException("Invalid NTLM challenge message.");
        // 只接受双方都提供的能力；排除 KEY_EXCH，使导出密钥始终等于
        // NTLMv2 会话基础密钥，避免引入尚未实现的 RC4 交换。
        var flags = Wire.U32(challenge, 20) & ClientFlags & ~KeyExchange;
        if ((flags & (Unicode | Ntlm | ExtendedSessionSecurity)) != (Unicode | Ntlm | ExtendedSessionSecurity))
            throw new SmbProtocolException("The server does not support NTLMv2 extended session security.");
        var minimumHeader = (flags & Version) != 0 ? 56 : 48;
        if (challenge.Length < minimumHeader ||
            (Wire.U16(challenge, 40) != 0 && Wire.U32(challenge, 44) < minimumHeader))
            throw new SmbProtocolException("The NTLM target information overlaps its message header.");
        var targetInfo = SecurityBuffer(challenge, 40);
        var avPairs = new List<(ushort Id, byte[] Value)>();
        var avOffset = 0;
        var hasTimestamp = false;
        uint avFlags = 0;
        var seen = new HashSet<ushort>();
        var terminated = targetInfo.Length == 0;
        while (avOffset < targetInfo.Length)
        {
            var id = Wire.U16(targetInfo, avOffset);
            var length = Wire.U16(targetInfo, avOffset + 2);
            avOffset += 4;
            if (id == 0)
            {
                if (length != 0 || avOffset != targetInfo.Length)
                    throw new SmbProtocolException("Invalid NTLM target information terminator.");
                terminated = true;
                break;
            }
            if (!seen.Add(id))
                throw new SmbProtocolException("Duplicate NTLM target information.");
            var value = Wire.Slice(targetInfo, avOffset, length).ToArray();
            avOffset += length;
            if (id == 7)
            {
                if (length != 8)
                    throw new SmbProtocolException("Invalid NTLM server timestamp.");
                timestamp = Wire.I64(value, 0);
                hasTimestamp = true;
            }
            if (id == 6)
            {
                if (length != 4)
                    throw new SmbProtocolException("Invalid NTLM AV flags.");
                avFlags = Wire.U32(value, 0);
            }
            // 下文重新构造标志、目标 SPN 和通道绑定信息，确保认证数据块中每个
            // 安全敏感 AV 字段都只有一个确定值，不存在互相冲突的重复项。
            if (id is not (6 or 9 or 10))
                avPairs.Add((id, value));
        }
        if (!terminated)
            throw new SmbProtocolException("The NTLM target information has no terminator.");
        // 服务器时间戳或显式 MIC 标志用于绑定初始协商、质询和最终认证字节；
        // 在全部安全缓冲区完成布局之前，MIC 所在位置必须保持全零。
        var micRequired = !credential.IsAnonymous && (hasTimestamp || (avFlags & 2) != 0);
        if (micRequired)
            avFlags |= 2;
        var flagValue = new byte[4];
        Wire.Put32(flagValue, 0, avFlags);
        avPairs.Add((6, flagValue));
        avPairs.Add((9, Wire.Unicode.GetBytes("cifs/" + host)));
        // 不使用 TLS 的 SMB Direct TCP 连接使用全零通道绑定哈希。
        avPairs.Add((10, new byte[16]));
        var av = new byte[avPairs.Sum(pair => pair.Value.Length + 4) + 4];
        if (av.Length > ushort.MaxValue - 48)
            throw new SmbProtocolException("The NTLM target information is too large.");
        var pos = 0;
        foreach (var (id, value) in avPairs)
        {
            Wire.Put16(av, pos, id);
            Wire.Put16(av, pos + 2, checked((ushort)value.Length));
            value.CopyTo(av, pos + 4);
            pos += value.Length + 4;
        }

        var user = Wire.Unicode.GetBytes(credential.UserName);
        var domain = Wire.Unicode.GetBytes(credential.Domain);
        var workstation = Wire.Unicode.GetBytes(Environment.MachineName);
        byte[] ntResponse, lmResponse, sessionKey;
        if (credential.IsAnonymous)
        {
            ntResponse = [];
            lmResponse = [0];
            sessionKey = new byte[16];
            flags |= Anonymous;
        }
        else
        {
            var random = clientChallenge.IsEmpty ? RandomNumberGenerator.GetBytes(8) : clientChallenge.ToArray();
            if (random.Length != 8)
                throw new ArgumentException("An NTLM client challenge is eight bytes.");
            var passwordBytes = Wire.Unicode.GetBytes(credential.Password);
            var passwordHash = Md4.Hash(passwordBytes);
            CryptographicOperations.ZeroMemory(passwordBytes);
            var responseKey = HMACMD5.HashData(passwordHash,
                Wire.Unicode.GetBytes(credential.UserName.ToUpperInvariant() + credential.Domain));
            CryptographicOperations.ZeroMemory(passwordHash);
            var blob = new byte[32 + av.Length];
            blob[0] = 1; blob[1] = 1;
            Wire.PutI64(blob, 8, timestamp ?? DateTimeOffset.UtcNow.ToFileTime());
            random.CopyTo(blob, 16);
            av.CopyTo(blob, 28);
            var proofInput = new byte[8 + blob.Length];
            challenge.Slice(24, 8).CopyTo(proofInput);
            blob.CopyTo(proofInput, 8);
            // NTProofStr 验证服务器质询与数据块的连接值；会话密钥则使用该证明值
            // 另行计算 HMAC；密码字节、NT 哈希和响应密钥必须在派生后及时清除。
            var proof = HMACMD5.HashData(responseKey, proofInput);
            ntResponse = new byte[16 + blob.Length];
            proof.CopyTo(ntResponse, 0);
            blob.CopyTo(ntResponse, 16);
            sessionKey = HMACMD5.HashData(responseKey, proof);
            // 服务器提供时间戳时，MS-NLMP 要求 LM 响应全部为零。
            // 在该分支复用 LMv2 证明会改变认证消息的原始字节序列。
            if (hasTimestamp)
                lmResponse = new byte[24];
            else
            {
                var lmInput = new byte[16];
                challenge.Slice(24, 8).CopyTo(lmInput);
                random.CopyTo(lmInput, 8);
                lmResponse = new byte[24];
                HMACMD5.HashData(responseKey, lmInput).CopyTo(lmResponse, 0);
                random.CopyTo(lmResponse, 16);
            }
            CryptographicOperations.ZeroMemory(responseKey);
        }
        var hasVersion = (flags & Version) != 0;
        var headerLength = 64 + (hasVersion ? 8 : 0) + (micRequired ? 16 : 0);
        var message = new byte[headerLength + lmResponse.Length + ntResponse.Length + domain.Length + user.Length + workstation.Length];
        "NTLMSSP\0"u8.CopyTo(message);
        Wire.Put32(message, 8, 3);
        Wire.Put32(message, 60, flags);
        if (hasVersion)
            WriteVersion(message.AsSpan(64));
        var offset = headerLength;
        WriteBuffer(message, 12, lmResponse, ref offset);
        WriteBuffer(message, 20, ntResponse, ref offset);
        WriteBuffer(message, 28, domain, ref offset);
        WriteBuffer(message, 36, user, ref offset);
        WriteBuffer(message, 44, workstation, ref offset);
        WriteBuffer(message, 52, [], ref offset);
        if (micRequired)
        {
            using var hmac = IncrementalHash.CreateHMAC(HashAlgorithmName.MD5, sessionKey);
            hmac.AppendData(negotiate);
            hmac.AppendData(challenge);
            hmac.AppendData(message);
            hmac.GetHashAndReset().CopyTo(message, 64 + (hasVersion ? 8 : 0));
        }
        return new NtlmResult(message, sessionKey);
    }

    /// <summary>根据线上长度和绝对偏移复制经过边界检查的 NTLM 安全缓冲区内容。</summary>
    /// <param name="message">完整 NTLM 消息。</param>
    /// <param name="field">八字节安全缓冲区描述符的偏移。</param>
    /// <returns>描述符引用的内容字节。</returns>
    /// <exception cref="SmbProtocolException">描述符指向支持范围或消息可用字节以外的位置。</exception>
    internal static byte[] SecurityBuffer(ReadOnlySpan<byte> message, int field)
    {
        var length = Wire.U16(message, field);
        var offset = Wire.U32(message, field + 4);
        if (offset > int.MaxValue)
            throw new SmbProtocolException("Invalid NTLM security buffer.");
        return Wire.Slice(message, (int)offset, length).ToArray();
    }

    /// <summary>写入一个安全缓冲区描述符，并将内容追加到认证消息中。</summary>
    /// <param name="message">输出的认证消息。</param>
    /// <param name="field">描述符位置。</param>
    /// <param name="value">需要原样写入的内容字节。</param>
    /// <param name="offset">下一段内容的位置，写入后按长度递增。</param>
    private static void WriteBuffer(byte[] message, int field, ReadOnlySpan<byte> value, ref int offset)
    {
        Wire.Put16(message, field, checked((ushort)value.Length));
        Wire.Put16(message, field + 2, checked((ushort)value.Length));
        Wire.Put32(message, field + 4, (uint)offset);
        value.CopyTo(message.AsSpan(offset));
        offset += value.Length;
    }

    /// <summary>写入固定的互操作 NTLM 版本标记，无需查询平台专用接口。</summary>
    /// <param name="value">新建全零消息中的八字节版本字段。</param>
    /// <remarks>此线上标记描述协议行为，并不表示客户端实际使用该版本操作系统。</remarks>
    private static void WriteVersion(Span<byte> value)
    {
        value[0] = 10;
        Wire.Put16(value, 2, 19041);
        value[7] = 15;
    }
}