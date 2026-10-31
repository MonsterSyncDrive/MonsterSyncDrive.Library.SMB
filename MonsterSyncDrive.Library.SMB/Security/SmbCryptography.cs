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
using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;

namespace MonsterSyncDrive.Library.SMB.Security;


/// <summary>内部 SMB3 密码套件，值与线上算法标识一致；None 表示不使用加密。</summary>
internal enum Cipher : ushort
{
    /// <summary>未协商消息加密。</summary>
    None,
    /// <summary>128 位 AES-CCM 会话加密。</summary>
    Aes128Ccm,
    /// <summary>128 位 AES-GCM 会话加密。</summary>
    Aes128Gcm,
    /// <summary>256 位 AES-CCM 会话加密。</summary>
    Aes256Ccm,
    /// <summary>256 位 AES-GCM 会话加密。</summary>
    Aes256Gcm
}

/// <summary>内部签名算法标识，与公开枚举及协议编号对应。</summary>
internal enum SigningAlgorithm : ushort
{
    /// <summary>HMAC-SHA256 的截断 16 字节签名。</summary>
    HmacSha256,
    /// <summary>AES-CMAC 签名。</summary>
    AesCmac,
    /// <summary>以消息方向和消息号区分 nonce 的 AES-GMAC 签名。</summary>
    AesGmac
}


/// <summary>SMB 签名、预认证和 AEAD 状态；密钥副本各自拥有释放生命周期，加密 nonce 空间跨绑定通道共享。</summary>
internal sealed class SmbCryptography : IDisposable
{

    /// <summary>当前通道签名密钥；绑定完成后由该通道的 GSS 会话密钥及预认证值派生。</summary>
    private readonly byte[] signingKey;

    /// <summary>逻辑会话的客户端到服务器加密密钥，在所有绑定通道保持相同。</summary>
    private readonly byte[] encryptionKey;

    /// <summary>逻辑会话的服务器到客户端解密密钥。</summary>
    private readonly byte[] decryptionKey;

    /// <summary>同一会话密钥的全局加密 nonce 状态，禁止因复制通道密码学对象而重新开始序号。</summary>
    private sealed class NonceSpace
    {

        /// <summary>会话初始化时随机生成的 nonce 前缀；CCM 使用其中三字节，GCM 使用四字节。</summary>
        internal readonly byte[] Prefix = RandomNumberGenerator.GetBytes(4);

        /// <summary>所有绑定通道共享的原子递增序号，耗尽时必须重新建立会话。</summary>
        internal long Counter;
    }

    /// <summary>与其他通道共享的 nonce 分配器；不包含需要按单个对象清零的密钥。</summary>
    private readonly NonceSpace nonceSpace;

    /// <summary>该会话采用的 SMB 加密套件。</summary>
    internal Cipher Cipher
    {
        get;
    }

    /// <summary>该通道采用的消息签名算法。</summary>
    internal SigningAlgorithm SigningAlgorithm
    {
        get;
    }


    /// <summary>创建独立密钥生命周期的会话或通道状态；协议版本决定密钥派生标签，绑定副本保留会话 nonce 分配器。</summary>
    internal SmbCryptography(ReadOnlySpan<byte> sessionKey, SmbDialect dialect, Cipher cipher,
        SigningAlgorithm signingAlgorithm, ReadOnlySpan<byte> preauthHash)
    {
        nonceSpace = new NonceSpace();
        Cipher = cipher;
        SigningAlgorithm = signingAlgorithm;
        if (dialect < SmbDialect.Smb300)
        {
            signingKey = sessionKey.ToArray();
            encryptionKey = [];
            decryptionKey = [];
        }
        else if (dialect == SmbDialect.Smb311)
        {
            signingKey = DeriveKey(sessionKey, "SMBSigningKey", preauthHash, 16);
            int keyLength = cipher is Cipher.Aes256Ccm or Cipher.Aes256Gcm ? 32 : 16;
            encryptionKey = DeriveKey(sessionKey, "SMBC2SCipherKey", preauthHash, keyLength);
            decryptionKey = DeriveKey(sessionKey, "SMBS2CCipherKey", preauthHash, keyLength);
        }
        else
        {
            signingKey = DeriveKey(sessionKey, "SMB2AESCMAC", "SmbSign\0"u8, 16);
            encryptionKey = DeriveKey(sessionKey, "SMB2AESCCM", "ServerIn \0"u8, 16);
            decryptionKey = DeriveKey(sessionKey, "SMB2AESCCM", "ServerOut\0"u8, 16);
        }
    }


    /// <summary>创建独立密钥生命周期的会话或通道状态；协议版本决定密钥派生标签，绑定副本保留会话 nonce 分配器。</summary>
    private SmbCryptography(byte[] signing, byte[] encryption, byte[] decryption,
        NonceSpace nonces, Cipher cipher, SigningAlgorithm algorithm)
    {
        signingKey = signing;
        encryptionKey = encryption;
        decryptionKey = decryption;
        nonceSpace = nonces;
        Cipher = cipher;
        SigningAlgorithm = algorithm;
    }

    /// <summary>复制会话密钥并使副本拥有独立清零生命周期，同时共享会话级加密 nonce 序号。</summary>
    internal SmbCryptography CloneForBinding()
    {
        return new(signingKey.ToArray(), encryptionKey.ToArray(),
        decryptionKey.ToArray(), nonceSpace, Cipher, SigningAlgorithm);
    }

    /// <summary>从绑定认证密钥派生通道签名密钥，仍保留原逻辑会话的方向加密密钥和 nonce 空间。</summary>
    internal SmbCryptography CreateChannel(ReadOnlySpan<byte> bindingSessionKey, SmbDialect dialect,
        Cipher cipher, SigningAlgorithm algorithm, ReadOnlySpan<byte> bindingPreauth)
    {
        if (dialect < SmbDialect.Smb300 || cipher != Cipher)
            throw new SmbProtocolException("A bound channel must preserve its SMB3 session encryption cipher.");
        using SmbCryptography channel = new(bindingSessionKey, dialect, cipher, algorithm, bindingPreauth);
        return new SmbCryptography(channel.signingKey.ToArray(), encryptionKey.ToArray(), decryptionKey.ToArray(),
            nonceSpace, cipher, algorithm);
    }


    /// <summary>按 SP800-108 Counter Mode 生成 SMB 密钥，包含带零结尾标签、额外分隔零、上下文及大端位长度。</summary>
    /// <param name="key">NTLM/GSS 导出的会话密钥。</param>
    /// <param name="label">协议指定的 ASCII 标签，内部补上终止零。</param>
    /// <param name="context">版本规定的方向字符串或预认证哈希。</param>
    /// <param name="length">输出字节数，本实现使用 16 或 32。</param>
    internal static byte[] DeriveKey(ReadOnlySpan<byte> key, string label, ReadOnlySpan<byte> context, int length)
    {
        byte[] labelBytes = Encoding.ASCII.GetBytes(label + "\0");
        byte[] input = new byte[4 + labelBytes.Length + 1 + context.Length + 4];
        BinaryPrimitives.WriteUInt32BigEndian(input, 1);
        labelBytes.CopyTo(input, 4);
        context.CopyTo(input.AsSpan(5 + labelBytes.Length));
        BinaryPrimitives.WriteUInt32BigEndian(input.AsSpan(input.Length - 4), checked((uint)length * 8));
        byte[] result = HMACSHA256.HashData(key, input);
        byte[] derived = result[..length];
        CryptographicOperations.ZeroMemory(result);
        return derived;
    }


    /// <summary>计算 SHA-512(previousHash || SMBMessage)，由会话层按顺序纳入协商、认证及中间回复。</summary>
    internal static byte[] PreauthHash(ReadOnlySpan<byte> previous, ReadOnlySpan<byte> packet)
    {
        using IncrementalHash hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA512);
        hash.AppendData(previous);
        hash.AppendData(packet);
        return hash.GetHashAndReset();
    }


    /// <summary>设置签名标志并先清空签名槽，再计算覆盖整个 SMB 消息的 16 字节签名。</summary>
    internal void Sign(byte[] packet)
    {
        Wire.Put32(packet, 16, Wire.U32(packet, 16) | Wire.Signed);
        packet.AsSpan(48, 16).Clear();
        ComputeSignature(packet).CopyTo(packet, 48);
    }


    /// <summary>按消息签名标志和本地要求验证签名；用恒定时间比较，恢复原签名后保留原报文。</summary>
    internal void Verify(byte[] packet, bool required)
    {
        if ((Wire.U32(packet, 16) & Wire.Signed) == 0)
        {
            if (required)
                throw new SmbProtocolException("The server omitted a required SMB signature.");
            return;
        }
        byte[] actual = packet.AsSpan(48, 16).ToArray();
        packet.AsSpan(48, 16).Clear();
        byte[] expected;
        try
        {
            expected = ComputeSignature(packet);
        }
        finally
        {
            actual.CopyTo(packet, 48);
        }
        if (!CryptographicOperations.FixedTimeEquals(actual, expected))
            throw new SmbProtocolException("SMB signature verification failed.");
    }


    /// <summary>按协商算法计算签名；GMAC 的 nonce 区分客户端、服务器和 CANCEL，防止同消息号跨用途复用。</summary>
    private byte[] ComputeSignature(ReadOnlySpan<byte> packet)
    {
        if (SigningAlgorithm == SigningAlgorithm.HmacSha256)
            return HMACSHA256.HashData(signingKey, packet)[..16];
        if (SigningAlgorithm == SigningAlgorithm.AesCmac)
            return Cmac(signingKey, packet);
        Span<byte> nonce = stackalloc byte[12];
        packet.Slice(24, 8).CopyTo(nonce);
        nonce[8..].Clear();
        nonce[8] = (byte)((Wire.U32(packet, 16) & Wire.ServerToClient) != 0 ? 1 : 0);
        if (Wire.U16(packet, 12) == (ushort)Command.Cancel)
            nonce[8] |= 2;
        byte[] tag = new byte[16];
        using AesGcm gcm = new(signingKey, 16);
        gcm.Encrypt(nonce, [], [], tag, packet);
        return tag;
    }


    /// <summary>实现 AES-CMAC 子密钥和最后一块处理，避免引入非微软加密依赖。</summary>
    internal static byte[] Cmac(ReadOnlySpan<byte> key, ReadOnlySpan<byte> message)
    {
        using Aes aes = Aes.Create();
        aes.Key = key.ToArray();
        Span<byte> zero = stackalloc byte[16];
        zero.Clear();
        Span<byte> subkey = stackalloc byte[16];
        _ = aes.EncryptEcb(zero, subkey, PaddingMode.None);
        Double(subkey);
        bool complete = message.Length > 0 && message.Length % 16 == 0;
        if (!complete)
            Double(subkey);
        Span<byte> state = stackalloc byte[16];
        state.Clear();
        int blocks = Math.Max(1, (message.Length + 15) / 16);
        Span<byte> block = stackalloc byte[16];
        for (int i = 0; i < blocks; i++)
        {
            block.Clear();
            int length = Math.Min(16, message.Length - (i * 16));
            message.Slice(i * 16, length).CopyTo(block);
            if (i == blocks - 1)
            {
                if (!complete)
                    block[length] = 0x80;
                for (int j = 0; j < 16; j++)
                    block[j] ^= subkey[j];
            }
            for (int j = 0; j < 16; j++)
                block[j] ^= state[j];
            _ = aes.EncryptEcb(block, state, PaddingMode.None);
        }
        return state.ToArray();
    }


    /// <summary>在 GF(2^128) 中左移倍乘 CMAC 子密钥，最高位溢出时以 0x87 约简。</summary>
    private static void Double(Span<byte> block)
    {
        bool carry = (block[0] & 0x80) != 0;
        for (int i = 0; i < 15; i++)
            block[i] = (byte)((block[i] << 1) | (block[i + 1] >> 7));
        block[15] <<= 1;
        if (carry)
            block[15] ^= 0x87;
    }


    /// <summary>构造 SMB3 加密变换头，分配不会跨通道重复的 nonce，并将头部身份和长度作为附加认证数据。</summary>
    internal byte[] Encrypt(ReadOnlySpan<byte> packet, ulong sessionId)
    {
        if (Cipher == Cipher.None)
            throw new SmbProtocolException("SMB encryption was not negotiated.");
        byte[] result = new byte[52 + packet.Length];
        result[0] = 0xFD;
        result[1] = 0x53;
        result[2] = 0x4D;
        result[3] = 0x42;
        bool ccm = Cipher is Cipher.Aes128Ccm or Cipher.Aes256Ccm;
        int nonceLength = ccm ? 11 : 12;
        nonceSpace.Prefix.AsSpan(0, nonceLength - 8).CopyTo(result.AsSpan(20));
        long counter = Interlocked.Increment(ref nonceSpace.Counter);
        if (counter <= 0)
            throw new SmbProtocolException("The SMB encryption nonce space was exhausted; reconnect.");
        BinaryPrimitives.WriteInt64BigEndian(result.AsSpan(20 + nonceLength - 8), counter);
        Wire.Put32(result, 36, checked((uint)packet.Length));
        Wire.Put16(result, 42, 1);
        Wire.Put64(result, 44, sessionId);
        EncryptPayload(encryptionKey, result.AsSpan(20, nonceLength), packet,
            result.AsSpan(52), result.AsSpan(4, 16), result.AsSpan(20, 32), ccm);
        return result;
    }


    /// <summary>先验证变换标识、长度、会话及标志，再执行 AEAD；认证失败时清空未可信明文。</summary>
    internal byte[] Decrypt(ReadOnlySpan<byte> packet, ulong sessionId)
    {
        if (packet.Length < 52 || !packet[..4].SequenceEqual(new byte[] { 0xFD, 0x53, 0x4D, 0x42 }) ||
            Wire.U16(packet, 40) != 0 || Wire.U16(packet, 42) != 1 || Wire.U64(packet, 44) != sessionId ||
            Wire.U32(packet, 36) != packet.Length - 52 || Cipher == Cipher.None)
            throw new SmbProtocolException("Invalid SMB encryption transform.");
        byte[] plaintext = new byte[packet.Length - 52];
        bool ccm = Cipher is Cipher.Aes128Ccm or Cipher.Aes256Ccm;
        try
        {
            if (ccm)
            {
                using AesCcm aes = new(decryptionKey);
                aes.Decrypt(packet.Slice(20, 11), packet[52..], packet.Slice(4, 16), plaintext, packet.Slice(20, 32));
            }
            else
            {
                using AesGcm aes = new(decryptionKey, 16);
                aes.Decrypt(packet.Slice(20, 12), packet[52..], packet.Slice(4, 16), plaintext, packet.Slice(20, 32));
            }
        }
        catch (CryptographicException ex)
        {
            CryptographicOperations.ZeroMemory(plaintext);
            throw new SmbProtocolException("SMB encryption authentication failed.", ex);
        }
        return plaintext;
    }


    /// <summary>使用平台 AES-CCM 或 AES-GCM 对给定数据和 AAD 加密，写入指定密文及 16 字节认证标签。</summary>
    internal static void EncryptPayload(ReadOnlySpan<byte> key, ReadOnlySpan<byte> nonce,
        ReadOnlySpan<byte> plaintext, Span<byte> ciphertext, Span<byte> tag, ReadOnlySpan<byte> aad, bool ccm)
    {
        if (ccm)
        {
            using AesCcm aes = new(key);
            aes.Encrypt(nonce, plaintext, ciphertext, tag, aad);
        }
        else
        {
            using AesGcm aes = new(key, 16);
            aes.Encrypt(nonce, plaintext, ciphertext, tag, aad);
        }
    }


    /// <summary>清零此对象持有的所有密钥副本，不重置其他存活通道仍在使用的共享 nonce 计数。</summary>
    public void Dispose()
    {
        CryptographicOperations.ZeroMemory(signingKey);
        CryptographicOperations.ZeroMemory(encryptionKey);
        CryptographicOperations.ZeroMemory(decryptionKey);
    }
}