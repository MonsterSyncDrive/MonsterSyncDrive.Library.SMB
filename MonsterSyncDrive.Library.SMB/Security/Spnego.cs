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
using System.Formats.Asn1;

namespace MonsterSyncDrive.SMB.Security;

/// <summary>使用 DER 编码 SPNEGO NTLM 令牌，并严格解析服务器返回的有界 NegTokenResp 字段。</summary>
/// <remarks>此辅助类只支持 NTLM 机制；使用 SPNEGO 封装并不代表已经支持 Kerberos。</remarks>
internal static class Spnego
{
    /// <summary>SPNEGO NegTokenResp 结构定义的协商状态。</summary>
    internal enum State
    {
        /// <summary>接收方已完成身份认证。</summary>
        AcceptCompleted,
        /// <summary>接收方要求继续交换认证机制令牌。</summary>
        AcceptIncomplete,
        /// <summary>接收方拒绝身份认证。</summary>
        Reject,
        /// <summary>接收方要求提供机制列表 MIC。</summary>
        RequestMic
    }
    /// <summary>解析后的 SPNEGO 响应，状态、机制令牌与 MIC 分别可以省略。</summary>
    /// <param name="NegotiationState">接收方状态；字段省略时为 null。</param>
    /// <param name="ResponseToken">未经修改的机制令牌字节；字段省略时为 null。</param>
    /// <param name="MechanismListMic">长度为 16 字节的 NTLM MIC；字段省略时为 null。</param>
    internal sealed record Token(State? NegotiationState, byte[]? ResponseToken, byte[]? MechanismListMic);
    /// <summary>创建带显式标记的 ASN.1 构造型上下文标签。</summary>
    /// <param name="value">上下文字段编号。</param>
    /// <returns>用于 SPNEGO 选择项与可选字段的标签。</returns>
    private static Asn1Tag Context(int value) => new(TagClass.ContextSpecific, value, true);
    /// <summary>NTLMSSP 的 GSS 机制对象标识符。</summary>
    private const string NtlmOid = "1.3.6.1.4.1.311.2.2.10";

    /// <summary>将 NTLM 协商消息封装到仅提供 NTLM 机制的 GSS-SPNEGO 初始上下文令牌中。</summary>
    /// <param name="token">NTLM 的 NEGOTIATE_MESSAGE 协商消息。</param>
    /// <returns>采用 DER 编码的 GSS 初始上下文令牌。</returns>
    internal static byte[] Initial(ReadOnlySpan<byte> token)
    {
        var writer = new AsnWriter(AsnEncodingRules.DER);
        var application = new Asn1Tag(TagClass.Application, 0, true);
        writer.PushSequence(application);
        writer.WriteObjectIdentifier("1.3.6.1.5.5.2");
        writer.PushSequence(Context(0));
        writer.PushSequence();
        writer.PushSequence(Context(0));
        writer.PushSequence();
        writer.WriteObjectIdentifier(NtlmOid);
        writer.PopSequence();
        writer.PopSequence(Context(0));
        writer.PushSequence(Context(2));
        writer.WriteOctetString(token);
        writer.PopSequence(Context(2));
        writer.PopSequence();
        writer.PopSequence(Context(0));
        writer.PopSequence(application);
        return writer.Encode();
    }

    /// <summary>构造 NegTokenResp，包含可选的机制数据、机制列表 MIC 和协商状态。</summary>
    /// <param name="token">认证机制字节；仅交换 MIC 时为空。</param>
    /// <param name="mic">机制列表 MIC；为空时省略该字段。</param>
    /// <param name="state">可选的协商状态。</param>
    /// <returns>采用 DER 编码的上下文专用响应令牌。</returns>
    internal static byte[] Response(ReadOnlySpan<byte> token, ReadOnlySpan<byte> mic = default, State? state = null)
    {
        var writer = new AsnWriter(AsnEncodingRules.DER);
        writer.PushSequence(Context(1));
        writer.PushSequence();
        if (state is { } negotiationState)
        {
            writer.PushSequence(Context(0));
            writer.WriteEnumeratedValue(negotiationState);
            writer.PopSequence(Context(0));
        }
        if (!token.IsEmpty)
        {
            writer.PushSequence(Context(2));
            writer.WriteOctetString(token);
            writer.PopSequence(Context(2));
        }
        if (!mic.IsEmpty)
        {
            writer.PushSequence(Context(3));
            writer.WriteOctetString(mic);
            writer.PopSequence(Context(3));
        }
        writer.PopSequence();
        writer.PopSequence(Context(1));
        return writer.Encode();
    }

    /// <summary>从 SPNEGO 响应或原始 NTLM 令牌中提取必需的 NTLM 质询。</summary>
    /// <param name="blob">SESSION_SETUP 的安全缓冲区。</param>
    /// <returns>认证机制的质询字节。</returns>
    /// <exception cref="SmbProtocolException">未提供 responseToken，或封装结构无效。</exception>
    internal static byte[] Challenge(ReadOnlyMemory<byte> blob)
        => Parse(blob).ResponseToken ?? throw new SmbProtocolException("The server did not return an NTLM challenge.");

    /// <summary>编码提供给服务器的规范机制列表，作为 SPNEGO MIC 的计算输入。</summary>
    /// <returns>包含 NTLM 机制 OID 的 DER SEQUENCE。</returns>
    /// <remarks>MIC 只覆盖此机制列表，不覆盖整个初始 SPNEGO 封装或 NTLM 消息。</remarks>
    internal static byte[] MechanismList()
    {
        var writer = new AsnWriter(AsnEncodingRules.DER);
        writer.PushSequence();
        writer.WriteObjectIdentifier(NtlmOid);
        writer.PopSequence();
        return writer.Encode();
    }

    /// <summary>解析原始 NTLM 令牌或完整的 BER NegTokenResp，并校验其中的已知字段。</summary>
    /// <param name="blob">服务器提供的完整安全缓冲区。</param>
    /// <returns>解析后的可选字段，认证机制字节保持不变。</returns>
    /// <exception cref="SmbProtocolException">封装结构畸形、字段重复、认证被拒绝，或服务器选择了其他机制。</exception>
    /// <remarks>为兼容服务器而接受 BER；发送令牌及需要签名的机制列表使用规范 DER。</remarks>
    internal static Token Parse(ReadOnlyMemory<byte> blob)
    {
        // 仅在偏移零识别原始 NTLM 令牌；扫描任意杂乱数据可能误接受伪造的封装。
        if (blob.Span.StartsWith("NTLMSSP\0"u8))
            return new Token(null, blob.ToArray(), null);
        try
        {
            var reader = new AsnReader(blob, AsnEncodingRules.BER);
            var outer = reader.ReadSequence(Context(1));
            reader.ThrowIfNotEmpty();
            var fields = outer.ReadSequence();
            outer.ThrowIfNotEmpty();
            byte[]? result = null;
            byte[]? mic = null;
            State? state = null;
            // 重复的可选字段会产生歧义，不能使用首值或末值优先规则解释安全输入。
            var seen = new HashSet<int>();
            while (fields.HasData)
            {
                var tag = fields.PeekTag();
                if (tag.TagClass != TagClass.ContextSpecific || !seen.Add(tag.TagValue))
                    throw new SmbProtocolException("Invalid or duplicate SPNEGO field.");
                if (tag.HasSameClassAndValue(Context(0)))
                {
                    var stateField = fields.ReadSequence(Context(0));
                    state = stateField.ReadEnumeratedValue<State>();
                    stateField.ThrowIfNotEmpty();
                    if (!Enum.IsDefined(state.Value) || state == State.Reject)
                        throw new SmbProtocolException("The server rejected the SPNEGO negotiation.");
                }
                else if (tag.HasSameClassAndValue(Context(1)))
                {
                    var mechanism = fields.ReadSequence(Context(1));
                    if (mechanism.ReadObjectIdentifier() != NtlmOid)
                        throw new SmbProtocolException("The server selected an unsupported authentication mechanism.");
                    mechanism.ThrowIfNotEmpty();
                }
                else if (tag.HasSameClassAndValue(Context(2)))
                {
                    var response = fields.ReadSequence(Context(2));
                    result = response.ReadOctetString();
                    response.ThrowIfNotEmpty();
                }
                else if (tag.HasSameClassAndValue(Context(3)))
                {
                    var micField = fields.ReadSequence(Context(3));
                    mic = micField.ReadOctetString();
                    micField.ThrowIfNotEmpty();
                    if (mic.Length != 16)
                        throw new SmbProtocolException("Invalid NTLM SPNEGO mechanism-list MIC length.");
                }
                else
                    fields.ReadEncodedValue();
            }
            return new Token(state, result, mic);
        }
        catch (AsnContentException ex) { throw new SmbProtocolException("Invalid SPNEGO token.", ex); }
    }
}