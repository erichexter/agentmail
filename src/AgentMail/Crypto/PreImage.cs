using System.Buffers.Binary;
using System.Text;

namespace AgentMail.Crypto;

/// <summary>Ingress validation rejected a field rather than normalizing it (P2-K). Never normalize identity text.</summary>
sealed class NonConformingFieldException(string field, string value)
    : Exception($"non_conforming_field: {field} = '{value}'")
{
    public string Field { get; } = field;
}

/// <summary>A materialized-with-default field carried presence 0x00 where 0x01 is required (FLAG-27.3).</summary>
sealed class ProjectionMismatchException(string field) : Exception($"projection_mismatch: {field}");

/// <summary>
/// Length-prefixed TLV signing pre-images — PRD Appendix C (normative), §5.1/§5.3.
///
/// The highest-risk surface in the build: these bytes ARE the signature. Everything here is gated by
/// cross-implementation vectors, not by review. Never sign JSON or protobuf bytes — only this TLV.
///
/// Two variants, and the ordering between them breaks the P0-A cycle:
///   aead_ad_v1   content-hash-FREE, so it is computable BEFORE the ciphertext exists. Used as AEAD AD.
///   sign_input_v1 the same structure PLUS content_hash at its fixed slot. Used for auth.agent_sig.
///
///   build aead_ad → seal(ad=aead_ad) → content_hash = sha256(ct‖tag) → build sign_input → sign
///
/// Transplant resistance comes from aead_ad binding msg_id‖from‖to‖size‖nonce‖eph_pub — content_hash in the
/// AD was never what prevented transplant. nonce and eph_pub are in BOTH variants, so a relay that flips
/// either produces a clean structural signature failure rather than a recipient-side decrypt oracle.
/// </summary>
static class PreImage
{
    // --- Domain-separation tags (App C; ASCII, no trailing NUL) -----------------------------------
    public const string DsAuth        = "agentmail/v1/auth-sig";
    public const string DsSpk         = "agentmail/v1/spk-sig";
    public const string DsEnroll      = "agentmail/v1/enroll";
    public const string DsX3dh        = "agentmail/v1/x3dh";
    public const string DsAuthPrefix  = "agentmail/v1/preimage";
    public const string DsAeadPrefix  = "agentmail/v1/aead-ad";
    public const string DsKeys        = "agentmail/v1/keys";
    /// <summary>The CA-issued AgentCert (App C, signed by the intermediate). Reserved for PR3 — do NOT use it for the self-signed pin.</summary>
    public const string DsAgentCert   = "agentmail/v1/agent-cert";
    /// <summary>
    /// The PR1 self-signed TOFU pin — a DIFFERENT object from the CA-issued AgentCert, not a reduced form of it.
    /// Domain-separated on Wolf's ruling (2026-07-17): sharing DS_AGENTCERT with a CA-signed cert would blur the
    /// object boundary PR3's dual-trust depends on (pin-check vs chain-to-root). App C tag-namespace addition is
    /// being routed to Harrell as a proposed diff; if he picks a different spelling, this one constant + its
    /// vector rename.
    /// </summary>
    public const string DsAgentCertLite = "agentmail/v1/agent-cert-lite";
    /// <summary>
    /// Authenticates a GET /keys fetch to the fetching agent's identity, not the shared relay token (brief PR1.4).
    /// A cross-implementation contract (another agent's fetch must reconstruct these exact bytes), so it is
    /// domain-separated and vector-pinned. Added to App C's tag namespace alongside DS_AGENTCERT_LITE — Wolf
    /// routes both to Harrell; a respell is one constant + one vector.
    /// </summary>
    public const string DsKeysFetch   = "agentmail/v1/keys-fetch";
    /// <summary>Receipts are signed envelopes, not bare status (FLAG-28). Not in App C's tag list — added by the brief §3.</summary>
    public const string DsReceipt     = "agentmail/v1/receipt";

    public const byte VersionByte = 1;

    // --- Encoding primitives (App C) --------------------------------------------------------------

    public static void U8(Stream s, byte x) => s.WriteByte(x);

    public static void Be32(Stream s, uint x)
    {
        Span<byte> b = stackalloc byte[4];
        BinaryPrimitives.WriteUInt32BigEndian(b, x);
        s.Write(b);
    }

    public static void Be64(Stream s, ulong x)
    {
        Span<byte> b = stackalloc byte[8];
        BinaryPrimitives.WriteUInt64BigEndian(b, x);
        s.Write(b);
    }

    /// <summary>field(present, bytes) := present ? 0x01‖be32(len)‖bytes : 0x00</summary>
    public static void Field(Stream s, bool present, ReadOnlySpan<byte> bytes)
    {
        if (!present) { s.WriteByte(0x00); return; }
        s.WriteByte(0x01);
        Be32(s, (uint)bytes.Length);
        s.Write(bytes);
    }

    public static void Field(Stream s, bool present, string ascii) =>
        Field(s, present, present ? Encoding.ASCII.GetBytes(ascii) : ReadOnlySpan<byte>.Empty);

    static void FieldBe32(Stream s, uint x) { Span<byte> b = stackalloc byte[4]; BinaryPrimitives.WriteUInt32BigEndian(b, x); Field(s, true, b); }
    static void FieldBe64(Stream s, ulong x) { Span<byte> b = stackalloc byte[8]; BinaryPrimitives.WriteUInt64BigEndian(b, x); Field(s, true, b); }
    static void FieldU8(Stream s, byte x) => Field(s, true, stackalloc byte[1] { x });

    /// <summary>rep(items) := be32(count)‖concat(enc(item)…). Order is SIGNED — a verifier never reorders.</summary>
    public static void Rep<T>(Stream s, IReadOnlyList<T> items, Action<Stream, T> encode)
    {
        Be32(s, (uint)items.Count);
        foreach (var item in items) encode(s, item);
    }

    /// <summary>
    /// addr(a) := field(1, ascii(name))‖field(1, ascii(host))‖field(session?, ascii(session))
    ///
    /// FLAG-27.2: an absent #session emits the presence byte 0x00 — it is NOT omitted. This is one of the
    /// two places a 0x00 presence byte is legal (the other is reply_to).
    /// </summary>
    public static void Addr(Stream s, Address a)
    {
        Field(s, true, AssertLdh(a.Name, "addr.name"));
        Field(s, true, AssertLdh(a.Host, "addr.host"));
        if (a.Session is { Length: > 0 }) Field(s, true, AssertAscii(a.Session, "addr.session"));
        else s.WriteByte(0x00);
    }

    // --- Ingress validation: reject, never normalize (P2-K / FLAG-6) ------------------------------

    /// <summary>LDH: [a-z0-9-], no leading/trailing hyphen, non-empty. Rejects — never lowercases. Lowercasing happens at MINT.</summary>
    public static string AssertLdh(string s, string field)
    {
        if (string.IsNullOrEmpty(s)) throw new NonConformingFieldException(field, s ?? "");
        if (s[0] == '-' || s[^1] == '-') throw new NonConformingFieldException(field, s);
        foreach (char c in s)
            if (!((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-'))
                throw new NonConformingFieldException(field, s);
        return s;
    }

    /// <summary>Printable ASCII (0x21–0x7E), non-empty. For msg_id and the *_key_id fingerprints, which are uppercase base32.</summary>
    public static string AssertAscii(string s, string field)
    {
        if (string.IsNullOrEmpty(s)) throw new NonConformingFieldException(field, s ?? "");
        foreach (char c in s)
            if (c < 0x21 || c > 0x7E) throw new NonConformingFieldException(field, s);
        return s;
    }

    // --- Shared body (both variants, minus content_hash) ------------------------------------------

    static void EnvCommon(Stream p, SealedEnvelope e)
    {
        Addr(p, e.From);
        Addr(p, e.To);

        // reply_to is the ONLY field where a 0x00 presence byte is legal at the top level (FLAG-27.3).
        if (e.ReplyTo is not null) Addr(p, e.ReplyTo); else p.WriteByte(0x00);

        Field(p, true, AssertAscii(e.ContentType, "content_type"));
        FieldBe32(p, e.Size);
        // content_hash slot lives here in sign_input_v1 ONLY — see SignInputV1.
        FieldBe64(p, e.CreatedAt);
        FieldBe64(p, e.ExpiresAt);
        FieldBe32(p, (uint)e.Priority);
        FieldBe32(p, (uint)e.Enc.Mode);
        FieldBe32(p, e.Enc.KeyEpoch);
        Field(p, true, AssertAscii(e.Enc.SenderKeyId, "enc.sender_key_id"));
        Field(p, true, AssertAscii(e.Enc.RecipientKeyId, "enc.recipient_key_id"));
        FieldBe32(p, e.Enc.SpkEpoch);
        FieldBe32(p, e.Enc.OpkId);
        Field(p, true, e.Enc.Nonce);        // SIGNED — a relay flip is a structural signature failure
        Field(p, true, e.Enc.EphPub);       // SIGNED — ditto
        FieldU8(p, (byte)(e.WantReceipt ? 1 : 0));
        FieldU8(p, (byte)(e.RequireE2e ? 1 : 0));
        FieldU8(p, (byte)(e.Ordered ? 1 : 0));
        FieldU8(p, (byte)(e.Fanout ? 1 : 0));
        FieldBe32(p, e.Auth.KeyEpoch);
    }

    /// <summary>
    /// aead_ad_v1(env) — content-hash-FREE. Computable before the ciphertext exists; that is what breaks the
    /// P0-A cycle. Used ONLY as AEAD associated data, never signed directly.
    /// </summary>
    public static byte[] AeadAdV1(SealedEnvelope e)
    {
        ValidateIngress(e);
        using var p = new MemoryStream();
        Field(p, true, DsAeadPrefix);
        U8(p, VersionByte);
        Field(p, true, AssertAscii(e.MsgId, "msg_id"));
        FieldBe32(p, e.ProtocolVersion);
        EnvCommon(p, e);
        return p.ToArray();
    }

    /// <summary>
    /// sign_input_v1(env) — the full pre-image: aead_ad's structure plus content_hash at its fixed slot,
    /// between size and created_at. Signed as Ed25519(ident_priv, DS_AUTH ‖ sign_input_v1).
    ///
    /// The content_hash slot is field()-wrapped per App C line 997 — ruled 2026-07-16 over the brief's earlier
    /// FLAG-27.1 text; see the comment at that slot below.
    /// </summary>
    public static byte[] SignInputV1(SealedEnvelope e)
    {
        ValidateIngress(e);
        if (e.ContentHash is null || e.ContentHash.Length != Primitives.Sha256Size)
            throw new ArgumentException("content_hash must be the raw 32-byte digest, not hex", nameof(e));

        using var p = new MemoryStream();
        Field(p, true, DsAuthPrefix);
        U8(p, VersionByte);
        Field(p, true, AssertAscii(e.MsgId, "msg_id"));
        FieldBe32(p, e.ProtocolVersion);
        Addr(p, e.From);
        Addr(p, e.To);
        if (e.ReplyTo is not null) Addr(p, e.ReplyTo); else p.WriteByte(0x00);
        Field(p, true, AssertAscii(e.ContentType, "content_type"));
        FieldBe32(p, e.Size);

        // content_hash — field()-wrapped over its raw 32 bytes, App C line 997:
        //     field(1, content_hash_raw32) = 0x01 ‖ be32(32) ‖ <32 raw bytes>
        // "raw-32" is the 32 DECODED digest bytes, as against the 64-char hex string the JSON carries — it does
        // NOT mean unwrapped. Every other value in the pre-image is field()-wrapped; an unwrapped content_hash
        // would be the sole exception. Vectors pin one accept and two rejects (unwrapped; hex-string-wrapped).
        // The brief's FLAG-27.1 said the opposite and demanded a reject vector for this, the App C form.
        // Escalated rather than guessed (49c2b5b851e8); Wolf ruled App C wins and fixed the brief at its site
        // (docs @ 903f177, sha 0349bb2a). The losing variant is deleted rather than left behind a flag — a dead
        // branch is how a superseded decision gets rebuilt later.
        Field(p, true, e.ContentHash);

        FieldBe64(p, e.CreatedAt);
        FieldBe64(p, e.ExpiresAt);
        FieldBe32(p, (uint)e.Priority);
        FieldBe32(p, (uint)e.Enc.Mode);
        FieldBe32(p, e.Enc.KeyEpoch);
        Field(p, true, AssertAscii(e.Enc.SenderKeyId, "enc.sender_key_id"));
        Field(p, true, AssertAscii(e.Enc.RecipientKeyId, "enc.recipient_key_id"));
        FieldBe32(p, e.Enc.SpkEpoch);
        FieldBe32(p, e.Enc.OpkId);
        Field(p, true, e.Enc.Nonce);
        Field(p, true, e.Enc.EphPub);
        FieldU8(p, (byte)(e.WantReceipt ? 1 : 0));
        FieldU8(p, (byte)(e.RequireE2e ? 1 : 0));
        FieldU8(p, (byte)(e.Ordered ? 1 : 0));
        FieldU8(p, (byte)(e.Fanout ? 1 : 0));
        FieldBe32(p, e.Auth.KeyEpoch);
        return p.ToArray();
    }

    /// <summary>
    /// receipt_v1 (FLAG-28) — receipts are first-class SIGNED envelopes, never bare status.
    ///
    /// On a cleartext LAN an attacker can otherwise forge a `consumed` (false delivery) or an
    /// `undecryptable`/`bounced` (resend loop / false failure). Binding orig_msg_id AND orig_content_hash
    /// stops a receipt being replayed onto a different message. The sender verifies against the PINNED peer
    /// ident_pub and ignores anything else — no delivery-state change, no resend-loop trigger.
    /// </summary>
    public static byte[] ReceiptV1(string origMsgId, ReadOnlySpan<byte> origContentHash,
                                   ReceiptType type, ulong receiptTime, Address recipient, Address sender)
    {
        using var p = new MemoryStream();
        Field(p, true, DsReceipt);
        Field(p, true, AssertAscii(origMsgId, "orig_msg_id"));
        Field(p, true, origContentHash);
        U8(p, (byte)type);
        Be64(p, receiptTime);
        Addr(p, recipient);
        Addr(p, sender);
        return p.ToArray();
    }

    /// <summary>
    /// Pre-image for the PR1 self-signed TOFU pin (brief PR1.3):
    ///     DS_AGENTCERT_LITE ‖ u8(1) ‖ addr(addr) ‖ field(1, ident_pub) ‖ field(1, be32(key_epoch)) ‖ field(1, be64(record_epoch))
    ///
    /// This is NOT a reduced App C AgentCert (Wolf's ruling, 2026-07-17). App C's AgentCert is signed by the
    /// intermediate CA and carries not_after + issuer_id — CA-issuance fields. A self-signed pin has no CA, no
    /// issuer, and no CA-set expiry, so those fields are ABSENT because they belong to a different object, not
    /// omitted-as-empty-values. That is why it gets its own DS tag rather than sharing DS_AGENTCERT: PR3's
    /// dual-trust verifies a pin (pin-check) and a cert (chain-to-root) by different paths, and the tag is what
    /// keeps them from being confused. Vectors pin one ACCEPT and one REJECT proving this pre-image does not
    /// equal a full AgentCert over the same identity fields.
    /// </summary>
    public static byte[] SignInputAgentCertLite(AgentCertLite c)
    {
        using var p = new MemoryStream();
        Field(p, true, DsAgentCertLite);
        U8(p, VersionByte);
        Addr(p, c.Addr);
        Field(p, true, c.IdentPub);
        FieldBe32(p, c.KeyEpoch);
        FieldBe64(p, c.RecordEpoch);
        return p.ToArray();
    }

    /// <summary>
    /// Pre-image for a signed GET /keys request (brief PR1.4):
    ///     DS_KEYS_FETCH ‖ u8(1) ‖ addr(requester) ‖ addr(target) ‖ field(1, be64(requested_at))
    ///
    /// Signed by the requester's ident_priv and verified against the requester's ident_pub, so a leaked bearer
    /// token cannot harvest Keys bundles (and, in PR2, cannot drain OPKs). requested_at is the requester's own
    /// clock; the relay clamps it to a bounded window against ITS clock — a read, so replay is low-harm in PR1,
    /// but the window keeps a captured request from being replayed indefinitely.
    /// </summary>
    public static byte[] SignInputKeysFetch(Address requester, Address target, ulong requestedAt)
    {
        using var p = new MemoryStream();
        Field(p, true, DsKeysFetch);
        U8(p, VersionByte);
        Addr(p, requester);
        Addr(p, target);
        FieldBe64(p, requestedAt);
        return p.ToArray();
    }

    /// <summary>
    /// The full App C AgentCert pre-image (line 332), signed by the intermediate CA. Built HERE only so a vector
    /// can prove the self-signed lite pin's pre-image differs from it — the real signing lands in PR3. If this
    /// ever grows a caller before PR3, that is a bug: nothing pre-PR3 has a CA to sign it.
    /// </summary>
    internal static byte[] SignInputAgentCertFull(Address addr, ReadOnlySpan<byte> identPub, uint keyEpoch,
                                                  ulong notAfter, ulong recordEpoch, string issuerId)
    {
        using var p = new MemoryStream();
        Field(p, true, DsAgentCert);
        U8(p, VersionByte);
        Addr(p, addr);
        Field(p, true, identPub);
        FieldBe32(p, keyEpoch);
        FieldBe64(p, notAfter);
        FieldBe64(p, recordEpoch);
        Field(p, true, AssertAscii(issuerId, "issuer_id"));
        return p.ToArray();
    }

    /// <summary>
    /// X3DH transcript (§6.5 / S4). FLAG-40: the *_pub fields are RAW 32-byte public keys; the two trailing
    /// *_key_id fields are base32 fingerprints. They are DIFFERENT values and swapping them silently desyncs
    /// SK — a vector pins that failure.
    ///
    /// IKM is DH‖transcript, deliberately omitting X3DH's canonical F = 32×0xFF prefix. That is a
    /// vector-gated deviation: the transcript binding supplies UKS resistance. Do not "fix" it toward
    /// canonical without a PRD round.
    /// </summary>
    public static byte[] Transcript(ReadOnlySpan<byte> ikSenderPub, ReadOnlySpan<byte> ikRecipientPub,
                                    ReadOnlySpan<byte> spkPub, ReadOnlySpan<byte> opkPub,
                                    ReadOnlySpan<byte> ephPub, uint keyEpoch, uint spkEpoch, uint opkId,
                                    string senderKeyId, string recipientKeyId)
    {
        using var p = new MemoryStream();
        p.Write(ikSenderPub);
        p.Write(ikRecipientPub);
        if (spkPub.Length > 0) p.Write(spkPub);
        if (opkPub.Length > 0) p.Write(opkPub);
        p.Write(ephPub);
        Be32(p, keyEpoch);
        Be32(p, spkEpoch);
        Be32(p, opkId);
        p.Write(Encoding.ASCII.GetBytes(AssertAscii(senderKeyId, "sender_key_id")));
        p.Write(Encoding.ASCII.GetBytes(AssertAscii(recipientKeyId, "recipient_key_id")));
        return p.ToArray();
    }

    // --- validate_ingress (App C) ------------------------------------------------------------------

    /// <summary>
    /// Reject non-conforming input; never normalize. Materialization (defaults) happens at mint, before this —
    /// on a signed envelope every materialized field is present, so a 0x00 presence byte is a
    /// projection_mismatch (FLAG-27.3), except for reply_to and addr's #session.
    /// </summary>
    public static void ValidateIngress(SealedEnvelope e)
    {
        AssertLdh(e.From.Name, "from.name");
        AssertLdh(e.From.Host, "from.host");
        AssertLdh(e.To.Name, "to.name");
        AssertLdh(e.To.Host, "to.host");
        AssertAscii(e.MsgId, "msg_id");
        AssertAscii(e.Enc.SenderKeyId, "enc.sender_key_id");
        AssertAscii(e.Enc.RecipientKeyId, "enc.recipient_key_id");

        if (!ContentTypes.IsRegistered(e.ContentType, e.ProtocolVersion))
            throw new NonConformingFieldException("content_type", e.ContentType);

        // FLAG-22: no chain and no sequence state exist, so nothing can enforce ordered=true. Reserved.
        if (e.Ordered) throw new NonConformingFieldException("ordered", "true (unsupported_capability)");

        // FLAG-45: reply_to is otherwise a reply-redirection primitive. It is signed, so this is structural.
        if (e.ReplyTo is not null && e.ReplyTo.Host != e.From.Host)
            throw new NonConformingFieldException("reply_to", $"reply_to_redirect: {e.ReplyTo.Host} != {e.From.Host}");

        if (e.Enc.Nonce.Length != Primitives.AeadNonceSize)
            throw new NonConformingFieldException("enc.nonce", $"{e.Enc.Nonce.Length} bytes");
        if (e.Enc.EphPub.Length != Primitives.X25519PublicKeySize)
            throw new NonConformingFieldException("enc.eph_pub", $"{e.Enc.EphPub.Length} bytes");
    }
}

/// <summary>
/// content_type allow-list, VERSIONED BY protocol_version (FLAG-44) — part of the protocol, NOT a node-local
/// per-build list. A content_type valid at protocol_version=1 is accepted by every protocol_version≥1 node,
/// so benign version skew never becomes delivery loss.
/// </summary>
static class ContentTypes
{
    static readonly string[] V1 = ["text/markdown", "text/plain", "application/json"];

    public static bool IsRegistered(string contentType, uint protocolVersion) =>
        protocolVersion >= 1 && Array.IndexOf(V1, contentType) >= 0;
}
