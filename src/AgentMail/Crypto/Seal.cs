using System.Buffers.Binary;
using System.Security.Cryptography;

namespace AgentMail.Crypto;

/// <summary>The recipient rejected an envelope before acting on it. Never surfaced to the agent; quarantined + signed bounce.</summary>
sealed class VerifyFailedException(string reason) : Exception(reason);

/// <summary>
/// PR1 sealing and verify-before-act.
///
/// FLAG-4 — this is the INTERIM seal, not PRD-spec X3DH. It builds the full frozen envelope and both TLV
/// pre-images, but derives SK from a SINGLE ephemeral→recipient-identity DH, signalled on the wire by
/// spk_epoch=0 and opk_id=0. PR2 enriches it to real X3DH (DH1‖DH2‖DH3‖DH4?) against signed prekeys; the
/// recipient's SK-subset rule keys off exactly those two signed fields, so PR1 and PR2 envelopes coexist.
/// Say this in the PR description — it must not be mistaken for spec X3DH.
///
/// SECURITY POSTURE: PR1 is delivery-safe but NOT production-secure. It has ZERO MITM protection against an
/// adversary present at or before first contact (FLAG-11), and opk_id=0 replay is open (FLAG-33). PR3 (PKI)
/// is the minimum production-security floor.
/// </summary>
static class Seal
{
    /// <summary>
    /// The ordering below is a cycle-break, not a style choice (FLAG-3 / P0-A):
    ///
    ///   nonce + eph_pub  →  AD = aead_ad_v1 (content-hash-FREE)  →  seal  →  content_hash = sha256(ct‖tag)
    ///   →  sign_input_v1  →  agent_sig
    ///
    /// content_hash cannot be in the AD because it does not exist until after the seal. nonce and eph_pub are
    /// in BOTH pre-images, so a relay that flips either gets a structural signature failure instead of a
    /// recipient-side decrypt oracle it could weaponise into poison/bounce.
    /// </summary>
    public static SealedEnvelope Create(Identity sender, Address to, byte[] recipientIdentityPublicKey,
                                        uint recipientKeyEpoch, string msgId, ReadOnlySpan<byte> plaintext,
                                        string contentType = "text/markdown", Address? replyTo = null,
                                        bool wantReceipt = true, bool requireE2e = false,
                                        ulong? createdAt = null, ulong? maxLifetimeMs = null)
    {
        ulong now = createdAt ?? (ulong)DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();

        var e = new SealedEnvelope
        {
            MsgId = msgId,
            ProtocolVersion = 1,
            From = sender.Address,
            To = to,
            ReplyTo = replyTo,
            ContentType = contentType,
            CreatedAt = now,
            ExpiresAt = now + (maxLifetimeMs ?? MaxMessageLifetimeMs),
            Priority = Priority.Normal,
            WantReceipt = wantReceipt,
            RequireE2e = requireE2e,
            Ordered = false,          // RESERVED — nothing can enforce it without chain state (FLAG-22)
            Fanout = false,
            Enc = new EncMeta
            {
                Mode = EncMode.Enc,
                SenderKeyId = sender.KeyId,
                RecipientKeyId = Base32.KeyId(recipientIdentityPublicKey),
                KeyEpoch = recipientKeyEpoch,
                SpkEpoch = 0,         // FLAG-4: identity-only interim seal
                OpkId = 0,
            },
            Auth = new AuthMeta { KeyId = sender.KeyId, KeyEpoch = sender.KeyEpoch },
        };

        // Ephemeral key + nonce FIRST — both are signed, so they must exist before either pre-image is built.
        Span<byte> ephPub = stackalloc byte[Primitives.X25519PublicKeySize];
        Span<byte> ephPriv = stackalloc byte[Primitives.X25519PrivateKeySize];
        Primitives.GenerateX25519KeyPair(ephPub, ephPriv);
        e.Enc.EphPub = ephPub.ToArray();
        e.Enc.Nonce = Primitives.RandomBytes(Primitives.AeadNonceSize);

        byte[] sk = DeriveSkSender(ephPriv, recipientIdentityPublicKey, sender.X25519Public(), e);
        try
        {
            // Self-describing padding INSIDE the AEAD (FLAG-41): len(be32)‖plaintext‖zeros. The recipient
            // slices by the integrity-protected length prefix, so a binary body whose real trailing bytes are
            // 0x00 still round-trips. size/content_hash cover the FINAL post-padding bytes (FLAG-23).
            byte[] padded = Pad(plaintext);

            e.Size = 0;                              // materialized below from the actual on-wire length
            byte[] ad = PreImage.AeadAdV1(WithSize(e, (uint)(padded.Length + Primitives.AeadTagSize)));
            byte[] body = Primitives.AeadSeal(sk, e.Enc.Nonce, padded, ad);

            e.Size = (uint)body.Length;
            e.Body = body;
            e.ContentHash = Primitives.Sha256(body);
            e.Auth.AgentSig = sender.SignEnvelope(e);
            return e;
        }
        finally
        {
            // FLAG-47: SK and nonce are single-use. Zero SK the instant the seal is done; never cache it for
            // a later encryption. The only thing persisted for a transport retry is the finished ct‖tag blob,
            // keyed (msg_id, to) — re-sealing under a retained nonce would be catastrophic.
            Primitives.Zero(sk);
            Primitives.Zero(ephPriv);
        }
    }

    /// <summary>
    /// Verify-before-act (§6.8 / PR1.6). Order is load-bearing and each step is a gate:
    ///   1. signature over sign_input_v1, against the PINNED sender key — before any decrypt
    ///   2. content_hash over the on-wire body
    ///   3. AEAD-open with ad = aead_ad_v1
    ///   4. strip the self-describing padding
    ///
    /// Dedup and the expiry clamp happen upstream of this, before any key is touched. Any failure here means
    /// quarantine + a signed bounce, and MUST NOT write .done (FLAG-30).
    /// </summary>
    public static byte[] Open(Identity recipient, SealedEnvelope e, byte[] senderPinnedIdentityPublicKey)
    {
        PreImage.ValidateIngress(e);

        // reply_to is otherwise a reply-redirection primitive; it is signed, so this is a structural check.
        if (e.ReplyTo is not null && e.ReplyTo.Host != e.From.Host)
            throw new VerifyFailedException("reply_to_redirect");

        // The pinned key must be the key that claims to have signed. Resolving auth.key_id against the pin is
        // what stops a self-signed record substituting its own identity (FLAG-8b).
        if (Base32.KeyId(senderPinnedIdentityPublicKey) != e.Auth.KeyId)
            throw new VerifyFailedException("auth.key_id does not match the pinned sender key");

        if (!Identity.VerifyDetached(PreImage.DsAuth, PreImage.SignInputV1(e), e.Auth.AgentSig, senderPinnedIdentityPublicKey))
            throw new VerifyFailedException("agent_sig verification failed");

        if (e.ContentHash is null || !Primitives.FixedTimeEquals(Primitives.Sha256(e.Body), e.ContentHash))
            throw new VerifyFailedException("content_hash does not cover the on-wire body");

        if (e.Size != (uint)e.Body.Length)
            throw new VerifyFailedException("size does not match the on-wire body length");

        // SK-subset rule (PR2.4): spk_epoch==0 && opk_id==0 ⇒ the PR1 identity-only seal. PR2 adds the
        // DH1‖DH2‖DH3 and full DH1..DH4 subsets, selected from these same SIGNED fields.
        if (e.Enc.SpkEpoch != 0 || e.Enc.OpkId != 0)
            throw new VerifyFailedException("spk_epoch/opk_id set — X3DH subsets land in PR2");

        byte[] sk = DeriveSkRecipient(recipient, senderPinnedIdentityPublicKey, e);
        try
        {
            byte[] ad = PreImage.AeadAdV1(e);
            byte[] padded = Primitives.AeadOpen(sk, e.Enc.Nonce, e.Body, ad);   // throws on tag mismatch
            return Unpad(padded);
        }
        catch (CryptographicException ex)
        {
            throw new VerifyFailedException($"AEAD open failed: {ex.Message}");
        }
        finally
        {
            Primitives.Zero(sk);
        }
    }

    /// <summary>Bounded delivery window (FLAG-31). 30 days: a message undelivered past this may be dropped-expired.</summary>
    public const ulong MaxMessageLifetimeMs = 30UL * 24 * 60 * 60 * 1000;

    // --- internals --------------------------------------------------------------------------------

    /// <summary>
    /// Sender-side SK. The FLAG-4 interim single DH: DH2 = DH(EK_priv, X25519(IK_r)).
    /// PR2 replaces this with DH1‖DH2‖DH3‖DH4? against the recipient's signed prekeys.
    /// </summary>
    static byte[] DeriveSkSender(ReadOnlySpan<byte> ephPriv, byte[] recipientIdentityEd25519,
                                 byte[] senderIdentityX25519, SealedEnvelope e)
    {
        byte[] ikRecipientX = Primitives.Ed25519ToX25519Public(recipientIdentityEd25519);
        byte[] dh2 = Primitives.X25519Dh(ephPriv, ikRecipientX);   // throws on all-zero/small-subgroup
        try { return Hkdf(dh2, senderIdentityX25519, ikRecipientX, e); }
        finally { Primitives.Zero(dh2); }
    }

    /// <summary>
    /// Recipient-side SK — the same DH2 computed from the other side: DH(X25519(IK_r)_priv, eph_pub).
    /// The transcript must be byte-identical to the sender's or SK silently diverges, so both sides build it
    /// from the SIGNED enc fields rather than from anything locally known.
    /// </summary>
    static byte[] DeriveSkRecipient(Identity recipient, byte[] senderIdentityEd25519, SealedEnvelope e)
    {
        byte[] xPriv = recipient.X25519Private();
        byte[] dh2 = Primitives.X25519Dh(xPriv, e.Enc.EphPub);
        try
        {
            return Hkdf(dh2, Primitives.Ed25519ToX25519Public(senderIdentityEd25519), recipient.X25519Public(), e);
        }
        finally { Primitives.Zero(dh2); Primitives.Zero(xPriv); }
    }

    /// <summary>
    /// SK = HKDF-SHA256(DH ‖ transcript, salt = 32×0x00, info = DS_X3DH) — BCL HKDF unconditionally (FLAG-8a),
    /// never libsodium's crypto_kdf (that is BLAKE2b, the wrong primitive).
    ///
    /// FLAG-40: the transcript's *_pub fields are RAW 32-byte public keys; only the two trailing fields are
    /// base32 fingerprints. Feeding a fingerprint where a raw pubkey belongs silently desyncs SK — a vector
    /// pins that failure.
    /// </summary>
    static byte[] Hkdf(byte[] dh, byte[] senderIdentityX25519, byte[] recipientIdentityX25519, SealedEnvelope e)
    {
        byte[] transcript = PreImage.Transcript(
            ikSenderPub: senderIdentityX25519,
            ikRecipientPub: recipientIdentityX25519,
            spkPub: [],                       // absent in the PR1 interim seal
            opkPub: [],
            ephPub: e.Enc.EphPub,
            keyEpoch: e.Enc.KeyEpoch,
            spkEpoch: e.Enc.SpkEpoch,
            opkId: e.Enc.OpkId,
            senderKeyId: e.Enc.SenderKeyId,
            recipientKeyId: e.Enc.RecipientKeyId);

        var ikm = new byte[dh.Length + transcript.Length];
        dh.CopyTo(ikm, 0);
        transcript.CopyTo(ikm, dh.Length);
        try
        {
            return Primitives.Hkdf(ikm, System.Text.Encoding.ASCII.GetBytes(PreImage.DsX3dh), Primitives.AeadKeySize);
        }
        finally { Primitives.Zero(ikm); }
    }

    static SealedEnvelope WithSize(SealedEnvelope e, uint size) { e.Size = size; return e; }

    /// <summary>len(be32) ‖ plaintext ‖ zero-pad. Self-describing so the recipient recovers the exact length (FLAG-41).</summary>
    internal static byte[] Pad(ReadOnlySpan<byte> plaintext, int bucket = 0)
    {
        int inner = 4 + plaintext.Length;
        int total = bucket > 0 ? ((inner + bucket - 1) / bucket) * bucket : inner;
        var buf = new byte[total];
        BinaryPrimitives.WriteUInt32BigEndian(buf, (uint)plaintext.Length);
        plaintext.CopyTo(buf.AsSpan(4));
        return buf;
    }

    /// <summary>Slice by the AEAD-protected length prefix; padding bytes are discarded whatever their value.</summary>
    internal static byte[] Unpad(ReadOnlySpan<byte> padded)
    {
        if (padded.Length < 4) throw new VerifyFailedException("padded plaintext shorter than its length prefix");
        uint len = BinaryPrimitives.ReadUInt32BigEndian(padded);
        if (len > padded.Length - 4) throw new VerifyFailedException("padding length prefix exceeds the buffer");
        return padded.Slice(4, (int)len).ToArray();
    }
}
