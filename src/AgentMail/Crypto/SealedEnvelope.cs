using System.Text.Json.Serialization;

namespace AgentMail.Crypto;

/// <summary>An agent address. `session` is unused in PR1–PR3 (one session per agent) but is in the signed pre-image.</summary>
sealed class Address
{
    public string Name { get; set; } = "";
    public string Host { get; set; } = "";
    public string? Session { get; set; }

    public Address() { }
    public Address(string name, string host, string? session = null) { Name = name; Host = host; Session = session; }

    [JsonIgnore] public string Key => $"{Name}@{Host}";
    public override string ToString() => Key;
}

/// <summary>Envelope mode. In the pre-image as be32, so the numeric values are wire contract.</summary>
enum EncMode : uint { Plaintext = 0, Enc = 1 }

/// <summary>Signed priority. In the pre-image as be32 — numeric values are wire contract.</summary>
enum Priority : uint { Low = 0, Normal = 1, High = 2 }

/// <summary>Receipt classes (FLAG-28). In receipt_v1 as u8 — numeric values are wire contract.</summary>
enum ReceiptType : byte { Consumed = 0, Bounced = 1, UndecryptableUnresolvable = 2 }

/// <summary>Sealing metadata. Every field here is inside BOTH signed pre-images, so a transit flip of any of
/// them is a clean structural signature failure rather than a manufacturable decrypt oracle.</summary>
sealed class EncMeta
{
    public EncMode Mode { get; set; } = EncMode.Enc;
    public string Alg { get; set; } = "xchacha20poly1305";

    /// <summary>base32(sha256(IK_s pub)), N=52 (FLAG-40). Stable long-term pseudonymous linker — accepted-exposed.</summary>
    public string SenderKeyId { get; set; } = "";
    /// <summary>base32(sha256(IK_r pub)), N=52 (FLAG-40). Accepted-exposed.</summary>
    public string RecipientKeyId { get; set; } = "";

    public uint KeyEpoch { get; set; }
    /// <summary>PR1 interim seal signals identity-only with spk_epoch=0 and opk_id=0 (FLAG-4).</summary>
    public uint SpkEpoch { get; set; }
    public uint OpkId { get; set; }

    public byte[] EphPub { get; set; } = [];
    public byte[] Nonce { get; set; } = [];
}

sealed class AuthMeta
{
    public uint SigProjectionVersion { get; set; } = 1;
    public byte[] AgentSig { get; set; } = [];
    /// <summary>base32(sha256(ident_pub)), N=52. Resolves to the pinned sender record.</summary>
    public string KeyId { get; set; } = "";
    public uint KeyEpoch { get; set; }
}

/// <summary>
/// The E2E envelope (§5). Serialized as <c>*.msg.json</c>; legacy plaintext stays on <c>*.msg.md</c>
/// frontmatter (FLAG-5), and the two are kept apart deliberately — see FLAG-9's atomic-deploy rule.
///
/// FLAG-42: the deserializer MUST tolerate unknown members. A strict parser would break gossip the moment a
/// newer node adds a field, splitting the directory. System.Text.Json skips unknowns by default; the test
/// suite pins that so nobody "hardens" it into a strict schema gate later.
///
/// Only <c>reply_to</c> is genuinely optional. Everything else is materialized at mint, so on a signed
/// envelope every presence byte is 0x01 and a 0x00 is a projection_mismatch (FLAG-27.3).
/// </summary>
sealed class SealedEnvelope
{
    public string MsgId { get; set; } = "";
    public uint ProtocolVersion { get; set; } = 1;

    public Address From { get; set; } = new();
    public Address To { get; set; } = new();
    /// <summary>Sender-owned. The recipient ENFORCES reply_to.host == from.host, else it is a redirect primitive (FLAG-45).</summary>
    public Address? ReplyTo { get; set; }

    public string ContentType { get; set; } = "text/markdown";

    /// <summary>FINAL on-wire body length — POST-padding (FLAG-23). Signed.</summary>
    public uint Size { get; set; }

    /// <summary>
    /// sha256 of the FINAL post-padding on-wire body bytes (ct‖tag under E2E). Raw 32 bytes, not hex.
    /// In sign_input_v1 only — never aead_ad_v1 (P0-A).
    /// </summary>
    [JsonIgnore] public byte[]? ContentHash { get; set; }

    /// <summary>Hex form for the JSON wire. The signed pre-image consumes the decoded bytes.</summary>
    [JsonPropertyName("content_hash")]
    public string? ContentHashHex
    {
        get => ContentHash is null ? null : Convert.ToHexString(ContentHash).ToLowerInvariant();
        set => ContentHash = string.IsNullOrEmpty(value) ? null : Convert.FromHexString(value);
    }

    /// <summary>Epoch ms, SENDER-ASSERTED. Never trusted for expiry or replay-anchoring (M5/B-NEW-1).</summary>
    public ulong CreatedAt { get; set; }
    /// <summary>Sender-asserted. The recipient re-clamps against its own clock AND MAX_MESSAGE_LIFETIME (M5/B1).</summary>
    public ulong ExpiresAt { get; set; }

    public Priority Priority { get; set; } = Priority.Normal;

    public bool WantReceipt { get; set; } = true;
    public bool RequireE2e { get; set; }
    /// <summary>RESERVED, MUST be false. With no ratchet there is no sequence state, so nothing can enforce it (FLAG-22).</summary>
    public bool Ordered { get; set; }
    /// <summary>N independent seals under one logical msg_id; seal-cache key is (msg_id, to) (FLAG-25).</summary>
    public bool Fanout { get; set; }

    /// <summary>ADVISORY ONLY — the recipient ignores this. The effective value is self-authenticating from the
    /// AEAD plaintext (FLAG-26), which is why an unsigned bit cannot steer recipient parsing.</summary>
    public bool SealSubject { get; set; }

    public EncMeta Enc { get; set; } = new();
    public AuthMeta Auth { get; set; } = new();

    /// <summary>PR3 only. The ONLY message-intrinsic authenticated time anchor (FLAG-33); null pre-PR3.</summary>
    public object? RelayAttest { get; set; }

    /// <summary>Outer subject family: used ONLY for legacy plaintext. Under E2E these live inside the seal (FLAG-26).</summary>
    public string? Subject { get; set; }
    public string? ThreadId { get; set; }
    public string? InReplyTo { get; set; }

    /// <summary>Advisory only — never gates a decision.</summary>
    public Dictionary<string, string> Headers { get; set; } = [];

    /// <summary>ct‖tag under E2E. Base64 on the wire.</summary>
    [JsonIgnore] public byte[] Body { get; set; } = [];

    [JsonPropertyName("body")]
    public string BodyB64
    {
        get => Convert.ToBase64String(Body);
        set => Body = string.IsNullOrEmpty(value) ? [] : Convert.FromBase64String(value);
    }

    [JsonIgnore] public string FileName => $"{MsgId}.msg.json";

    /// <summary>Seal-cache / persist key. NOT msg_id alone — a fanout message is N seals, one per recipient (FLAG-25).</summary>
    [JsonIgnore] public string SealKey => $"{MsgId}|{To.Key}";
}

/// <summary>
/// A signed receipt (FLAG-28). Receipts are first-class signed envelopes: on a cleartext LAN a bare status
/// can be forged into false delivery, or into a resend loop via a fake bounce.
/// </summary>
sealed class SignedReceipt
{
    public string OrigMsgId { get; set; } = "";
    [JsonIgnore] public byte[] OrigContentHash { get; set; } = [];

    [JsonPropertyName("orig_content_hash")]
    public string OrigContentHashHex
    {
        get => Convert.ToHexString(OrigContentHash).ToLowerInvariant();
        set => OrigContentHash = string.IsNullOrEmpty(value) ? [] : Convert.FromHexString(value);
    }

    public ReceiptType Type { get; set; }
    public ulong ReceiptTime { get; set; }
    public Address Recipient { get; set; } = new();
    public Address Sender { get; set; } = new();

    [JsonIgnore] public byte[] Signature { get; set; } = [];

    [JsonPropertyName("signature")]
    public string SignatureB64
    {
        get => Convert.ToBase64String(Signature);
        set => Signature = string.IsNullOrEmpty(value) ? [] : Convert.FromBase64String(value);
    }
}
