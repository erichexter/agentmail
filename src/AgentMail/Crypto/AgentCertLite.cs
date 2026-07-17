using System.Text.Json.Serialization;

namespace AgentMail.Crypto;

/// <summary>
/// The PR1 TOFU record: a self-published, agent-signed identity claim (brief PR1.3). No root CA exists in
/// PR1/PR2 — this record, anchored solely by the first-sight pin, is the entire trust root (FLAG-8d).
///
/// PRE-IMAGE REDUCTION — flagged, not guessed (awaiting maintainer review, same posture as the content_hash escalation):
/// App C's sign_input_agentcert carries PR3 fields (not_after, issuer_id) and there is no CA to fill them in
/// PR1. The signed pre-image here is the identity-only subset the brief specifies:
///     DS_AGENTCERT || u8(1) || addr(addr) || field(1, ident_pub) || field(1, be32(key_epoch)) || field(1, be64(record_epoch))
/// i.e. sign_input_agentcert with the two PR3 fields OMITTED (not zero-filled). That omission is a wire choice
/// a PR3 node must know about to verify a PR1 record, so it is isolated in <see cref="PreImage.SignInputAgentCertLite"/>
/// and pinned in vectors. If the PR3 fields are ruled present-but-empty instead, only that method changes.
/// </summary>
sealed class AgentCertLite
{
    public Address Addr { get; set; } = new();

    [JsonIgnore] public byte[] IdentPub { get; set; } = [];

    [JsonPropertyName("ident_pub")]
    public string IdentPubB64
    {
        get => Convert.ToBase64String(IdentPub);
        set => IdentPub = string.IsNullOrEmpty(value) ? [] : Convert.FromBase64String(value);
    }

    public uint KeyEpoch { get; set; } = 1;

    /// <summary>Monotonic per (name@host), within a fixed ident_pub. Reject-lower is enforced on merge (FLAG-8b).</summary>
    public ulong RecordEpoch { get; set; } = 1;

    [JsonIgnore] public byte[] AgentSig { get; set; } = [];

    [JsonPropertyName("agent_sig")]
    public string AgentSigB64
    {
        get => Convert.ToBase64String(AgentSig);
        set => AgentSig = string.IsNullOrEmpty(value) ? [] : Convert.FromBase64String(value);
    }

    /// <summary>base32(sha256(ident_pub)), N=52 — resolves an envelope's auth.key_id to this record.</summary>
    [JsonIgnore] public string KeyId => Base32.KeyId(IdentPub);

    /// <summary>Self-publish: sign the identity-only pre-image with the agent's own identity key.</summary>
    public static AgentCertLite Create(Identity id, ulong recordEpoch = 1)
    {
        var c = new AgentCertLite
        {
            Addr = id.Address,
            IdentPub = id.PublicKey,
            KeyEpoch = id.KeyEpoch,
            RecordEpoch = recordEpoch,
        };
        c.AgentSig = id.Sign(PreImage.DsAgentCertLite, PreImage.SignInputAgentCertLite(c));
        return c;
    }

    /// <summary>True iff the agent signature verifies against the record's OWN ident_pub. That is all TOFU can
    /// check — the record vouches for itself; the pin is what makes it trustworthy across sightings.</summary>
    public bool VerifySelfSignature() =>
        Identity.VerifyDetached(PreImage.DsAgentCertLite, PreImage.SignInputAgentCertLite(this), AgentSig, IdentPub);
}
