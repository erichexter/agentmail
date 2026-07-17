using System.Text.Json;

namespace AgentMail.Crypto;

/// <summary>
/// The self-authenticating token a fetcher attaches to GET /keys (brief PR1.4). Carried base64-JSON in the
/// X-AgentMail-Fetch-Auth header. Proves the request comes from the holder of `requester`'s identity key —
/// not merely from someone who has the shared relay token.
/// </summary>
sealed class KeysFetchAuth
{
    public Address Requester { get; set; } = new();
    public Address Target { get; set; } = new();
    public ulong RequestedAt { get; set; }

    [System.Text.Json.Serialization.JsonIgnore] public byte[] RequesterIdentPub { get; set; } = [];

    [System.Text.Json.Serialization.JsonPropertyName("requester_ident_pub")]
    public string RequesterIdentPubB64
    {
        get => Convert.ToBase64String(RequesterIdentPub);
        set => RequesterIdentPub = string.IsNullOrEmpty(value) ? [] : Convert.FromBase64String(value);
    }

    [System.Text.Json.Serialization.JsonIgnore] public byte[] Signature { get; set; } = [];

    [System.Text.Json.Serialization.JsonPropertyName("signature")]
    public string SignatureB64
    {
        get => Convert.ToBase64String(Signature);
        set => Signature = string.IsNullOrEmpty(value) ? [] : Convert.FromBase64String(value);
    }

    public const string HeaderName = "X-AgentMail-Fetch-Auth";

    /// <summary>Bounded replay window for the requester-asserted timestamp. A read, so this is lenient by design.</summary>
    public static TimeSpan MaxClockSkew { get; } = TimeSpan.FromMinutes(5);

    public static KeysFetchAuth Create(Identity requester, Address target, ulong? requestedAt = null)
    {
        var a = new KeysFetchAuth
        {
            Requester = requester.Address,
            Target = target,
            RequestedAt = requestedAt ?? (ulong)DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
            RequesterIdentPub = requester.PublicKey,
        };
        a.Signature = requester.Sign(PreImage.DsKeysFetch, PreImage.SignInputKeysFetch(a.Requester, a.Target, a.RequestedAt));
        return a;
    }

    public string ToHeader() => Convert.ToBase64String(JsonSerializer.SerializeToUtf8Bytes(this, Paths.Json));

    public static KeysFetchAuth? FromHeader(string? header)
    {
        if (string.IsNullOrWhiteSpace(header)) return null;
        try { return JsonSerializer.Deserialize<KeysFetchAuth>(Convert.FromBase64String(header), Paths.Json); }
        catch { return null; }
    }

    /// <summary>
    /// Verify the fetch is authentic and fresh. Returns null on success, else a reason.
    ///
    /// Note what this does and does NOT establish. It proves the requester holds the private key for the
    /// ident_pub it presents (signature) and that the request is recent (window). It does NOT prove that
    /// ident_pub is who they claim to be at the directory level — on a cleartext LAN pre-PR3 that is unpinnable
    /// first-contact (FLAG-11). The value in PR1 is attribution + defeating a bare-token harvest, not identity
    /// assurance. A caller that wants assurance checks the requester against its pin store separately.
    /// </summary>
    public string? Verify(ulong nowMs)
    {
        if (RequesterIdentPub.Length != Primitives.Ed25519PublicKeySize) return "malformed requester_ident_pub";
        if (Signature.Length != Primitives.Ed25519SignatureSize) return "malformed signature";

        long skew = Math.Abs((long)nowMs - (long)RequestedAt);
        if (skew > (long)MaxClockSkew.TotalMilliseconds) return $"stale/future fetch ({skew}ms skew)";

        byte[] preImage = PreImage.SignInputKeysFetch(Requester, Target, RequestedAt);
        if (!Identity.VerifyDetached(PreImage.DsKeysFetch, preImage, Signature, RequesterIdentPub))
            return "fetch signature verification failed";

        return null;
    }
}

/// <summary>
/// The target's identity-only Keys bundle served by GET /keys (brief PR1.4) — exactly the self-signed
/// AgentCertLite ({addr, ident_pub, key_epoch, record_epoch}, hub_sig ignored per FLAG-8d). PR2 extends the
/// stored bundle with spk_pub / opk[]; the JSON is unknown-field-tolerant so a PR1 node ignores those.
///
/// Published at `register` and served as a static signed blob, so the relay never touches a private key on the
/// fetch path. Only LOCAL agents are servable: a relay publishes bundles for the agents it hosts; a fetch for
/// a non-local target 404s (FLAG-9.3, non-fatal — the sender falls back to the gossiped record).
/// </summary>
static class KeysBundle
{
    static string Dir => Path.Combine(Paths.Root, "pki", "published");
    static string PathFor(Address a) => Path.Combine(Dir, $"{a.Name}@{a.Host}.json");

    /// <summary>Publish this host's self-signed bundle so GET /keys can serve it. Called from register.</summary>
    public static void Publish(AgentCertLite record)
    {
        Directory.CreateDirectory(Dir);
        Io.WriteAtomic(PathFor(record.Addr), JsonSerializer.Serialize(record, Paths.Json));
    }

    /// <summary>Load a published bundle, or null if this relay does not host that agent.</summary>
    public static AgentCertLite? Get(Address a)
    {
        try
        {
            string p = PathFor(a);
            return File.Exists(p) ? JsonSerializer.Deserialize<AgentCertLite>(File.ReadAllText(p), Paths.Json) : null;
        }
        catch { return null; }
    }

    public static AgentCertLite? Deserialize(string json)
    {
        try { return JsonSerializer.Deserialize<AgentCertLite>(json, Paths.Json); }
        catch { return null; }
    }
}
