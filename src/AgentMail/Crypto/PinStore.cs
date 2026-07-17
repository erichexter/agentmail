using System.Text.Json;

namespace AgentMail.Crypto;

/// <summary>The outcome of offering a record to the pin store — the caller alerts on anything but Accepted/Unchanged.</summary>
enum PinResult
{
    /// <summary>First sight of this peer — pinned.</summary>
    PinnedFirstSight,
    /// <summary>Same ident_pub, higher record_epoch — accepted.</summary>
    Updated,
    /// <summary>Same ident_pub, same-or-lower record_epoch — ignored (rollback-resistant).</summary>
    Unchanged,
    /// <summary>DIFFERENT ident_pub for an already-pinned peer — REJECTED. Attack or a rotation needing OOB re-pin.</summary>
    RejectedKeyMismatch,
    /// <summary>The record's own self-signature did not verify — rejected before any pin decision.</summary>
    RejectedBadSignature,
    /// <summary>Epoch state was missing/corrupt and could not be re-derived — fail closed (FLAG-43).</summary>
    RejectedEpochStateLost,
}

/// <summary>
/// Trust-on-first-use pinning — the entire trust root in PR1/PR2 (there is no CA until PR3).
///
/// SECURITY POSTURE: TOFU provides ZERO MITM protection against an adversary present at or before first
/// contact (FLAG-11). On a cleartext LAN with a forgeable relay token, an attacker can land-grab a peer's name
/// and pin its own key first. What TOFU *does* guarantee is that once a key is pinned, it never silently
/// changes: a later record with a DIFFERENT ident_pub is rejected regardless of how high its epoch claims to be
/// (FLAG-8b — otherwise a self-signed higher-epoch record would be free key substitution). PR3 PKI is the floor.
/// </summary>
sealed class PinStore
{
    readonly string _pinDir;
    readonly string _epochPath;

    public PinStore(string? root = null)
    {
        string r = root ?? Path.Combine(Paths.Root, "pki");
        _pinDir = Path.Combine(r, "pinned");
        _epochPath = Path.Combine(r, "state", "epochs.json");
    }

    string PinPath(Address a) => Path.Combine(_pinDir, $"{a.Name}@{a.Host}.json");

    public PinnedRecord? Get(Address a)
    {
        try
        {
            string p = PinPath(a);
            return File.Exists(p) ? JsonSerializer.Deserialize<PinnedRecord>(File.ReadAllText(p), Paths.Json) : null;
        }
        catch { return null; }
    }

    /// <summary>
    /// Offer a self-published record to the store. The order of checks is the security contract:
    ///   1. self-signature must verify — a record that cannot vouch for itself is not considered at all
    ///   2. first sight ⇒ pin
    ///   3. SAME ident_pub ⇒ apply record_epoch monotonicity (reject-lower), fail-closed on lost epoch state
    ///   4. DIFFERENT ident_pub ⇒ REJECT, no matter the epoch (FLAG-8b). Never auto-accept a key change.
    /// </summary>
    public PinResult Offer(AgentCertLite record)
    {
        if (!record.VerifySelfSignature()) return PinResult.RejectedBadSignature;

        var existing = Get(record.Addr);
        if (existing is null)
        {
            WritePin(record);
            RecordEpochHighWater(record.Addr, record.RecordEpoch);
            return PinResult.PinnedFirstSight;
        }

        // A pinned key changes ONLY by out-of-band operator re-pin (or the FLAG-11 direct-Tailscale path).
        // A self-signed record presenting a different ident_pub — however high its epoch — is refused. This is
        // the whole point: with no CA, the pin is the only thing standing between us and key substitution.
        if (!Primitives.FixedTimeEquals(existing.IdentPub, record.IdentPub))
            return PinResult.RejectedKeyMismatch;

        // Same key: enforce record_epoch monotonicity, and FAIL CLOSED if we cannot prove freshness (FLAG-43).
        // An empty/corrupt epoch map must mean "refuse a possible downgrade", never "accept anything".
        if (!TryGetEpochHighWater(record.Addr, out ulong known))
        {
            // Re-derive from the pin still on disk before giving up — the pinned record is itself authority.
            known = existing.RecordEpoch;
            if (!RecordEpochHighWater(record.Addr, known)) return PinResult.RejectedEpochStateLost;
        }

        if (record.RecordEpoch <= known) return PinResult.Unchanged;

        WritePin(record);
        RecordEpochHighWater(record.Addr, record.RecordEpoch);
        return PinResult.Updated;
    }

    void WritePin(AgentCertLite record)
    {
        Directory.CreateDirectory(_pinDir);
        var pin = new PinnedRecord
        {
            Addr = record.Addr,
            IdentPub = record.IdentPub,
            KeyEpoch = record.KeyEpoch,
            RecordEpoch = record.RecordEpoch,
            KeyId = record.KeyId,
            PinnedAt = null,   // stamped by the caller if it wants provenance; not security-relevant
        };
        Io.WriteAtomic(PinPath(record.Addr), JsonSerializer.Serialize(pin, Paths.Json));
    }

    // --- Epoch high-water: fail closed on absence/corruption (FLAG-43) ----------------------------

    bool TryGetEpochHighWater(Address a, out ulong epoch)
    {
        epoch = 0;
        var map = LoadEpochs();
        return map is not null && map.TryGetValue($"{a.Name}@{a.Host}", out epoch);
    }

    bool RecordEpochHighWater(Address a, ulong epoch)
    {
        try
        {
            var map = LoadEpochs() ?? new Dictionary<string, ulong>();
            string key = $"{a.Name}@{a.Host}";
            if (map.TryGetValue(key, out ulong cur) && cur >= epoch) return true;   // never lower the high-water
            map[key] = epoch;
            Directory.CreateDirectory(Path.GetDirectoryName(_epochPath)!);
            Io.WriteAtomic(_epochPath, JsonSerializer.Serialize(map, Paths.Json));
            return true;
        }
        catch { return false; }
    }

    /// <summary>Returns null on a missing OR unreadable/corrupt file — the caller treats null as "unknown ⇒ fail closed".</summary>
    Dictionary<string, ulong>? LoadEpochs()
    {
        try
        {
            return File.Exists(_epochPath)
                ? JsonSerializer.Deserialize<Dictionary<string, ulong>>(File.ReadAllText(_epochPath), Paths.Json)
                : new Dictionary<string, ulong>();   // absent-but-readable is a legitimate empty map, not corruption
        }
        catch { return null; }   // parse failure ⇒ corrupt ⇒ unknown ⇒ fail closed
    }
}

/// <summary>What the pin store persists: the trusted identity for a peer. The agent signature is not kept —
/// once pinned, this record IS the trust, not the signature that established it.</summary>
sealed class PinnedRecord
{
    public Address Addr { get; set; } = new();

    [System.Text.Json.Serialization.JsonIgnore] public byte[] IdentPub { get; set; } = [];

    [System.Text.Json.Serialization.JsonPropertyName("ident_pub")]
    public string IdentPubB64
    {
        get => Convert.ToBase64String(IdentPub);
        set => IdentPub = string.IsNullOrEmpty(value) ? [] : Convert.FromBase64String(value);
    }

    public uint KeyEpoch { get; set; }
    public ulong RecordEpoch { get; set; }
    public string KeyId { get; set; } = "";
    public string? PinnedAt { get; set; }
}
