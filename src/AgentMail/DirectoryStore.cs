using System.Text.Json;
using System.Text.Json.Serialization;

namespace AgentMail;

/// <summary>A white-pages entry: one reachable agent on some host.</summary>
sealed class AgentRecord
{
    public string Agent { get; set; } = "";
    public string User { get; set; } = "";
    public string Host { get; set; } = "";
    public string? Tailnet { get; set; }              // MagicDNS suffix; peers must share it to reach each other
    public string Endpoint { get; set; } = "";
    public List<string> Aliases { get; set; } = new();  // alternate names that route to this agent
    public List<string> Endpoints { get; set; } = new(); // all reachable relay URLs (tailnet + LAN); sender tries each
    /// <summary>
    /// online | offline (tombstone). SELF-ASSERTED AT REGISTER AND NEVER REFRESHED — it cannot go false on
    /// its own, so it is NOT evidence of liveness and MUST NOT gate routing or capability decisions.
    /// Use <see cref="DirectoryStore.IsStale"/> (last_seen freshness) for that. Only the record's OWNER may
    /// set offline, and only explicitly (`register --offline`).
    /// </summary>
    public string Status { get; set; } = "online";
    public long Version { get; set; }                 // bumped on every change; LWW ordering key
    public string LastSeen { get; set; } = "";        // ISO-8601 UTC
    public List<string> Capabilities { get; set; } = new();
    public string? Pubkey { get; set; }               // reserved for signed records

    [JsonIgnore] public string Key => $"{Agent}@{Host}";
}

/// <summary>
/// The replicated directory, persisted one JSON file per record under directory/.
/// Merge is last-write-wins by (Version, then LastSeen).
/// </summary>
static class DirectoryStore
{
    public static IEnumerable<AgentRecord> All()
    {
        if (!Directory.Exists(Paths.DirectoryDir)) yield break;
        foreach (var file in Directory.EnumerateFiles(Paths.DirectoryDir, "*.json"))
        {
            AgentRecord? r = null;
            try { r = JsonSerializer.Deserialize<AgentRecord>(File.ReadAllText(file), Paths.Json); }
            catch { /* skip a corrupt/partial record file */ }
            if (r is not null) yield return r;
        }
    }

    public static AgentRecord? Get(string agent, string host)
    {
        string path = Paths.RecordPath(agent, host);
        if (!File.Exists(path)) return null;
        try { return JsonSerializer.Deserialize<AgentRecord>(File.ReadAllText(path), Paths.Json); }
        catch { return null; }
    }

    /// <summary>Find every record for a bare agent name or alias (any host).</summary>
    public static List<AgentRecord> FindByName(string agent) =>
        All().Where(r => Matches(r, agent)).ToList();

    private static bool Matches(AgentRecord r, string name) =>
        string.Equals(r.Agent, name, StringComparison.OrdinalIgnoreCase) ||
        r.Aliases.Any(a => string.Equals(a, name, StringComparison.OrdinalIgnoreCase));

    /// <summary>Resolve a name-or-alias to the canonical record on a given host (exact agent wins).</summary>
    public static AgentRecord? Resolve(string name, string host) =>
        Get(name, host) ?? All().FirstOrDefault(r =>
            string.Equals(r.Host, host, StringComparison.OrdinalIgnoreCase) && Matches(r, name));

    public static void Save(AgentRecord r)
    {
        Paths.EnsureRoot();
        Io.WriteAtomic(Paths.RecordPath(r.Agent, r.Host), JsonSerializer.Serialize(r, Paths.Json));
    }

    /// <summary>True if <paramref name="a"/> is strictly newer than <paramref name="b"/> (LWW: version, then last_seen).</summary>
    public static bool IsNewer(AgentRecord a, AgentRecord b)
    {
        if (a.Version != b.Version) return a.Version > b.Version;
        return string.CompareOrdinal(a.LastSeen, b.LastSeen) > 0;
    }

    /// <summary>True if <paramref name="incoming"/> is newer than what we hold for its key.</summary>
    public static bool IsNewer(AgentRecord incoming)
    {
        var current = Get(incoming.Agent, incoming.Host);
        return current is null || IsNewer(incoming, current);
    }

    /// <summary>LWW-merge a record; returns true if the local view changed.</summary>
    public static bool Merge(AgentRecord incoming)
    {
        if (!IsNewer(incoming)) return false;
        Save(incoming);
        return true;
    }

    public static void Delete(string agent, string host)
    {
        string p = Paths.RecordPath(agent, host);
        if (File.Exists(p)) File.Delete(p);
    }

    // --- Freshness (#8) ---------------------------------------------------------------------------
    //
    // Staleness is COMPUTED AT READ TIME and never stored or gossiped. That is deliberate: a stored
    // "offline" is an assertion, and only the record's owner is entitled to make it. If a non-owner could
    // write staleness into the record and gossip it, one node that merely hadn't heard from a peer in a day
    // would tombstone that peer fleet-wide — strictly worse than the bug this replaces.

    /// <summary>How long since last_seen before a record stops being trusted for routing. Never deletes anything.</summary>
    public static TimeSpan StaleAfter { get; } =
        TimeSpan.FromHours(int.TryParse(Environment.GetEnvironmentVariable("AGENTMAIL_STALE_HOURS"), out int h) && h > 0 ? h : 24);

    /// <summary>True if this record is for an agent hosted by THIS relay.</summary>
    public static bool IsLocal(AgentRecord r) => string.Equals(r.Host, Paths.Host, StringComparison.OrdinalIgnoreCase);

    public static bool TryParseLastSeen(AgentRecord r, out DateTime utc) =>
        DateTime.TryParse(r.LastSeen, null,
            System.Globalization.DateTimeStyles.AdjustToUniversal | System.Globalization.DateTimeStyles.AssumeUniversal,
            out utc);

    /// <summary>
    /// True if the record is too old to be trusted for a routing or capability decision.
    ///
    /// A LOCALLY-HOSTED record is NEVER stale, whatever its last_seen says. A relay always knows which agents
    /// it hosts; `Resolve(name, Paths.Host)` failing for a local agent is incoherent by construction, and is
    /// exactly what took wolf@windev2407eval offline on 2026-07-17 — his own relay 404'd him at 24.2h.
    ///
    /// Freshness — not <see cref="AgentRecord.Status"/> — is the signal. Status is self-asserted at register
    /// and never refreshed, so it cannot go false; four agents were reporting "online" while unroutable.
    /// </summary>
    public static bool IsStale(AgentRecord r, DateTime? nowUtc = null)
    {
        if (IsLocal(r)) return false;
        if (!TryParseLastSeen(r, out var seen)) return true;   // unparseable ⇒ untrustworthy, but still not deleted
        return (nowUtc ?? DateTime.UtcNow) - seen > StaleAfter;
    }

    /// <summary>True if this record may be used for a routing/capability decision: present, fresh, not tombstoned.</summary>
    public static bool IsRoutable(AgentRecord r, DateTime? nowUtc = null) =>
        !IsStale(r, nowUtc) && !string.Equals(r.Status, "offline", StringComparison.OrdinalIgnoreCase);

    /// <summary>
    /// Explicit, operator-invoked reaping. NOT automatic and NOT on any timer — the relay's 60s prune loop
    /// that used to call this is gone (#8).
    ///
    /// Automatic deletion is what produced the flap: prune removed the file, a peer gossiped the record back
    /// (Merge sees current==null ⇒ IsNewer ⇒ Save), prune removed it again — so delivery to a live agent
    /// alternated 202/404 on a ~60s cycle with neither end told. Deletion also destroys the LWW high-water:
    /// register computes Version = (existing?.Version ?? 0) + 1, so a re-register into a deleted slot restarts
    /// at v1 and LOSES to any peer still holding v3, silently undoing the recovery.
    ///
    /// Never deletes a locally-hosted record. To retire an agent, its OWNER tombstones it explicitly with
    /// `register --offline`, which bumps Version so the tombstone wins LWW and propagates instead of being
    /// resurrected.
    /// </summary>
    public static int PruneExplicit(DateTime cutoffUtc)
    {
        int n = 0;
        foreach (var r in All())
        {
            if (IsLocal(r)) continue;                                  // a relay never forgets its own agents
            if (TryParseLastSeen(r, out var t) && t < cutoffUtc) { Delete(r.Agent, r.Host); n++; }
        }
        return n;
    }
}
