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
    public string Status { get; set; } = "online";   // online | offline (tombstone)
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

    /// <summary>Delete records whose last_seen is older than <paramref name="cutoffUtc"/>. Returns count pruned.</summary>
    public static int Prune(DateTime cutoffUtc)
    {
        int n = 0;
        foreach (var r in All())
        {
            if (DateTime.TryParse(r.LastSeen, null,
                    System.Globalization.DateTimeStyles.AdjustToUniversal | System.Globalization.DateTimeStyles.AssumeUniversal,
                    out var t) && t < cutoffUtc)
            {
                Delete(r.Agent, r.Host);
                n++;
            }
        }
        return n;
    }
}
