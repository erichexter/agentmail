using System.Text.Json;

namespace AgentMail;

/// <summary>Per-node settings, persisted at ~/.claude/agentmail/config.json.</summary>
sealed class Config
{
    public string User { get; set; } = Environment.UserName;
    public int Port { get; set; } = 8787;
    public string Token { get; set; } = "";      // shared bearer token for the relay (Phase 2)
    public List<string> Seeds { get; set; } = new();  // seed host endpoints for gossip (Phase 3)

    public static Config Load()
    {
        if (!File.Exists(Paths.ConfigPath)) return new Config();
        try { return JsonSerializer.Deserialize<Config>(File.ReadAllText(Paths.ConfigPath), Paths.Json) ?? new Config(); }
        catch { return new Config(); }
    }

    public void Save()
    {
        Paths.EnsureRoot();
        Io.WriteAtomic(Paths.ConfigPath, JsonSerializer.Serialize(this, Paths.Json));
    }

    /// <summary>The bearer token to present/verify: AGENTMAIL_TOKEN env wins, else config.json.</summary>
    [System.Text.Json.Serialization.JsonIgnore]
    public string EffectiveToken =>
        Environment.GetEnvironmentVariable("AGENTMAIL_TOKEN") is { Length: > 0 } t ? t : Token;

    /// <summary>
    /// The endpoint peers should use to reach this node. AGENTMAIL_ENDPOINT overrides the
    /// MagicDNS-derived value — set it to a LAN address (e.g. http://192.168.2.192:8787) when the
    /// mesh isn't reachable and peers connect over the local network.
    /// </summary>
    public string EndpointFor(TailscaleInfo ts) =>
        Environment.GetEnvironmentVariable("AGENTMAIL_ENDPOINT") is { Length: > 0 } e ? e : ts.EndpointFor(Port);

    /// <summary>Generate + persist a token if none is set (unless one is supplied via env). Returns the effective token.</summary>
    public string EnsureToken()
    {
        if (EffectiveToken.Length > 0) return EffectiveToken;
        Token = Convert.ToHexString(System.Security.Cryptography.RandomNumberGenerator.GetBytes(24)).ToLowerInvariant();
        Save();
        return Token;
    }
}
