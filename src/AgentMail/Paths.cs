using System.Diagnostics;
using System.Text.Json;

namespace AgentMail;

/// <summary>
/// Resolves the on-disk layout under ~/.claude/agentmail and the identity of this host.
/// </summary>
static class Paths
{
    public static string Root { get; } = Environment.GetEnvironmentVariable("AGENTMAIL_ROOT")
        ?? Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
            ".claude", "agentmail");

    public static string DirectoryDir => Path.Combine(Root, "directory");
    public static string AgentsDir => Path.Combine(Root, "agents");
    public static string ConfigPath => Path.Combine(Root, "config.json");

    public static string AgentDir(string name) => Path.Combine(AgentsDir, name);
    public static string Inbox(string name) => Path.Combine(AgentDir(name), "inbox");
    public static string Processed(string name) => Path.Combine(AgentDir(name), "processed");
    public static string Outbox(string name) => Path.Combine(AgentDir(name), "outbox");

    public static string RecordPath(string agent, string host) =>
        Path.Combine(DirectoryDir, $"{agent}@{host}.json");

    /// <summary>Create the base layout (idempotent).</summary>
    public static void EnsureRoot()
    {
        Directory.CreateDirectory(DirectoryDir);
        Directory.CreateDirectory(AgentsDir);
    }

    /// <summary>Create an agent's inbox/processed/outbox folders (idempotent).</summary>
    public static void EnsureAgent(string name)
    {
        Directory.CreateDirectory(Inbox(name));
        Directory.CreateDirectory(Processed(name));
        Directory.CreateDirectory(Outbox(name));
    }

    private static TailscaleInfo? _ts;

    /// <summary>This machine's Tailscale identity (or a machine-name fallback). Cached.</summary>
    public static TailscaleInfo Tailscale => _ts ??= TailscaleInfo.Detect();

    /// <summary>
    /// Routing name: the Tailscale MagicDNS short name when available, else the machine name.
    /// Stable per device across tailnets.
    /// </summary>
    public static string Host => Tailscale.Host;

    public static readonly JsonSerializerOptions Json = new()
    {
        WriteIndented = true,
        PropertyNamingPolicy = JsonNamingPolicy.SnakeCaseLower,

        // FLAG-42: the wire deserializer MUST ignore unknown members, on legacy AND new nodes. PR1 adds fields
        // to AgentRecord (record_epoch, key_epoch, Keys) and PR2 adds more; a strict parser
        // (UnmappedMemberHandling.Disallow or a schema gate) would REJECT a newer record and split the gossip
        // directory. Skip is the System.Text.Json default, but it is stated EXPLICITLY here so a later change to
        // Disallow is a visible, reviewable edit rather than a one-word regression. A cross-version parse test
        // (Storage/FLAG-42 tests) pins it. Never gate wire JSON on a strict schema.
        UnmappedMemberHandling = System.Text.Json.Serialization.JsonUnmappedMemberHandling.Skip,
    };
}
