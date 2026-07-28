using System.Diagnostics;
using System.Text.Json;

namespace AgentMail;

/// <summary>
/// This machine's Tailscale identity, from a single `tailscale status --json` call.
/// Falls back to the machine name (and no tailnet) when Tailscale isn't available.
/// </summary>
sealed class TailscaleInfo
{
    public required string Host { get; init; }        // short MagicDNS label, e.g. "laptop"
    public string? MagicDnsName { get; init; }        // full, trailing dot trimmed, e.g. "laptop.tailnet-abc.ts.net"
    public string? Tailnet { get; init; }             // MagicDNS suffix, e.g. "tailnet-abc.ts.net"
    public string? Ip { get; init; }                  // 100.x IPv4
    public bool OnTailnet => Ip is not null;

    /// <summary>Relay endpoint others use to reach this host: http over the encrypted tailnet.</summary>
    public string EndpointFor(int port)
    {
        string authority = MagicDnsName ?? Ip ?? Host;
        return $"http://{authority}:{port}";
    }

    public static TailscaleInfo Detect()
    {
        // The Tailscale MagicDNS short name is the only non-truncating source of this host's routing identity.
        // On Windows, Environment.MachineName is the NetBIOS name — hard-capped at 15 chars (e.g.
        // "eric-aliya-laptop" -> "eric-aliya-lapt"). Paths.Host caches the first Detect() for the whole process
        // AND that name gets persisted into the gossip directory, so a single slow/failed `tailscale status`
        // used to permanently split an agent into a truncated ghost record. Retry with a generous timeout
        // before ever falling back to the machine name.
        for (int attempt = 0; attempt < 3; attempt++)
            if (TryQueryTailscale(out var info))
                return info;

        string machine = Environment.MachineName.ToLowerInvariant();
        Console.Error.WriteLine(
            "agentmail: WARNING - `tailscale status` unavailable; falling back to machine name '" + machine + "'."
            + (machine.Length >= 15
                ? " This is likely NetBIOS-truncated (>=15 chars) and will MISROUTE. Set AGENTMAIL_HOST to the full host name."
                : " Set AGENTMAIL_HOST to pin a stable routing name."));
        return new TailscaleInfo { Host = machine };
    }

    /// <summary>One attempt to read this host's identity from `tailscale status --json`. Returns false on any
    /// failure (not installed, non-zero exit, timeout, or JSON without a Self short name) so the caller can
    /// retry or fall back. Kills the child on timeout so a wedged CLI can't hang startup, and reads stdout
    /// asynchronously so the deadline is real (a blocking ReadToEnd would wait until the child exits anyway).</summary>
    static bool TryQueryTailscale(out TailscaleInfo info)
    {
        info = null!;
        try
        {
            var psi = new ProcessStartInfo("tailscale", "status --json")
            {
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true,
            };
            using var p = Process.Start(psi);
            if (p is null) return false;

            var stdoutTask = p.StandardOutput.ReadToEndAsync();
            if (!p.WaitForExit(8000)) { try { p.Kill(entireProcessTree: true); } catch { /* best effort */ } return false; }
            if (p.ExitCode != 0) return false;
            string json = stdoutTask.GetAwaiter().GetResult();
            if (json.Length == 0) return false;

            using var doc = JsonDocument.Parse(json);
            var root = doc.RootElement;
            string suffix = root.TryGetProperty("MagicDNSSuffix", out var sfx) ? (sfx.GetString() ?? "") : "";
            if (!root.TryGetProperty("Self", out var self)) return false;

            string full = (self.TryGetProperty("DNSName", out var dns) ? dns.GetString() : null)?.TrimEnd('.') ?? "";
            string shortName = full.Split('.', StringSplitOptions.RemoveEmptyEntries).FirstOrDefault() ?? "";
            if (shortName.Length == 0) return false;

            string? ip = null;
            if (self.TryGetProperty("TailscaleIPs", out var ips) && ips.ValueKind == JsonValueKind.Array)
                foreach (var e in ips.EnumerateArray())
                    if (e.GetString() is { } s && s.Contains('.')) { ip = s; break; } // IPv4

            info = new TailscaleInfo
            {
                Host = shortName.ToLowerInvariant(),
                MagicDnsName = full.Length > 0 ? full : null,
                Tailnet = suffix.Length > 0 ? suffix : null,
                Ip = ip,
            };
            return true;
        }
        catch
        {
            // tailscale not installed / not on PATH / transient error — caller retries or falls back.
            return false;
        }
    }
}
