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
            if (p is not null)
            {
                string json = p.StandardOutput.ReadToEnd();
                p.WaitForExit(3000);
                if (p.HasExited && p.ExitCode == 0 && json.Length > 0)
                {
                    using var doc = JsonDocument.Parse(json);
                    var root = doc.RootElement;
                    string suffix = root.TryGetProperty("MagicDNSSuffix", out var sfx)
                        ? (sfx.GetString() ?? "") : "";

                    if (root.TryGetProperty("Self", out var self))
                    {
                        string full = (self.TryGetProperty("DNSName", out var dns) ? dns.GetString() : null)
                            ?.TrimEnd('.') ?? "";
                        string shortName = full.Split('.', StringSplitOptions.RemoveEmptyEntries)
                            .FirstOrDefault() ?? "";
                        string? ip = null;
                        if (self.TryGetProperty("TailscaleIPs", out var ips) && ips.ValueKind == JsonValueKind.Array)
                            foreach (var e in ips.EnumerateArray())
                                if (e.GetString() is { } s && s.Contains('.')) { ip = s; break; } // IPv4

                        if (shortName.Length > 0)
                            return new TailscaleInfo
                            {
                                Host = shortName.ToLowerInvariant(),
                                MagicDnsName = full.Length > 0 ? full : null,
                                Tailnet = suffix.Length > 0 ? suffix : null,
                                Ip = ip,
                            };
                    }
                }
            }
        }
        catch
        {
            // Tailscale not installed / not on PATH — fall through.
        }
        return new TailscaleInfo { Host = Environment.MachineName.ToLowerInvariant() };
    }
}
