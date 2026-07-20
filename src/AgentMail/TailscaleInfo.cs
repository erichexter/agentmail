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
        // Try each candidate binary path until one yields a status. On Windows the CLI is NOT on PATH by
        // default (it lives under Program Files), so a bare "tailscale" invocation fails there — and the
        // MachineName fallback returns the 15-char-truncated NetBIOS name (e.g. "eric-aliya-lapt"), which
        // then MISMATCHES the full MagicDNS name the directory advertises ("eric-aliya-laptop") and 404s all
        // inbound mail. Finding the real binary keeps the relay's self-host equal to its published name.
        foreach (var exe in BinaryCandidates())
        {
            var info = TryDetect(exe);
            if (info is not null) return info;
        }
        return new TailscaleInfo { Host = MachineName() };
    }

    private static TailscaleInfo? TryDetect(string exe)
    {
        try
        {
            var psi = new ProcessStartInfo(exe, "status --json")
            {
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true,
            };
            using var p = Process.Start(psi);
            if (p is null) return null;

            string json = p.StandardOutput.ReadToEnd();
            p.WaitForExit(3000);
            if (!p.HasExited || p.ExitCode != 0 || json.Length == 0) return null;

            using var doc = JsonDocument.Parse(json);
            var root = doc.RootElement;
            string suffix = root.TryGetProperty("MagicDNSSuffix", out var sfx) ? (sfx.GetString() ?? "") : "";
            if (!root.TryGetProperty("Self", out var self)) return null;

            string full = (self.TryGetProperty("DNSName", out var dns) ? dns.GetString() : null)?.TrimEnd('.') ?? "";
            string shortName = full.Split('.', StringSplitOptions.RemoveEmptyEntries).FirstOrDefault() ?? "";
            string? ip = null;
            if (self.TryGetProperty("TailscaleIPs", out var ips) && ips.ValueKind == JsonValueKind.Array)
                foreach (var e in ips.EnumerateArray())
                    if (e.GetString() is { } s && s.Contains('.')) { ip = s; break; } // IPv4

            if (shortName.Length == 0) return null;
            return new TailscaleInfo
            {
                Host = shortName.ToLowerInvariant(),
                MagicDnsName = full.Length > 0 ? full : null,
                Tailnet = suffix.Length > 0 ? suffix : null,
                Ip = ip,
            };
        }
        catch
        {
            return null;   // this candidate isn't it — try the next
        }
    }

    /// <summary>Ordered `tailscale` binary locations to try: PATH first, then per-OS standard install paths.</summary>
    internal static IEnumerable<string> BinaryCandidates()
    {
        yield return "tailscale";   // on PATH (Linux/macOS, and Windows if the user added it)

        if (OperatingSystem.IsWindows())
        {
            foreach (var v in new[] { "ProgramFiles", "ProgramW6432", "ProgramFiles(x86)" })
                if (Environment.GetEnvironmentVariable(v) is { Length: > 0 } dir)
                    yield return Path.Combine(dir, "Tailscale", "tailscale.exe");
        }
        else if (OperatingSystem.IsMacOS())
        {
            yield return "/Applications/Tailscale.app/Contents/MacOS/Tailscale";
            yield return "/usr/local/bin/tailscale";
        }
        else
        {
            yield return "/usr/bin/tailscale";
            yield return "/usr/local/bin/tailscale";
        }
    }

    /// <summary>Best available machine name for the fallback. On Windows the DNS hostname avoids the 15-char
    /// NetBIOS truncation that <see cref="Environment.MachineName"/> can carry.</summary>
    private static string MachineName()
    {
        string name = Environment.MachineName;
        if (OperatingSystem.IsWindows())
        {
            try { var dns = System.Net.Dns.GetHostName(); if (dns.Length > name.Length) name = dns; } catch { }
        }
        return name.ToLowerInvariant();
    }
}
