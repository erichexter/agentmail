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
        // Two failure modes both used to fall through to the machine name — which on Windows is the NetBIOS
        // name, hard-capped at 15 chars (e.g. "eric-aliya-laptop" -> "eric-aliya-lapt"). Because Paths.Host
        // caches the first Detect() for the whole process AND that name is persisted into the gossip directory,
        // a single miss permanently split an agent into a truncated ghost record that 404s inbound mail. Guard
        // BOTH modes before falling back:
        //   (a) the CLI is off-PATH on Windows (under Program Files) -> try known binary locations;
        //   (b) `tailscale status` is transiently slow/wedged -> retry with a real deadline.
        for (int attempt = 0; attempt < 3; attempt++)
            foreach (var exe in BinaryCandidates())
            {
                var info = TryDetect(exe);
                if (info is not null) return info;
            }

        string machine = MachineName();
        Console.Error.WriteLine(
            "agentmail: WARNING - `tailscale status` unavailable; falling back to machine name '" + machine + "'."
            + (machine.Length >= 15
                ? " This may be NetBIOS-truncated (>=15 chars) and can MISROUTE. Set AGENTMAIL_HOST to the full host name."
                : " Set AGENTMAIL_HOST to pin a stable routing name."));
        return new TailscaleInfo { Host = machine };
    }

    /// <summary>One attempt to read this host's identity from `tailscale status --json` at a given binary path.
    /// Returns null on any failure (wrong path, non-zero exit, timeout, or JSON without a Self short name) so the
    /// caller can try the next candidate or retry. Reads stdout asynchronously and kills the child on timeout so
    /// the deadline is real — a blocking ReadToEnd would wait until the child exits anyway, defeating it.</summary>
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

            var stdoutTask = p.StandardOutput.ReadToEndAsync();
            if (!p.WaitForExit(6000)) { try { p.Kill(entireProcessTree: true); } catch { /* best effort */ } return null; }
            if (p.ExitCode != 0) return null;
            string json = stdoutTask.GetAwaiter().GetResult();
            if (json.Length == 0) return null;

            using var doc = JsonDocument.Parse(json);
            var root = doc.RootElement;
            string suffix = root.TryGetProperty("MagicDNSSuffix", out var sfx) ? (sfx.GetString() ?? "") : "";
            if (!root.TryGetProperty("Self", out var self)) return null;

            string full = (self.TryGetProperty("DNSName", out var dns) ? dns.GetString() : null)?.TrimEnd('.') ?? "";
            string shortName = full.Split('.', StringSplitOptions.RemoveEmptyEntries).FirstOrDefault() ?? "";
            if (shortName.Length == 0) return null;

            string? ip = null;
            if (self.TryGetProperty("TailscaleIPs", out var ips) && ips.ValueKind == JsonValueKind.Array)
                foreach (var e in ips.EnumerateArray())
                    if (e.GetString() is { } s && s.Contains('.')) { ip = s; break; } // IPv4

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
            return null;   // this candidate isn't it / transient error — caller tries the next or retries
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
