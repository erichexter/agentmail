using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace AgentMail;

/// <summary>
/// The per-machine relay: `agentmail serve`. Bound to the Tailscale interface only so it is
/// reachable across the tailnet but not on public interfaces. Bearer-token auth guards the
/// mutating endpoints (a second factor on top of Tailscale's device auth + encryption).
/// </summary>
static class Relay
{
    public static async Task<int> Run(Cli cli)
    {
        var config = Config.Load();
        if (cli.Get("port") is { } ps && int.TryParse(ps, out int p)) { config.Port = p; config.Save(); }
        string token = config.EnsureToken();
        var ts = Paths.Tailscale;

        // Bind to the tailnet IP by default; AGENTMAIL_BIND overrides (comma-separated hosts, e.g.
        // "0.0.0.0" to also listen on the LAN when the mesh isn't reachable).
        string[] binds = Environment.GetEnvironmentVariable("AGENTMAIL_BIND") is { Length: > 0 } b
            ? b.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            : new[] { ts.Ip ?? "127.0.0.1" };

        Paths.EnsureRoot();

        var builder = WebApplication.CreateSlimBuilder();
        builder.Logging.SetMinimumLevel(LogLevel.Warning);
        var app = builder.Build();
        foreach (var host in binds) app.Urls.Add($"http://{host}:{config.Port}");

        // --- auth gate for mutating endpoints ---
        bool Authorized(HttpRequest req) =>
            req.Headers.Authorization.ToString() is var h &&
            h.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase) &&
            CryptoEquals(h["Bearer ".Length..].Trim(), token);

        app.MapGet("/health", () => Results.Text("ok"));

        app.MapGet("/agents", () =>
            Results.Json(DirectoryStore.All().ToList(), Paths.Json));

        // Signed key distribution (brief PR1.4). Authenticated to the FETCHING agent's Ed25519 identity via the
        // X-AgentMail-Fetch-Auth header — NOT the shared bearer token — so a leaked token cannot harvest bundles.
        // Serves only agents THIS relay hosts; a non-local target 404s (FLAG-9.3, non-fatal for the sender).
        app.MapGet("/keys", (HttpRequest req) =>
        {
            string? to = req.Query["to"];
            if (string.IsNullOrWhiteSpace(to)) return Results.BadRequest("missing ?to=name@host");
            var (name, host) = AgentRef.Split(to);
            if (host is null || !string.Equals(host, Paths.Host, StringComparison.OrdinalIgnoreCase))
                return Results.NotFound($"keys for '{to}' are served by that agent's home relay, not this one");

            var auth = Crypto.KeysFetchAuth.FromHeader(req.Headers[Crypto.KeysFetchAuth.HeaderName]);
            if (auth is null) return Results.Unauthorized();   // GET /keys requires a signed fetch, not the token
            string? bad = auth.Verify((ulong)DateTimeOffset.UtcNow.ToUnixTimeMilliseconds());
            if (bad is not null) return Results.Json(new { error = bad }, Paths.Json, statusCode: 401);

            var bundle = Crypto.KeysBundle.Get(new Crypto.Address(name, host));
            return bundle is null
                ? Results.NotFound($"no published keys for '{to}'")
                : Results.Json(bundle, Paths.Json);
        });

        app.MapPost("/inbox", async (HttpRequest req) =>
        {
            if (!Authorized(req)) return Results.Unauthorized();
            Envelope? env;
            try { env = await System.Text.Json.JsonSerializer.DeserializeAsync<Envelope>(req.Body, Paths.Json); }
            catch { return Results.BadRequest("invalid envelope"); }
            if (env is null || string.IsNullOrWhiteSpace(env.To)) return Results.BadRequest("missing 'to'");

            var (name, _) = AgentRef.Split(env.To);
            // Only deliver to agents registered on this host (name or alias).
            var target = DirectoryStore.Resolve(name, Paths.Host);
            if (target is null)
                return Results.NotFound($"no agent '{name}' on host '{Paths.Host}'");

            if (string.IsNullOrWhiteSpace(env.Id)) env.Id = Guid.NewGuid().ToString("N")[..12];
            Paths.EnsureAgent(target.Agent);

            // FLAG-32/38 — this endpoint carries LEGACY PLAINTEXT (enc envelopes are *.msg.json). If the local
            // recipient is an e2e agent, an e2e peer sending plaintext must be gated. Convergence-safe: a peer
            // that hasn't yet learned the recipient does e2e is accepted-with-alert, not blackholed. Enforcement
            // is meaningful only now that the #8 directory fix is fleet-wide — a flapping directory here would
            // be the exact FLAG-38 race.
            var decision = CapabilityGate.InboundPlaintext(target, env.From, ulongNow());
            if (decision == Crypto.InboundDecision.Quarantine)
            {
                string qdir = Path.Combine(Paths.AgentDir(target.Agent), "quarantine");
                Directory.CreateDirectory(qdir);
                Io.WriteAtomic(Path.Combine(qdir, env.FileName), env.Serialize());
                Console.Error.WriteLine($"alert: quarantined plaintext {env.Id} for e2e agent {target.Agent} from e2e peer {env.From} (should have sealed)");
                return Results.Accepted($"/quarantine/{env.Id}", new { quarantined = env.Id, reason = "e2e-peer-sent-plaintext" });
            }
            if (decision == Crypto.InboundDecision.DeliverWithAlert)
                Console.Error.WriteLine($"alert: delivered plaintext {env.Id} to e2e agent {target.Agent} from {env.From} during convergence window (peer not yet converged)");

            Io.WriteAtomic(Path.Combine(Paths.Inbox(target.Agent), env.FileName), env.Serialize());
            return Results.Accepted($"/inbox/{env.Id}", new { delivered = env.Id, to = $"{target.Agent}@{Paths.Host}" });
        });

        app.MapPost("/register", async (HttpRequest req) =>
        {
            if (!Authorized(req)) return Results.Unauthorized();
            AgentRecord? rec;
            try { rec = await System.Text.Json.JsonSerializer.DeserializeAsync<AgentRecord>(req.Body, Paths.Json); }
            catch { return Results.BadRequest("invalid record"); }
            if (rec is null || string.IsNullOrWhiteSpace(rec.Agent) || string.IsNullOrWhiteSpace(rec.Host))
                return Results.BadRequest("missing agent/host");
            bool changed = DirectoryStore.Merge(rec);
            return Results.Json(new { changed, key = rec.Key }, Paths.Json);
        });

        // Anti-entropy exchange: merge the sender's batch, return records they lack or are stale on.
        app.MapPost("/gossip", async (HttpRequest req) =>
        {
            if (!Authorized(req)) return Results.Unauthorized();
            List<AgentRecord>? incoming;
            try { incoming = await System.Text.Json.JsonSerializer.DeserializeAsync<List<AgentRecord>>(req.Body, Paths.Json); }
            catch { return Results.BadRequest("invalid batch"); }
            incoming ??= new();

            var byKey = new Dictionary<string, AgentRecord>(StringComparer.OrdinalIgnoreCase);
            foreach (var r in incoming)
            {
                if (string.IsNullOrWhiteSpace(r.Agent) || string.IsNullOrWhiteSpace(r.Host)) continue;
                byKey[r.Key] = r;
                DirectoryStore.Merge(r);
            }
            var reply = new List<AgentRecord>();
            foreach (var mine in DirectoryStore.All())
                if (!byKey.TryGetValue(mine.Key, out var theirs) || DirectoryStore.IsNewer(mine, theirs))
                    reply.Add(mine);
            return Results.Json(reply, Paths.Json);
        });

        // Background convergence: periodic anti-entropy with peers.
        //
        // The prune loop that used to run here is GONE (#8). It deleted any record older than 24h every 60s,
        // which fought gossip: prune removed the file, a peer gossiped it back, prune removed it again — so a
        // live agent's inbound alternated 202/404 on a ~60s cycle with neither end told. It also 404'd agents
        // out of their OWN relay. Records are no longer auto-deleted; staleness is computed at read time
        // (DirectoryStore.IsStale) and gates routing instead. Reaping is explicit: DirectoryStore.PruneExplicit.
        _ = Task.Run(() => GossipLoop(config, token, ts));

        Console.WriteLine($"agentmail relay on {string.Join(", ", binds.Select(h => $"http://{h}:{config.Port}"))}  (host={ts.Host}, tailnet={ts.Tailnet ?? "none"})");
        Console.WriteLine($"  endpoints others use: {string.Join(", ", config.EndpointsFor(ts))}");
        if (!ts.OnTailnet) Console.WriteLine("  warning: not on a tailnet — bound to loopback only.");
        await app.RunAsync();
        return 0;
    }

    private static int EnvInt(string name, int fallback) =>
        int.TryParse(Environment.GetEnvironmentVariable(name), out int v) ? v : fallback;

    private static async Task GossipLoop(Config config, string token, TailscaleInfo ts)
    {
        int interval = EnvInt("AGENTMAIL_GOSSIP_SECONDS", 20);
        while (true)
        {
            try { await Task.Delay(TimeSpan.FromSeconds(interval)); } catch { return; }
            try
            {
                var mine = DirectoryStore.All().ToList();
                foreach (var peer in Gossip.Peers(ts, config))
                {
                    var back = await Transport.Gossip(peer, token, mine);
                    if (back is not null)
                        foreach (var r in back) DirectoryStore.Merge(r);
                }
            }
            catch { /* a peer being down must not kill the loop */ }
        }
    }

    // PruneLoop deleted (#8) — do not reintroduce it. AGENTMAIL_PRUNE_HOURS is likewise gone; the equivalent
    // knob is AGENTMAIL_STALE_HOURS, which controls when a record stops being TRUSTED, not when it is erased.
    // Automatic deletion cannot coexist with LWW gossip: a delete is indistinguishable from "never seen", so
    // any peer holding the record replays it straight back.

    static ulong ulongNow() => (ulong)DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();

    // Constant-time compare so token check doesn't leak length/prefix via timing.
    private static bool CryptoEquals(string a, string b)
    {
        var ba = System.Text.Encoding.UTF8.GetBytes(a);
        var bb = System.Text.Encoding.UTF8.GetBytes(b);
        return System.Security.Cryptography.CryptographicOperations.FixedTimeEquals(ba, bb);
    }
}
