using AgentMail;
using AgentMail.Crypto;

return await Program_.Run(args);

static class Program_
{
    public static async Task<int> Run(string[] args)
    {
        var cli = Cli.Parse(args);
        try
        {
            return cli.Verb switch
            {
                "register" => await Register(cli),
                "send" => await Send(cli),
                "resolve" => Resolve(cli),
                "agents" => await Agents(cli),
                "fetch-keys" => await FetchKeys(cli),
                "serve" => await Relay.Run(cli),
                "" or "help" or "--help" => Help(),
                _ => Fail($"unknown verb '{cli.Verb}'. Try `agentmail help`."),
            };
        }
        catch (CliError e)
        {
            return Fail(e.Message);
        }
    }

    static string NowUtc() => DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ");

    // register --name X [--user U] [--port P] [--offline] [--push]
    static async Task<int> Register(Cli cli)
    {
        string name = cli.Require("name");
        var config = Config.Load();
        if (cli.Get("user") is { } u) config.User = u;
        if (cli.Get("port") is { } p && int.TryParse(p, out int port)) config.Port = port;
        config.Save();

        Paths.EnsureRoot();
        Paths.EnsureAgent(name);
        var ts = Paths.Tailscale;

        var existing = DirectoryStore.Get(name, Paths.Host);
        var rec = existing ?? new AgentRecord { Agent = name, Host = Paths.Host };
        rec.User = config.User;
        rec.Tailnet = ts.Tailnet;
        rec.Endpoints = config.EndpointsFor(ts);
        rec.Endpoint = rec.Endpoints.FirstOrDefault() ?? config.EndpointFor(ts);
        if (cli.Get("alias") is { } aliasCsv)
            rec.Aliases = aliasCsv.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
                .Select(s => s.ToLowerInvariant()).Distinct().ToList();
        rec.Status = cli.Has("offline") ? "offline" : "online";
        rec.LastSeen = NowUtc();
        rec.Version = (existing?.Version ?? 0) + 1;   // every change advances the LWW clock
        DirectoryStore.Save(rec);

        // Publish this agent's identity-only Keys bundle (brief PR1.4) so its home relay can serve GET /keys.
        // The bundle is the self-signed AgentCertLite; record_epoch tracks the LWW Version so a re-register
        // advances the published bundle's epoch monotonically, matching the pin store's reject-lower rule.
        if (!cli.Has("offline"))
        {
            var identity = Identity.LoadOrCreate(new Address(name, Paths.Host));
            KeysBundle.Publish(AgentCertLite.Create(identity, recordEpoch: (ulong)rec.Version));
        }

        string aliasNote = rec.Aliases.Count > 0 ? $", aliases=[{string.Join(",", rec.Aliases)}]" : "";
        Console.WriteLine($"{(cli.Has("offline") ? "offline" : "registered")}: {rec.Key}  (user={rec.User}{aliasNote}, v{rec.Version})");
        Console.WriteLine($"  endpoints: {string.Join(", ", rec.Endpoints)}");

        // Optionally announce this record to seed hosts (Phase 2 precursor to full gossip).
        if (cli.Has("push") && config.Seeds.Count > 0)
        {
            string token = config.EnsureToken();
            foreach (var seed in config.Seeds)
            {
                var (ok, detail) = await Transport.Register(seed, token, rec);
                Console.WriteLine($"  push -> {seed}: {(ok ? "ok" : "FAILED " + detail)}");
            }
        }
        return 0;
    }

    // send --to Y --from X --subject S [--body text|-] [--reply-to R]
    static async Task<int> Send(Cli cli)
    {
        string to = cli.Require("to");
        string from = cli.Require("from");
        string subject = cli.Get("subject") ?? "(no subject)";
        string? replyTo = cli.Get("reply-to");

        string body = cli.Get("body") switch
        {
            "-" => await Console.In.ReadToEndAsync(),
            { } text => text,
            null => "",
        };

        var (toName, toHost) = AgentRef.Split(to);
        var env = new Envelope
        {
            Id = Guid.NewGuid().ToString("N")[..12],
            From = from,
            To = to,
            Subject = subject,
            ReplyTo = replyTo,
            Sent = NowUtc(),
            Body = body,
        };

        bool local = toHost is null || toHost == Paths.Host;
        if (!local)
        {
            var config = Config.Load();
            var rec = DirectoryStore.Get(toName, toHost!);
            // Try every advertised endpoint (tailnet + LAN); use the first that answers a health probe.
            var candidates = new List<string>();
            if (rec is not null)
            {
                candidates.AddRange(rec.Endpoints);
                if (candidates.Count == 0 && !string.IsNullOrWhiteSpace(rec.Endpoint)) candidates.Add(rec.Endpoint);
            }
            if (candidates.Count == 0)
            {
                var ts = Paths.Tailscale;
                string authority = ts.Tailnet is { } suffix ? $"{toHost}.{suffix}" : toHost!;
                candidates.Add($"http://{authority}:{config.Port}");
            }
            string? endpoint = null;
            foreach (var ep in candidates)
                if (await Transport.Probe(ep)) { endpoint = ep; break; }
            if (endpoint is null)
                return Fail($"remote delivery to {to}: no reachable endpoint (tried {string.Join(", ", candidates)})");
            var (ok, detail) = await Transport.SendInbox(endpoint, config.EffectiveToken, env);
            if (!ok) return Fail($"remote delivery to {to} via {endpoint} failed: {detail}");

            // keep a local outbox copy when the sender is on this host
            var (fn, fh) = AgentRef.Split(from);
            if (fh is null || fh == Paths.Host) { Paths.EnsureAgent(fn); Io.WriteAtomic(Path.Combine(Paths.Outbox(fn), env.FileName), env.Serialize()); }
            Console.WriteLine($"delivered {env.Id} -> {to} via {endpoint}  ({detail})");
            return 0;
        }

        var target = DirectoryStore.Resolve(toName, Paths.Host);
        string deliverName = target?.Agent ?? toName;
        if (target is null)
            Console.Error.WriteLine($"note: no agent '{toName}' on host '{Paths.Host}' — delivering anyway.");
        else if (!string.Equals(target.Agent, toName, StringComparison.OrdinalIgnoreCase))
            Console.Error.WriteLine($"note: '{toName}' is an alias of '{target.Agent}' — delivering there.");

        Paths.EnsureAgent(deliverName);
        Io.WriteAtomic(Path.Combine(Paths.Inbox(deliverName), env.FileName), env.Serialize());

        // Keep a copy in the sender's outbox when the sender is local.
        var (fromName, fromHost) = AgentRef.Split(from);
        if (fromHost is null || fromHost == Paths.Host)
        {
            Paths.EnsureAgent(fromName);
            Io.WriteAtomic(Path.Combine(Paths.Outbox(fromName), env.FileName), env.Serialize());
        }

        Console.WriteLine($"delivered {env.Id} -> {deliverName}@{Paths.Host}  ({Path.Combine(Paths.Inbox(deliverName), env.FileName)})");
        return 0;
    }

    // fetch-keys --to Y@host --as X   — signed GET /keys, authenticated to X's identity (brief PR1.4)
    static async Task<int> FetchKeys(Cli cli)
    {
        var (toName, toHost) = AgentRef.Split(cli.Require("to"));
        if (toHost is null) return Fail("fetch-keys needs a fully-qualified --to agent@host");
        string asName = cli.Get("as") ?? throw new CliError("fetch-keys needs --as <local-agent> to sign the request");

        var requester = Identity.LoadOrCreate(new Address(asName, Paths.Host));
        var target = new Address(toName, toHost);

        // Resolve the target's relay: an explicit --endpoint wins (operator pointing at a specific relay),
        // otherwise the advertised endpoints, first that answers — same as send.
        var config = Config.Load();
        var rec = DirectoryStore.Get(toName, toHost);
        var candidates = cli.Get("endpoint") is { } ep0
            ? new List<string> { ep0 }
            : rec?.Endpoints.Count > 0 ? new List<string>(rec.Endpoints) : new();
        if (candidates.Count == 0)
        {
            var ts = Paths.Tailscale;
            candidates.Add($"http://{(ts.Tailnet is { } s ? $"{toHost}.{s}" : toHost)}:{config.Port}");
        }

        foreach (var ep in candidates)
        {
            if (!await Transport.Probe(ep)) continue;
            var bundle = await Transport.GetKeys(ep, requester, target);
            if (bundle is null) { Console.Error.WriteLine($"note: {ep} returned no keys for {target.Key} (404 or auth-refused)"); continue; }
            if (!bundle.VerifySelfSignature()) return Fail($"fetched bundle for {target.Key} FAILED self-signature verification");
            Console.WriteLine($"{target.Key}\tkey_id={bundle.KeyId}\tkey_epoch={bundle.KeyEpoch}\trecord_epoch={bundle.RecordEpoch}\tvia {ep}");
            return 0;
        }
        return Fail($"fetch-keys {target.Key}: no reachable endpoint served a bundle (tried {string.Join(", ", candidates)})");
    }

    // resolve Y   (positional) or resolve --to Y
    static int Resolve(Cli cli)
    {
        string target = cli.Get("to") ?? throw new CliError("usage: agentmail resolve --to <agent[@host]>");
        var (name, host) = AgentRef.Split(target);
        var matches = host is null
            ? DirectoryStore.FindByName(name)
            : DirectoryStore.Get(name, host) is { } r ? new List<AgentRecord> { r } : new();

        if (matches.Count == 0) { Console.WriteLine($"no record for '{target}'"); return 1; }
        foreach (var m in matches)
        {
            bool isLocal = DirectoryStore.IsLocal(m);
            bool stale = DirectoryStore.IsStale(m);
            // Report FRESHNESS, not Status. Status is self-asserted at register and never goes false, so
            // printing it alone told operators "online" about agents unroutable for 37h (#8).
            Console.WriteLine($"{m.Key}\t{(stale ? "STALE" : m.Status)}\t{(isLocal ? "local" : "remote")}\t{m.Endpoint}\tinbox={Paths.Inbox(m.Agent)}");
            if (stale)
                Console.Error.WriteLine(
                    $"note: {m.Key} last_seen {m.LastSeen} (older than {DirectoryStore.StaleAfter.TotalHours:0}h) — " +
                    $"its record still says '{m.Status}', but that field is never refreshed. Not trusted for routing.");
        }
        return 0;
    }

    // agents [--host H]   H = a host name (resolved via MagicDNS) or a full http://... endpoint
    static async Task<int> Agents(Cli cli)
    {
        List<AgentRecord>? all;
        if (cli.Get("host") is { } host)
        {
            string endpoint = host.StartsWith("http", StringComparison.OrdinalIgnoreCase)
                ? host
                : $"http://{(Paths.Tailscale.Tailnet is { } s ? $"{host}.{s}" : host)}:{Config.Load().Port}";
            all = await Transport.GetAgents(endpoint);
            if (all is null) return Fail($"could not reach {endpoint}/agents");
        }
        else
        {
            all = DirectoryStore.All().ToList();
        }

        all = all.OrderBy(r => r.Key, StringComparer.OrdinalIgnoreCase).ToList();
        if (all.Count == 0) { Console.WriteLine("(no agents)"); return 0; }
        // AGE is computed from last_seen and is the real signal; STATUS is self-asserted at register and never
        // refreshed, so it stays "online" forever. Showing them side by side makes the divergence visible
        // instead of letting an operator read "online" off a record that has been unroutable for 37h (#8).
        var now = DateTime.UtcNow;
        Console.WriteLine($"{"AGENT@HOST",-30} {"USER",-12} {"STATUS",-8} {"AGE",-9} {"VER",-5} LAST_SEEN");
        foreach (var r in all)
        {
            string age = DirectoryStore.TryParseLastSeen(r, out var seen)
                ? $"{(now - seen).TotalHours,6:0.0}h" + (DirectoryStore.IsStale(r, now) ? "!" : " ")
                : "    ?  ";
            Console.WriteLine($"{r.Key,-30} {r.User,-12} {r.Status,-8} {age,-9} v{r.Version,-4} {r.LastSeen}");
        }
        int stale = all.Count(r => DirectoryStore.IsStale(r, now));
        if (stale > 0)
            Console.Error.WriteLine(
                $"note: {stale} of {all.Count} record(s) are STALE (marked !) — last_seen older than " +
                $"{DirectoryStore.StaleAfter.TotalHours:0}h. They are NOT trusted for routing regardless of STATUS.");
        return 0;
    }

    static int Help()
    {
        Console.WriteLine("""
            agentmail — asynchronous agent messaging

            USAGE
              agentmail register --name <X> [--user <U>] [--port <P>] [--offline]
              agentmail send --to <Y[@host]> --from <X> [--subject <S>] [--body <text>|-] [--reply-to <R>]
              agentmail resolve --to <Y[@host]>
              agentmail agents
              agentmail serve [--port <P>]            (Phase 2)

            NOTES
              Names route as agent@host (host = Tailscale MagicDNS short name).
              --body -  reads the message body from stdin.
              Data lives under ~/.claude/agentmail/.
            """);
        return 0;
    }

    static int Fail(string message)
    {
        Console.Error.WriteLine($"error: {message}");
        return 1;
    }
}
