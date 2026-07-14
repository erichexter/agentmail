using AgentMail;

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
        rec.Endpoint = ts.EndpointFor(config.Port);
        if (cli.Get("alias") is { } aliasCsv)
            rec.Aliases = aliasCsv.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
                .Select(s => s.ToLowerInvariant()).Distinct().ToList();
        rec.Status = cli.Has("offline") ? "offline" : "online";
        rec.LastSeen = NowUtc();
        rec.Version = (existing?.Version ?? 0) + 1;   // every change advances the LWW clock
        DirectoryStore.Save(rec);

        string aliasNote = rec.Aliases.Count > 0 ? $", aliases=[{string.Join(",", rec.Aliases)}]" : "";
        Console.WriteLine($"{(cli.Has("offline") ? "offline" : "registered")}: {rec.Key}  (user={rec.User}, tailnet={rec.Tailnet ?? "none"}{aliasNote}, v{rec.Version})");

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
            // Prefer the endpoint from a known directory record; else construct from MagicDNS.
            string? endpoint = DirectoryStore.Get(toName, toHost!)?.Endpoint;
            if (endpoint is null)
            {
                var ts = Paths.Tailscale;
                string authority = ts.Tailnet is { } suffix ? $"{toHost}.{suffix}" : toHost!;
                endpoint = $"http://{authority}:{config.Port}";
            }
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
            bool isLocal = m.Host == Paths.Host;
            Console.WriteLine($"{m.Key}\t{m.Status}\t{(isLocal ? "local" : "remote")}\t{m.Endpoint}\tinbox={Paths.Inbox(m.Agent)}");
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
        Console.WriteLine($"{"AGENT@HOST",-30} {"USER",-12} {"STATUS",-8} {"VER",-5} LAST_SEEN");
        foreach (var r in all)
            Console.WriteLine($"{r.Key,-30} {r.User,-12} {r.Status,-8} v{r.Version,-4} {r.LastSeen}");
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
