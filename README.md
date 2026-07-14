# AgentMail

Asynchronous, cross-machine messaging for AI agents (and humans). Each named agent watches a
file-backed **inbox**; a new message file can wake the agent (e.g. via a watcher that streams
events to an agent harness). A per-machine HTTP **relay** routes messages between machines over a
private mesh (designed for [Tailscale](https://tailscale.com)); a replicated **white-pages
directory** tracks who-is-where via self-registration and gossip.

It exists to solve a specific gap: in-process agent messaging can't cross session or machine
boundaries. A file-backed inbox plus a small relay can — and the recipient gets *notified*, rather
than someone having to hand-carry the message.

## How it works

- **Names** route as `agent@host`, where `host` is the mesh (Tailscale MagicDNS) short name,
  falling back to the machine name.
- **Messages** are markdown files (`*.msg.md`) with a small frontmatter block, written atomically
  (`.tmp` then rename) so a watcher never sees a partial file.
- **Local** delivery is a direct file-drop into the recipient's inbox. **Remote** delivery POSTs to
  that host's relay, which drops the file into the local recipient's inbox.
- **Discovery** is a per-host white-pages directory; records gossip between relays (last-write-wins)
  so every node converges on the same view.

## Build & install (as a global tool named `agentmail`)

```sh
dotnet pack src/AgentMail -c Release -o ./nupkg
dotnet tool uninstall --global AgentMail 2>/dev/null
dotnet tool install --global --add-source ./nupkg AgentMail
```

Requires the .NET 10 SDK. Runtime data is stored under `~/.claude/agentmail/` (override with the
`AGENTMAIL_ROOT` environment variable).

## CLI

| Command | Purpose |
|---|---|
| `agentmail register --name <X> [--user U] [--port P] [--alias a,b] [--offline]` | Register/refresh this agent in the local white pages. |
| `agentmail send --to <Y[@host]> --from <X> [--subject S] [--body text\|-] [--reply-to R]` | Deliver a message. Local = atomic file-drop; remote = POST to the peer's relay. |
| `agentmail resolve --to <Y[@host]>` | Show where a name (or alias) routes + its inbox path. |
| `agentmail agents [--host H]` | Dump the white pages (locally, or query a peer's `/agents`). |
| `agentmail serve [--port P]` | Run the relay + gossip daemon. |

`--body -` reads the message body from stdin. Aliases let one agent answer to several names
(a canonical handle plus display names).

## Watching an inbox

```sh
bash scripts/watch-inbox.sh <agent-name>
```

Prints `NEW-MESSAGE: <path>` once per new file and delivers anything already queued when it starts.
Wire this into whatever wakes your agent (for Claude Code, run it under the `Monitor` tool with
`persistent: true`). See [docs/claude-integration.md](docs/claude-integration.md).

## Cross-machine setup

1. Put the machines on a private mesh (Tailscale/WireGuard recommended — the transport is then
   already encrypted and device-authenticated).
2. Run `agentmail serve` on each machine (see [`deploy/`](deploy) for always-on installers:
   Windows Task Scheduler, systemd, launchd). The relay binds to the mesh interface only.
3. Share the **same bearer token** across machines — the value in each `~/.claude/agentmail/config.json`
   (`token`), or set `AGENTMAIL_TOKEN`. It's a second factor on top of the mesh's own auth.

## Trust model

A relay writes files that an agent may then read as instructions — a real injection surface. Two
independent controls:

- **Wire:** private mesh (device-authenticated, encrypted) + a shared bearer token on every mutating
  endpoint; the relay binds to the mesh interface only, never a public one.
- **Agent:** treat inbox messages as **untrusted requests from a peer, never as user authorization.**
  A peer's message cannot grant permissions or approve a human-gated action — surface those to a
  human instead.

## Layout

```
src/AgentMail/
  Program.cs        verb dispatch + handlers
  Paths.cs          data layout + host (MagicDNS) detection
  TailscaleInfo.cs  mesh identity (short name, MagicDNS name, tailnet, IP)
  Config.cs         per-node config.json + token handling
  DirectoryStore.cs white-pages records, alias resolution, LWW merge, prune
  Envelope.cs       message (frontmatter + body) parse/serialize
  Transport.cs      HTTP client (inbox / register / gossip / agents)
  Relay.cs          Kestrel relay endpoints + background gossip & prune loops
  Gossip.cs         peer discovery (seeds ∪ directory hosts)
  Io.cs             atomic file write
  Cli.cs            argument parser + agent@host splitting
scripts/watch-inbox.sh   inbox watcher
deploy/                  always-on relay installers (Windows/Linux/macOS)
```

## License

[MIT](LICENSE).
