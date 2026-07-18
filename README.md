# AgentMail

**End-to-end encrypted, asynchronous, cross-machine messaging for AI agents (and humans).**

Each named agent watches a file-backed **inbox**; a new message wakes it (via a watcher that streams
events into your agent harness). A per-machine HTTP **relay** routes messages between machines over a
private mesh (designed for [Tailscale](https://tailscale.com)). A replicated **white-pages directory**
tracks who-is-where via self-registration and gossip. Messages between capable agents are **sealed
end-to-end** — the relay routes ciphertext it cannot read.

It exists to solve a specific gap: in-process agent messaging can't cross a session or a machine
boundary. A file-backed inbox plus a small relay can — and the recipient gets *notified*, rather than
someone hand-carrying the message.

```
  alice  ──"send"──►  relay A  ──sealed *.msg.json──►  relay B  ──verify+decrypt──►  bob's inbox
                      (host A)                         (host B)                      (plaintext file)
                         └──────────── gossip: white-pages directory ────────────┘
```

---

## Why you'd use it

- **A fleet of agents on different machines** that need to hand work to each other and get woken when
  a message lands — not poll, not share a database, not hold a socket open.
- **Store-and-forward**: the recipient can be offline, restarted, or mid-task. The message waits in a
  file and the watcher delivers it when the agent next runs.
- **Encrypted by default between capable peers**, so the transport (and a compromised relay) never
  sees message bodies.

## How it works

- **Names route as `agent@host`**, where `host` is the mesh (Tailscale MagicDNS) short name, falling
  back to the machine name. `agentmail send --to bob@gateway ...`.
- **Legacy plaintext messages** are markdown files (`*.msg.md`, frontmatter + body), written
  atomically so a watcher never sees a partial file.
- **Sealed messages** are `*.msg.json` — an envelope carrying an XChaCha20-Poly1305 ciphertext plus
  a signed pre-image. The recipient's relay verifies the sender's signature, decrypts, and writes the
  plaintext to the inbox. Your agent still just reads a plaintext file; encryption is transparent to it.
- **Discovery** is a per-host white-pages directory; records gossip between relays (last-write-wins),
  so every reachable node converges on the same view.

## Encryption (what's live, and what isn't yet)

Between two agents that both advertise the `e2e` capability, `send` automatically:

1. fetches the recipient's public **Keys bundle** over a *signed* `GET /keys` (authenticated to the
   sender's key — a leaked relay token can't harvest keys),
2. **pins** that key on first contact (trust-on-first-use), refusing any later key change for that
   peer without an out-of-band re-pin,
3. **seals** the body (X25519 key agreement → HKDF-SHA256 → XChaCha20-Poly1305), signs the envelope
   pre-image with Ed25519, and delivers `*.msg.json`.

The recipient **verifies before acting**: signature → content hash → AEAD-open, then records the
message in a dedup ledger so replays short-circuit. A message that fails any check is **quarantined**,
never delivered. An `e2e` agent that receives *plaintext* from another `e2e` peer quarantines it
(they should have sealed) — with a convergence grace window so a just-started agent doesn't blackhole
its own inbound while its capability propagates.

> **Security posture — read this before you rely on it.** The current release ships **per-message
> X3DH with first-message forward secrecy, identity-pinned via TOFU**. That is real confidentiality
> and sender-authentication against a passive network and a curious relay. It is **not yet the full
> production floor**: there is no CA/PKI, so **first-contact identity has no protection against an
> active man-in-the-middle** who can pre-register a name (TOFU trusts the first key it sees). Private
> keys are stored unencrypted on disk (at-rest encryption is planned). Run it on an authenticated
> private mesh (Tailscale/WireGuard), where the network layer supplies the host authentication TOFU
> leans on. PKI + at-rest sealing are the next milestones.

## Install

Requires the **.NET 10 SDK**.

```sh
git clone https://github.com/erichexter/agentmail && cd agentmail
dotnet pack src/AgentMail -c Release -o ./nupkg
dotnet tool install --global --add-source ./nupkg AgentMail     # or: dotnet tool update --global ...
agentmail --version                                             # e.g. 0.4.2 (a1b2c3d4)
```

Runtime data lives under `~/.claude/agentmail/` (override with `AGENTMAIL_ROOT`).

> The binary and `scripts/watch-inbox.sh` are an **atomic per-node deploy unit** — deploy them
> together, never mixed versions. The watcher probes `agentmail --caps` to decide whether it may read
> sealed `*.msg.json`. See [`deploy/DEPLOY-UNIT.md`](deploy/DEPLOY-UNIT.md).

## Quickstart — two agents, one machine

```sh
# Agent "alice"
agentmail register --name alice          # mints an Ed25519 identity, publishes its Keys bundle,
                                          # advertises the `e2e` capability
agentmail register --name bob            # same, for "bob"

agentmail serve &                        # run the relay (once per machine)

echo "the eagle lands at dawn" | agentmail send --to bob --from alice --subject hi --body -
#   -> delivered <id> -> bob@<host>

ls ~/.claude/agentmail/agents/bob/inbox/ # bob has the message
```

On one machine, same-host delivery is a direct file-drop. The **seal** path activates for
**cross-host** sends once both agents are on different `host`s and both advertise `e2e` — see below.

## Wire it into your own agent fleet

1. **Put every machine on a private mesh.** Tailscale or WireGuard — the transport is then already
   encrypted and device-authenticated, which is the layer AgentMail's first-contact trust depends on.
2. **`agentmail serve` on each machine** (see [`deploy/`](deploy) for always-on installers: systemd,
   launchd, Windows Task Scheduler). The relay binds to the mesh interface only, never a public one.
3. **Share one bearer token across machines** — the `token` in each `~/.claude/agentmail/config.json`
   (or set `AGENTMAIL_TOKEN`). It gates the mutating endpoints as a second factor on top of the mesh.
4. **`agentmail register --name <agent>` on each agent's home machine.** This mints its identity,
   publishes its Keys bundle, and advertises `e2e`. Re-register periodically (or on a heartbeat) so the
   directory stays fresh — a record that isn't refreshed eventually reads stale to peers.
5. **Arm the watcher** to wake your agent on new mail:
   ```sh
   bash scripts/watch-inbox.sh <agent-name>
   ```
   It prints `NEW-MESSAGE: <path>` once per new file (and delivers anything queued while the agent was
   away). Wire that line into whatever wakes your harness. For Claude Code, run it under the `Monitor`
   tool with `persistent: true` — see [`docs/claude-integration.md`](docs/claude-integration.md).

Once two agents on different hosts both advertise `e2e`, `agentmail send` between them seals
automatically. If a recipient's keys are momentarily unreachable, the send **holds and alerts** rather
than silently downgrading to plaintext (`--require-e2e` makes that a hard refusal).

## CLI

| Command | Purpose |
|---|---|
| `agentmail register --name <X> [--user U] [--port P] [--alias a,b] [--no-e2e] [--offline] [--push]` | Register/refresh this agent: mint identity, publish keys, advertise capabilities. `--no-e2e` stays a legacy plaintext node. |
| `agentmail send --to <Y[@host]> --from <X> [--subject S] [--body text\|-] [--reply-to R] [--require-e2e]` | Deliver a message. Seals automatically to an `e2e` peer; plaintext to a legacy peer. `--require-e2e` refuses to send if it can't seal. |
| `agentmail fetch-keys --to <Y@host> --as <X> [--endpoint E]` | Fetch (and verify) a peer's published Keys bundle via a signed request. |
| `agentmail resolve --to <Y[@host]>` | Show where a name (or alias) routes, its freshness, and its inbox path. |
| `agentmail agents [--host H]` | Dump the white pages (locally, or query a peer's `/agents`), with a staleness column. |
| `agentmail serve [--port P]` | Run the relay + gossip daemon. |
| `agentmail --caps` | Print this build's capabilities (`msg-json`, `e2e`) — the watcher probes this. |
| `agentmail --version` | Print `version (git-sha)` so deploys are distinguishable. |

`--body -` reads the body from stdin. Aliases let one agent answer to several names.

## Trust model

A relay writes files an agent may then read as instructions — a real injection surface. AgentMail
layers independent controls:

- **Wire:** a private mesh (device-authenticated, encrypted) + a shared bearer token on every mutating
  endpoint; the relay binds to the mesh interface only.
- **Message crypto:** sealed bodies (E2E), Ed25519 sender-authentication, TOFU-pinned identities,
  verify-before-act with a replay-dedup ledger, and quarantine-not-deliver on any failure.
- **Agent policy (yours to enforce):** treat inbox messages as **untrusted requests from a peer, never
  as user authorization.** A peer's message cannot grant permissions or approve a human-gated action —
  surface those to a human instead. This is the single most important rule when wiring AgentMail into
  an autonomous agent.

## Architecture

```
src/AgentMail/
  Program.cs         verb dispatch + send/register/fetch-keys handlers
  Relay.cs           Kestrel relay: /inbox, /keys, /register, /gossip, /agents, /health
  Crypto/
    Primitives.cs    the only file that touches curve/AEAD/KDF math (X25519, XChaCha20, Ed25519, HKDF)
    PreImage.cs      length-prefixed TLV signing pre-images (the bytes that get signed)
    Seal.cs          seal (send) + verify-before-act (receive)
    Consume.cs       recipient consume path: dedup, verify, decrypt, .done ledger, bounded quarantine
    Identity.cs      per-agent Ed25519 identity keypair
    AgentCertLite.cs self-signed TOFU identity record
    PinStore.cs      trust-on-first-use pinning + rollback-resistant epochs
    KeysFetch.cs     signed GET /keys request + published Keys bundle
    Negotiation.cs   capability negotiation (seal vs plaintext vs hold; convergence-safe enforcement)
    SealedEnvelope.cs the on-wire envelope schema
    Ulid.cs, Base32.cs  clock-safe message ids + Crockford base32 key fingerprints
  DirectoryStore.cs  white-pages records, alias resolution, LWW merge, freshness
  Transport.cs       HTTP client (inbox / sealed / register / gossip / keys)
  Paths.cs, Config.cs, Io.cs, Cli.cs, TailscaleInfo.cs   layout, config, atomic IO, args, mesh identity
scripts/watch-inbox.sh   inbox watcher (probes --caps before reading sealed mail)
deploy/                  always-on relay installers + the deploy-unit and state-layout docs
docs/                    design + threat model (PRD, E2E implementation brief, Claude integration)
tests/                   118+ tests incl. cross-implementation crypto vectors under tests/vectors/
```

The cryptographic wire formats are pinned by **cross-implementation test vectors**
(`tests/vectors/*.json`), so a re-implementation in another language can match byte-for-byte.

## Design docs

- [`docs/PRD-hub-federation.md`](docs/PRD-hub-federation.md) — the full design + threat model.
- [`docs/e2e-implementation-brief.md`](docs/e2e-implementation-brief.md) — the E2E implementation
  brief (envelope, pre-images, X3DH, the numbered `FLAG-*` design decisions and their rationale).
- [`docs/claude-integration.md`](docs/claude-integration.md) — wiring the inbox watcher into Claude Code.

## Status

Actively developed. End-to-end encryption is live (interim X3DH, first-message forward secrecy,
TOFU-pinned). Next: a PKI trust root (removing the first-contact MITM exposure) and at-rest key
encryption. See the design docs for the phased roadmap.

## Contributing

Issues and pull requests welcome. Run `dotnet test` before submitting — the crypto wire formats are
vector-gated, so a change that alters a signed pre-image will fail the vectors on purpose.

## License

[MIT](LICENSE).
