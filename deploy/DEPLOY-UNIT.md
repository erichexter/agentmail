# The AgentMail binary + watcher are an ATOMIC per-node deploy unit (FLAG-9)

This is a **blocker-grade deploy constraint** for the E2E slices, not a suggestion. Read it before
rolling out any build that introduces or changes the `*.msg.json` E2E format.

## The rule

On any single node, the `agentmail` binary and `scripts/watch-inbox.sh` are deployed **together, as
one unit**. A node is **either** fully on the new build **or** fully legacy — never a split where a
new binary runs against an old watcher, or vice versa.

## Why (the failure it prevents)

E2E envelopes are stored as `*.msg.json`; legacy plaintext stays `*.msg.md`. The two are kept
distinct on disk on purpose:

- A **legacy** binary cannot parse a `*.msg.json` envelope. If a watcher fed it one, the result is
  parse-error / quarantine churn on every enc message.
- So the watcher **probes `agentmail --caps` for the `msg-json` token before it will glob
  `*.msg.json`** (FLAG-9.4). A legacy binary has no `--caps` verb, so the watcher stays
  `*.msg.md`-only and never hands json to a binary that would choke on it.

That probe only works if the binary and the watcher move together. Ship a new watcher against an old
binary and the watcher advertises a capability the binary doesn't have; ship a new binary against an
old watcher and enc messages are never picked up.

> The rev-2 "watcher SHOULD glob both formats unconditionally" guidance was **withdrawn as actively
> harmful** — feeding `*.msg.json` to a binary that can't parse it is exactly the churn above. Do
> **not** reintroduce an unconditional glob-both.

## Cross-node corollary (FLAG-9.2)

A node advertises the `e2e` capability in its directory record only when it reads `*.msg.json`. A
sender **MUST NOT** emit `*.msg.json` to a peer that has not advertised `e2e`; such a peer receives
only legacy `*.msg.md`. `GET /keys` against a pre-E2E relay returns 404, which is **non-fatal** — the
sender falls back to the gossiped record. (Capability negotiation that enforces this lands in the
last PR1 slice.)

## Verify a node after deploy

1. `agentmail --caps` prints `msg-json` (and `e2e`).
2. The watcher log line says it is watching `*.msg.md and *.msg.json` (not "legacy").
3. Unknown-field tolerance holds — a record/envelope with newer fields still parses (FLAG-42), so a
   mixed-version fleet does not split its gossip directory.
