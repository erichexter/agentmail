# AgentMail Hub-Federation — PRD v1 (rev. 6, FINAL)

Status: FINAL v1-rev6 · Owner: Wolf (drafting) → Hex (approve) · Author of system: Harrell/eric-main
Date: 2026-07-16 · Supersedes: v1-rev5 (round-4 resolution) and the point-to-point direct-delivery design (current production)

---

## Executive Summary

AgentMail is the fleet's async agent-to-agent messaging system, in production today as point-to-point direct delivery: a sender's hub dials the recipient's hub and `POST`s `/inbox`. The directory gossips everywhere, so agents are *discoverable* fleet-wide — but *delivery* silently fails whenever the sender cannot open an inbound connection to the target (cross-tailnet, NAT, corp firewall, ESET). Today we hand-relay through a bridging laptop. This PRD replaces that with **federated store-and-forward hubs** joined by a **persistent-outbound-socket backbone mesh**: constrained hubs dial out to always-on backbones and receive over the same socket, so reachability no longer depends on who can accept a connection.

The design commits to: durable boot-started hub daemons that survive agent restarts; disk-backed queues with durable-before-ack, retry, TTL/hop and `msg_id` dedup; a **binary (Protobuf) federation wire with a JSON agent boundary**; **mandatory transport encryption plus default-on, forward-secret end-to-end payload encryption (X3DH)** built only from vetted primitives; **root-anchored agent identity** via an offline-root → online-intermediate → `AgentCert` PKI so a compromised home hub can neither forge identity nor silently downgrade to plaintext; and **freshness-based health** with corroborated, forward-ack-driven circuit-breaking of misbehaving backbones. All signed objects — the envelope (in two pre-image variants) and every PKI/directory record — use explicit length-prefixed TLV pre-images with no canonicalization and no Unicode normalization, gated by cross-language byte-for-byte test vectors. The signing rule is treated as the single most likely place an exploitable, cross-language bug ships, so bespoke surface is minimized and conformance is proven by vectors, not inspection.

The document is honest about two operational realities. First, the marquee property — **per-agent unforgeability** — is *inoperative intra-box* on today's single-user Git-Bash hosts where any agent can read a sibling's private key; the near-term remediation is **container-per-agent**, and until then boxes run a flagged `same_user_degraded` posture. Second, forward secrecy trades against the at-least-once delivery window: superseded private keys are reference-counted and destroyed early, but a bounded at-rest residual is disclosed rather than claimed away. Migration is zero-downtime and phased (contracts → local daemon → federation+transport → E2E+receipts → optimization → deprecate direct-only), with direct delivery and federation coexisting throughout. Nine open decisions remain for Hex, led by standing up a second backbone host and confirming the container-per-agent isolation rollout.

---

Revision note: rev6 resolves the round-5 hostile review. The five P0s the reviewer flagged are the load-bearing fixes:

- **P0-A (uncomputable seal — circular `content_hash`⇄AEAD-AD).** The AEAD associated data is now a **content-hash-free pre-image variant** `aead_ad_v1(env)` (identical to the signing pre-image *minus* `content_hash`), while the Ed25519 `agent_sig` still covers the **full** `sign_input_v1(env)` including `content_hash = sha256(ciphertext)`. This breaks the cycle: seal with `ad=aead_ad` (no hash needed) → compute `content_hash` over the ciphertext → sign the full pre-image. Both variants are pinned in the Phase-0 vectors (§5.1/§5.3/App C).
- **P0-B (trust-root record signatures were unspecified).** Every PKI/directory signature — `HubCert.root_sig`/issuer sig, `IssuerCert.root_sig`, `AgentCert.issuer_sig`, `Keys.hub_sig`, `spk_sig`, `Crl.root_sig`, `HubRecord.sig`, `LinkState.sig` — now has an explicit length-prefixed TLV `sign_input_<type>` pre-image with fixed field order and presence rules, added to the Phase-0 cross-language vector suite. Record protobuf bytes are **never** signed (§6.4/§5.6/App C).
- **P0-C (loop bound was re-grantable).** `ttl_hops` is no longer the sole bound. Two attacker-independent bounds are added: (1) a **hard cap on `len(route_trace)` ≤ `ROUTE_TRACE_CAP`** enforced regardless of any `gen` claim, and (2) a **per-`msg_id` monotonic `ttl_hops` floor** persisted with the dedup entry (`ttl_hops := min(received, previously_seen)`) so a relay can never raise it back to the cap. Progress-proof revisits remain, but bounded by `ROUTE_TRACE_CAP` (§3.5/§5.5/§8.4).
- **P0-D (superseded gate was backdatable).** Acceptance of a `superseded` (routine-rotation) key now requires a **hub-countersigned ingress attestation** (`relay_attest{msg_id, ingress_time, hub_sig}`) whose `ingress_time` — a hub-key-controlled timestamp the leaked agent key cannot forge — is `< superseded_at`, **and** the accepted grace is shrunk to `SUPERSESSION_GRACE` (default 1 h) `≪ MAX_LIFETIME`. Any suspected leak MUST use the `revoked` path (hard-reject any `created_at`). Backdating `created_at` no longer helps (§6.4/§6.6).
- **P0-E (home hub was the sole voucher for its agents' identity).** Agent identity `ident_pub` is now **root-anchored via an `AgentCert`** issued by a root-signed **intermediate issuing CA**, not vouched by the home hub. `spk_sig` is signed by the agent's **own ident key** (not the hub). A compromised home hub therefore cannot substitute an agent's identity or prekeys, and cannot silently downgrade to plaintext by withholding the `Keys` record (a valid `AgentCert` makes E2E effectively mandatory for that recipient — missing prekeys ⇒ hold+alert, not plaintext). The residual (intermediate-CA compromise) is disclosed (§6.4/§6.5/T4/T-HUBROOT).

P1/P2/Minor round-5 fixes: **P1-F** circuit-breaker now demotes only on **multi-destination-corroborated loss of a signed forward-path ack** (distinct from the E2E receipt) plus active probes, not on a single confounded end-to-end signal (§3.5). **P1-G** lost-`ident_priv` recovery via root/operator override — CRL-revoke old + intermediate issues a fresh `AgentCert`, possession-proof waived on the operator-authenticated path (§6.4/§7.3). **P1-H** the same-user-degraded reality is promoted to the **top-line operational risk** with **per-agent containers** named as the concrete near-term remediation (§0.1/§2.1/§7.4/OD-5). **P1-I** `consumed` receipts now route over the **multi-backbone mesh with alternate-path failover** and their loss is attributed **separately** from forward-path health (§8.2/§8.6). **P2-J** "NTP-confirmed" now means **authenticated time (NTS/roughtime)**; unauthenticated NTP never flips the trusted bit, and clock-uncertainty holds shed **`bulk`-first** (§5.4/§8.7). **P2-K** identity fields `name`/`host`/`session` and all signed key-ids are restricted to an **LDH/ASCII subset** and **NFC is removed from the signing path entirely**; any non-conforming input is **rejected at ingress**, never silently normalized (§5.1/§7.1/App C). **P2-L** `ConsumedQuery` is authenticated over the mutually-authenticated s2s session and answered **only** for `msg_id`s whose stored `from`'s home-hub equals the querying hub (§8.2). **P2-M** an `ordered` bounce **fails the whole stream and surfaces to the agent** — no silent out-of-order retransmit (§8.6). **P2-N** an **online root-constrained intermediate issuing CA** removes monthly offline-root ceremonies (offline root signs only the intermediate) (§6.4). **P2-O** new signed security fields roll out **advertise-then-enforce** (verify-capability fleet-wide before any sender may set a floor) (§4.6/§5.1/§11). **P2-P** inbox readers MUST open with `FILE_SHARE_DELETE`; sharing-violation retries are **bounded + escalate/alert**; a denied ESET exclusion **degrades + alerts**, never silent-infinite-retry (§4.5). **Minors**: agent-side verification (sig/hash/epoch) failures quarantine+bounce **immediately** (no N=3) (§8.9); backbones enforce a **global reassembly-byte cap** in addition to per-sender (§4.7/§8.7); `enc.nonce` and `enc.eph_pub` are **now signed** so relay tampering is an attributable structural signature failure rather than a recipient-side decrypt-poison (§5.1/App C); `spk_sig` now binds `ident_pub` + `key_epoch` (§6.5/App C).

Carried forward from rev5 (unchanged in intent): vetted primitives only (§6.0); length-prefixed TLV signing pre-image (§5.1); X3DH prekey sealing without a ratchet (§6.5); `#session` is a hub-assigned delivery discriminator (§7.1); per-record `record_epoch` rollback defense scoped to `name@host` (§6.6); OOB root-pin bootstrap (§6.4/P0-5-rev5); loop/priority/receipt/retention resolutions (§3.5/§8).

---

## 0. Reader's guide to the crypto posture (start here)

This system is a **personal fleet at human-conversation rates** (N1: dozens of msgs/min, a handful of hosts, one operator). The round-4 META finding remains load-bearing: *the composition of many crypto primitives is itself the primary vulnerability, and a byte-for-byte-identical-across-languages signing rule is where an exploitable bug is most likely to ship.* rev6's posture:

1. **We never hand-implement cryptographic math.** All primitives come from a single vetted library per language (libsodium / a libsodium binding, plus one vetted Noise-IK implementation). No bespoke curve arithmetic, AEAD, HKDF, or XEdDSA code (§6.0).
2. **We shrink and de-risk the bespoke surface — the signing pre-images.** Signatures are computed over **explicit length-prefixed TLV concatenations** with fixed field order and explicit presence bytes. There is no map to sort, no canonicalization mode to mismatch, no float rule, and — new in rev6 — **no NFC in the signing path** (identity/key fields are ASCII-LDH). rev6 also removes the last unspecified bespoke surfaces: **every PKI record now has an explicit TLV pre-image** (§5.6/§6.4), and the **AEAD-AD/`content_hash` cycle is broken** (§5.3).
3. **We adopt off-the-shelf where it fits and justify where it doesn't** (§6.0): vetted Noise-IK for transport; libsodium `crypto_box`-family primitives for AEAD/DH; libsignal's *prekey* concept for async FS. We reject libsignal's full session/double-ratchet for one-shot async store-and-forward (§6.5).
4. **The conformance gate is cross-language test vectors**, not inspection. No hub ships until it reproduces the Phase-0 vector suite byte-for-byte — now including **all record pre-images and both the signing and AEAD-AD envelope variants** (§5.1/§5.6/§11).

### 0.1 Top-line operational risk (read this before anything else) — P1-H

The design's marquee security property — **per-agent unforgeability (G6/T3)** — is **inoperative on every box in the fleet as it exists today.** Every current host is a **single-user Git-Bash box running multiple agents in one OS trust domain**, where any local agent can read any other's `ident_priv` and pass its possession-proof. On those boxes, per-agent keys buy **cross-box** unforgeability only; **intra-box, an agent can spoof a co-resident sibling.** This is not a corner case — it is the whole fleet.

rev6 treats this as the **#1 operational risk, not a Phase-1 footnote.** The concrete, near-term remediation is **one container per agent** (a per-agent Linux container / Windows container with its own filesystem view and key store), which is materially **cheaper and more portable than provisioning per-user Windows local accounts + per-user Claude auth-env** — the mechanism rev5 leaned on. Until agents are isolated (container-per-agent preferred; per-OS-user acceptable), boxes run `same_user_degraded`, **flagged/logged/alerted at startup** (§7.4), and G6/T3/T-REG are explicitly **not met intra-box**. This is a disclosed status, not a silent default, and it is the first thing an operator must decide (OD-5).

---

## 1. Problem Statement

AgentMail is an async agent-messaging system in production today. Each machine runs a relay ("hub") bound to its Tailscale IP. Agents register into a gossiped directory. To deliver a message, the **sender's hub opens a direct connection to the target agent's hub** and `POST`s `/inbox` (HTTP, `SnakeCaseLower` JSON, bearer token layered on Tailscale). Endpoints today: `/health /agents /inbox /register /gossip`. Storage is file-based inboxes at `~/.claude/agentmail/agents/<name>/inbox/*.msg.md`.

**The directory propagates fine; delivery does not.** Gossip reaches every peer through any shared neighbor, so agents are *discoverable* everywhere. But direct delivery requires the sender to have *direct IP reachability* to the target hub, and that assumption breaks in production:

- **Cross-tailnet.** Sender on `tailc17728` cannot reach a target on `tailb3cb9`. Observed: gateway could not reach `secondbrain@second-brain` (Azure `10.80.0.4`, tailnet `tailb3cb9`). We hand-relayed through `garrison` (a bridging node on the laptop) to get the message across.
- **NAT / corp firewall / ESET.** A constrained host cannot accept inbound connections; the sender's `POST` never lands.

Three additional failure modes proven in production:

- **Silent directory aging.** The `wolf` agent record aged out after 24h because it did not periodically re-register. The relay was up, but the agent was invisible — *relay-up ≠ agent-present*.
- **Port-open ≠ healthy.** A month-old wedged node held its port; a restart hit `EADDRINUSE`. Liveness was inferred from a bound socket, which lied.
- **Name collision.** Two agents both claimed `vincent@desktop-bqgtlc4` on one box; delivery `404`'d because the address was ambiguous. (This is a **name-authority / first-writer-wins** problem, not a per-session-key problem — resolved in §6.4/§7.3.)

This PRD specifies the agreed target design: **federated store-and-forward hubs** with a **persistent-outbound-socket backbone**, a **binary hub-to-hub wire / JSON agent boundary**, **mandatory transport encryption + default-on forward-secret end-to-end payload encryption built from vetted primitives**, and **freshness-based health** — while keeping today's direct delivery working through a phased cutover.

---

## 2. Goals / Non-Goals

### 2.1 Goals

- G1. Deliver reliably between **any** two agents in the fleet regardless of tailnet, NAT, or firewall, without hand-relaying.
- G2. Hubs are **durable daemons**, started at boot, that **survive agent restarts**. Agents are clients of their local hub and never bind a shared listening port themselves.
- G3. **Reachability by outbound dial**: constrained nodes initiate a long-lived socket to an always-on backbone; replies return over that socket.
- G4. **Store-and-forward reliability**: disk-backed queues, retry+backoff, TTL/hop-count and message-id dedup, at-least-once with idempotent consume, **durable-before-ack** semantics.
- G5. **Token-efficient receive**: pointer-not-payload notification; the agent reads the full body only when it decides to act.
- G6. **Stable identity** that eliminates the `vincent` collision (via name-authority first-writer-wins, §6.4); per-agent auth so a shared local send-port cannot spoof a `from`. **Per-agent unforgeability requires per-agent isolation (container-per-agent preferred, per-OS-user acceptable, §7.4). It is HONESTLY CONCEDED that on the fleet's current single-user Git-Bash boxes G6 holds only cross-box, not intra-box, until isolation lands (§0.1/§7.4, P1-H).** The design does not *claim* intra-box unforgeability it cannot deliver.
- G7. **Forward-secret end-to-end payload encryption, default-on**, keyed only from **root-anchored** agent identity keys (`AgentCert`, §6.4) plus hub-published prekeys, that fails closed when no authenticated recipient key exists, gives **first-message forward secrecy**, and whose FS-key deletion is reconciled against the at-least-once delivery window so in-flight mail never becomes permanently undecryptable (§6.5/§6.8). **The FS/retention tension is disclosed honestly (§6.5): retention of superseded privates *does* lengthen the at-rest window; we reference-count to delete early and bound the residual, we do not claim it away.**
- G8. **Freshness-based health**: watchdogs, periodic self-re-register, dead-man's-switch alerts, **and corroborated, forward-ack-driven circuit-breaking of misbehaving backbones (§3.5, P1-F)**.
- G9. **Zero-downtime migration**: direct delivery and federation coexist; per-leg cutover; a **frozen routing envelope** + integer protocol version + capability negotiation (incl. `max_sig_projection_version`) for mixed-version, mixed-language fleets; **new signed security fields roll out advertise-then-enforce (§4.6/P2-O)**.
- G10. **Windows is first-class** (Git-Bash). The agent boundary uses a **squat-resistant, DACL'd named pipe (Windows) / permission-scoped Unix-domain socket (POSIX)**. Durable storage uses Windows-correct atomic-replace + write-through + explicit flush + **`FILE_SHARE_DELETE` reader semantics** (§4.5).

### 2.2 Non-Goals

- N1. Web-scale throughput. Target is a **personal fleet at human-conversation rates**. No sharding, no Kafka, no consensus. This scale is why we minimize bespoke surface (§0/§6.0).
- N2. Global ordering / exactly-once. We provide **either** strict per-`(from,to)` end-to-end FIFO (stop-and-wait gated on a **reliably-delivered, mesh-routed** terminal `consumed` receipt, §8.6) **or** explicitly-unordered delivery, per-priority; exactly-once is out of scope.
- N3. A general pub/sub or topic bus; broadcast/multicast groups are out of scope for v1 (§7.5). Fan-out to live instances of **one** address is supported (§7.2); cross-agent fan-out is client-side.
- N4. Replacing Tailscale. Tailscale remains the underlay and a *transport* trust anchor where present — but is **not** the application identity root (that is the PKI, §6.4).
- N5. Multi-tenant isolation / untrusted third parties. This is one operator's fleet. **However**, the threat model (§10) assumes **any backbone can be compromised**, and — new in rev6 — explicitly models **home-hub compromise** (T-HUBROOT) and **intermediate-CA compromise** as disclosed residuals. "One operator's fleet" is **not** used to excuse same-user co-resident impersonation as a *silent* default — it is either isolated (§7.4) or an explicitly flagged degraded posture (§0.1).

---

## 3. Architecture

### 3.1 Roles

- **Agent (client).** An LLM session. Talks *only* to its local hub. **Send** = write a JSON line to the local hub's **agent-boundary IPC endpoint** (a squat-resistant DACL'd named pipe on Windows / a `0600` Unix-domain socket on POSIX — §7.6). **Receive** = run its own `Monitor` watching *only* its own inbox directory, opening inbox files with **`FILE_SHARE_DELETE`/shared-read** so the hub can atomically replace under it (§4.5/P2-P). Never binds the shared port; never reaches the network directly. **Multiple concurrent sessions of one logical agent (`name@host`) share one identity keypair (§7.1); `#session` distinguishes delivery targets/liveness, not crypto principals.**
- **Local hub (daemon).** One per machine. Durable OS service (systemd unit / Windows NSSM-wrapped service / launchd — §11). Responsibilities: accept local agent sends; maintain per-agent inbox dirs; run disk-backed forward queues; hold the gossip directory; dial and maintain backbone sockets; transcode JSON⇄binary; enforce per-agent auth; run health; hold its **hub identity keypair** and the **pinned fleet root pubkey + pinned intermediate-CA cert + ≥1 backbone `HubCert`** provisioned out-of-band (§6.4/§7.3). A local hub is **not** the identity voucher for its agents — that is the intermediate CA (§6.4/P0-E).
- **Backbone hub (rendezvous).** An always-on, widely reachable hub that other hubs **dial out** to and keep a persistent socket open against. Forwards frames between hubs that cannot reach each other, and **advertises its live downstream link-state to the other backbones** (§3.5). Primary candidate: the **Azure box**. **MUST NOT** be the ESET-managed laptop. **≥2 backbone-capable hubs are the design target**; all backbones form a full mesh (§3.5). Single-backbone is a known SPOF surfaced as `backbone_count=1` (§3.5, OD-1).
- **Issuing intermediate CA (new, P0-E/P2-N).** A root-constrained **online** service (may co-reside on a backbone but with a distinct key and access path) that issues short-lived `HubCert`s and `AgentCert`s. The **offline root signs only the intermediate's `IssuerCert`** (§6.4). This is *not* a relay and *not* a home hub — separating identity-issuance from relaying is what closes P0-E.

A backbone hub is an ordinary hub with `backbone=true`. Every hub is *both* a local hub for its agents and a federation relay.

### 3.2 Topology

```
 agent(a1)  agent(a2)          agent(sb)
    \         /                    |
   [ Local Hub A ]            [ Backbone Hub Z (Azure) ]════[ Backbone Hub Y (2nd) ]
   NAT/tailc17728  ── dials out ──►  always-on, tailb3cb9  ◄── dials out ── [ Local Hub B ]
                                          ▲   full mesh (════) + link-state          ESET laptop
                                          └─────gossip over the s2s mesh────┘
        [ Intermediate Issuing CA ]  (root-signed; issues HubCert + AgentCert; NOT a relay)
                    ▲ offline root signs ONLY this cert
```

- Local hubs keep an **outbound, long-lived** framed socket to **every** backbone they are configured for; they record all live attachments in the directory (§3.5).
- All backbones maintain a **full mesh** of s2s sockets and over it (a) exchange **backbone link-state** (§3.5) and (b) **propagate all gossiped directory/PKI records** (§3.5). Each backbone can **re-forward** a durably-held message to a peer backbone that *live-state* says can reach the target's home hub (§3.5).
- Two hubs that *can* reach each other directly MAY open a **direct s2s leg** (optimization; §7.6). The backbone mesh is the guaranteed path.

### 3.3 Message-flow walkthrough (end to end)

Scenario: `wolf@gateway` (NATed) → `secondbrain@second-brain` (Azure). No direct reachability. Backbone Z runs on the Azure box.

1. **Agent send.** `wolf` writes one JSON line to its local hub's agent-boundary IPC endpoint, authenticated with `wolf`'s per-agent key: `{"to":"secondbrain@second-brain","subject":"...","body":"...","require_e2e":true}`.
2. **Ingress + envelope mint.** Hub A validates the agent's identity, confirms `from` matches the authenticated agent (rejecting non-LDH/non-NFC-idempotent `name`/`host` — §5.1/P2-K), mints a canonical **Envelope** (§5): assigns `msg_id` (ULID), sets `from=wolf@gateway#<hub-assigned-session>`, `ttl_hops=8`, `created_at`, `expires_at` (clamped ≤ `created_at + MAX_LIFETIME`). It resolves the recipient's **root-anchored** `AgentCert` + home-hub-published prekey `Keys` record and applies **X3DH E2E sealing** (default-on, first-message FS — §6.5) with **`ad = aead_ad_v1(env)`** (the content-hash-free AD variant — §5.3/P0-A). It then computes `content_hash` over the **on-wire body bytes** (ciphertext under E2E), materializes explicit-presence flags, selects `sig_projection_version` (§5.1) subject to per-field floors, and signs `auth.agent_sig` over the **full length-prefixed pre-image** `sign_input_v1(env)` (which includes `content_hash`, `enc.nonce`, `enc.eph_pub` — §5.1/App C). It stamps a **hub ingress attestation** `relay_attest{msg_id, ingress_time, hub_sig}` (§6.6/P0-D), persists the body to the **spool** with fsync, and enqueues. Body persisted + fsync'd **before** the agent gets `ok`.
3. **Route decision (§7.6).** Hub A resolves `secondbrain@second-brain` → `home_hub = second-brain`, verifying the `hub_record`'s `record_epoch ≥ persisted-highest` (§6.6). It picks a backbone the target is attached to — Z. If it held only Y, it routes to Y; the mesh + link-state guarantees relay (§3.5). Next hop = Z.
4. **Federation hop (binary, encrypted transport).** Hub A serializes the envelope as a **Protobuf `Frame`** over the **always-encrypted** persistent s2s socket to Z. Ack by `msg_id` only after Z has **durably persisted** it (§8.1); until then it stays on A's disk queue.
5. **Backbone relay.** Z **validates `auth.agent_sig` + `content_hash` early** (before transcode — §8.5), checks the **persisted dedup set** (applying the per-`msg_id` `ttl_hops` monotonic floor and `ROUTE_TRACE_CAP` — §3.5/P0-C; rate-limiting duplicate `msg_id` injection per source — §8.3), decrements `ttl_hops`, appends `{Z, linkstate_gen}` to `route_trace`, emits a **signed forward-path ack** upstream (`FwdAck`, distinct from the E2E receipt — §3.5/P1-F), and routes per the loop-safe algorithm (§3.5). If Z's downstream link to B is dead, Z consults the **live backbone link-state table**, applies **corroborated circuit-breaker state** (§3.5/P1-F), and re-forwards to a peer backbone advertising a *live, non-demoted* downstream to B (subject to the revisit rule + `ROUTE_TRACE_CAP`), else holds-and-retries B.
6. **Terminal delivery.** Hub B confirms `secondbrain` is a local agent, **transcodes** to JSON, writes to the inbox via **platform-correct atomic replace** with a reader holding the file open under `FILE_SHARE_DELETE` (§4.5). The inbox-file create and the notify-pointer append are **one `msg_id`-keyed atomic outcome** (§4.5). B acks Z **only after** the flush.
7. **Pointer signal.** B appends a **newline-terminated** one-line **pointer** to `secondbrain`'s **notify stream** (`notify.jsonl`, §4.3/§4.5). No body. The `Monitor` tolerates a partial trailing line (§4.5).
8. **Agent read (lazy) + crash-safe consume.** `secondbrain` sees the pointer, reads the inbox file, **verifies `auth.agent_sig` against `wolf@gateway`'s `AgentCert` (root-anchored) and `content_hash` BEFORE decrypting or acting (§6.8)**, applies the signature epoch-gate (accept `superseded` keys only with a valid `relay_attest.ingress_time < superseded_at` within `SUPERSESSION_GRACE`; reject `revoked` — §6.6/P0-D), decrypts (X3DH, AD = `aead_ad_v1(env)`, using retained privates from the reference-counted retention ring — §6.5), performs the **atomic consume transaction** (§6.8), and **caches a re-emittable `consumed` receipt keyed by `msg_id`** (§8.2). Dedup/`.done` short-circuits any duplicate *before* any key op; a duplicate hitting `.done` **re-emits the cached `consumed` receipt** (§8.2).
9. **End-to-end receipt.** The terminal hub emits a best-effort hub-signed `Receipt{delivered}` (hint). The **recipient agent** emits an **agent-`ident`-signed `Receipt{consumed}`**; because `consumed` may gate ordering (§8.6), it is **reliably delivered over the multi-backbone mesh with alternate-path failover** (disk-backed, retried, acked — §8.2/P1-I) — **not** best-effort and **not** pinned to a single return hop. Both receipt kinds remain **terminal** (never receipt-tracked, never bounce-on-dead-letter — §8.2). On `consumed` timeout the sender may issue an **authenticated `ConsumedQuery`** (§8.2/P2-L) before retransmitting.

Reply travels the reverse path over the **same** persistent sockets.

### 3.4 Why outbound sockets solve both problems

Cross-tailnet and NAT/firewall are the same problem: "I cannot *accept* a connection from the peer." A **persistent outbound** socket inverts who initiates. **Corollary (§4.6):** because inbound is impossible for constrained hubs, no delivery mechanism may require the recipient to *pull* — large bodies are **pushed** as chunks (§4.7). This is also why the reliable `consumed` receipt must ride the **push mesh** with failover, not a pull (§8.2/P1-I).

### 3.5 Backbone redundancy, link-state routing, downstream re-forwarding, and corroborated forward-ack circuit-breaking (P0-C, P1-F, P1-I)

Round-5 raised: (P0-C) `ttl_hops` cap is re-grantable and `gen`-progress revisits are unbounded; (P1-F) demoting a backbone on missing end-to-end receipts is an unattributable, exploitable signal; (P1-I) reliable receipts must not be single-return-path. Resolved below.

- **Gossip transport.** All directory/PKI records — `hub_record`, `Keys`, `AgentCert`, `HubCert`, `IssuerCert`, `Crl`, `bb_linkstate` — propagate **only over the encrypted, mutually-authenticated s2s mesh** (Noise-IK, §6.2). The legacy `/gossip` HTTP+bearer channel is retired at Phase 2 for these record types. Every gossiped record is a signed object verified via the cert chain to the pinned root (§6.4).
- **Monotonic anti-rollback on EVERY gossiped record.** Each record carries a **monotonic `record_epoch`** (`key_epoch` for `Keys`; `epoch` for CRL; explicit `record_epoch`/`gen` for the rest). A receiver persists (fsync'd) the **highest `record_epoch` per (record-type, subject)** and **rejects any validly-signed record whose `record_epoch ≤ persisted-highest`** (§6.6).

- **Loop bound — now attacker-independent (rewritten, P0-C).** Loop termination no longer depends on `ttl_hops` alone or on any self-signed `gen`. Three bounds, in order of authority:
  1. **`ROUTE_TRACE_CAP` (hard, gen-independent).** `len(route_trace)` is capped at `ROUTE_TRACE_CAP = 16`. A frame arriving with `len(route_trace) ≥ ROUTE_TRACE_CAP`, or that would exceed it on append, is **dropped + dead-lettered** regardless of any link-state `gen` claim. Because a revisit *always* appends a `route_trace` entry (§5.5), an attacker bumping its own `gen` to manufacture "progress" can force at most `ROUTE_TRACE_CAP` total hops before the frame is killed. This is the finite bound the reviewer required — it holds even if `ttl_hops` and every `gen` are adversarial.
  2. **Per-`msg_id` monotonic `ttl_hops` floor (persisted).** Each ingress persists, in the dedup entry for `msg_id`, the **lowest `ttl_hops` ever seen** for that `msg_id`, and enforces `ttl_hops := min(received, previously_seen_floor)` before decrementing. A relay that re-raises `ttl_hops` to the cap cannot lift the effective budget above the floor the honest path already drove it to — so a two-backbone ping-pong strictly decreases and cannot be reset.
  3. **Ingress re-cap.** `ttl_hops := min(received, TTL_HOPS_CAP=16)` at every backbone ingress bounds a first-injection inflation; at 0 → drop + dead-letter.
- **Backbone-to-backbone link-state sub-protocol.** Each backbone advertises `bb_linkstate = {backbone_id, live_downstream:[home_hub_id…], gen, emitted_at, sig}` where `live_downstream` is the set of home hubs to which it **currently holds a live, ping-fresh downstream s2s socket**. `LINKSTATE_TTL` default 15 s (3× the 5 s downstream ping); older → **unknown/stale**, not "up." `gen` is monotonic per backbone and persisted-highest-checked. `sig` is over `sign_input_linkstate` (§5.6/P0-B).
- **Corroborated, forward-ack-driven circuit-breaking (rewritten, P1-F).** Confidentiality is protected by E2E; *availability* is not — a compromised backbone can advertise `live_downstream=[all]` to attract-and-drop, or `[]` to deny. But demoting on a **missing end-to-end `consumed`/`delivered` receipt** is wrong: that signal is confounded by an offline recipient, a stalled queue, or a dropped *return*-path receipt — and an attacker on any return hop could drop receipts to frame an **honest** forward backbone (a routing-capture primitive). rev6 fixes attribution:
  - **Signed forward-path ack (`FwdAck`), distinct from the E2E receipt.** When a backbone durably accepts a relayed frame from an upstream hub, it returns a **hub-signed `FwdAck{msg_id, next_hop, at, sig}`** (over `sign_input_fwdack`). This attests *forward progress on this hop only* and is independent of whether the recipient is online or the return path is healthy. Loss of `FwdAck` from a given peer backbone attributes cleanly to **that forward hop**.
  - **Active path probes.** Independent of traffic, each hub periodically sends **signed probe frames** toward a destination via each candidate backbone and expects a `FwdAck` from the downstream-adjacent backbone. Probe loss is forward-attributable.
  - **Multi-destination corroboration.** A peer backbone is demoted **only when `FwdAck`/probe loss crosses a threshold across ≥ `CB_MIN_DISTINCT_DESTINATIONS` (default 2) independent destinations** within the window — a single offline recipient (one destination) can **never** demote a backbone. Demotion for a *single* destination requires corroborating probe loss for that same destination (not merely one missing user-traffic receipt).
  - On demotion: skip the peer for the affected destination(s) while demoted, **alert**, steer to an alternate live backbone or hold-and-retry; confidence recovers on subsequent `FwdAck`/probe success. The **residual (T7)**: a compromised backbone can still cause *transient, bounded* loss/latency until probes+corroboration demote it; E2E prevents disclosure/forgery, not this bounded availability degradation. End-to-end `consumed` loss is tracked **separately** (it drives sender retransmit/`ConsumedQuery`, §8.2) and is **never** by itself an input to backbone demotion.
- **Reliable-receipt path diversity (new, P1-I).** The `consumed` receipt is routed like a message — over the **multi-backbone mesh with alternate-path failover** (it picks a different backbone on `FwdAck` loss), not re-tried over the same return hop. A single compromised/failed return backbone therefore cannot silently stall an `ordered` stream; its loss is attributed to that backbone (via `FwdAck`), not conflated with forward health.
- **Full backbone mesh / single-backbone honesty.** Every backbone maintains a live s2s socket to every other; a backbone that cannot reach another marks itself `degraded` and alerts. Until a second inbound-reachable host exists (OD-1), the fleet runs **one** backbone; T7's mesh guarantee degrades to single-backbone-SPOF, surfaced as `backbone_count=1` and alerted.
- **Backbone in-flight durability.** A backbone does **not** ack upstream on a *relayed* hop until a *second* durable copy exists downstream (`backbone_ack_requires_second_copy=true` for relayed hops); terminal-attached one-hop delivery uses single-copy-then-ack (disclosed bounded window covered by upstream retry).
- **Local hubs attach to every configured backbone** and publish live attachments in `hub_record = {hub_id, addr, backbones:[Z,Y], capabilities, hub_pubkey, max_sig_projection_version, record_epoch, sig}`.

- **Next-hop algorithm (deterministic, loop-safe, progress-aware).**
  1. Resolve `to → home_hub` (verify `hub_record.record_epoch ≥ persisted-highest`).
  2. **Enforce `len(route_trace) < ROUTE_TRACE_CAP`** (else drop + dead-letter, P0-C bound 1).
  3. Apply the **per-`msg_id` `ttl_hops` floor** (P0-C bound 2), re-cap `ttl_hops := min(received, 16)`, decrement; if 0 → drop + dead-letter.
  4. If sender shares a direct s2s leg with `home_hub`, next hop = `home_hub` (optimization).
  5. Else, among backbones the sender holds a live socket to, choose one whose **live, non-demoted** link-state advertises `home_hub ∈ live_downstream`, preferring one **not already in `route_trace`**.
  6. **`route_trace` revisit rule.** A backbone already in `route_trace` MAY be re-selected **iff** the current live `bb_linkstate.gen` for that reachability is **strictly greater** than the `linkstate_gen` recorded at its prior visit (a progress proof) **and** appending stays within `ROUTE_TRACE_CAP` (step 2). The `ROUTE_TRACE_CAP` makes revisits finite **regardless** of `gen`, so a self-signed monotonic `gen` cannot manufacture unbounded progress.
  7. Else route to any live, non-demoted backbone permissible under 5–6; the mesh relays onward.
  8. If none permissible, **hold with backoff and retry**, dead-lettering only on `expires_at`.
- **Downstream-failure re-forwarding** runs the same algorithm over any durably-held message, using live link-state + corroborated circuit-breaker state, appending `{self, current_gen}` and respecting `ROUTE_TRACE_CAP`.
- **Backbone directory-freshness fail-safe.** A backbone whose directory view exceeds `DIR_STALE_THRESHOLD` marks itself `degraded(directory_stale)`, alerts, and holds-and-retries rather than dead-letters on resolutions it cannot freshly trust.
- **Backbones are stateless-ish relays**: in-flight durable queues + persisted dedup set (with `ttl_hops` floor) + persisted highest-`record_epoch` map + the soft link-state/circuit-breaker tables.

---

## 4. Wire Formats & Transcoding

**Hard requirement:** binary on the federation wire, JSON at the agent boundary; the hub transcodes.

### 4.1 Hub-to-hub: Protobuf (transport encoding) — but **not** the signing encoding

**Protobuf 3** for hub↔hub `Frame` *transport* encoding. **Critical correctness note:** Protobuf serialization is **not deterministic** across languages. Therefore **signatures and content hashes are NEVER computed over raw protobuf wire bytes** (nor over canonical CBOR). They are computed over **explicit length-prefixed byte concatenations (TLV)** with pinned field order and explicit presence bytes (§5.1/§5.6/App C). This is now true of **every** signed object — envelopes *and* all PKI/directory records (§5.6/P0-B). Protobuf is the mutable transport container only.

Framing: length-prefixed (`uint32` BE + protobuf `Frame` bytes), hard **max frame size** (§8.7). A `Frame` is a control frame (HELLO, KEYS, ACK, PING, RECEIPT, LINKSTATE, GOSSIP, FWDACK, CQUERY), a `MessageFrame`, or a **`Chunk`** frame (§4.7).

### 4.2 Agent boundary: JSON / JSONL

- **Send:** agent writes **one JSON object per line (JSONL)** to the agent-boundary IPC endpoint (§7.6).
- **Receive notify:** hub appends **newline-terminated JSONL pointer lines** to `notify.jsonl` (§4.3/§4.5).
- **Receive body:** hub writes **one JSON file per message** into the durable inbox.

### 4.3 JSONL vs file-per-message — torn-append durability

We use both: JSONL (append log) for the streamy notify leg; file-per-message JSON for the durable, per-message-atomic inbox. Contract: `notify.jsonl` line ⟺ exactly one inbox file, joined by `msg_id`, produced as **one atomic `msg_id`-keyed outcome** (§4.5).

**Torn-append durability.** Each pointer is a **single newline-terminated append**. Normative rules:
- The **hub** never treats an append as committed until the write (including `\n`) returns; on restart it truncates any trailing bytes after the last `\n` before appending further.
- The **`Monitor`** MUST tolerate a partial trailing line: parse only up to the last `\n`, **hold/await** an unterminated line, never act on an unterminated fragment. A malformed *terminated* line is skipped-and-logged, never fatal.
- Correctness never depends on the notify stream: the authoritative record is the inbox file + `.done` set.

**Rotation.** On >8 MiB or >24h, the hub writes `notify.jsonl.next`, emits a `{"rotate":…}` sentinel, atomically replaces, and the Monitor re-opens on the sentinel.

### 4.4 Transcoding rules + the unsigned-field conformance rule (P2-6)

- **Ingress (agent→hub):** parse JSONL → validate (incl. **LDH/ASCII identity-field check**, §5.1/P2-K) → populate protobuf `Envelope`, materialize explicit-presence flags, seal, sign. Reject on schema/charset violation with a JSON error line.
- **Egress (hub→agent):** protobuf `Envelope` → JSON file + JSONL pointer, `snake_case`.
- Transcoding is **lossless for known fields**; unknown protobuf fields are preserved on relay but **never** part of any signing pre-image.
- **Unsigned-field conformance rule (P2-6).** **Any field that influences a security or routing decision MUST be added to the signing pre-image in the same change that introduces it.** Interpreting any unsigned field to make a security/routing decision is a **conformance violation**. Purely advisory fields (`headers`, `subject` when not sealed) may remain unsigned but MUST NOT gate a decision.

### 4.5 Windows-correct atomicity & durability (+ open-reader / AV, P2-P)

Durability is **proven by a power-loss conformance test (§11 Phase 2)**, never asserted.

- **Atomic replace + durable write.**
  - POSIX: `write tmp → fsync(tmp) → rename(tmp, final) → fsync(parent dir)`.
  - Windows: `write tmp` → **`FlushFileBuffers(tmp)`** → **`MoveFileExW(tmp, final, MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)`** (or `ReplaceFileW` with write-through). Do not rely on NTFS journaling.
- **fsync/flush is mandatory and explicit.** Git-Bash `mv`/redirection does not flush; the daemon MUST flush data file then parent dir before acking.
- **Atomic file+pointer outcome.** Intent journal `{msg_id, target_file, pointer}` (fsync'd) → atomic file replace → newline-terminated pointer append → clear intent. Restart replays incomplete intents idempotently by `msg_id`. A retried already-delivered `msg_id` is a **no-op**.
- **Readers MUST open inbox files with `FILE_SHARE_DELETE` (Windows) / not hold an exclusive lock (POSIX) (new, P2-P).** A lazy-reading agent that opens the inbox file **without** `FILE_SHARE_DELETE` blocks `MoveFileExW(REPLACE_EXISTING)` with `ERROR_SHARING_VIOLATION`. Normative: the agent-side `Monitor`/reader opens with `FILE_SHARE_READ | FILE_SHARE_DELETE` (POSIX: read without an exclusive advisory lock), so the hub can atomically replace under an open reader. Conformance-tested (§11).
- **Sharing-violation retry is bounded + escalates (P2-P).** On `ERROR_SHARING_VIOLATION`/`EBUSY`, retry against the **same `msg_id`-keyed name** with bounded backoff up to `SHARE_VIOLATION_MAX` (default 30 s); on exceeding it, **escalate: alert + surface a `delivery_stalled(sharing_violation)` health event** and continue retrying at a slow cadence — never spin silently forever, never invent a second name.
- **AV (ESET) exclusion (P2-P).** Deployment doc MUST request an ESET exclusion for the spool/inbox tree. **When the exclusion is denied (corp-managed laptop):** the hub **detects quarantine/removal of a spool file mid-write** (open/rename failure with `ERROR_FILE_NOT_FOUND`/access-denied on a file it just wrote), **degrades that host to `av_unexcludable` posture, alerts, and marks the leg unreliable** (routes that host's traffic via a backbone hold-and-retry rather than local spool where possible) — it does **not** silently retry forever. `/queues` reports `av_unexcludable` and stall counts.

### 4.6 Frozen routing envelope + additive-only evolution + advertise-then-enforce (P2-O)

- The **routing envelope** — `msg_id`, `protocol_version`, `from`, `to`, `ttl_hops`, `route_trace`, `expires_at`, `enc.mode`, `enc.key_epoch`, `size`, `content_hash`, `auth` — is **frozen forever**.
- **Evolution is additive-only.** Unknown/empty `oneof` → **nack `Ack{RETRY_UNSUPPORTED}` + log**, never silent-drop. Any additive field that gates a security/routing decision MUST land in the signing pre-image in the same change (§4.4/P2-6).
- **Advertise-then-enforce staged rollout for new signed security fields (new, P2-O).** Introducing a new signed protection is a two-stage rollout, never a flag day: **(Stage 1 — advertise/verify)** deploy the new `sig_projection_version` as *verify-capable* to **100% of hubs** (they can verify the field if present but do not require it and do not raise their advertised `max_sig_projection_version` floor); senders MAY sign it but MUST still interoperate with recipients that don't require it. **(Stage 2 — enforce)** only after fleet-wide verify-capability is confirmed (a monitored rollout gate) may any sender set the per-field `min_projection_floor` that *refuses* to send below it. This prevents a single new signed field from partitioning the fleet (`projection_floor_unmet`) until every node upgrades. The roadmap (§11) sequences this explicitly.
- **Backbones relay any parseable version** (they read only frozen fields).
- **Cross-tailnet capability negotiation is directory-mediated.** B's `capabilities`/`protocol_version`/`max_sig_projection_version` reach A via B's signed, rollback-checked directory record. A signs at `min(A-supported, B-advertised)` subject to per-field floors; a stale-directory guess-high is corrected by `Ack{RETRY_UNSUPPORTED}`/`Receipt{bounced}`.

### 4.7 Large-body chunking, per-sender AND global reassembly caps (+ Minor)

Bodies larger than one frame are **pushed** as ordered `Chunk{msg_id, index, total, bytes, chunk_hash}` frames; each hop reassembles to its own fsync'd spool, verifies `chunk_hash` per chunk and `content_hash` over the whole, re-chunks onward, acks the whole `msg_id` only after the reassembled body is fsync'd.
- **Per-sender:** `MAX_INFLIGHT_CHUNKED_PER_SENDER=4` + per-message reassembly idle timeout (5 min → abort + bounce `reassembly_timeout`).
- **Global reassembly cap (new, Minor).** A backbone aggregating many upstreams also enforces `MAX_TOTAL_REASSEMBLY_BYTES` (default 256 MiB, always < the 2 GiB spool quota) across **all** in-progress reassemblies; new reassembly starts are refused (`Ack{RETRY}`, backpressure) once over it, so `many_senders × 4 × ~8 MiB` cannot exhaust the spool. Reassembly spool counts against the byte quota (§8.7).

---

## 5. Message Envelope Schema

| Field | Type | Req | Description |
|---|---|---|---|
| `msg_id` | string (ULID) | yes | Globally unique, time-sortable. Minted by ingress hub. **The only dedup key** (§5.3). ASCII. |
| `protocol_version` | uint32 | yes | Integer, ordered. Directory-mediated (§4.6). |
| `from` | AgentAddr | yes | Canonical sender `name@host#session`. Set by hub from authenticated agent. In pre-image. **Crypto identity is `name@host`; `#session` is a delivery discriminator (§7.1). `name`/`host`/`session` are LDH/ASCII (§5.1/P2-K).** |
| `to` | AgentAddr | yes | Destination; MAY omit `#session` (§7.2). In pre-image. LDH/ASCII. |
| `reply_to` | AgentAddr | no | Reply destination; MUST be sender-owned `name@host` (§5.2). In pre-image. |
| `thread_id` | string | no | Thread grouping. **Relay-visible unless sealed** (§6.5). |
| `in_reply_to` | string | no | `msg_id` responded to. **Relay-visible unless sealed** (§6.5). |
| `subject` | string | no | Short summary (pointer). **Relay-visible unless sealed** (§6.5). Advisory only — never gates a decision (§4.4). |
| `content_type` | string | yes | Default `text/markdown`. **Registered ASCII token** (§5.1/P2-K). In pre-image. |
| `payload` | oneof {`body` bytes \| `body_ref` string} | yes | `body` = inline (ciphertext under E2E); `body_ref` = **origin-hub-local** spool handle streamed as `Chunk` (§4.7) — never a pull URL. |
| `size` | uint32 | yes | On-wire body length. **SIGNED (§5.1)** — a relay cannot inflate it to trigger a spurious quota rejection. Bounded by max-body cap (§8.7). |
| `content_hash` | string | yes | `sha256` of **on-wire body bytes** = ciphertext when E2E. **Integrity only, not a dedup key** (§5.3). In `sign_input` (signed) but **excluded from `aead_ad`** (§5.3/P0-A). |
| `created_at` | int64 (epoch ms) | yes | Origin timestamp. Skew-tolerated (§5.4). In pre-image. **Gates the `superseded`-key acceptance window jointly with `relay_attest.ingress_time` (§6.6/P0-D).** |
| `ttl_hops` | uint32 | yes | Remaining hops; **subject to the persisted per-`msg_id` monotonic floor + ingress re-cap ≤16** (§3.5/P0-C). Excluded from signature (mutable). |
| `expires_at` | int64 (epoch ms) | no | Absolute expiry + skew slack; clamped ≤ `created_at + MAX_LIFETIME` (24h). In pre-image. |
| `route_trace` | repeated RouteHop | yes | Ordered `{hub_id, linkstate_gen}` entries (§3.5). Append-on-relay. **`len ≤ ROUTE_TRACE_CAP=16` hard bound (§3.5/P0-C).** Mutable, excluded from signature. |
| `priority` | enum | no | `bulk`\|`normal`\|`interactive`. **SIGNED (P1-1)** — relay adjustment clamped to this ceiling; hard-watermark eviction is priority-agnostic (§8.7). Default `normal`. In pre-image. |
| `want_receipt` | optional bool | yes-present | Typed + signed, explicit presence. Semantic default **true**. |
| `require_e2e` | optional bool | yes-present | Typed + signed fail-closed flag (§6.3). Default false. |
| `ordered` | optional bool | yes-present | Typed + signed strict FIFO request (§8.6). Default false. |
| `fanout` | optional bool | yes-present | Typed + signed deliver-to-all-live-instances (§7.2). Default false. |
| `seal_subject` | bool | no | Seal `subject`/`thread_id`/`in_reply_to` into payload (§6.5). Not signed (self-evident from field absence; never gates a decision). |
| `enc` | EncMeta | no | Encryption metadata (§6). `mode`,`key_epoch`,`sender_key_id`,`recipient_key_id`,`spk_epoch`,`opk_id`,**`nonce`,`eph_pub`** all in `sign_input` (signed — Minor). |
| `relay_attest` | RelayAttest | cond | Hub ingress attestation `{msg_id, ingress_time, hub_id, hub_sig}` (§6.6/P0-D). **Required for acceptance of a `superseded`-key signature.** `hub_sig` over `sign_input_relayattest` (§5.6). Not part of `sign_input_v1` (added by hub after the agent signs; verified independently against the hub's cert). |
| `auth` | AuthMeta | yes | `sig_projection_version`; `agent_sig` over `sign_input_v1`; `key_id`/`key_epoch`, verified per §6.6. |
| `headers` | map<string,string> | no | **Non-security hints only.** Not in any pre-image; **MUST NOT gate any security/routing decision (§4.4/P2-6).** |

### 5.1 Envelope signing pre-image (length-prefixed TLV), the AEAD-AD variant, NFC removal, version selection, floors (P0-A, P2-K, P2-O, P2-4)

`auth.agent_sig` is computed over an **explicit length-prefixed byte concatenation** — not raw protobuf, not canonical CBOR. There is no map to sort, no CBOR mode, no float rule, and **no NFC in the signing path** (P2-K).

- **Encoding.** The pre-image is `DS_<purpose> || VERSION_BYTE || field₀ || … || fieldₙ` in **fixed field order**. Each `fieldᵢ` is: **1 presence byte** (`0x00` absent / `0x01` present); if present, **`uint32` big-endian length `L`** then **exactly `L` raw bytes**. Integers are **fixed-width big-endian**. `content_hash` is the **raw 32 bytes** (not hex). No sorting; conformance is a byte-compare against fixed vectors.
- **NFC removed from the signing path (new, P2-K).** All signed text fields are restricted to an **ASCII subset** so runtime Unicode/ICU version differences can never produce divergent pre-images:
  - `name`, `host`: **LDH** (`[a-z0-9-]`, no leading/trailing hyphen, lowercased at mint), rejected at ingress otherwise (no silent normalization).
  - `session`: lowercase hex (hub-assigned, §7.1).
  - `content_type`: a **registered ASCII token** from a fixed allow-list (`text/markdown`, `text/plain`, `application/json`, …); unknown → reject.
  - `msg_id`: Crockford-ULID ASCII.
  - `enc.sender_key_id`/`recipient_key_id`, `auth.key_id`: ASCII (base32/hex fingerprints).
  Any input that is not already in-subset / not NFC-idempotent is **rejected at ingress** (`error: non_conforming_field`), never silently normalized. Because no free-form Unicode text enters `sign_input`, NFC is **entirely out of the security path.**
- **Two envelope pre-image variants (new, P0-A).** To break the `content_hash`⇄AEAD-AD cycle:
  - **`aead_ad_v1(env)`** — the fixed-order pre-image **excluding `content_hash`** (but including `enc.nonce`, `enc.eph_pub`, `msg_id`, `from`, `to`, `size`, all other signed fields). Used **only** as AEAD associated data. Computable **before** the ciphertext exists (it contains no ciphertext-derived value).
  - **`sign_input_v1(env)`** — the full pre-image, `aead_ad_v1` **plus `content_hash`** inserted at its fixed position. Used for `auth.agent_sig`. Computed **after** the ciphertext exists.
  Ordering: build `aead_ad_v1` → seal (`ad=aead_ad_v1`) → `content_hash = sha256(ciphertext)` → build `sign_input_v1` → sign. **Transplant resistance is preserved**: `aead_ad_v1` binds `msg_id||from||to||size||nonce||eph_pub`, so a sealed body cannot be moved to a different envelope (AD mismatch → tag fails) — `content_hash` in the AD was never what prevented transplant. The signature still covers `content_hash = sha256(ciphertext)`, transitively binding the exact ciphertext. Both variants are pinned in the Phase-0 vectors.
- **`enc.nonce`/`enc.eph_pub` are now SIGNED (new, Minor).** Both are in `sign_input_v1` (and `aead_ad_v1`). Consequence: a relay that flips the nonce or ephemeral pubkey produces a **signature failure** — an attributable **structural** fault caught at verify-time (§8.5) — rather than surfacing as a recipient-side AEAD decrypt failure that a relay could weaponize into agent-side poison/bounce (round-5 Minor). They remain generated at mint, before sealing, so no cycle is introduced.
- **Presence materialization.** The four delivery-integrity flags and `priority`/`size` are materialized to explicit values at ingress, so on a signed envelope their presence byte is always `0x01`. A verifier seeing `0x00` on any of these rejects (`projection_mismatch`). `reply_to` is the only genuinely-optional pre-image field.
- **`sig_projection_version` is `VERSION_BYTE`**, echoed in `auth.sig_projection_version`.
- **Directory-mediated version selection with per-field floors + advertise-then-enforce (P2-4/P2-O).** A sender signs at `min(sender-supported, recipient-advertised)`, except a field carrying a `min_projection_floor v` MUST be signed at `≥ v`; if the recipient advertises below a required floor, the sender **refuses with an alert** (`projection_floor_unmet`), never silently downgrading. **Floors may only be enforced after the advertise-then-enforce gate (§4.6/P2-O):** a sender may not set a floor until fleet-wide verify-capability for that version is confirmed. A `min()` below the sender's max logs+alerts a downgrade event.
- **Unknown/higher projection version = REJECT-with-bounce.** `Receipt{bounced, reason=unsupported_sig_projection, max_supported=k}`; the sender re-signs `≤ k` (subject to floors).
- **Signed field set, version 1** (fixed order): `msg_id`, `protocol_version`, `from{name,host,session}`, `to{name,host,session}`, `reply_to{…}|null`, `content_type`, `size`, `content_hash` *(only in `sign_input`, not `aead_ad`)*, `created_at`, `expires_at`, `priority`, `enc.mode`, `enc.key_epoch`, `enc.sender_key_id`, `enc.recipient_key_id`, `enc.spk_epoch`, `enc.opk_id`, `enc.nonce`, `enc.eph_pub`, `want_receipt`, `require_e2e`, `ordered`, `fanout`, `auth.key_epoch`.
- **Explicitly excluded** (mutable/metadata): `auth.agent_sig`/`auth.key_id`, `route_trace`, `ttl_hops`, `relay_attest` (separately hub-signed), `subject`/`thread_id`/`in_reply_to` (sealed when requested), `headers`, `seal_subject`, raw body (covered via `content_hash`).
- **Conformance gate.** The Phase-0 cross-language vector suite pins: field order, presence bytes, integer widths, ASCII/LDH validation (incl. reject vectors for non-conforming input), raw-`content_hash`, **both `aead_ad_v1` and `sign_input_v1` outputs**, signed-`nonce`/`eph_pub`, materialization, floor-refusal, and the advertise-then-enforce gate. No hub ships until it reproduces every vector byte-for-byte.

### 5.2 `reply_to` authorization

`reply_to`, if present, MUST be the **same `name@host` as the authenticated `from`** (any owned `#session`). Third-party `name@host` rejected at ingress. Signed. Cross-`host` reply out of scope for v1.

### 5.3 `content_hash` semantics, dedup, AEAD binding (P0-A)

- Plaintext body: hash over plaintext. E2E body: hash over **ciphertext**. In `sign_input_v1`.
- **AEAD associated data = `aead_ad_v1(env)`** (the content-hash-free pre-image variant, §5.1/P0-A), min set `msg_id||from||to||size||nonce||eph_pub`. A compromised relay cannot transplant a sealed `body` onto a different envelope (AD mismatch → tag fails).
- **Recipient MUST verify before acting**: (1) resolve `auth.key_id → sender's `name@host` `AgentCert` → chain to **pinned** root via the intermediate (§6.4); (2) verify `auth.agent_sig` over `sign_input_v1`; (3) verify `content_hash`; (4) apply the signature epoch-gate incl. `relay_attest` for superseded keys (§6.6/P0-D). Only then AEAD-open with `ad=aead_ad_v1`. Backbones additionally validate sig+hash early (§8.5).
- **`content_hash` is NOT a dedup key** (fresh `eph_pub`+`nonce` ⇒ differing ciphertext). Dedup/idempotency key solely `msg_id` (§8.3). Quarantine keys `(msg_id, content_hash)` (§8.5).

### 5.4 Clocks, TTL, skew, authenticated time (P2-J)

- **`ttl_hops`/`ROUTE_TRACE_CAP` are the primary loop/aging bounds** (clock-independent). Expiry's only remaining job is GC.
- **`expires_at` carries `SKEW = 5 min` slack**; `created_at` more than `SKEW` in the future is clamped+logged.
- **Clock-jump handling.** On a detected wall-clock jump the hub enters **hold-and-recheck**: it never dead-letters or replay-rejects on a suspected jump. It re-evaluates expiry only after **authenticated-time sync is confirmed OR `CLOCK_SETTLE_MAX` (10 min) elapses.**
- **Authenticated time is required to flip the trusted bit (new, P2-J).** "NTP-confirmed" is redefined as **NTS (RFC 8915) or roughtime** — an **authenticated** time source. **Plain, unauthenticated NTP over the LAN/Tailscale never sets the trusted bit** (an on-path attacker can forge it). Until authenticated time is obtained, the clock stays *unconfirmed* and the hub stays in hold-and-alert.
- **Unconfirmed-clock policy.** When the settle window elapses with the clock still unconfirmed, the hub **biases to HOLD-AND-ALERT — it MUST NOT dead-letter.** Under quota pressure while the clock is unconfirmed, eviction is **`bulk`-first, priority-aware** (not priority-agnostic-oldest), so an attacker who desyncs the clock cannot force eviction of high-priority mail (§8.7/P2-J). Expiry-driven dead-letter resumes only once authenticated time is confirmed.
- ULID sortability is best-effort local ordering only.

### 5.5 `route_trace` on retry/failover (P0-C)

- `route_trace` entries are `{hub_id, linkstate_gen}`. A re-queue to the same next hop keeps the trace unchanged; a failover/re-forward appends `{self, current_gen}`.
- **`len(route_trace) ≤ ROUTE_TRACE_CAP=16` is a hard, gen-independent bound** (§3.5/P0-C bound 1): exceeding it → drop + dead-letter, regardless of any progress claim.
- **Per-`msg_id` monotonic `ttl_hops` floor** (§3.5/P0-C bound 2) prevents a relay re-raising the budget.
- A revisit is permitted only under a **strictly-newer link-state gen** *and* within `ROUTE_TRACE_CAP`. Because the cap is enforced independently of `gen`, a self-signed monotonic `gen` cannot manufacture unbounded revisits.

### 5.6 PKI / directory record pre-images (new — closes P0-B)

**Every** trust-anchoring signature is computed over an explicit length-prefixed TLV pre-image with a fixed field order, fixed-width integers, ASCII fields, and explicit presence bytes — **never** over protobuf bytes. Each has a distinct domain-separation tag. All are added to the Phase-0 cross-language vector suite. The pre-images (full byte layout in App C):

| Signature | Signer | Domain tag | Covered fields (fixed order) |
|---|---|---|---|
| `IssuerCert.root_sig` | offline root | `DS_ISSUER` | `issuer_id`, `issuer_pubkey`, `name_authority_constraints[]`, `not_after`, `record_epoch` |
| `HubCert.cert_sig` | intermediate | `DS_HUBCERT` | `hub_id`, `hub_pubkey`, `allowed_name_authority[]`, `not_after`, `record_epoch`, `issuer_id` |
| `AgentCert.cert_sig` | intermediate | `DS_AGENTCERT` | `addr(name@host)`, `ident_pub`, `key_epoch`, `not_after`, `record_epoch`, `issuer_id` |
| `Keys.hub_sig` | home hub | `DS_KEYS` | `addr(name@host)`, `ident_pub`, `spk_pub`, `spk_epoch`, `opk_root_hash`, `key_epoch`, `record_epoch` |
| `spk_sig` | agent ident key | `DS_SPK` | `ident_pub`, `spk_pub`, `spk_epoch`, `key_epoch` *(now binds `ident_pub`+`key_epoch` — Minor)* |
| `Crl.root_sig` | offline root *(or intermediate under a root-signed CRL-issuance grant)* | `DS_CRL` | `revoked_hub_ids[]`, `revoked_agent_key_ids[]`, `superseded_keys[{key_id,superseded_at}]`, `epoch`, `next_update`, `issuer_id` |
| `HubRecord.sig` | home hub | `DS_HUBREC` | `hub_id`, `addr`, `backbones[]`, `capabilities[]`, `hub_pubkey`, `max_sig_projection_version`, `record_epoch` |
| `LinkState.sig` | backbone | `DS_LINKSTATE` | `backbone_id`, `live_downstream[]`, `gen`, `emitted_at` |
| `FwdAck.sig` | relaying hub | `DS_FWDACK` | `msg_id`, `next_hop`, `at`, `hub_id` |
| `RelayAttest.hub_sig` | ingress hub | `DS_RELAYATTEST` | `msg_id`, `ingress_time`, `hub_id` |

Repeated fields (`allowed_name_authority[]`, `live_downstream[]`, `superseded_keys[]`, etc.) are encoded as a **count-prefixed** (`uint32` BE) sequence of length-prefixed elements, in the order the signer emitted them (order is part of the signed content; a verifier does not reorder). `opk_root_hash` is a hash over the count-prefixed one-time-prekey list so the `Keys` signature covers the OPK set without signing each OPK inline. **Record protobuf bytes are never signed or hashed.**

---

## 6. Encryption (transport + forward-secret E2E, default-on, from vetted primitives)

### 6.0 Why not an off-the-shelf stack — and what we DO adopt

- **Primitives: adopt, never hand-roll.** Every cryptographic operation uses a **single vetted library per language** — libsodium (or an audited binding) for X25519 DH, XChaCha20-Poly1305 AEAD, HKDF, Ed25519, and Ed25519↔X25519 conversion; a **vetted Noise-IK implementation** for transport. We write **no** curve/AEAD/KDF/ratchet arithmetic.
- **Transport: adopt Noise-IK (or TLS 1.3) wholesale** (§6.2).
- **Payload sealing: adopt libsodium AEAD + a *standard X3DH prekey* construction** (§6.5).
- **Reject libsignal's full session/double-ratchet.** Our delivery is one-shot, unidirectional, store-and-forward, frequently never-answered, with FS-from-message-1 and no ordering dependency (§6.5). A ratchet adds session-establishment round trips, ordering coupling, and an unbounded skipped-key cache we do not want.
- **The bespoke surfaces are minimized and test-vector-gated.** Length-prefixed TLV for **all** signed objects (envelope + every PKI record, §5.6), NFC removed from the path (§5.1), the AEAD-AD cycle broken (§5.3) — all gated by cross-language byte-for-byte vectors (§11).
- **Residual honesty.** We still compose primitives (Noise transport, X3DH payload, Ed25519 signing, a PKI with an offline root + online intermediate). That composition is inherent to "async E2E across an untrusted relay with an offline root," which is the actual requirement (N5). We shrink it, adopt vetted pieces, test-vector the seams, and disclose the two residual hot surfaces (intermediate-CA key, home-hub prekey publication — §6.4).

### 6.1 Model decision

- If any backbone can be compromised (T4/T7), **E2E is DEFAULT-ON for every pair with an authenticated recipient key** and is the only protection surviving backbone compromise.
- **Transport encryption (hub↔hub) is mandatory** from Phase 2.
- **Plaintext payload is a fallback**, permitted only when (a) **no `AgentCert` exists** for the recipient **and** (b) `require_e2e` is false; it rides encrypted transport and alerts. **If a valid `AgentCert` exists but the prekey `Keys` record is missing/stale, the sender HOLDS + alerts (a possible hub-withholding downgrade attack, §6.4/P0-E) — it does NOT fall back to plaintext.**
- **No plaintext-transport negotiation across a backbone, ever.**

### 6.2 Transport layer (hub↔hub) — vetted Noise-IK

- Every persistent s2s socket uses a **vetted Noise-IK implementation** (recommended) or TLS 1.3, with the **hub identity keys** (§6.4) as static keys. Mutual auth + transport FS.
- A hub **refuses** any s2s peer that cannot complete the encrypted handshake; never downgradable to plaintext.
- **HELLO runs inside the established session**; both sides hash the negotiation transcript into a session-keyed confirmation MAC and abort on mismatch.
- **All gossip rides this mesh (§3.5).** `ConsumedQuery`/`FwdAck` are authenticated by this session (§8.2/P2-L).

### 6.3 End-to-end payload layer — key acquisition (directory-only, root-anchored)

- **Two-part authenticated key material:** the recipient's **`AgentCert`** (root-anchored `ident_pub` binding, issued by the intermediate CA — §6.4) plus the home-hub-signed **`Keys`** prekey bundle (spk/opk). The `Keys.spk_sig` is signed by the agent's **own ident key** (§5.6/§6.5), so the hub cannot substitute prekeys. No inline-pubkey TOFU.
- Sender: valid `AgentCert` + fresh `Keys` → **X3DH-seal from message #1**; valid `AgentCert` but missing/stale `Keys` → **hold+alert** (possible downgrade, §6.1); no `AgentCert` + `require_e2e=true` → **refuse+alert**; no `AgentCert` + `require_e2e=false` → plaintext over encrypted transport + alert.

### 6.4 PKI: offline root, online intermediate CA, root-anchored agent identity, rotation-vs-revocation, stale-CRL policy, recovery (P0-D, P0-E, P1-G, P2-N)

**Trust root + issuing intermediate (rewritten, P0-E/P2-N).** A single fleet **root key** (operator, offline) signs **only** an `IssuerCert` for a **root-constrained online intermediate issuing CA**: `IssuerCert{issuer_id, issuer_pubkey, name_authority_constraints:[host…], not_after, record_epoch, root_sig}`. The intermediate then issues, online:
- `HubCert{hub_id, hub_pubkey, allowed_name_authority:[host…], not_after(30d), record_epoch, issuer_id, cert_sig}` — hub identity for Noise + relaying + `Keys`/`HubRecord` signing.
- `AgentCert{addr(name@host), ident_pub, key_epoch, not_after, record_epoch, issuer_id, cert_sig}` — **root-anchored (via the intermediate) binding of an agent's identity key.** This is the authority the recipient's signature is verified against, and it is what a sealed E2E message is anchored to.

This removes the **monthly offline-root ceremony** (P2-N): the offline root signs only the intermediate (rare); routine 30-day hub certs and agent certs are issued online. It also closes **P0-E**: the **home hub is no longer the voucher for its agents' identity** — the intermediate is. A compromised home hub cannot (a) bind an attacker-controlled `ident_pub` for its `name@host` (that requires an `AgentCert` from the intermediate), nor (b) substitute prekeys (`spk_sig` is by the agent's ident key), nor (c) silently downgrade to plaintext by withholding `Keys` (a present `AgentCert` makes E2E mandatory — missing prekeys ⇒ hold+alert, §6.1/§6.3).

**Disclosed residual hot surfaces (P0-E/N5).** (1) **Home-hub compromise** now yields only **denial** (it can refuse to relay/withhold prekeys → hold+alert) and **metadata exposure of plaintext-fallback mail that predates an `AgentCert`**, **not** identity forgery or E2E decryption of `AgentCert`-covered agents. Stated plainly in T-HUBROOT. (2) **Intermediate-CA compromise** = fleet-wide identity forgery until revoked — the price of an online issuer (P2-N trade). Mitigations: the intermediate is a **distinct key on a distinct access path** (not a relay, not a home hub); it issues only **short-lived** certs; issuance is **logged (append-only issuance transparency log)**; the **offline root can revoke the intermediate** (`revoked_hub_ids`/issuer revocation in the CRL) and cross-sign a replacement. Disclosed, not eliminated (replicating a fully-offline per-agent enrollment ceremony over-engineers for N1, but see OD-8).

**Out-of-band trust bootstrap.** At provisioning over the operator channel: the operator drops the **fleet root pubkey**, the **intermediate `IssuerCert`**, and **≥1 backbone `HubCert`** into the hub's pinned trust store (fsync'd). The hub **pins the root fingerprint**; every incoming record must chain **root → intermediate → leaf**. A hub with no pinned root, or a record chaining to a different root/intermediate fingerprint, is **fail-closed** (refuses s2s, refuses E2E, alerts).

**Rotation implies revocation — with a hub-attested supersession window (rewritten, P0-D).** Rotating an agent/hub key publishes a higher-epoch record **and** publishes the superseded `key_id` into the CRL **with a `superseded_at` timestamp**. Signature verification (§6.6) distinguishes:
- `key_id ∈ revoked_agent_key_ids` (emergency/leak) → **hard-reject every signature**, any `created_at`, any attestation.
- `key_id ∈ superseded_agent_key_ids` (routine rotation) → **accept iff ALL of:** (i) signed `created_at < superseded_at`; (ii) `now ≤ created_at + MAX_LIFETIME`; **(iii, new/P0-D) a valid `relay_attest{msg_id, ingress_time, hub_sig}` is present whose `ingress_time < superseded_at` and whose signing hub's cert was valid at `ingress_time`;** **(iv, new/P0-D) `superseded_at − ingress_time ≤ SUPERSESSION_GRACE` (default 1 h) ≪ MAX_LIFETIME.** Because `ingress_time` is stamped by a **hub key** the leaked *agent* key cannot forge, **backdating `created_at` no longer buys the attacker a window** — a message not actually ingested by an honest hub before `superseded_at` has no valid attestation and is rejected. Operators MUST route any *suspected* leak through the **`revoked`** path (which ignores attestations entirely). `superseded` is thus limited to genuinely-in-flight, honestly-attested mail within a short grace, not a 24 h impersonation window.

*(Note: this makes `relay_attest` mandatory on the wire for E2E mail so that in-flight grace can be honored after a rotation; the hub stamps it at ingress (§3.3 step 2) at negligible cost for N1 rates.)*

**Revocation freshness + enumerated stale-CRL fail-closed set (P1-6).** A signed `Crl{revoked_agent_key_ids, superseded_keys[{key_id,superseded_at}], revoked_hub_ids, epoch, next_update, root_sig}` is gossiped and pinned by `epoch`. When stale (older than `next_update + grace`), the hub **alerts continuously** and:
- **CONTINUES:** delivering/relaying in-flight and new mail; enforcing the **CRL it already holds**.
- **REFUSES (until fresh):** honoring a **new key rotation**; accepting a **new agent enrollment**; accepting a **new `HubCert`/`AgentCert`** superseding an existing binding. These hold (queued, alerted) until freshness returns.

**Name re-enrollment / squat refusal (P1-7) + lost-key recovery override (new, P1-G).**
- A hub/intermediate **MUST refuse** to bind an **already-bound** `name@host` under a **different** `ident_pub` unless the request carries the **supersession possession-proof** (new key signs a root/issuer-issued nonce, old key's supersession published to CRL). **First-writer-wins only on an unbound name.**
- **Lost-`ident_priv` recovery override (P1-G).** If an agent's box dies with its `ident_priv`, the possession-proof is unprovidable. rev6 defines an **operator/root override**: over the operator-authenticated provisioning channel, the operator directs the **intermediate to CRL-revoke the old `ident_pub` and issue a fresh `AgentCert`** for a new `ident_pub` on the same `name@host` — **the possession-proof is waived on this out-of-band-authenticated path** (parallel to hub-cert supersession). The rebind is logged in the issuance-transparency log and gossiped with a bumped `record_epoch`. This is the *only* path that rebinds without the old key, and it is gated by operator authentication, not network input.

**Verification.** Any hub verifies a record by: chain root→intermediate→leaf to the **pinned** root; unexpired; not-revoked; `@host` within `allowed_name_authority`⊆`name_authority_constraints`; the record's TLV signature (§5.6); and `record_epoch ≥ persisted-highest` (§6.6). **Agent identity** `auth.agent_sig` is verified against the `AgentCert`-bound `ident_pub` for `name@host`, with the epoch-gate + `relay_attest` check (§6.6/P0-D).

**Fleet-root recovery.** Offline root + geographically-separate encrypted backup; a **backup root cross-signs** the primary; M-of-N split a documented future option (OD-8).

### 6.5 Forward-secret sealing — X3DH, ident-signed prekeys, reference-counted retention

Adopts **X3DH per-message sealing** (§6.0) with recipient-side ephemeral prekeys and **no advancing chain state**. All primitives from libsodium.

**Identity scoping (P0-3).** Prekey bundles and identity keys are scoped to **`name@host`** — one keypair per logical agent, shared across live `#session` instances. A sender seals to the single `name@host` bundle; the home hub late-binds delivery to any live instance; `fanout=true` delivers the **same** sealed body to all live instances — no per-instance key ambiguity.

**Recipient prekey bundle:** carried in the **`AgentCert`** (`ident_pub`, root-anchored) + the home-hub-signed **`Keys`** record (`spk_pub`, `spk_sig`, `spk_epoch`, `opk[]`, `key_epoch`). **`spk_sig` is signed by the agent's own ident key** over `DS_SPK || ident_pub || spk_pub || spk_epoch || key_epoch` (§5.6 — now binds `ident_pub`+`key_epoch`, Minor). So neither a compromised home hub nor a relay can substitute a signed prekey without `ident_priv`.

**Reference-counted superseded-private retention (P1-5).** Retaining superseded privates lengthens the at-rest window — **disclosed, not claimed away.** Minimized by:
- **Reference-counting for already-received mail.** Per retired epoch, track received-but-not-yet-consumed messages referencing it; at zero-and-retired, **destroy the private immediately.**
- **Time window only for not-yet-arrived mail.** For messages still in-flight, retain until `MAX_LIFETIME + SKEW` past retirement, then destroy. This is the residual FS-degradation window.
- **Honest disclosure (G7/T-STRANDED).** An attacker imaging the recipient's disk **during** this window recovers privates for epochs retired within the last ≤ `MAX_LIFETIME + SKEW` and can decrypt still-outstanding messages sealed to them. Bounded, shortened by reference-counting, lowerable via `MAX_LIFETIME` (OD-6).
- Retained privates persisted (fsync'd) alongside `.done`; destroyed (best-effort secure-erase) on refcount-zero or window expiry.

**XEdDSA + per-use domain separation** (from the vetted library): signatures include their `DS_*` prefixes; X3DH HKDF `info` includes `DS_X3DH`. Pinned in App C + vectors.

**Sender (per message, one-shot):** generate ephemeral X25519 `EK`; select current `spk_pub` (verify `spk_sig` **against the AgentCert-bound `ident_pub`**) + one `opk` if available; compute `DH1=DH(IK_s,spk)`, `DH2=DH(EK,IK_r)`, `DH3=DH(EK,spk)`, `DH4=DH(EK,opk)?`; `SK=HKDF(DH1||DH2||DH3||DH4?||transcript, info=DS_X3DH)`; set `enc.*`, seal body with **AD = `aead_ad_v1(env)`** (§5.3). `EK` discarded; FS from message #1.

**Transcript binds RAW DH public-key bytes** (`IK_s_pub||IK_r_pub||spk_pub||opk_pub?||eph_pub || be32(key_epoch)||be32(spk_epoch)||be32(opk_id) || sender_key_id||recipient_key_id`) — UKS resistance. Note `eph_pub`/`nonce` are **additionally signed** in the envelope (§5.1), so relay tampering is a structural signature failure, not a decrypt failure.

**AEAD = XChaCha20-Poly1305** (192-bit random nonce; AD = `aead_ad_v1`). No advancing ratchet, no skipped-key cache.

**Rotation policy.** `spk` 7-day (private → reference-counted retention → destroy). `opk` single-use; home hub keeps pool ≥32; **opk-drain rate-limited per sender + rapid-drain alert (P2-2)**; on exhaustion, fall back to **spk-window FS** (never zero FS, never a decrypt failure). `ident`/`key_epoch` 90-day / 50k-msg / operator-forced; each bump publishes a new `AgentCert` (intermediate) + `Keys` record **and publishes the superseded `key_id`+`superseded_at` to the CRL** (P0-1/P0-D).

**Lowest-ever-published watermark (supports P1-3).** The home hub persists, per agent, the **lowest `spk_epoch`, lowest `key_epoch`, lowest live `opk_id`** ever published. An `enc.*` epoch/id **below** this floor can never resolve → permanently unresolvable structural fault (§8.5/§8.9/P1-3).

**Metadata sealing (T-META).** `seal_subject=true` moves `subject`/`thread_id`/`in_reply_to` inside the AEAD payload.

### 6.6 Rollback defense, epoch scoping, superseded-key acceptance with attestation (P0-1, P0-2, P0-4, P0-D)

- **Persisted highest-seen, scoped to `name@host` and record-type (P0-2/P0-4).** Each hub persists (fsync'd) the **highest `record_epoch` per (record-type, subject)** with **subject = `name@host`** for identity/`Keys`/message scope — never `#session`. Applies to `Keys`, `AgentCert`, `hub_record`, `HubCert`, `IssuerCert`, `Crl`, `bb_linkstate`: any validly-signed record with `record_epoch ≤ persisted` is **rejected as rollback**.
- **Message-signature epoch-gate (rewritten, P0-1/P0-D).** A verifier evaluating `auth.agent_sig` for sender `name@host`:
  - If `auth.key_id ∈ revoked_agent_key_ids` → **reject** (hard, any `created_at`, any attestation).
  - Else if `auth.key_id ∈ superseded_agent_key_ids` → **accept iff** `created_at < superseded_at` **and** `now ≤ created_at + MAX_LIFETIME` **and** a valid `relay_attest` exists with `ingress_time < superseded_at` (hub cert valid at `ingress_time`) **and** `superseded_at − ingress_time ≤ SUPERSESSION_GRACE`; else reject (P0-D).
  - Else if `auth.key_epoch <` persisted-highest `key_epoch` for `name@host` **and** the key is not in the CRL → unknown-old key: reject (rollback), pending propagation.
  - Else accept (current or plausibly-pending epoch), verified against the `AgentCert`-bound `ident_pub`.
- A key change backed by a higher-epoch, root-anchored `AgentCert` + rollback-checked `Keys` is accepted (except a new `AgentCert`/`HubCert` over an existing binding needs the possession-proof or the operator override, §6.4).
- A key change **not** backed by a higher-epoch cert is refused; the message is held + alerted.

### 6.7 No-directory / cross-org backstop

Operator confirms a short `ident_fp` out of band and pins it manually. The only path (besides the root/intermediate pin) that trusts a manually-supplied fingerprint.

### 6.8 Crypto-state durability, duplicates, verify-before-act, decrypt sub-classing (P0-A, P1-3, P1-2)

- **Verify-before-act.** Before any key op: verify `auth.agent_sig` (sender `name@host` `AgentCert` → intermediate → pinned root), `content_hash`, and the epoch-gate incl. `relay_attest` for superseded keys (§6.6/P0-D). Failure → quarantine (§8.9) + bounce, never surfaced.
- **Dedup before decrypt.** Persisted `msg_id` `.done` check first; a duplicate is a **no-op** and **re-emits the cached `consumed` receipt** (§8.2).
- **Crypto-durability durable set:** current `ident`/`spk`/`opk` privates; the reference-counted superseded-private retention ring; the consumed-`opk_id` set; persisted highest-seen `key_epoch`/`record_epoch` per `name@host`; the lowest-ever-published watermarks; the `.done`/dedup set (incl. the per-`msg_id` `ttl_hops` floor, §3.5/P0-C).
- **Atomic decrypt→consume transaction (fsync-ordered):** (1) verify+decrypt (AD=`aead_ad_v1`) using current-or-retained key; (2) single fsync'd step: record `msg_id` in `.done`, cache the re-emittable `consumed` receipt, settle the retention refcount, mark `opk_id` consumed; (3) remove the inbox file. Crash between steps re-derives idempotently via `.done`.
- **Decrypt-failure sub-classing (P1-3).** A signature-valid frame that fails to decrypt is classified:
  - **Permanently unresolvable → STRUCTURAL (drop + bounce, no retry):** `enc.spk_epoch`/`opk_id`/`key_epoch` **below the lowest-ever-published watermark**, a consumed-and-destroyed `opk` past retention, or a never-issued epoch. `Receipt{bounced, reason=undecryptable_unresolvable}`.
  - **Plausibly-pending → PROCESSING (temporal quarantine):** an epoch **≥ a plausibly-pending threshold** (record still propagating). Only these get the `POISON_RETRY_WINDOW` path (§8.9).

---

## 7. Addressing, Identity & Auth

### 7.1 Address grammar — `#session` is a hub-assigned delivery discriminator; identity fields are LDH/ASCII (P0-3, P2-K, Minor)

```
AgentAddr := name "@" host [ "#" session ]
  name    := LDH ASCII, lowercased        ([a-z0-9-], no leading/trailing '-')  — CRYPTO PRINCIPAL is name@host
  host    := LDH ASCII, lowercased        (machine / home-hub id)
  session := lowercase hex (128-bit)      (HUB-ASSIGNED at registration)
```

- **The cryptographic identity is `name@host`** (root-anchored via `AgentCert`, §6.4). All live sessions share one identity keypair (§6.5). `#session` distinguishes delivery targets, not crypto principals.
- **`name`/`host` are LDH/ASCII (new, P2-K).** Restricting identity fields to LDH removes NFC from the signing path (§5.1): two hubs on different ICU/Unicode versions can never produce divergent pre-images for identity fields. Non-conforming input is **rejected at ingress**, never normalized.
- **`session` is HUB-ASSIGNED.** The home hub assigns the hex session id; an agent cannot mint its own. The original `vincent` collision is fixed by **name-authority first-writer-wins + re-enroll possession-proof** (§6.4/§7.3/P1-7).

### 7.2 `to` without `#session` — live-instance selection

`to` MAY omit `#session`. The sender seals **once** to the `name@host` bundle; selection happens at the **home hub** at delivery time:
1. Home hub owns the inboxes + each instance's freshness beacon (§9).
2. **Default:** deliver to the one fresh (<60 s) instance.
3. **Multiple fresh:** most-recently-active, **or** fan to **all** live instances if `fanout=true` — the **same sealed body** to each. One `msg_id`; per-instance `.done`/consume tracked per inbox.
4. **None fresh:** **bounce** (dead-letter + receipt/alert), never a silent write into an untailed inbox.

### 7.3 Registration, enrollment & the directory — possession-proof, root-pin, lost-key override

- **Provisioning (P0-5).** At provisioning over the operator channel, the launcher drops: the agent's **identity keypair** (or one-time enrollment token) and, into the hub trust store, the **fleet root pubkey + intermediate `IssuerCert` + ≥1 backbone `HubCert`** (§6.4). The hub pins the root. The agent's `ident_pub` is registered and an **`AgentCert` is requested from the intermediate** over the operator-authenticated admin channel.
- **Challenge–response.** Every (re-)registration: the hub issues a fresh nonce; the agent returns `Ed25519_sign(ident_priv, DS_ENROLL || nonce || hub_id || timestamp)`. The hub signs the directory record only after verifying against the `AgentCert`-bound `ident_pub`.
- **Name-squat refusal (P1-7).** Re-binding an already-bound `name@host` under a different `ident_pub` requires the supersession possession-proof + CRL publish. First-writer-wins only on an unbound name.
- **Lost-key operator override (P1-G).** Over the operator channel, CRL-revoke the old `ident_pub` and have the intermediate issue a fresh `AgentCert`; the possession-proof is waived on this authenticated path (§6.4).
- Directory record = `{addr(name@host), home_hub, agentcert_ref, spk_pub, spk_epoch, opk[], key_epoch, capabilities, protocol_version, max_sig_projection_version, record_epoch, last_seen, hub_sig}`; rollback-checked by `record_epoch`.
- **Periodic self-re-register** every 5 min (TTL 30 min); stale → dead-man alert.

### 7.4 Intra-box trust boundary — container-per-agent (target) or honest concession (rewritten, P1-H)

Per §0.1, this is the **top-line operational risk.** rev6 either isolates or honestly concedes — no hand-waving:

- **Concrete isolation mechanism (the target) — container-per-agent PREFERRED.** rev6's recommended mechanism is **one container per agent** (Linux container / Windows container), each with its own filesystem view, its own `ident_priv` key store, and its own agent-boundary socket, the hub service brokering delivery across the container boundary. This is **cheaper and more portable** than the per-OS-user path and is the recommended near-term remediation. The per-OS-user path remains acceptable where containers are impractical:
  - **POSIX (per-user):** each agent a distinct OS user; `ident_priv`/inbox `0700`/`0600` owned by that user; hub service (separate user) writes deliveries and sets ownership/ACLs; per-user auth-env provisioning.
  - **Windows (per-user):** each agent a distinct local account; hub runs under a service account; per-delivery the service SID writes the inbox file and applies a per-agent DACL granting only that agent's SID; per-user hub-admin credential + per-user Claude auth-env provisioning. (Heavier; container-per-agent is preferred.)
- **Honest concession where not provisioned (P1-H).** The fleet's **current reality is multi-agent single-user Git-Bash boxes.** There, agents share one trust domain and **can read each other's `ident_priv` and pass each other's possession-proof** — so **G6/T3/T-REG are NOT met intra-box.** Such a box **runs `same_user_degraded`**, **detected/flagged at startup, logged, and alerted** (`/agents` reports `isolation=same_user_degraded`). Its agents are cross-box-unforgeable but **not intra-box-unforgeable.** Moving a box to **container-per-agent** is the remediation and is the first operator decision (OD-5).
- A **single-agent box** is trivially isolated.

### 7.5 Broadcast / groups — out of scope for v1

`to` is a single `AgentAddr`. Cross-agent fan-out is client-side; `fanout` covers live instances of **one** address (§7.2).

### 7.6 Per-agent auth + squat-resistant agent-boundary IPC

- One DACL'd Windows named pipe / `0600` UDS per hub (per container where isolated); **not** loopback TCP.
- **Squat resistance:** hub creates the pipe with `FILE_FLAG_FIRST_PIPE_INSTANCE` (fail-if-exists → detect squat, alert+refuse); each **client verifies the server's owner SID** before sending; POSIX equivalent via `0700` dir + owner-uid `stat` + `SO_PEERCRED`.
- Per-agent Ed25519 key; hub sets `from` from the authenticated identity, ignoring client-supplied `from`. Intra-box unforgeability holds **only** under §7.4 isolation (honestly bounded).
- Routing uses the loop-safe, progress-aware, corroborated-circuit-broken next-hop algorithm (§3.5).

---

## 8. Reliability, Queueing & Loop Prevention

### 8.1 Durability & the ack contract

- **Ack = durably persisted** (flushed) before acking the previous hop. **Relayed backbone hops additionally gate ack on a second downstream durable copy** (§3.5). The **signed `FwdAck`** (§3.5/P1-F) is emitted on this durable accept and drives circuit-breaker attribution.
- Disk-backed per-next-hop forward queue (journal + index) + spool; crash resumes from journal.

### 8.2 Receipts / bounces — split classes, mesh-routed reliable `consumed`, authenticated query, terminal (P1-2, P1-I, P2-L)

- **Hints — best-effort (droppable).** `Receipt{delivered}` (hub-signed) and advisory receipts: best-effort; if the return path fails, **dropped and logged** (surfaced in `/queues`). Never retried.
- **`consumed` — reliably delivered over the MESH (P1-2/P1-I).** `Receipt{consumed}` (recipient-agent `ident`-signed) is the end-to-end proof that survives a compromised terminal hub and may gate ordering. It is **disk-backed, retried with backoff, acked, and routed over the multi-backbone mesh with alternate-path failover exactly like a message** — **not** re-tried over a single return hop (a compromised/failed return backbone cannot silently stall it; on `FwdAck` loss it fails over to another backbone, §3.5/P1-I). It is **cached, keyed by `msg_id`, at the recipient**, so a **duplicate hitting `.done` re-emits the cached receipt.** Its loss is attributed **separately** from forward-path health and is **never** an input to backbone demotion (§3.5/P1-F).
- **Authenticated sender-initiated self-heal (P2-L).** On a `consumed` timeout for an `ordered`/`want_receipt` message, the sender's hub may issue a **`ConsumedQuery{msg_id, from, to}`** to the recipient's home hub **over the mutually-authenticated s2s session.** The recipient hub answers **only if** the querying hub is the **home-hub of the stored envelope's `from`** for that `msg_id` (bind-to-`from`) — so `ConsumedQuery` is **not** an open consumption-status oracle: a third party who can merely reach the home hub cannot probe whether an arbitrary `msg_id` was consumed, nor confirm its existence (unknown/unauthorized `msg_id` → uniform `unknown`). If authorized and `msg_id ∈ .done`, the recipient re-emits the cached `consumed` receipt.
- **Terminal-control invariant.** All receipts/bounces are **terminal control traffic**: never carry `want_receipt`, never receipt-tracked, never bounce-on-dead-letter. "Reliable delivery" of `consumed` (retry+ack+failover) is **not** "receipt-tracked": ultimate failure to deliver is **dropped+logged**, never a further bounce.
- `want_receipt` default-on drives the sender's delivery-confirmation timeout (retransmit/alert, or `ConsumedQuery` first).
- On dead-letter, a **bounce `Receipt{bounced, reason}`** is emitted whenever `msg_id` is recoverable, subject to the terminal-control invariant.

### 8.3 At-least-once + idempotent consume; persisted dedup; replay-amp bound (P2-7)

- **`msg_id` is the sole dedup/idempotency key**; terminal write atomic-replace-keyed by `msg_id`; duplicate → no-op (+ `consumed`-re-emit).
- **Persisted dedup set**, restart-surviving, storing the **per-`msg_id` `ttl_hops` monotonic floor** (§3.5/P0-C).
- **`expires_at` capped to `MAX_LIFETIME`** (24h); dedup set, `.done`, retention ring share the `MAX_LIFETIME + SKEW` GC clock.
- **Replay-amplification bound (P2-7).** Each ingress **rate-limits duplicate/near-duplicate `msg_id` injection per source socket**; past a threshold, the source is quarantined (§8.5). Noted in T6.

### 8.4 Loop prevention (P0-C)

1. **`len(route_trace) ≤ ROUTE_TRACE_CAP=16` is the hard, gen-independent, attacker-independent bound** — exceeded → drop + dead-letter (§3.5/P0-C bound 1).
2. **Per-`msg_id` monotonic `ttl_hops` floor** prevents a relay re-raising the budget (bound 2); ingress re-cap `min(received,16)` bounds first-injection inflation (bound 3). At 0 → drop + dead-letter.
3. **`route_trace`-with-gen is a progress guard within the cap**, not the primary bound: a revisit requires a strictly-newer gen *and* room under `ROUTE_TRACE_CAP`, so a self-signed monotonic `gen` cannot manufacture unbounded revisits.

### 8.5 Poison-message quarantine — early validation, structural vs processing (P1-3, Minor)

- **Early, cheap validation before expensive work:** parse frozen envelope → **validate `auth.agent_sig` + `content_hash` (and signed `enc.nonce`/`enc.eph_pub`) BEFORE any transcode/decrypt.** A parse-but-sig/hash-fail frame — including relay-tampered nonce/eph_pub (now signed, §5.1/Minor) — is a structural fault dropped immediately.
- **Fault classes:**
  - **Structural** (won't parse; sig/hash/signed-field invalid; **or unresolvable decrypt per §6.8/P1-3**) → **drop immediately; bounce if `msg_id`+verifiable-sender recoverable**, else drop+alert. **Never retried.**
  - **Processing** (parses, sig-valid, transient — a pending prekey **≥ plausibly-pending threshold**, a mid-deploy transcode bug, a temporarily unreadable spool) → **temporal quarantine** with `POISON_RETRY_WINDOW` (≤ `MAX_LIFETIME`) + periodic re-attempt; on give-up, dead-letter with a bounce.
- **Quarantine keying `(msg_id, content_hash)`** (both signed/immutable) so a one-byte mutation of a mutable field can't multiply entries.
- **Pre-parse flood defense:** rate-limit and, past a threshold, **quarantine/close the offending s2s source socket** + alert.
- **Persisted counters** fsync'd per fault. **No single frame may ever kill the daemon** (P0 conformance).

### 8.6 Ordering & anti-starvation — stop-and-wait on a mesh-reliable `consumed`; bounce fails the stream (P1-2, P1-I, P2-M)

- **`ordered=false` (default):** unordered delivery.
- **`ordered=true`: end-to-end stop-and-wait.** The sender's hub holds the next `(from,to)` message until the prior's **agent-signed, mesh-reliably-delivered `consumed` receipt** (§8.2/P1-2/P1-I) returns. Because `consumed` is mesh-routed + cached + queryable, a lost receipt **self-heals** instead of producing a false stall.
- **Bounded ordered-queue-depth bounce, with defined stream semantics (rewritten, P2-M).** `MAX_ORDERED_QUEUE_DEPTH=32`, `MAX_ORDERED_STALL=min(configured, MAX_LIFETIME)`. On hitting either **after** a `ConsumedQuery` confirms the head was genuinely *not* consumed, the oldest unconsumed head is **bounced** — and the **sender contract is: FAIL THE WHOLE `ordered` STREAM and surface it to the origin agent.** The sender **does not** silently retransmit the bounced message after its successors (which would violate FIFO/N2) and **does not** deliver its successors. It emits `Receipt{bounced, reason=ordered_stall}` **plus** a stream-level `ordered_stream_failed{from,to,first_unacked_msg_id}` error to the agent, and **aborts** the pair's ordered stream; the agent decides whether to restart it. Silent reordering is never performed — reordering defeats the only reason to request `ordered`.
- **Anti-starvation aging.** `bulk` effective priority rises with queue-wait (60 s/level), operating on the **signed** `priority` ceiling (§8.7/P1-1).

### 8.7 Bounds: body size, byte quotas, backpressure, chunking, eviction (P1-1, P2-J, Minor)

- **Max body size cap** default **8 MiB** inline; larger → `body_ref` chunked (§4.7). Over-cap rejected at ingress.
- **Byte quotas** per-hub spool+journal default **2 GiB** + per-next-hop depth. **Reassembly counts against it, plus the global `MAX_TOTAL_REASSEMBLY_BYTES=256 MiB` cap (§4.7/Minor).**
- **Eviction & shedding order (P1-1 + P2-J).** Watermarks:
  - **Soft watermark:** shed **oldest `bulk` first** (dead-letter + alert), then backpressure sending agents (`busy`), using the **signed** `priority` (relay adjustment clamped to the signed ceiling).
  - **Clock-uncertainty holds (P2-J):** while the clock is **unconfirmed** (no authenticated time, §5.4), quota-pressure eviction is **`bulk`-first, priority-aware** — an attacker who desyncs the clock cannot force eviction of high-priority mail.
  - **Hard watermark (P1-1):** once over the hard watermark **with a confirmed clock**, eviction is **priority-agnostic — evict the OLDEST regardless of class** (with alert), guaranteeing the spool can always drain even if every frame claims `interactive`. Signing `priority` blocks the rewrite; priority-agnostic hard eviction is the confirmed-clock backstop. (The two policies compose: unconfirmed clock ⇒ bulk-first; confirmed clock at hard watermark ⇒ oldest-agnostic.)
- **opk-consumption rate-limit (P2-2)** and **duplicate-`msg_id` source rate-limit (P2-7)** enforced here.
- **Max frame size** default 9 MiB. No unbounded crypto cache; the retention ring is O(tens) of key blobs (§6.5).

### 8.8 Retry, backoff, dead-letter

Exponential backoff + jitter (1s→…→5 min), bounded by `expires_at` (+skew, hard-capped by `MAX_LIFETIME`). Give-up → dead-letter + alert + bounce (§8.2). Acks by `msg_id`; statuses `OK`/`RETRY`/`DROP`/`RETRY_UNSUPPORTED`. **On an unconfirmed (unauthenticated-time) clock, give-up biases to hold-and-alert, not dead-letter (§5.4/P2-J).**

### 8.9 Agent-side poison / undecryptable / unverifiable handling — immediate on verification failure (P1-3, Minor)

- **Verification failures are STRUCTURAL and quarantine+bounce IMMEDIATELY — no N retries (rewritten, Minor).** A bad `auth.agent_sig`/`content_hash`/signed-`nonce`/`eph_pub`, or an epoch-gate/`relay_attest` reject (§6.6/P0-D), is a **deterministic failure against a stable input** — retrying cannot change the outcome. The `Monitor` **moves it to `…/inbox/.poison/` and bounces on the first occurrence**, no N=3 counter. (rev5's "N=3 → .poison" applied *only* to genuinely environmental/transient processing faults; rev6 makes that scoping explicit and removes the contradiction the reviewer flagged.)
- **Decrypt failures are sub-classed (P1-3):** **below the lowest-ever-published watermark (permanently unresolvable) → STRUCTURAL, immediate bounce `undecryptable_unresolvable`, no retry;** **at/above the plausibly-pending threshold (record maybe still propagating) → a bounded re-attempt window** (this is the *only* agent-side case that retries) before quarantine, then bounce `undecryptable`.
- **Bounce via the hub admin API** `POST /agent/undeliverable {msg_id, reason}` (agent-key-authenticated on the local admin socket) → hub emits `Receipt{bounced, reason}` subject to the terminal-control rule.
- Quarantines recorded in `/queues` counters.

---

## 9. Health / Observability (freshness-based)

- **Freshness beacons, not port checks.** Health is `now − last_progress`.
- **Agent liveness beacons** drive live-instance selection (§7.2) + staleness.
- **Backbone-socket liveness.** App-level `Ping/Pong` (30s; downstream link-state ping 5s). Missed N → mark dead, promote/redial, alert, gossip fresh `bb_linkstate`. **Corroborated, `FwdAck`/probe-driven circuit-breaker state (§3.5/P1-F) is reported in `/peers` per `(backbone,destination)`** with demotion alerts and the **corroboration count** (which/how-many distinct destinations drove a demotion).
- **Periodic self-re-register** (§7.3).
- **Dead-man's switch / absence-of-signal** for each expected signal (agent re-register, backbone ping, link-state freshness, `FwdAck`/probe liveness, queue heartbeat, **CRL `next_update` freshness**, **root-pin + intermediate-`IssuerCert` presence**, **authenticated-time sync freshness** — §5.4/P2-J). Telegram only for what Wolf can't self-fix.
- **Authenticated introspection.** `/health`,`/agents`,`/queues`,`/peers` bound to the local admin channel; not unauthenticated over s2s/tailnet. `/agents` reports **isolation posture per box** incl. `same_user_degraded` (§7.4/P1-H). `/peers` reports link-state table + freshness, `backbone_count`, `directory_stale`, **per-destination circuit-breaker demotions + corroboration counts (P1-F)**, and `av_unexcludable` legs (§4.5/P2-P). `/queues` reports depth/oldest-age/byte-usage/dead-letter/quarantine (structural vs processing, below-watermark-unresolvable, agent-side poison, reassembly timeouts, dropped hint-receipts, held-on-unconfirmed-clock counts, sharing-violation stalls).
- **EADDRINUSE guard.** Multi-probe reap (3×, ≥5s, + grace + no queue-drain). **A pre-existing named pipe fails `FILE_FLAG_FIRST_PIPE_INSTANCE` → squat → alert + refuse, not auto-reap (§7.6).**

---

## 10. Security Threat Model

| # | Threat | Vector | Mitigation |
|---|---|---|---|
| T1 | Bootstrap MITM / key substitution | Attacker injects own pubkey on cleartext first leg | **Root-anchored** key acquisition: recipient `AgentCert` (intermediate→pinned root) + hub `Keys` (§6.3/§6.4); no inline-pubkey trust; X3DH prekey handshake (§6.5). |
| T2 | Encryption strip / downgrade | Peer forces mode=NONE; HELLO omits crypto; projection downgrade; **hub withholds `Keys`** | Fail-closed `require_e2e` signed (§6.3); **valid `AgentCert` ⇒ E2E mandatory, missing prekeys ⇒ hold+alert, never plaintext (§6.1/§6.3/P0-E)**; no plaintext-transport across backbone (§6.1/6.2); HELLO-in-session transcript-MAC (§6.2); per-field projection floors + downgrade alerts + advertise-then-enforce (§5.1/P2-4/P2-O). |
| T3 | `from` spoofing on shared local endpoint | One local agent claims another's identity | Per-agent signing key + hub-set `from` + `auth.agent_sig` (§7.6); squat-resistant pipe/UDS (§7.6/T9). **Intra-box unforgeability holds under §7.4 isolation (container-per-agent preferred); on current single-user boxes HONESTLY CONCEDED as not met — cross-box only (§0.1/§7.4/P1-H).** |
| T4 | Relay reading/forging payload | Backbone or hub compromised | E2E default-on, first-message FS (§6.1/6.5); **AEAD AD = `aead_ad_v1` (content-hash-free, computable) prevents transplant (§5.3/P0-A)**; **recipient verifies `auth.agent_sig` (root-anchored `AgentCert`) before acting (§6.8)**; signed `enc.nonce`/`eph_pub` make relay tampering a structural fault (§5.1/Minor); relays validate sig/hash early (§8.5); **mesh-reliable agent-signed `consumed` receipts** so a compromised hub can't forge/black-hole delivery (§8.2/P1-2/P1-I). Metadata caveat: `subject`/`thread_id`/`in_reply_to`/`size`/`to` relay-visible unless sealed (§6.5, T-META). |
| T-HUBROOT | **Home-hub compromise vs its own agents** | Home hub is key-distributor AND relay | **Agent identity root-anchored via `AgentCert` (intermediate, NOT the home hub); `spk_sig` by the agent's own ident key (§6.4/§6.5/P0-E).** A compromised home hub therefore **cannot** forge identity or decrypt `AgentCert`-covered E2E; it **can** deny (withhold relay/prekeys → hold+alert) and read **plaintext-fallback mail predating an `AgentCert`**. **Stated plainly (P0-E).** |
| T5 | Loops / amplification | Misrouting, directory cycles, receipt loops | **`ROUTE_TRACE_CAP` hard gen-independent bound + per-`msg_id` `ttl_hops` monotonic floor + ingress re-cap (§3.5/§8.4/P0-C)**; persisted `msg_id` dedup (§8.3); receipts/bounces terminal (§8.2). |
| T6 | Replay / replay-amplification | Re-inject captured envelope at many backbones | Persisted `msg_id` dedup within hard-capped lifetime (§8.3); signed `created_at` + **hub `relay_attest` (§6.6/P0-D)**; persisted highest `record_epoch`/`key_epoch` (§6.6); per-source duplicate-`msg_id` ingress rate-limit + source-socket quarantine (§8.3/§8.5/P2-7). |
| T7 | Backbone SPOF / DoS / durability / **routing-trust** | Backbone down, flooded, disk-lost, **or lying about link-state / dropping to frame an honest peer** | Full mesh + failover + link-state re-forwarding (§3.5); **corroborated, `FwdAck`/probe-driven circuit-breaking — demotion needs multi-destination corroboration of a FORWARD-attributable signal, never a single confounded end-to-end receipt (§3.5/P1-F)**; **reliable `consumed` mesh-routed with alternate-path failover (§8.2/P1-I)**; residual: bounded transient loss/latency until probes demote a liar; single-backbone + in-flight-durability SPOFs disclosed (`backbone_count`, second-copy-before-ack); quotas + `bulk` shed + priority-agnostic hard eviction (§8.7/P1-1). |
| T8 | Address squat / directory impersonation | Rogue signs `secondbrain@…` | PKI (root→intermediate→leaf) + name-authority binding + short certs + supersession possession-proof + **freshness-checked CRL with enumerated fail-closed set (§6.4/P1-6)** + **every-record `record_epoch` rollback defense (§6.6/P0-4)**. |
| T9 | Local access / pipe squat | Another user connects or squats the pipe | `FILE_FLAG_FIRST_PIPE_INSTANCE` + client server-SID verification (§7.6); `0600` UDS in `0700` dir + peer-cred. |
| T10 | Token/key leakage on disk | Local file exposure | Per-agent keys under per-agent isolation **where provisioned (container-per-agent, §7.4)**; enrollment via operator channel + possession-proof (§7.3); OOB-pinned root + intermediate (§6.4); transport always encrypted; **reference-counted retention limits at-rest blast radius, FS-degradation HONESTLY DISCLOSED (§6.5/P1-5)**. |
| T11 | Stale/wedged node accepted as healthy | Port held, no progress | Freshness health; multi-probe reaper; squat-not-reap for pipes (§9/§7.6); dead-man switches incl. CRL + link-state + root/intermediate-pin + authenticated-time freshness. |
| T-META | Metadata leakage to relays | `subject`/`thread_id`/`in_reply_to`/`size`/`to` visible under E2E | Documented (§6.5); `seal_subject` seals `subject`/`thread_id`/`in_reply_to`; `size`/routing addrs relay-visible — called out (`size` signed so it can't be quota-weaponized, §5/P1-1). |
| T-POISON | Poison-message DoS | Always-faulting frame, mutating flooder, unresolvable-decrypt pin, **relay nonce-flip** | Early sig/hash + **signed-nonce/eph_pub** validation (relay flip ⇒ structural, not recipient poison — §5.1/Minor); `(msg_id, content_hash)` quarantine; source-socket rate-limit; structural-vs-processing split; below-watermark decrypt = STRUCTURAL (§8.5/§8.9/P1-3); **verification failures quarantine+bounce IMMEDIATELY, no N=3 (§8.9/Minor)**; loop never aborts. |
| T-REG | Registration hijack / name re-squat / **lost-key lockout** | Unauthenticated reg; rebinding an offline name; **agent box dies with `ident_priv`** | Operator-provisioned credential + per-registration possession-proof (§7.3); rebinding an already-bound `name@host` requires supersession possession-proof + CRL publish (§6.4/§7.3/P1-7); **lost-`ident_priv` recovery = operator/root override: CRL-revoke old + intermediate issues fresh `AgentCert`, possession-proof waived on the authenticated channel (§6.4/§7.3/P1-G)**; hub-assigned `#session` blocks session-minting (§7.1). Intra-box: bounded by §7.4 concession (P1-H). |
| T-ROLLBACK | Rollback across restart | Replay a superseded but validly-signed record/signature | Persisted highest `record_epoch`/`key_epoch` per **`name@host`** (§6.6/P0-2), reject `≤ persisted`, for **every gossiped record type** (§6.6/P0-4). |
| T-ROTREVOKE | Post-rotation impersonation via a **backdated** superseded key | Leaked old `ident_priv` signs new mail, `created_at` backdated | **Hub-attested supersession gate:** accept a `superseded`-key signature only with a valid `relay_attest.ingress_time < superseded_at` (hub-key timestamp the agent can't forge) within `SUPERSESSION_GRACE ≪ MAX_LIFETIME`; hard-reject `revoked` keys; suspected leaks MUST use `revoked` (§6.4/§6.6/P0-D). Backdating `created_at` no longer opens a window. |
| T-STRANDED | In-flight mail undecryptable after rotation | Sealed to an epoch that rotated before arrival | Reference-counted superseded-private retention (§6.5/§6.8); signature accepted for attested pre-supersession mail (§6.6/P0-D); FS degradation disclosed (P1-5). |
| T-BOOTSTRAP | Fresh hub trusts a forged root/backbone | No a-priori root knowledge | OOB root-pin (root pubkey + intermediate `IssuerCert` + ≥1 backbone `HubCert`); unpinned/mismatched ⇒ fail-closed (§6.4/§7.3). |
| T-ORACLE | Consumption-status probing | Unauthenticated `ConsumedQuery` | **Authenticated over the s2s session + answered only when the querying hub is the stored `from`'s home-hub (bind-to-`from`); unknown/unauthorized ⇒ uniform `unknown` (§8.2/P2-L).** |
| T-TIME | Unauthenticated NTP as a DoS lever | On-path attacker desyncs a hub's clock | Only **authenticated time (NTS/roughtime)** flips the trusted bit; unconfirmed clock ⇒ hold-and-alert with **`bulk`-first** eviction (§5.4/§8.7/P2-J). |
| T-INTERMED | **Intermediate-CA compromise** | Online issuer key stolen | Disclosed residual (P0-E/P2-N): distinct key + access path, short-lived certs, append-only issuance-transparency log, offline root revokes+replaces the intermediate. Not eliminated. |

Trust boundary summary: **crypto is built from vetted primitives with minimized, test-vector-gated bespoke surfaces — the length-prefixed TLV signing pre-images for BOTH the envelope (two variants: `sign_input_v1` and the content-hash-free `aead_ad_v1`) AND every PKI/directory record (§5.1/§5.6/§6.0); NFC is out of the signing path (§5.1)**; **transport is never cleartext (Phase 2) with session-authenticated capability negotiation**; **relays are trusted for routing but NOT for payload, delivery-attestation, sender-binding, quota-priority, or blind availability claims** (E2E default-on + AEAD-bound envelope + recipient-verifies-before-acting against a root-anchored `AgentCert` + mesh-reliable agent-signed `consumed` + signed `priority`/`size`/`nonce`/`eph_pub` + corroborated forward-ack circuit-breaking); **agent identity is root-anchored via an offline-root→online-intermediate→`AgentCert` chain, so the home hub is NOT the identity voucher (P0-E)**; **the directory root is an OOB-pinned PKI with name-authority binding, short-lived certs, freshness-checked revocation with an enumerated fail-closed set, per-record rollback-resistant epochs scoped to `name@host`, and rotation-≡-hub-attested-superseded-gated-revocation**; **intra-box per-agent unforgeability holds under provisioned isolation (container-per-agent) and is HONESTLY CONCEDED as unmet on current single-user boxes (the #1 operational risk, §0.1).**

---

## 11. Phased Implementation Roadmap

**Phase 0 — Contracts & scaffolding.** Freeze `agentmail.v1` `.proto` (frozen routing envelope + control frames incl. `Chunk`/`Receipt`/`LinkState`/`Gossip`/`ConsumedQuery`/`FwdAck`/`RelayAttest`; flags `optional`; `RouteHop{hub_id, linkstate_gen}`; `priority`/`size`/`enc.nonce`/`enc.eph_pub` signed). Pin the **length-prefixed TLV pre-images**: **envelope `sign_input_v1` AND `aead_ad_v1` (content-hash-free) variants (P0-A)**, fixed field order, presence bytes, fixed-width integers, **LDH/ASCII identity fields with reject vectors (no NFC in the path, P2-K)**, raw-`content_hash`, per-field projection floors + **advertise-then-enforce gate (P2-O)**; **AND every PKI record pre-image — `IssuerCert`/`HubCert`/`AgentCert`/`Keys`/`spk_sig`(binds ident_pub+key_epoch)/`Crl`/`HubRecord`/`LinkState`/`FwdAck`/`RelayAttest` (§5.6/P0-B)** — all with cross-language byte-for-byte test vectors (flag-materialization, unknown-version-reject, floor-refusal, both AEAD-AD + signing variants, transcript-raw-pubkey, domain-separation). Schemas for `IssuerCert` + `AgentCert` + `Keys`(X3DH bundle, `name@host`-scoped) + `Crl`(`next_update`+`superseded_keys`+`revoked_agent_key_ids`) + `HubRecord`(`record_epoch`) + `bb_linkstate` + `RelayAttest`. Integer `protocol_version` + `capabilities` + `max_sig_projection_version`. **Select and vendor vetted crypto libraries (libsodium binding + Noise-IK impl) per language (§6.0).** Stand up the **offline root + root-constrained online intermediate issuing CA + issuance-transparency log (P0-E/P2-N)** and the **OOB root/intermediate-pin provisioning procedure**; issue initial short-lived `HubCert`s + `AgentCert`s. No behavior change.

**Phase 1 — Durable local hub daemon.** Boot-started service (systemd / NSSM / launchd). Per-agent inbox dirs + `notify.jsonl` (rotation + torn-append durability) + per-agent `Monitor` (liveness beacons; **readers open with `FILE_SHARE_DELETE`, P2-P**; agent-side poison/verify quarantine incl. **immediate structural bounce on verification failure, no N=3 (§8.9/Minor)** and **below-watermark structural drop, P1-3**). Operator-enrolled per-agent identity keys + `AgentCert` issuance + per-registration possession-proof + **lost-key operator override (P1-G)** + hub-assigned `#session` + name-squat refusal (P1-7) over the squat-resistant pipe/UDS. **Provision isolation: container-per-agent where possible (preferred, P1-H); per-user where containers are impractical; on unsupported single-user boxes flag `same_user_degraded` at startup + alert.** **Pin fleet root + intermediate `IssuerCert` + bootstrap backbone `HubCert`.** Windows-correct atomic-replace + write-through + FlushFileBuffers + `msg_id`-atomic file+pointer + **bounded/escalating sharing-violation retry + `av_unexcludable` degrade-and-alert (P2-P)** (§4.5). Freshness health + self-re-register + **authenticated-time (NTS/roughtime) client (P2-J)**. **Direct delivery still the transport.**

**Phase 2 — Federation + backbone + MANDATORY transport encryption.** Protobuf s2s over **vetted Noise-IK/TLS** with in-session authenticated HELLO; persistent outbound backbone sockets; **all gossip on the encrypted mesh with per-record `record_epoch` rollback checks**; the **backbone mesh + link-state + loop-safe next-hop with `ROUTE_TRACE_CAP` + per-`msg_id` `ttl_hops` floor (P0-C) + corroborated `FwdAck`/probe circuit-breaking (P1-F) + second-copy-before-ack + directory-freshness fail-safe**; large-body chunking (**per-sender + global `MAX_TOTAL_REASSEMBLY_BYTES` caps, Minor**); disk-backed forward queues with durable-before-ack; acks, retry/backoff, TTL/`route_trace`/persisted `msg_id` dedup + expiry cap + duplicate-`msg_id` source rate-limit; poison quarantine; byte quotas + **signed-`priority` clamp + clock-aware/`bulk`-first + priority-agnostic hard eviction (P1-1/P2-J)**. **Conformance gate:** cross-language pre-image vectors (envelope + all records) **and a power-loss crash test (incl. open-reader replace, P2-P)**. Per-leg cutover. No plaintext-transport across a backbone.

**Phase 3 — E2E DEFAULT-ON (X3DH) + receipts + rollback/revocation hardening.** Directory-published `AgentCert` + signed `Keys` bundles (`name@host`-scoped, ident-signed `spk_sig`); **X3DH per-message sealing with `aead_ad_v1` AD (P0-A) + reference-counted retention + honest FS disclosure (P1-5)**; **mandatory recipient verify against root-anchored `AgentCert` (P0-E)**; transcript raw-pubkey binding + XEdDSA domain separation; XChaCha20-Poly1305; fail-closed `require_e2e` + **hold-not-plaintext on withheld prekeys (P0-E)**; **hub-attested `superseded_at` signature gate + `RelayAttest` at ingress (P0-D) + persisted highest `record_epoch`/`key_epoch` (name@host-scoped) + rotation-publishes-to-CRL**; **freshness-checked CRL with enumerated fail-closed set (P1-6)** + supersession possession-proof; **lowest-ever-published watermark + decrypt-failure sub-classing (P1-3)**; **opk-consumption rate-limit (P2-2)**. **E2E default-on.** **Split receipt classes: mesh-reliable agent-signed `consumed` (cached/re-emit/authenticated-`ConsumedQuery`, alternate-path failover — P1-2/P1-I/P2-L) + best-effort hints, all terminal.** **End-to-end stop-and-wait `ordered` on the mesh-reliable `consumed`; ordered-stall bounce FAILS THE STREAM to the agent (P2-M).** Metadata-sealing option (T-META). Crash-safe verify→decrypt→consume (§6.8). **Any new signed security field ships advertise-then-enforce (P2-O).**

**Phase 4 — Optimization & polish.** Direct-s2s legs, ordering-knob validation, quota tuning, richer `/metrics`, notify-rotation tuning, circuit-breaker + corroboration-threshold tuning. Optional M-of-N root custody.

**Phase 5 — Deprecate direct-only paths.** Once all hubs advertise `federation`, make backbone routing default, direct s2s a pure optimization, remove hand-relay (garrison).

Each phase is independently shippable. Backward compat via integer `protocol_version` + capability negotiation (directory-mediated, incl. `max_sig_projection_version` + per-field floors + advertise-then-enforce): direct pairs speak the highest common version; backbones relay any parseable version; the frozen envelope + additive-only evolution (security/routing fields signed in the same change, P2-6) + directory-mediated versioned pre-image + unknown-version nack keep mixed-language, three-party relay safe.

**Windows durable-daemon mechanism (decided): NSSM-wrapped service.**

---

## 12. Open Decisions for Hex

Security-critical decisions (E2E default, rekey policy, retention-vs-delivery, isolation posture, off-the-shelf-vs-bespoke, **online-intermediate-CA vs offline-only**) are **decided in the body** (§0/§6.0/§6.1/§6.4/§6.5/§7.4). The sharpest still-unresolved trade-offs surfaced by the adversarial rounds are captured below.

- **OD-1. Second backbone host (gates T7's mesh; SPOF until resolved).** Second cheap cloud VM, or expose services-vm via a stable tailnet/Funnel address. Which host? *(Until resolved the fleet runs `backbone_count=1` — a disclosed single point of failure.)*
- **OD-2. Transport crypto: vetted Noise-IK vs TLS 1.3.** Lean **Noise-IK.** Confirm?
- **OD-3. Hub implementation language + the vetted crypto binding per language.** Node today? Go/Rust for the daemon?
- **OD-4. Cadences.** 5 min re-register / 30 min TTL; beacon-TTL 60 s; `spk` 7-day; `opk` pool ≥32; `ident` 90-day/50k; backbone ping 5 s / `LINKSTATE_TTL` 15 s; **`CB_MIN_DISTINCT_DESTINATIONS`=2 + demotion threshold (P1-F)**; **`SUPERSESSION_GRACE`=1 h (P0-D)**; **`ROUTE_TRACE_CAP`=16 (P0-C)**. Acceptable or tighter?
- **OD-5. Intra-box isolation reality — THE #1 OPERATIONAL RISK (§0.1/§7.4/P1-H).** Confirm the plan to move current single-user boxes to **container-per-agent** (preferred remediation), and which boxes run `same_user_degraded` (honestly not meeting G6/T3 intra-box) until then. This is a disclosed status, not a silent default — confirm the list and the container rollout.
- **OD-6. Byte-quota / max-body / chunk-concurrency / `MAX_LIFETIME` / global reassembly cap.** 8 MiB inline, `MAX_INFLIGHT_CHUNKED_PER_SENDER`=4, `MAX_TOTAL_REASSEMBLY_BYTES`=256 MiB, 2 GiB spool, `MAX_LIFETIME`=24h (= dedup = `.done` = **retention-ring window = the disclosed residual FS window, P1-5**). Lowering `MAX_LIFETIME` **directly shrinks the FS residual**.
- **OD-7. Skew + clock-jump + authenticated time (§5.4/§8.7/P2-J).** `SKEW`=5 min; `CLOCK_SETTLE_MAX`=10 min; **only NTS/roughtime flips the trusted bit; unconfirmed ⇒ hold-and-alert + bulk-first eviction.** Which authenticated-time source (NTS server vs roughtime)?
- **OD-8. PKI custody (§6.4/P0-E/P2-N).** Offline root + cross-signed backup + **online intermediate issuing CA** (accepted trade for removing monthly ceremonies; residual = intermediate-compromise, disclosed T-INTERMED). Confirm the online-intermediate posture, or require offline-only issuance (heavier ceremonies) instead? M-of-N root split later?
- **OD-9. Backbone ack-durability posture (§3.5/§8.1).** Default: relayed hops require a second downstream durable copy; terminal-attached single-copy-then-ack. Accept, or set `backbone_ack_requires_second_copy=true` globally?

---

## Appendix A — Key protobuf sketch (agentmail.v1)

```proto
syntax = "proto3";
package agentmail.v1;

// NOTE: protobuf wire bytes AND canonical CBOR are NEVER signed/hashed — for the envelope
// OR any PKI/directory record. Envelope: auth.agent_sig over sign_input_v1 (incl. content_hash,
// enc.nonce, enc.eph_pub); AEAD associated-data over the CONTENT-HASH-FREE aead_ad_v1 variant
// (breaks the content_hash<->AD cycle, §5.1/§5.3/App C). Records: each *_sig over its own
// length-prefixed TLV sign_input_<type> (§5.6/App C). No map sorting, no CBOR mode, no NFC,
// no implicit default — fixed field order + explicit presence bytes + fixed-width integers +
// LDH/ASCII text.

message Frame {
  oneof kind {
    Hello     hello     = 1;
    Keys      keys      = 2;
    MessageFrame msg     = 3;
    Ack       ack       = 4;
    Ping      ping      = 5;
    Receipt   receipt   = 6;   // TERMINAL; consumed = mesh-reliable, delivered/hints = best-effort (§8.2)
    Chunk     chunk     = 7;
    LinkState linkstate = 8;
    Gossip    gossip    = 9;
    ConsumedQuery cquery = 10; // authenticated, bind-to-from (§8.2/P2-L)
    FwdAck    fwdack    = 11;  // signed forward-path ack; circuit-breaker attribution (§3.5/P1-F)
  }
  // Unknown/empty oneof on an older hub => nack RETRY_UNSUPPORTED, never silent-drop (§4.6).
}

message MessageFrame { Envelope env = 1; }
message RouteHop { string hub_id = 1; uint64 linkstate_gen = 2; } // len(route_trace) <= ROUTE_TRACE_CAP (§3.5/P0-C)

message Envelope {
  string msg_id = 1;
  uint32 protocol_version = 2;
  AgentAddr from = 3;                 // crypto principal name@host; #session is a delivery discriminator (§7.1)
  AgentAddr to = 4;
  AgentAddr reply_to = 5;             // sender-OWNED name@host only (§5.2); in pre-image
  string thread_id = 6;              // relay-visible unless sealed
  string in_reply_to = 7;            // relay-visible unless sealed
  string subject = 8;                // relay-visible unless sealed; ADVISORY, never gates a decision
  string content_type = 9;           // registered ASCII token (§5.1/P2-K)
  oneof payload { bytes body = 10; string body_ref = 11; }
  uint32 size = 12;                  // SIGNED
  string content_hash = 13;          // sha256 of ON-WIRE bytes; in sign_input, EXCLUDED from aead_ad (P0-A)
  int64  created_at = 14;            // gates superseded-key acceptance jointly with relay_attest (§6.6/P0-D)
  uint32 ttl_hops = 15;              // excluded from signature; per-msg_id monotonic floor + ingress re-cap (P0-C)
  int64  expires_at = 16;            // clamped <= created_at + MAX_LIFETIME
  repeated RouteHop route_trace = 17;// append-only; len <= ROUTE_TRACE_CAP=16 hard bound (§3.5/P0-C)
  Priority priority = 18;            // SIGNED (P1-1)
  optional bool want_receipt = 22;   // default true
  optional bool require_e2e = 23;    // default false; fail-closed (§6.3)
  optional bool ordered = 24;        // default false; stop-and-wait on mesh-reliable consumed (§8.6)
  optional bool fanout = 25;         // default false; same sealed body to all live instances (§7.2)
  bool seal_subject = 26;            // seal subject/thread_id/in_reply_to (not signed)
  EncMeta enc = 19;
  AuthMeta auth = 20;
  RelayAttest relay_attest = 27;     // hub ingress attestation; REQUIRED to accept a superseded-key sig (§6.6/P0-D)
  map<string,string> headers = 21;   // NON-security hints; NOT in any pre-image; MUST NOT gate a decision
}

message AgentAddr { string name = 1; string host = 2; string session = 3; } // LDH/ASCII; session HUB-ASSIGNED (§7.1)
enum Priority { BULK = 0; NORMAL = 1; INTERACTIVE = 2; }

message EncMeta {
  Mode   mode = 1;
  string alg = 2;                    // "xchacha20poly1305"
  string sender_key_id = 3;          // IK_sender (name@host-scoped); ASCII
  string recipient_key_id = 4;       // IK_recipient (name@host-scoped); ASCII
  uint32 key_epoch = 5;              // in pre-image
  uint32 spk_epoch = 6;              // in pre-image
  uint32 opk_id = 7;                 // 0 reserved/none; in pre-image
  bytes  eph_pub = 8;                // SIGNED (in sign_input & aead_ad) — relay flip => structural fault (Minor)
  bytes  nonce = 9;                  // 192-bit; SIGNED (in sign_input & aead_ad) — relay flip => structural fault (Minor)
  enum Mode { NONE = 0; ENC = 1; }
}

message AuthMeta {
  uint32 sig_projection_version = 1;
  bytes  agent_sig = 2;              // Ed25519 (DS_AUTH) over sign_input_v1 (§5.1)
  string key_id = 3;                 // agent ident key id (name@host) -> AgentCert -> intermediate -> pinned root
  uint32 key_epoch = 4;              // epoch-gated per §6.6/P0-1/P0-D; in pre-image
}

message RelayAttest {                // §6.6/P0-D: hub-key ingress timestamp the leaked agent key cannot forge
  string msg_id = 1; int64 ingress_time = 2; string hub_id = 3;
  bytes  hub_sig = 4;                // over sign_input_relayattest (§5.6)
}

message Ack { string msg_id = 1; Status status = 2;
  enum Status { OK = 0; RETRY = 1; DROP = 2; RETRY_UNSUPPORTED = 3; } }
message Ping { int64 ts = 1; }
message ConsumedQuery { string msg_id = 1; AgentAddr from = 2; AgentAddr to = 3; } // authenticated; bind-to-from (P2-L)
message FwdAck { string msg_id = 1; string next_hop = 2; int64 at = 3; string hub_id = 4; bytes sig = 5; } // §3.5/P1-F

message Hello {
  string hub_id = 1;
  uint32 protocol_version = 2;
  repeated string capabilities = 3;  // "federation","e2e","noise","chunk","linkstate","gossip","fwdack","agentcert"
  bool   backbone = 4;
  repeated string backbones = 5;
  uint32 max_sig_projection_version = 6;
}

message LinkState {
  string backbone_id = 1;
  repeated string live_downstream = 2;
  uint64 gen = 3;                     // monotonic; persisted-highest-checked (§6.6)
  int64  emitted_at = 4;              // stale > LINKSTATE_TTL => unknown
  bytes  sig = 5;                     // over sign_input_linkstate (§5.6/P0-B)
}

message Gossip { bytes record = 1; RecordType type = 2;
  enum RecordType { DIRECTORY=0; KEYS=1; HUBCERT=2; CRL=3; HUBRECORD=4; LINKSTATE=5; AGENTCERT=6; ISSUERCERT=7; } }

message Chunk { string msg_id = 1; uint32 index = 2; uint32 total = 3; bytes bytes = 4; string chunk_hash = 5; }

message IssuerCert {                  // offline ROOT signs ONLY this (§6.4/P0-E/P2-N)
  string issuer_id = 1;
  bytes  issuer_pubkey = 2;
  repeated string name_authority_constraints = 3;
  int64  not_after = 4;
  uint64 record_epoch = 5;
  bytes  root_sig = 6;               // over sign_input_issuer (§5.6)
}

message HubCert {                     // issued by the INTERMEDIATE (§6.4)
  string hub_id = 1;
  bytes  hub_pubkey = 2;
  repeated string allowed_name_authority = 3;
  int64  not_after = 4;              // SHORT (default 30d)
  uint64 record_epoch = 5;
  string issuer_id = 6;
  bytes  cert_sig = 7;               // intermediate; over sign_input_hubcert (§5.6/P0-B)
}

message AgentCert {                   // ROOT-ANCHORED agent identity binding (intermediate); NOT the home hub (P0-E)
  AgentAddr addr = 1;                 // name@host (no #session)
  bytes  ident_pub = 2;
  uint32 key_epoch = 3;
  int64  not_after = 4;
  uint64 record_epoch = 5;
  string issuer_id = 6;
  bytes  cert_sig = 7;               // intermediate; over sign_input_agentcert (§5.6/P0-B)
}

message Keys {                        // home-hub prekey bundle; spk_sig is by the AGENT ident key (§6.5)
  AgentAddr addr = 1;                 // name@host (§7.1/P0-3)
  bytes  ident_pub = 2;               // MUST match the AgentCert-bound ident_pub
  bytes  spk_pub = 3;
  bytes  spk_sig = 4;                 // AGENT Ed25519 over (DS_SPK||ident_pub||spk_pub||spk_epoch||key_epoch) (§5.6, Minor)
  uint32 spk_epoch = 5;
  repeated OneTimePrekey opk = 6;     // ids >= 1
  uint32 key_epoch = 7;
  string ident_fp = 8;
  uint64 record_epoch = 9;
  bytes  hub_sig = 10;                // home hub; over sign_input_keys (§5.6/P0-B)
}
message OneTimePrekey { uint32 opk_id = 1; bytes opk_pub = 2; }

message SupersededKey { string key_id = 1; int64 superseded_at = 2; } // §6.4/§6.6/P0-D
message Crl {
  repeated string revoked_hub_ids = 1;           // may include a revoked intermediate issuer_id (§6.4/T-INTERMED)
  repeated string revoked_agent_key_ids = 2;     // emergency/leak: hard-reject all signatures
  repeated SupersededKey superseded_keys = 3;    // routine: accept only with valid relay_attest (P0-D)
  uint64 epoch = 4;
  int64  next_update = 5;                         // stale => enumerated fail-closed set (§6.4/P1-6)
  string issuer_id = 6;
  bytes  root_sig = 7;                            // over sign_input_crl (§5.6)
}

message HubRecord {
  string hub_id = 1; string addr = 2; repeated string backbones = 3;
  repeated string capabilities = 4; bytes hub_pubkey = 5;
  uint32 max_sig_projection_version = 6;
  uint64 record_epoch = 7;
  bytes  sig = 8;                    // over sign_input_hubrec (§5.6/P0-B)
}

message Receipt {                     // TERMINAL (§8.2)
  string msg_id = 1;
  Status status = 2;
  int64  at = 3;
  bytes  sig = 4;                    // hub_sig for DELIVERED (best-effort); AGENT ident_sig for CONSUMED (mesh-reliable)
  bool   agent_signed = 5;
  string reason = 6;                // "no live instance","undecryptable","undecryptable_unresolvable","unverifiable",
                                    // "ordered_stall","ordered_stream_failed","reassembly_timeout",
                                    // "unsupported_sig_projection","projection_floor_unmet","projection_mismatch"
  enum Status { DELIVERED = 0; CONSUMED = 1; BOUNCED = 2; }
}
```

## Appendix B — Agent-boundary JSON examples

Send (agent → local hub; `require_e2e` fails closed if no `AgentCert`; holds if `AgentCert` present but prekeys withheld):
```json
{"to":"secondbrain@second-brain","subject":"ledger sync","content_type":"text/markdown","require_e2e":true,"seal_subject":true,"body":"…"}
```

Notify pointer (hub → `notify.jsonl`; NEWLINE-TERMINATED; pointer only; subject/thread absent because sealed):
```json
{"msg_id":"01J…","from":"wolf@gateway#3f9c…e21a","size":184,"enc":"enc","key_epoch":3,"ts":1752700000000}
```

Notify rotation sentinel:
```json
{"rotate":"notify.jsonl.0007"}
```

Durable inbox file `inbox/1752700000000-01J….msg.json` (full JSON envelope; body ciphertext under E2E; recipient VERIFIES `auth.agent_sig` against the sender's root-anchored `AgentCert` + `content_hash` + signed `enc.nonce`/`eph_pub` + signature-epoch-gate (incl. `relay_attest` for superseded keys) before decrypting/acting, then AEAD-opens with `ad=aead_ad_v1`; crash-safe verify→decrypt→consume per §6.8. Reader opens with `FILE_SHARE_DELETE`, §4.5).

Bounce receipt to sender (terminal; never itself bounced):
```json
{"receipt":"bounced","msg_id":"01J…","reason":"no live instance (beacon stale)","hub":"second-brain","agent_signed":false,"ts":1752700050000}
```

Agent-signed consumed receipt (E2E proof; mesh-reliably delivered with alternate-path failover, cached for re-emit — P1-2/P1-I):
```json
{"receipt":"consumed","msg_id":"01J…","by":"secondbrain@second-brain#a1b2…","agent_signed":true,"ts":1752700060000}
```

Ordered-stream failure surfaced to the agent (bounce FAILS THE WHOLE STREAM; no silent reorder — §8.6/P2-M):
```json
{"error":"ordered_stream_failed","from":"wolf@gateway","to":"secondbrain@second-brain","first_unacked_msg_id":"01J…","reason":"ordered_stall","ts":1752700065000}
```

Unresolvable-decrypt bounce (epoch below lowest-ever-published watermark → structural, no retry — §8.9/P1-3):
```json
{"receipt":"bounced","msg_id":"01J…","reason":"undecryptable_unresolvable","by_agent":"secondbrain@second-brain","ts":1752700070000}
```

Projection-floor-unmet (recipient can't verify a security-critical signed field; only enforceable post advertise-then-enforce — §5.1/P2-4/P2-O):
```json
{"error":"send_refused","reason":"projection_floor_unmet","field":"<security_field>","recipient_max":1,"required":2}
```

## Appendix C — Length-prefixed signing pre-images, AEAD-AD variant, record pre-images, transcript, domain separation (normative)

Pseudocode all hub languages MUST match, gated by Phase-0 cross-language byte-for-byte vectors. There is **no CBOR, no map sorting, no float rule, and NO NFC** — only fixed field order, explicit presence bytes, fixed-width big-endian integers, **LDH/ASCII text**, and raw `content_hash` bytes.

```
# --- Domain-separation tags (ASCII, no trailing NUL) ---
DS_AUTH        = "agentmail/v1/auth-sig"
DS_SPK         = "agentmail/v1/spk-sig"
DS_ENROLL      = "agentmail/v1/enroll"
DS_X3DH        = "agentmail/v1/x3dh"
DS_AUTH_PREFIX = "agentmail/v1/preimage"        # envelope signing pre-image
DS_AEAD_PREFIX = "agentmail/v1/aead-ad"         # envelope AEAD-AD pre-image (content-hash-free, P0-A)
DS_ISSUER      = "agentmail/v1/issuer-cert"     # record pre-images (P0-B)
DS_HUBCERT     = "agentmail/v1/hub-cert"
DS_AGENTCERT   = "agentmail/v1/agent-cert"
DS_KEYS        = "agentmail/v1/keys"
DS_CRL         = "agentmail/v1/crl"
DS_HUBREC      = "agentmail/v1/hub-record"
DS_LINKSTATE   = "agentmail/v1/linkstate"
DS_FWDACK      = "agentmail/v1/fwdack"
DS_RELAYATTEST = "agentmail/v1/relay-attest"

# --- Encoding primitives ---
u8(x)     := single byte
be32(x)   := 4-byte big-endian
be64(x)   := 8-byte big-endian
ascii(s)  := raw bytes of s AFTER ingress asserts s is in the allowed ASCII/LDH subset (NO normalization; reject otherwise)
field(present, bytes) := present ? (u8(0x01) || be32(len(bytes)) || bytes) : (u8(0x00))
rep(items, enc_elem)  := be32(len(items)) || concat(enc_elem(items[i]) for i in 0..len-1)   # order is signed; verifier does NOT reorder
addr(a)   := field(1, ascii(a.name)) || field(1, ascii(a.host)) || field(a.session?, ascii(a.session))

# --- Fixed-width enum wire values + fingerprint encoding (normative; pinned by the Phase-0 vectors) ---
# These are signed bytes: enc.mode/priority ride in be32 fields of both pre-images, receipt_type is a u8 in
# receipt_v1, and *_key_id/msg_id are ascii() inside the pre-image. An implementation that guesses a different
# value or alphabet produces a different pre-image and every cross-implementation signature fails, so the
# concrete values are stated here rather than left to each binding.
EncMode      := { PLAINTEXT = 0, ENC = 1 }                                   # env.enc.mode, be32
Priority     := { LOW = 0, NORMAL = 1, HIGH = 2 }                            # env.priority, be32; materialize -> NORMAL
ReceiptType  := { CONSUMED = 0, BOUNCED = 1, UNDECRYPTABLE_UNRESOLVABLE = 2 } # receipt_v1, u8 (P1-2/§8.2)

base32(b)    := Crockford base32, UPPERCASE, UNPADDED, big-endian, 5 bits per char, over the alphabet
                0123456789ABCDEFGHJKMNPQRSTVWXYZ
                # Stated literally on purpose. This is DIGITS-FIRST (0-9 then A-Z excluding I, L, O, U) and is
                # NOT RFC 4648's alphabet, which is A-Z then 2-7: a different symbol set AND a different
                # ordering. Deriving it as "RFC 4648 minus I/L/O/U" yields 28 symbols, not 32, and no digits.
                # A reader who reconstructs the alphabet instead of reading it produces different characters
                # for every key_id and msg_id -> every signature over those ascii() fields mismatches.
                # Chosen because the output is LDH/ASCII-safe (uppercase alphanumeric, no '=' padding) so it
                # passes ascii() unchanged and cannot collide with the addr() LDH rule, and because it is the
                # alphabet msg_id's ULID already implies.
*_key_id     := base32(sha256(pubkey))  # N = 52 chars = the FULL 256-bit digest, NEVER truncated (P0-B/FLAG-40).
                # A shorter display form is display-only and MUST NOT change this on-wire, AD-signed value.
                # NOT interchangeable with a raw public key: the §6.5 transcript consumes RAW 32-byte pubkeys
                # and only its two trailing fields are these fingerprints. Vectors pin the swap as a failure.
msg_id       := base32(48-bit big-endian unix-ms timestamp || 80 bits CSPRNG) # ULID, 26 chars, time-ordered.
                # Monotonicity requirement is CLOCK-REGRESSION safety: if now <= last-minted ms, hold the
                # high-water timestamp and increment the 80-bit random field (low-order, with carry) rather
                # than minting a smaller/colliding id after an NTP step back.

# --- Ingress validation (P2-K): reject, never normalize ---
validate_ingress(env):
    assert LDH_ascii(env.from.name) and LDH_ascii(env.from.host)     # else -> error non_conforming_field
    assert LDH_ascii(env.to.name)   and LDH_ascii(env.to.host)
    assert env.content_type in REGISTERED_CONTENT_TYPES
    assert ascii(env.msg_id) and ascii(env.enc.sender_key_id) and ascii(env.enc.recipient_key_id) and ascii(env.auth.key_id)
    # No NFC anywhere: all signed text is a fixed ASCII subset.

# --- Flag/field materialization at ingress (P0-β) ---
materialize(env):
    if !present(env.want_receipt): env.want_receipt = true
    if !present(env.require_e2e):  env.require_e2e  = false
    if !present(env.ordered):      env.ordered      = false
    if !present(env.fanout):       env.fanout       = false
    if !present(env.priority):     env.priority     = NORMAL
    env.size = actual_on_wire_body_length
    # reply_to stays genuinely optional (presence 0x00 = null)

# --- Common envelope body (shared by both variants, EXCEPT content_hash) ---
env_common(env):
    B  = addr(env.from)
    B += addr(env.to)
    B += (env.reply_to ? addr(env.reply_to) : u8(0x00))
    B += field(1, ascii(env.content_type))
    B += field(1, be32(env.size))
    # (content_hash inserted here ONLY in sign_input_v1 — see below)
    B += field(1, be64(env.created_at))
    B += field(1, be64(env.expires_at))
    B += field(1, be32(env.priority))
    B += field(1, be32(env.enc.mode))
    B += field(1, be32(env.enc.key_epoch))
    B += field(1, ascii(env.enc.sender_key_id))
    B += field(1, ascii(env.enc.recipient_key_id))
    B += field(1, be32(env.enc.spk_epoch))
    B += field(1, be32(env.enc.opk_id))
    B += field(1, env.enc.nonce)                      # SIGNED (Minor)
    B += field(1, env.enc.eph_pub)                    # SIGNED (Minor)
    B += field(1, u8(env.want_receipt ? 1 : 0))
    B += field(1, u8(env.require_e2e  ? 1 : 0))
    B += field(1, u8(env.ordered      ? 1 : 0))
    B += field(1, u8(env.fanout       ? 1 : 0))
    B += field(1, be32(env.auth.key_epoch))
    return B

# --- aead_ad_v1: CONTENT-HASH-FREE (computable BEFORE ciphertext exists) — breaks the P0-A cycle ---
aead_ad_v1(env):
    validate_ingress(env); materialize(env)
    P  = field(1, DS_AEAD_PREFIX) || u8(1)            # VERSION_BYTE = 1
    P += field(1, ascii(env.msg_id))
    P += field(1, be32(env.protocol_version))
    P += env_common(env)                              # NO content_hash
    return P

# --- sign_input_v1: full pre-image = aead_ad structure PLUS content_hash at its fixed slot ---
sign_input_v1(env):
    validate_ingress(env); materialize(env)
    P  = field(1, DS_AUTH_PREFIX) || u8(1)            # VERSION_BYTE = 1
    P += field(1, ascii(env.msg_id))
    P += field(1, be32(env.protocol_version))
    P += addr(env.from)
    P += addr(env.to)
    P += (env.reply_to ? addr(env.reply_to) : u8(0x00))
    P += field(1, ascii(env.content_type))
    P += field(1, be32(env.size))
    P += field(1, env.content_hash_raw32)             # raw 32 bytes; ONLY in sign_input, NOT in aead_ad (P0-A)
    P += field(1, be64(env.created_at))
    P += field(1, be64(env.expires_at))
    P += field(1, be32(env.priority))
    P += field(1, be32(env.enc.mode))
    P += field(1, be32(env.enc.key_epoch))
    P += field(1, ascii(env.enc.sender_key_id))
    P += field(1, ascii(env.enc.recipient_key_id))
    P += field(1, be32(env.enc.spk_epoch))
    P += field(1, be32(env.enc.opk_id))
    P += field(1, env.enc.nonce)
    P += field(1, env.enc.eph_pub)
    P += field(1, u8(env.want_receipt ? 1 : 0))
    P += field(1, u8(env.require_e2e  ? 1 : 0))
    P += field(1, u8(env.ordered      ? 1 : 0))
    P += field(1, u8(env.fanout       ? 1 : 0))
    P += field(1, be32(env.auth.key_epoch))
    return P

# --- Seal / sign ordering (NO cycle): aead_ad -> seal -> content_hash -> sign_input -> sign ---
AD              = aead_ad_v1(env)                                   # content-hash-free (P0-A)
ct, tag         = XChaCha20Poly1305_seal(key=SK, nonce=enc.nonce, plaintext=body, ad=AD)  # libsodium (§6.0)
env.content_hash = sha256(on_wire_body_bytes = ct||tag)            # ciphertext hash
agent_sig       = Ed25519_sign(agent_ident_priv, DS_AUTH || sign_input_v1(env))   # covers content_hash

# Recipient MUST, BEFORE surfacing/acting (§6.8):
#   (1) verify auth.agent_sig over sign_input_v1(env) via sender name@host AgentCert -> intermediate -> PINNED root,
#   (2) verify content_hash over on-wire body,
#   (3) epoch-gate: reject if key_id in revoked; if key_id in superseded, accept ONLY with valid relay_attest
#       (ingress_time < superseded_at, hub cert valid at ingress_time, superseded_at-ingress_time <= SUPERSESSION_GRACE)
#       AND created_at < superseded_at AND now <= created_at+MAX_LIFETIME; else reject if key_epoch < highest (§6.6/P0-D),
#   (4) AEAD-open with ad = aead_ad_v1(env).

# --- RECORD pre-images (P0-B): each *_sig is over its own DS-tagged length-prefixed TLV; protobuf bytes NEVER signed ---
sign_input_issuer(c)  = field(1,DS_ISSUER)||u8(1)|| field(1,ascii(c.issuer_id))|| field(1,c.issuer_pubkey)||
                        rep(c.name_authority_constraints, x->field(1,ascii(x)))|| field(1,be64(c.not_after))||
                        field(1,be64(c.record_epoch))
sign_input_hubcert(c) = field(1,DS_HUBCERT)||u8(1)|| field(1,ascii(c.hub_id))|| field(1,c.hub_pubkey)||
                        rep(c.allowed_name_authority, x->field(1,ascii(x)))|| field(1,be64(c.not_after))||
                        field(1,be64(c.record_epoch))|| field(1,ascii(c.issuer_id))
sign_input_agentcert(c)= field(1,DS_AGENTCERT)||u8(1)|| addr(c.addr)|| field(1,c.ident_pub)|| field(1,be32(c.key_epoch))||
                        field(1,be64(c.not_after))|| field(1,be64(c.record_epoch))|| field(1,ascii(c.issuer_id))
sign_input_keys(k)    = field(1,DS_KEYS)||u8(1)|| addr(k.addr)|| field(1,k.ident_pub)|| field(1,k.spk_pub)||
                        field(1,be32(k.spk_epoch))|| field(1, sha256(rep(k.opk, o->field(1,be32(o.opk_id))||field(1,o.opk_pub))))||
                        field(1,be32(k.key_epoch))|| field(1,be64(k.record_epoch))     # opk set via opk_root_hash
sign_input_spk(k)     = DS_SPK || field(1,k.ident_pub) || field(1,k.spk_pub) || field(1,be32(k.spk_epoch)) ||
                        field(1,be32(k.key_epoch))       # NOW binds ident_pub + key_epoch (Minor)
sign_input_crl(r)     = field(1,DS_CRL)||u8(1)|| rep(r.revoked_hub_ids, x->field(1,ascii(x)))||
                        rep(r.revoked_agent_key_ids, x->field(1,ascii(x)))||
                        rep(r.superseded_keys, s->field(1,ascii(s.key_id))||field(1,be64(s.superseded_at)))||
                        field(1,be64(r.epoch))|| field(1,be64(r.next_update))|| field(1,ascii(r.issuer_id))
sign_input_hubrec(h)  = field(1,DS_HUBREC)||u8(1)|| field(1,ascii(h.hub_id))|| field(1,ascii(h.addr))||
                        rep(h.backbones, x->field(1,ascii(x)))|| rep(h.capabilities, x->field(1,ascii(x)))||
                        field(1,h.hub_pubkey)|| field(1,be32(h.max_sig_projection_version))|| field(1,be64(h.record_epoch))
sign_input_linkstate(l)= field(1,DS_LINKSTATE)||u8(1)|| field(1,ascii(l.backbone_id))||
                        rep(l.live_downstream, x->field(1,ascii(x)))|| field(1,be64(l.gen))|| field(1,be64(l.emitted_at))
sign_input_fwdack(a)  = field(1,DS_FWDACK)||u8(1)|| field(1,ascii(a.msg_id))|| field(1,ascii(a.next_hop))||
                        field(1,be64(a.at))|| field(1,ascii(a.hub_id))
sign_input_relayattest(r)= field(1,DS_RELAYATTEST)||u8(1)|| field(1,ascii(r.msg_id))|| field(1,be64(r.ingress_time))||
                        field(1,ascii(r.hub_id))
# All record signatures: Ed25519_sign(signer_priv, sign_input_<type>(record)). Verifier reconstructs the TLV and
# byte-compares against the Phase-0 vectors. Repeated fields are signed IN ORDER; no reordering on verify.

# --- X3DH transcript binds RAW DH PUBLIC-KEY BYTES (UKS resistance); primitives from libsodium (§6.0) ---
transcript = IK_s_pub_raw || IK_r_pub_raw || spk_pub_raw ||
             (opk_pub_raw if enc.opk_id != 0 else "") || eph_pub_raw ||
             be32(enc.key_epoch) || be32(enc.spk_epoch) || be32(enc.opk_id) ||
             enc.sender_key_id || enc.recipient_key_id
SK = HKDF( DH(IK_s, spk_pub) || DH(EK, IK_r) || DH(EK, spk_pub) || [DH(EK, opk_pub) if opk] || transcript,
           info = DS_X3DH )
# IK_s/IK_r are XEdDSA(X25519) forms of the Ed25519 identity keys (name@host-scoped, AgentCert-bound); DH is
# domain-separated from signing via the DS tags + XEdDSA's independent nonce derivation (library-provided).
# enc.nonce/eph_pub are ADDITIONALLY signed in the envelope (§5.1), so relay tampering is an attributable
# structural signature failure, not a recipient decrypt-poison (round-5 Minor).
```

---

### Round-5 points: resolution status

- **P0-A / P0-B / P0-C / P0-D / P0-E** — all five accepted as valid and fixed in the body (§5.1/§5.3; §5.6/§6.4; §3.5/§5.5/§8.4; §6.4/§6.6; §6.4/§6.5/T-HUBROOT). These were the "fix before approval" set.
- **P1-F / P1-G / P1-H / P1-I** — accepted and fixed (§3.5; §6.4/§7.3; §0.1/§7.4; §8.2/§8.6).
- **P2-J … P2-P** — accepted and fixed (§5.4/§8.7; §5.1/§7.1; §8.2; §8.6; §6.4; §4.6/§11; §4.5).
- **Minors** — all fixed: §8.9 contradiction (immediate on verification failure); global reassembly cap (§4.7/§8.7); signed `enc.nonce`/`eph_pub` (§5.1); `spk_sig` binds `ident_pub`+`key_epoch` (§6.5/§5.6).
- **No round-5 point was judged wrong.** The one *trade* the reviewer flagged (P2-N introduces an online intermediate = a new hot key) is adopted with the residual disclosed (T-INTERMED) and surfaced as OD-8 for Hex to accept or reject in favor of offline-only issuance.
