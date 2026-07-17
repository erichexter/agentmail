# AgentMail Enhancements — tracking (seed for GitHub issues)

Source of truth is GitHub Issues on erichexter/agentmail (the operator: "make sure it all stays in GitHub,
use issues to keep track of enhancements"). This file seeds those issues; create them once a
write-capable PAT is available on the building box (see BLOCKER).

## BLOCKER — GitHub write access
Every PAT reachable from the gateway is EXPIRED (gateway `gh` + cron-helpers both 401 on
erichexter/agentmail, 2026-07-16). Need a fresh PAT (classic: repo+workflow, or fine-grained on
erichexter/agentmail: Contents/Issues/PullRequests RW) provisioned on:
  - Acer (Agent One builds + opens PRs there), and
  - ideally the gateway too (my heartbeat's issue-work has been silently failing).
Until then, issue/PR creation is done by whoever holds a valid PAT (Agent One on Acer, or Agent Four).

## EPIC: End-to-end encryption (full PRD-grade) — builder: Agent One (Acer)
Design: PRD-hub-federation.md §6/§7/§10 + e2e-implementation-brief.md (adversarially validated brief).
Phased PRs (each independently mergeable, mixed-version-safe):
- [ ] PR1 — identity keys (Ed25519) + sealed E2E (X25519/AEAD) + SIGNED key distribution via directory + capability flag (encrypted-capable vs legacy)
- [ ] PR2 — X3DH PER-MESSAGE forward secrecy, NO Double Ratchet (FLAG-1, confirmed by the operator): session key derived fresh per message from an ephemeral key + recipient prekeys, no advancing chain/skipped-key cache (correct for one-shot unidirectional store-and-forward). Plus prekey bundles, OTP exhaustion, out-of-order/replay handling. + at-rest retention encryption.
- [ ] PR3 — PKI + revocation (TOFU/pinning now; offline-root -> intermediate -> AgentCert path; revoked/superseded epochs + relay attestation)
- [ ] PR4 — OPTIONAL transport TLS (config flag; self-signed OR Let's Encrypt via Tailscale for *.ts.net; NEVER required; graceful fallback to plain HTTP; document metadata-on-cleartext trade)

## ENHANCEMENT: Attachments (zipped) — the operator idea 2026-07-16
"Sending attachments would be pretty kickass. Probably needs to be zipped."
Design sketch (composes with the E2E layer — do AFTER PR1/PR2 land, likely PR5):
- Sender zips file(s) -> single blob (bundles multiple files, shrinks size).
- Chunk if over a threshold (file-drop transport favors bounded messages); each chunk carries index/total.
- E2E-encrypt the blob/chunks with the same ratchet session key; content-address by hash.
- Envelope carries a POINTER: attachment id + sha256 + size + chunk count + zip flag — hash included in
  the SIGNED pre-image (integrity). Pointer-not-payload: the message stays small; recipient pulls the blob.
- Transfer: blob/chunks as separate file(s) in the inbox alongside the message, OR fetched on demand.
- Recipient: reassemble -> verify hash -> decrypt -> verify sender sig -> unzip.
- Guards: per-message + per-inbox size quotas (anti-flood), max attachment size, malformed-zip rejection,
  zip-bomb defense (bounded decompression), MIME/type note. Keep binary OUT of the agent's context
  (agent gets the pointer + metadata; only materializes the file if it acts on it).

## Also open (from the federation PRD / field reports)
- [ ] Bug: `agentmail send --to <bare-name>` does host-scoped Resolve (Program.cs:135) and dead-drops to a
      LOCAL inbox even for a KNOWN-REMOTE agent, printing "delivered" (exit 0). NOT silent — there is a
      stderr warning (Program.cs:138) but it's lost when stdout is piped. Meanwhile `resolve` uses FindByName
      (Program.cs:163) and correctly finds the remote — so send and resolve DISAGREE on the same name.
      Dangerous case = a known-remote agent, not a nonexistent one. Fix: reject bare names on send outright.
      (Source-confirmed by Agent One; corrects earlier wrong "silent / nonexistent" wording.)
- [ ] Periodic self-re-register so agents don't silently age out of the directory after 24h (Agent Two hit this).
- [ ] Freshness-based health/watchdogs (not port-based) — port-open != healthy (location svc + this).
- [ ] Federation: hub-to-hub store-and-forward backbone (full PRD) — the cross-tailnet reachability fix.
