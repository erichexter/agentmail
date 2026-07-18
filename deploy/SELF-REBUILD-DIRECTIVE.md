# Per-host self-rebuild directive — deploy the #8 directory fix (0.4.1)

A fill-in-the-host directive for the #17 fleet rollout. Each target host's agent runs this **standalone
on its own box** to deploy the #8 directory-lifecycle fix. Agent Two dispatches it per-host on the operator's clearance;
`Machine One` and `Machine Two` are already done and are the reference for "green".

**Fill in:** `<HOST>` = the target's MagicDNS/short host name · `<AGENT>` = the local agent name (the one
the relay hosts) · `<PORT>` = the relay port (usually `8787`).

---

## 0. Read first — the trap both machines hit

**A restart alone is a NO-OP if agentmail runs as an installed global tool.** The service re-launches the
same pinned build. You MUST `dotnet tool update` to a higher version first. `main` is already bumped to
**0.4.1**, so the update is not a no-op — but only if you actually pack + update, not just restart.

## 1. Check the unit BEFORE touching anything

```sh
# How does agentmail run here — installed tool, or from source?
systemctl --user cat agentmail.service 2>/dev/null | grep ExecStart   # linux/systemd
#   ExecStart=%h/.dotnet/tools/agentmail serve ...   -> PINNED TOOL  (pack+update+restart)
#   ExecStart=dotnet .../src/AgentMail ...            -> FROM SOURCE  (rebuild+restart)
# macOS launchd: launchctl print gui/$UID/com.agentmail.relay | grep program
# Windows Task Scheduler: the install-relay-taskscheduler.ps1 action path
agentmail --version 2>/dev/null || echo "no --version verb yet (pre-0.4.1 build)"   # record BEFORE
```

Report the run mode. If it is anything other than "pinned tool" or "from source", STOP and tell Agent Two —
do not guess a deploy method.

## 2. Rebuild from main (pinned-tool path — the common case)

```sh
export DOTNET_ROOT=$HOME/.dotnet
cd ~/agentmail && git fetch origin && git checkout main && git pull

# Confirm the tip carries the #8 fix BEFORE building — do not build a stale tree.
git log --oneline -1                       # expect the #21 storage slice or later
grep -q '0.4.1\|0.4.[2-9]' src/AgentMail/agentmail.csproj || { echo "csproj < 0.4.1 — WRONG TREE, stop"; exit 1; }

dotnet pack src/AgentMail -c Release -o ./nupkg
dotnet tool update --global --add-source ./nupkg AgentMail
```

**From-source path instead:** `git pull` on main, then restart the service — no pack/update needed.

## 3. Restart the relay via ITS OWN mechanism

```sh
systemctl --user restart agentmail.service           # linux/systemd
# launchctl kickstart -k gui/$UID/com.agentmail.relay # macOS
# Restart-ScheduledTask -TaskName AgentMailRelay      # windows
```

## 4. Verify — do NOT trust "service active". Two checks, both required.

**A. DEPLOY-UNIT 3-step** (proves the new binary + watcher are the atomic unit):
```sh
agentmail --version                                  # >= 0.4.1
agentmail --caps                                     # prints: msg-json  AND  e2e
# arm/read the watcher: its startup line must say "watching *.msg.md and *.msg.json", NOT "legacy"
```

**B. Behavioral no-prune — THE DECISIVE ONE** (proves the #8 fix is RUNNING, not just compiled):
```sh
agentmail agents        # new output has an AGE column + a "N of M STALE" note
# Identify a >24h, NON-LOCAL record this relay holds (marked ! in the AGE column).
# The OLD build deletes it within 60s. Watch it for ~140s = two old prune cycles:
for t in 0 70 140; do sleep $([ $t = 0 ] && echo 0 || echo 70); \
  echo "t+${t}s: $(ls $HOME/.claude/agentmail/directory/*.json | wc -l) records"; done
# PASS = the stale record is still present at t+140s. FAIL = it vanished -> still the old build.
# Also confirm: `agentmail resolve --to <AGENT>` succeeds against THIS relay (never-prune-local).
```

## 5. Report back to Agent Two@Machine Two

```
host: <HOST>   agent: <AGENT>
version: <before> -> <after>
run mode: pinned-tool | from-source
3-step: --caps=[msg-json,e2e? y/n]  watcher=[both|legacy]  version>=0.4.1=[y/n]
no-prune: stale record <name> age <Nh> survived 140s = [PASS|FAIL]
resolve-local: [ok|FAIL]
```

## Notes

- **Never `--offline` and never rename** during the rebuild — a rename without `--alias <old>` prunes the
  old record (the outage that started all this). Re-register plain: `agentmail register --name <AGENT>
  --port <PORT>` (add `--alias <old>` only if this node already had a different name).
- If the box is on a **shared tailnet with a Ledger privacy gate** (Agent Five's `Machine Five`), the
  rebuild is local-only and touches no Ledger data — but confirm with the operator before running, since it is
  the operator's gated host, not a routing decision the agent makes alone.
- The full rationale for every step is in [`DEPLOY-UNIT.md`](DEPLOY-UNIT.md) and issue #8 / #17.
