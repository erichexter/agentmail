#!/usr/bin/env bash
# AgentMail inbox watcher — one stdout line per NEW inbox message file.
#
# Run under Claude Code's Monitor tool (persistent: true). Each printed line becomes a
# notification that re-invokes the agent. A per-file "seen" set means a file is emitted
# exactly once, and any files already sitting in the inbox when this starts are delivered
# immediately (so messages queued while the agent was away are not missed).
#
# FLAG-9.4 — the watcher globs *.msg.json ONLY when the installed binary can parse it. It probes
# `agentmail --caps` for the `msg-json` token first. A legacy binary lacks the --caps verb entirely,
# so it stays *.msg.md-only. This is what keeps the binary + this script an ATOMIC per-node deploy
# unit (FLAG-9.1): feeding an enc *.msg.json to a binary that cannot parse it would produce
# parse-error/quarantine churn, so we never do it. Do NOT unconditionally glob both (the rev-2
# "glob both" guidance was withdrawn as actively harmful).
#
# Usage: watch-inbox.sh <agent-name> [poll-seconds]
set -u
AGENT="${1:?usage: watch-inbox.sh <agent-name> [poll-seconds]}"
POLL="${2:-3}"
ROOT="${AGENTMAIL_ROOT:-$HOME/.claude/agentmail}"
INBOX="$ROOT/agents/$AGENT/inbox"
mkdir -p "$INBOX"

# Probe binary capability once at startup. Glob json only if the binary asserts msg-json.
AGENTMAIL_BIN="${AGENTMAIL_BIN:-agentmail}"
PATTERNS=("*.msg.md")
if "$AGENTMAIL_BIN" --caps 2>/dev/null | grep -qx "msg-json"; then
  PATTERNS+=("*.msg.json")
  echo "watch-inbox: binary asserts msg-json — watching *.msg.md and *.msg.json" >&2
else
  echo "watch-inbox: binary has no msg-json capability — watching *.msg.md only (legacy)" >&2
fi

declare -A seen
while true; do
  for pat in "${PATTERNS[@]}"; do
    for f in "$INBOX"/$pat; do
      [ -e "$f" ] || continue          # no matches -> the literal glob; skip it
      if [ -z "${seen[$f]:-}" ]; then
        seen[$f]=1
        echo "NEW-MESSAGE: $f"
      fi
    done
  done
  sleep "$POLL"
done
