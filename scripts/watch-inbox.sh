#!/usr/bin/env bash
# AgentMail inbox watcher — one stdout line per NEW *.msg.md file.
#
# Run under Claude Code's Monitor tool (persistent: true). Each printed line becomes a
# notification that re-invokes the agent. A per-file "seen" set means a file is emitted
# exactly once, and any files already sitting in the inbox when this starts are delivered
# immediately (so messages queued while the agent was away are not missed).
#
# Usage: watch-inbox.sh <agent-name> [poll-seconds]
set -u
AGENT="${1:?usage: watch-inbox.sh <agent-name> [poll-seconds]}"
POLL="${2:-3}"
ROOT="${AGENTMAIL_ROOT:-$HOME/.claude/agentmail}"
INBOX="$ROOT/agents/$AGENT/inbox"
mkdir -p "$INBOX"

declare -A seen
while true; do
  for f in "$INBOX"/*.msg.md; do
    [ -e "$f" ] || continue          # no matches -> the literal glob; skip it
    if [ -z "${seen[$f]:-}" ]; then
      seen[$f]=1
      echo "NEW-MESSAGE: $f"
    fi
  done
  sleep "$POLL"
done
