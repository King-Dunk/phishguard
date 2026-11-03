#!/usr/bin/env bash
# Starts a Mock-mode server (3s MFA timeout), runs the demo client, stops the server.
set -euo pipefail
cd "$(dirname "$0")/.."
LOG=$(mktemp)
PHISHGUARD_LLM_MODE=mock PHISHGUARD_MFA_TIMEOUT=3 \
  python -m uvicorn phishguard.api:get_app --factory --port 8765 --log-level warning 2>"$LOG" &
PID=$!
trap 'kill $PID 2>/dev/null; rm -f "$LOG"' EXIT
for _ in $(seq 50); do curl -sf localhost:8765/health >/dev/null && break; sleep 0.2; done
python examples/demo_client.py --base-url http://127.0.0.1:8765 --code-log "$LOG"
