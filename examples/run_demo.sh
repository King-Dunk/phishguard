#!/usr/bin/env bash
# Starts a Mock-mode server (3s MFA timeout, API key auth, SQLite persistence), runs the demo client, stops the server.
set -euo pipefail
cd "$(dirname "$0")/.."
LOG=$(mktemp)
DB=$(mktemp -u).db
KEY=demo-$(python -c 'import secrets;print(secrets.token_hex(8))')
PHISHGUARD_LLM_MODE=mock PHISHGUARD_MFA_TIMEOUT=3 PHISHGUARD_API_KEYS=$KEY PHISHGUARD_ADMIN_KEYS=$KEY PHISHGUARD_DB_PATH=$DB \
  python -m uvicorn phishguard.api:get_app --factory --port 8765 --log-level warning 2>"$LOG" &
PID=$!
trap 'kill $PID 2>/dev/null; rm -f "$LOG" "$DB"*' EXIT
for _ in $(seq 50); do curl -sf localhost:8765/health >/dev/null && break; sleep 0.2; done
python examples/demo_client.py --base-url http://127.0.0.1:8765 --code-log "$LOG" --api-key "$KEY"
