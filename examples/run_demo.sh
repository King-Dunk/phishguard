#!/usr/bin/env bash
# Starts a Mock-mode server (5s MFA timeout, API key auth, SQLite persistence, two-factor policy),
# runs the demo client, stops the server.
set -euo pipefail
cd "$(dirname "$0")/.."
LOG=$(mktemp)
DB=$(mktemp -u).db
KEY=demo-$(python -c 'import secrets;print(secrets.token_hex(8))')
ADMIN=admin-$(python -c 'import secrets;print(secrets.token_hex(8))')
PORT=8765
PHISHGUARD_LLM_MODE=mock PHISHGUARD_MFA_TIMEOUT=5 PHISHGUARD_API_KEYS=$KEY PHISHGUARD_ADMIN_KEYS=$ADMIN \
  PHISHGUARD_DB_PATH=$DB PHISHGUARD_WEBAUTHN_ORIGINS=http://localhost:$PORT \
  python -m uvicorn phishguard.api:get_app --factory --port $PORT --log-level warning 2>"$LOG" &
PID=$!
trap 'kill $PID 2>/dev/null; rm -f "$LOG" "$DB"*' EXIT
for _ in $(seq 50); do curl -sf localhost:$PORT/health >/dev/null && break; sleep 0.2; done
python examples/demo_client.py --base-url http://localhost:$PORT --api-key "$KEY" --admin-key "$ADMIN"
