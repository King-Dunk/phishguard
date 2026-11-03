#!/usr/bin/env bash
# Manual walkthrough. Start the server first:
#   PHISHGUARD_API_KEYS=dev-key uvicorn phishguard.api:get_app --factory --port 8000
# The MFA code is printed on the SERVER console (dev channel), never in an API response.
B=${BASE:-http://localhost:8000}
H='content-type: application/json'
K="x-api-key: ${PHISHGUARD_KEY:-dev-key}"

echo "1) analyze a phishing email"
curl -s $B/analyze -H "$H" -H "$K" -d '{"email":{"id":"m1","timestamp":"2026-03-03T03:10:00+00:00","sender_name":"David Chen",
 "sender_email":"david@acme-c0rp.com","reply_to":"d@gmail.com","subject":"Urgent","body":"Wire transfer today, keep this confidential.",
 "sender_reputation":0.1,"sender_domain_age_days":5,"spf":"fail","dkim":"fail","dmarc":"fail"}}'; echo

echo "2) transfer is suspended (HTTP 202)"
R=$(curl -s $B/actions -H "$H" -H "$K" -d '{"action_type":"transfer_funds","requested_by":"alice","params":{"amount":50000}}'); echo "$R"
PID=$(echo "$R" | python -c 'import sys,json;print(json.load(sys.stdin)["pending_id"])')
DIG=$(echo "$R" | python -c 'import sys,json;print(json.load(sys.stdin)["confirm_digest"])')

echo "3) wrong code -> 403"
curl -s -w ' [HTTP %{http_code}]\n' $B/mfa/verify -H "$H" -H "$K" -d "{\"pending_id\":\"$PID\",\"code\":\"000000\",\"confirm_digest\":\"$DIG\"}"

read -rp "4) enter the code shown on the server console: " CODE
curl -s -w ' [HTTP %{http_code}]\n' $B/mfa/verify -H "$H" -H "$K" -d "{\"pending_id\":\"$PID\",\"code\":\"$CODE\",\"confirm_digest\":\"$DIG\"}"

echo "5) timeout: submit another transfer and wait longer than PHISHGUARD_MFA_TIMEOUT, then verify -> 410"
