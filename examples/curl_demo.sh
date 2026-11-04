#!/usr/bin/env bash
# Manual walkthrough of the two-factor flow (password + TOTP). Start the server first:
#   PHISHGUARD_API_KEYS=dev-key PHISHGUARD_ADMIN_KEYS=dev-admin uvicorn phishguard.api:get_app --factory --port 8000
# For a passkey (Touch ID) as the second factor use the browser page http://localhost:8000/demo/webauthn.
B=${BASE:-http://localhost:8000}
H='content-type: application/json'
K="x-api-key: ${PHISHGUARD_KEY:-dev-key}"
A="x-api-key: ${PHISHGUARD_ADMIN:-dev-admin}"
U=${DEMO_USER:-carol}
PW='correct horse battery staple'

echo "1) analyze a phishing email"
curl -s $B/analyze -H "$H" -H "$K" -d '{"email":{"id":"m1","timestamp":"2026-03-03T03:10:00+00:00","sender_name":"David Chen",
 "sender_email":"david@acme-c0rp.com","reply_to":"d@gmail.com","subject":"Urgent","body":"Wire transfer today, keep this confidential.",
 "sender_reputation":0.1,"sender_domain_age_days":5,"spf":"fail","dkim":"fail","dmarc":"fail"}}'; echo

echo "2) enroll $U (admin key): password + TOTP. Add the otpauth:// URI to an authenticator app."
curl -s $B/mfa/enroll/password -H "$H" -H "$A" -d "{\"user\":\"$U\",\"password\":\"$PW\"}"; echo
curl -s $B/mfa/enroll -H "$H" -H "$A" -d "{\"user\":\"$U\"}"; echo

echo "3) transfer is suspended (HTTP 202)"
R=$(curl -s $B/actions -H "$H" -H "$K" -d "{\"action_type\":\"transfer_funds\",\"requested_by\":\"$U\",\"params\":{\"amount\":5000,\"payee_id\":\"ACME-VENDOR\"}}"); echo "$R"
PID=$(echo "$R" | python -c 'import sys,json;print(json.load(sys.stdin)["pending_id"])')
DIG=$(echo "$R" | python -c 'import sys,json;print(json.load(sys.stdin)["confirm_digest"])')

echo "4) password factor -> 202, still held (one more, non-knowledge factor needed)"
curl -s -w ' [HTTP %{http_code}]\n' $B/mfa/factor -H "$H" -H "$K" \
  -d "{\"pending_id\":\"$PID\",\"confirm_digest\":\"$DIG\",\"method\":\"password\",\"response\":{\"password\":\"$PW\"}}"

read -rp "5) enter the 6-digit code from your authenticator app: " CODE
curl -s -w ' [HTTP %{http_code}]\n' $B/mfa/verify -H "$H" -H "$K" -d "{\"pending_id\":\"$PID\",\"code\":\"$CODE\",\"confirm_digest\":\"$DIG\"}"

echo "6) history"
curl -s $B/payments/accounts/OPERATING/transactions -H "$K"; echo
