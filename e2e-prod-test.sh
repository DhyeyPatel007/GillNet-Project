#!/bin/bash
# GillNet production end-to-end verification (Render backend + Atlas MongoDB).
# Requires MONGO_URI env var. Run: MONGO_URI='...' bash e2e-prod-test.sh
set -u
BASE="https://gillnet-backend-recovery.onrender.com"
TS=$(date +%s)
EMAIL="e2e-${TS}@gillnet.test"
PASS="TestPass123!"
PASS_COUNT=0
FAIL_COUNT=0

ok()   { PASS_COUNT=$((PASS_COUNT+1)); echo "  PASS: $1"; }
bad()  { FAIL_COUNT=$((FAIL_COUNT+1)); echo "  FAIL: $1 -- $2"; }

echo "== 1. Backend health =="
R=$(curl -s -m 15 "$BASE/health"); C=$(curl -s -o /dev/null -w "%{http_code}" -m 15 "$BASE/health")
[ "$C" = "200" ] && echo "$R" | grep -q '"status":"UP"' && ok "GET /health -> 200 UP" || bad "GET /health" "http=$C body=$R"

echo "== 2. Forged Google token rejected =="
C=$(curl -s -o /dev/null -w "%{http_code}" -m 20 -X POST "$BASE/api/auth/google" -H "Content-Type: application/json" -d '{"idToken":"forged.garbage.token"}')
{ [ "$C" = "400" ] || [ "$C" = "401" ]; } && ok "POST /api/auth/google forged token -> $C" || bad "forged Google token" "http=$C (expected 400/401)"

echo "== 3. Register new user -> 100 credits =="
REG=$(curl -s -m 20 -X POST "$BASE/api/auth/register" -H "Content-Type: application/json" -d "{\"name\":\"E2E Test\",\"email\":\"$EMAIL\",\"password\":\"$PASS\"}")
C=$(curl -s -o /dev/null -w "%{http_code}" -m 20 -X POST "$BASE/api/auth/register" -H "Content-Type: application/json" -d "{\"name\":\"E2E Dup\",\"email\":\"$EMAIL\",\"password\":\"$PASS\"}")
TOKEN=$(echo "$REG" | python3 -c "import sys,json; print(json.load(sys.stdin).get('token') or '')")
CREDITS=$(echo "$REG" | python3 -c "import sys,json; u=json.load(sys.stdin).get('user') or {}; print(u.get('credits'))")
[ -n "$TOKEN" ] && [ "$TOKEN" != "" ] && ok "register returned JWT" || bad "register JWT" "$REG"
[ "$CREDITS" = "100" ] && ok "new user has exactly 100 credits" || bad "signup credits" "got=$CREDITS"
[ "$C" = "400" ] && ok "duplicate registration rejected (400)" || bad "duplicate registration" "http=$C"

echo "== 4. /api/auth/me =="
ME=$(curl -s -m 15 "$BASE/api/auth/me" -H "Authorization: Bearer $TOKEN")
MC=$(echo "$ME" | python3 -c "import sys,json; print(json.load(sys.stdin).get('credits'))")
[ "$MC" = "100" ] && ok "/me shows 100 credits" || bad "/me credits" "got=$MC body=$ME"

echo "== 5. Scan deducts exactly 1 credit =="
SC=$(curl -s -m 60 -X POST "$BASE/api/url/analyze" -H "Content-Type: application/json" -H "Authorization: Bearer $TOKEN" -d '{"url":"https://www.google.com"}')
PRED=$(echo "$SC" | python3 -c "import sys,json; print(json.load(sys.stdin).get('prediction','?'))")
ME2=$(curl -s -m 15 "$BASE/api/auth/me" -H "Authorization: Bearer $TOKEN")
MC2=$(echo "$ME2" | python3 -c "import sys,json; print(json.load(sys.stdin).get('credits'))")
[ "$PRED" = "SAFE" ] && ok "scan returned prediction=SAFE" || bad "scan prediction" "got=$PRED"
[ "$MC2" = "99" ] && ok "credits 100 -> 99 after one scan" || bad "credit deduction" "got=$MC2"

echo "== 6. Failed scan does NOT deduct =="
FC=$(curl -s -o /dev/null -w "%{http_code}" -m 60 -X POST "$BASE/api/url/analyze" -H "Content-Type: application/json" -H "Authorization: Bearer $TOKEN" -d '{"url":"not a url at all !!!"}')
ME3=$(curl -s -m 15 "$BASE/api/auth/me" -H "Authorization: Bearer $TOKEN")
MC3=$(echo "$ME3" | python3 -c "import sys,json; print(json.load(sys.stdin).get('credits'))")
{ [ "$FC" = "400" ] || [ "$FC" = "500" ]; } && ok "invalid URL scan rejected ($FC)" || bad "invalid URL scan" "http=$FC"
[ "$MC3" = "99" ] && ok "credits unchanged at 99 after failed scan" || bad "failed-scan deduction" "got=$MC3"

echo "== 7. Wrong password -> 401 =="
WC=$(curl -s -o /dev/null -w "%{http_code}" -m 20 -X POST "$BASE/api/auth/login" -H "Content-Type: application/json" -d "{\"email\":\"$EMAIL\",\"password\":\"WrongPass999\"}")
[ "$WC" = "401" ] && ok "wrong password -> 401" || bad "wrong password" "http=$WC"

echo "== 8. Unauthenticated scan -> 401 =="
UC=$(curl -s -o /dev/null -w "%{http_code}" -m 20 -X POST "$BASE/api/url/analyze" -H "Content-Type: application/json" -d '{"url":"https://www.google.com"}')
[ "$UC" = "401" ] && ok "scan without token -> 401" || bad "unauthenticated scan" "http=$UC"

echo "== 9. Zero credits -> 402 (set via MongoDB, then scan) =="
python3 - "$EMAIL" <<'EOF'
import os, sys
from pymongo import MongoClient
email = sys.argv[1]
c = MongoClient(os.environ["MONGO_URI"])
r = c["gillnet_db"]["user"].update_one({"email": email}, {"$set": {"credits": 1}})
print("set credits=1, matched:", r.matched_count)
EOF
SC1=$(curl -s -o /dev/null -w "%{http_code}" -m 60 -X POST "$BASE/api/url/analyze" -H "Content-Type: application/json" -H "Authorization: Bearer $TOKEN" -d '{"url":"https://www.google.com"}')
ZC=$(curl -s -o /dev/null -w "%{http_code}" -m 60 -X POST "$BASE/api/url/analyze" -H "Content-Type: application/json" -H "Authorization: Bearer $TOKEN" -d '{"url":"https://www.google.com"}')
ZB=$(curl -s -m 60 -X POST "$BASE/api/url/analyze" -H "Content-Type: application/json" -H "Authorization: Bearer $TOKEN" -d '{"url":"https://www.google.com"}')
[ "$SC1" = "200" ] && ok "scan at 1 credit succeeds (200)" || bad "scan at 1 credit" "http=$SC1"
[ "$ZC" = "402" ] && ok "scan at 0 credits -> 402" || bad "zero-credit scan" "http=$ZC body=$ZB"

echo "== 10. User persisted in MongoDB =="
python3 - "$EMAIL" <<'EOF'
import os, sys
from pymongo import MongoClient
email = sys.argv[1]
c = MongoClient(os.environ["MONGO_URI"])
u = c["gillnet_db"]["user"].find_one({"email": email})
print("PERSISTED:", bool(u), "| credits:", u.get("credits") if u else None, "| name:", u.get("name") if u else None)
EOF

echo "== 11. Cleanup test user =="
python3 - "$EMAIL" <<'EOF'
import os, sys
from pymongo import MongoClient
email = sys.argv[1]
c = MongoClient(os.environ["MONGO_URI"])
r = c["gillnet_db"]["user"].delete_one({"email": email})
print("deleted test user, count:", r.deleted_count)
EOF

echo ""
echo "RESULT: $PASS_COUNT passed, $FAIL_COUNT failed"
[ "$FAIL_COUNT" = "0" ]
