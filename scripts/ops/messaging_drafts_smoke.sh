#!/usr/bin/env bash
set -euo pipefail

: "${API_BASE:?API_BASE is required}"
: "${AUTH_TOKEN:?AUTH_TOKEN is required}"
: "${CONVERSATION_ID:?CONVERSATION_ID is required}"

api() {
  local method="$1"
  local path="$2"
  local body="${3:-}"
  local extra_header="${4:-}"
  if [[ -n "$body" ]]; then
    curl -sS -X "$method" "$API_BASE$path" \
      -H "Authorization: Bearer $AUTH_TOKEN" \
      -H "Content-Type: application/json" \
      ${extra_header:+-H "$extra_header"} \
      -d "$body"
  else
    curl -sS -X "$method" "$API_BASE$path" \
      -H "Authorization: Bearer $AUTH_TOKEN" \
      ${extra_header:+-H "$extra_header"}
  fi
}

echo "[smoke] create draft"
create_resp="$(api POST "/messaging/conversations/$CONVERSATION_ID/drafts" '{"text":"smoke draft"}' 'Idempotency-Key: smoke-msgd017')"
create_id="$(python3 - <<'PY' "$create_resp"
import json,sys
obj=json.loads(sys.argv[1])
print(obj["draft"]["draft_id"])
PY
)"

echo "[smoke] list drafts"
list_resp="$(api GET "/messaging/conversations/$CONVERSATION_ID/drafts")"
python3 - <<'PY' "$list_resp" "$create_id"
import json,sys
obj=json.loads(sys.argv[1]); did=sys.argv[2]
ids=[i.get("draft_id") for i in obj.get("items",[])]
assert did in ids, f"draft {did} missing from list"
print("list ok")
PY

echo "[smoke] get draft"
get_resp="$(api GET "/messaging/conversations/$CONVERSATION_ID/drafts/$create_id")"
python3 - <<'PY' "$get_resp"
import json,sys
obj=json.loads(sys.argv[1])
assert obj["draft"]["text"] == "smoke draft"
print("get ok")
PY

echo "[smoke] update draft"
patch_resp="$(api PATCH "/messaging/conversations/$CONVERSATION_ID/drafts/$create_id" '{"text":"smoke draft updated"}')"
python3 - <<'PY' "$patch_resp"
import json,sys
obj=json.loads(sys.argv[1])
assert obj["draft"]["text"] == "smoke draft updated"
print("update ok")
PY

echo "[smoke] delete draft"
curl -sS -o /dev/null -w "%{http_code}" -X DELETE "$API_BASE/messaging/conversations/$CONVERSATION_ID/drafts/$create_id" \
  -H "Authorization: Bearer $AUTH_TOKEN" | grep -q '^204$'

echo "[smoke] verify deleted"
deleted_status="$(curl -sS -o /dev/null -w "%{http_code}" -X GET "$API_BASE/messaging/conversations/$CONVERSATION_ID/drafts/$create_id" \
  -H "Authorization: Bearer $AUTH_TOKEN")"
if [[ "$deleted_status" != "404" ]]; then
  echo "expected 404 after delete, got $deleted_status" >&2
  exit 1
fi

echo "[smoke] messaging drafts smoke test passed"
