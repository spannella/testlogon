#!/usr/bin/env bash
# Live-HTTP verification of contacts hub + suggestions against uvicorn :8000.
set -uo pipefail
cd /home/sean/dev/testlogon
BASE=http://127.0.0.1:8000
SECRET=devsecret_1781764988_xyz

mint() { .venv/bin/python - "$1" << 'PY'
import jwt, time, sys
sub=sys.argv[1]
print(jwt.encode({'sub':sub,'role':'user','exp':int(time.time())+3600},'devsecret_1781764988_xyz',algorithm='HS256'))
PY
}

A=$(mint verify-A)
B=$(mint verify-B)
C=$(mint verify-C)

echo "===== 1) create profiles for A/B/C (so display_name enrichment + follow user_not_found guard work) ====="
for who in A:verify-A:Alice_A B:verify-B:Bob_B C:verify-C:Carol_C; do
  tok_var="${who%%:*}"; sub="${who#*:}"; sub="${sub%%:*}"; name="${who##*:}"
  case "$tok_var" in A) T=$A;; B) T=$B;; C) T=$C;; esac
  curl -s -b "ui_access_token=$T" -H 'content-type: application/json' \
    -X PATCH "$BASE/ui/profile" -d "{\"display_name\":\"$name\"}" -o /dev/null -w "profile $name PATCH -> %{http_code}\n"
done

echo
echo "===== 2) build the social graph: A follows B; C follows A; B follows C (so A gets mutuals/followers) ====="
curl -s -b "ui_access_token=$A" -H 'content-type: application/json' -X POST "$BASE/ui/social/follow" -d '{"target_user_id":"verify-B"}' -w "\n A->B follow HTTP:%{http_code}\n"
curl -s -b "ui_access_token=$C" -H 'content-type: application/json' -X POST "$BASE/ui/social/follow" -d '{"target_user_id":"verify-A"}' -w "\n C->A follow HTTP:%{http_code}\n"
curl -s -b "ui_access_token=$B" -H 'content-type: application/json' -X POST "$BASE/ui/social/follow" -d '{"target_user_id":"verify-C"}' -w "\n B->C follow HTTP:%{http_code}\n"

echo
echo "===== 3) follow-status A->B ====="
curl -s -b "ui_access_token=$A" "$BASE/ui/social/status/verify-B" -w "\n HTTP:%{http_code}\n" 2>/dev/null || \
curl -s -b "ui_access_token=$A" "$BASE/ui/social/status/verify-B" -w "\n HTTP:%{http_code}\n"

echo
echo "===== 4) A's suggestions BEFORE saving anyone (should include B=You follow, C=Follows you, and mutual via B->C) ====="
curl -s -b "ui_access_token=$A" "$BASE/ui/contacts/suggestions" -w "\n HTTP:%{http_code}\n"

echo
echo "===== 5) A saves B as a contact ====="
curl -s -b "ui_access_token=$A" -H 'content-type: application/json' -X POST "$BASE/ui/contacts" -d '{"user_id":"verify-B"}' -w "\n add-contact HTTP:%{http_code}\n"

echo
echo "===== 6) A lists contacts (should show Bob_B) ====="
curl -s -b "ui_access_token=$A" "$BASE/ui/contacts" -w "\n HTTP:%{http_code}\n"

echo
echo "===== 7) A favorites B ====="
curl -s -b "ui_access_token=$A" -H 'content-type: application/json' -X PATCH "$BASE/ui/contacts/verify-B" -d '{"is_favorite":true}' -w "\n favorite HTTP:%{http_code}\n"

echo
echo "===== 8) A's suggestions AFTER saving B (B must be EXCLUDED now; self never appears) ====="
curl -s -b "ui_access_token=$A" "$BASE/ui/contacts/suggestions" -w "\n HTTP:%{http_code}\n"

echo
echo "===== 9) profile-by-id for B ====="
curl -s -b "ui_access_token=$A" "$BASE/ui/profiles/verify-B" -w "\n HTTP:%{http_code}\n" | head -c 400

echo
echo "===== 10) A unfollows B, then deletes contact B ====="
curl -s -b "ui_access_token=$A" -H 'content-type: application/json' -X POST "$BASE/ui/social/unfollow" -d '{"target_user_id":"verify-B"}' -w "\n unfollow HTTP:%{http_code}\n"
curl -s -b "ui_access_token=$A" -X DELETE "$BASE/ui/contacts/verify-B" -w " delete-contact HTTP:%{http_code}\n"

echo
echo "===== 11) final contacts list (empty) ====="
curl -s -b "ui_access_token=$A" "$BASE/ui/contacts" -w "\n HTTP:%{http_code}\n"
