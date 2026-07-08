# TIP-B4 — pay-to-message gate + tip-free allowlist (prod hotfix fold)

Backend for epic TIP-B4 (TIP-401/402/403). LIVE prod hotfix, mirrored into the repo.

## What it does
- **TIP-401 MessagePrivacy** — a per-user record on the `profile` settings row
  (`message_privacy = {require_tip_to_message: bool, min_tip_cents: int,
  tip_free_allowlist: [user_sub]}`) with endpoints:
  - `GET  /messaging/privacy/message`
  - `PUT  /messaging/privacy/message` (partial: require/min/allowlist)
  - `POST /messaging/privacy/message/allowlist` `{user_id}`
  - `DELETE /messaging/privacy/message/allowlist/{allow_user_id}`
- **TIP-402 gate** — `find_or_create_dm` and the first `send_text_message` raise
  `402 {code:"tip_required", min_tip_cents, recipient, conversation_id?}` when the
  recipient gates DMs and the sender is not bypassed. Bypasses: recipient not gating /
  sender in `tip_free_allowlist` / mutual-follow / an established conversation (any
  prior message — this also covers the recipient-messaged-first case).
- **TIP-403 charge** — the first message to a gated recipient must carry a tip
  `>= min_tip_cents`; the existing attached-tip path routes it through
  `charge_tip(content_type="message", recipient=the gated user)` as **non-refundable
  creator earnings** (net `type:"credit"`, minus the 20% platform fee). A failed
  charge (402 / no ledger) means the message is not delivered.

## Files
- `apply_tipb4.py <path/to/messaging.py>` — idempotent in-place patcher (guarded by the
  `TIP-B4 pay-to-message` marker; re-runs print `ALREADY_PATCHED`).
- `verify_tipb4.py` — in-process money-path verification (run under the prod env).

## Apply (prod, via SSM)
```
cp app/routers/messaging.py app/routers/messaging.py.bak_tipb4_<ts>
.venv/bin/python apply_tipb4.py app/routers/messaging.py
python -c "import ast,io; ast.parse(io.open('app/routers/messaging.py').read())"
chown ubuntu:ubuntu app/routers/messaging.py
su - ubuntu -c "bash /home/ubuntu/restart_backend.sh"   # openapi -> 200
```

## Prod verification (9/9 ALL_PASS)
recipient sets require_tip min=500 → non-allowlisted sender open-DM 402 / first-send
no-tip 402 / first-send +500 delivered + recipient credited net 400 (`type:"credit"`,
`content_type:"message"`) / existing-conversation bypass / allowlist bypass /
recipient-messaged-first bypass / allowlist add+remove.

Backups: `messaging.py.bak_tipb4_1783487279`.
