# APIK EPIC E2 — Messaging parity (#118)

Registry-only. The `/messaging` router already carries
`Depends(maybe_enforce_api_key_route_policy)` and the `messager` product is `ga` (enforce)
from E0, but only 9 messaging routes were in the scope registry — every other messaging
route was either an explicit "session-auth" exemption or unmapped, and since enforcement
reads **only** the registry (exempt == unmapped == 403), an API key could not bootstrap a
conversation, rich-send, react, mark read, poll realtime, organize, manage scheduled
sends, or run a campaign. E2 registers the real messaging surface with the right
`messager:{read,write,manage}` scope and fixes the image-send contract.

## What changed (registry-only; no router/handler code touched)
File: `app/services/api_key_route_scope_registry.py`

- **APIK-E2-1 Conversation bootstrap** — `POST /messaging/conversations`,
  `/conversations/group`, `/conversations/dm/find-or-create`, `/{id}/accept`, `/{id}/leave`
  → `messager:write`. A `messager:write` key can now create a DM/group and send into it.
- **APIK-E2-2 Rich sends + image-presign contract fix** — gallery / video-share / voice /
  voicemail / tts / gif / sticker / countdown / calendar-event / calendar-share /
  meeting-poll / find-datetime / file-share **and `images/presign`** → `messager:write`.
  The presign step was exempt→403, so a key could not upload an image the way clients do;
  it is now keyable, so the presign→PUT→`messages/image` flow works end-to-end.
- **APIK-E2-3 Realtime + read + reactions** — `GET /events`,`/events/stream`,`/events/poll`,
  `/presence`,`/typing` → `messager:read`; `POST /read`, `/messages/{id}/reactions`,
  `/messages/{id}/view` (delivery receipt), `/presence/heartbeat`, `POST /typing`
  → `messager:write`; `reactions/details`,`views` reads → `messager:read`.
- **APIK-E2-4 Organize + read parity + scheduled manage** — pins (get read / set+unset
  write), forward (write), search + threads + gallery (read), scheduled list (read);
  **scheduled cancel (`DELETE …/schedule`) + edit (`PATCH …/schedule`) → `messager:manage`**;
  participant + conversation lifecycle (add/remove/patch participant, rename/delete convo)
  → `messager:manage`; calls (invite/accept/decline/end/timeout/signal/heartbeat/
  turn-credentials) → `messager:write`; helpdesk read → read, claim → write,
  transfer → manage; message privacy (get read / put+allowlist write); transcribe/translate
  → write.
- **APIK-E2-5 Mass-messaging** — `/messaging/mass-messages*` gated behind the distinct
  high-priv `messager:manage` scope **+ `entitlement_required`** (broadcast/admin
  capability, never a coarse `messager:write`).

### Intentional blocks stay fail-closed (exempt == 403 under GA)
Drafts, mute, compliance+moderation (`/compliance/archive/*`, legal-holds, hidden-messages,
hide, report, `reports/{id}/status`, moderate-revoke), the chat-delegate acts-as-creator
surface (`/messaging/delegate/{creator_id}/*`, dak_ delegation only), admin user-upsert and
health probe remain explicit exemptions.

### Money routes stay fail-closed
There is **no `messager` money scope**, so the message tip / paid-unlock / lottery /
paid-attachment grant+consume routes stay exempt (403) rather than being opened under a
coarse `messager:write` — consistent with the E0/E1 rule that money moves only under a
distinct high-priv scope. They remain fully deny until such a scope is modeled.

Result: messaging registry drift → 0 (94 protected + 35 exempt == 129 live route ids).

## Files
- `apply_apik_e2_patch.py` — idempotent, region-scoped patcher (usage:
  `python apply_apik_e2_patch.py <repo>/app/services/api_key_route_scope_registry.py`).
- `verify_apik_e2.py` — in-process TestClient verifier on real DDB
  (`APIK_PHASE=BEFORE|AFTER`), synthetic keys+users, auto-cleaned (0 residue).

## Verify (in-process on PROD DDB, synthetic, auto-cleaned)
BEFORE: new messaging routes `unmapped_route` 403 (baseline keyed GET still 200).
AFTER: bootstrap+send+react+read-receipt+realtime-poll all pass with the right scope;
image works end-to-end (presign→send); scheduled send retractable only with
`messager:manage`; mass-message needs `messager:manage`; wrong/insufficient scope → 403
`api_key_scope_denied`; no-key → 401; intentional blocks + money routes stay 403 even with
`messager:manage`; UI-session and `dak_` delegation unaffected; send/edit/delete no
regression.
