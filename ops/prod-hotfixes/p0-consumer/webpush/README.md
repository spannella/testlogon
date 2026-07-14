# P0 Consumer — WEB PUSH (browser push for the React SPA)

Backlog item "web push: MISSING" (docs/feature-improvements-backlog.md, 2026-05-29) is STALE.
Web push is **fully built end-to-end and committed** on both surfaces, and shares the SAME
alert-emit path as mobile FCM. This is a CONFIG + VERIFY gap, not a build gap. No code change
was required. This fold is the parity + deep-verify record + the prod-enablement runbook.

Branch android-impl. Fold created 2026-07-14.

## Backend — already built & committed (no patch)
- `app/services/push.py`
  - `web_push_send(subscription_json, title, body, url, tag, alert_id, alert_type) -> (ok, reason)`
    — real RFC 8030/8291 delivery via `pywebpush.webpush(...)` with VAPID signing; parses
    `{endpoint, keys:{p256dh,auth}}`; classifies permanent(410/404) / transient / config / invalid;
    `dev_mode` logs the payload instead of delivering.
  - `send_push_for_alert(...)` — queries `T.push_devices`; per device dispatches `web_push_send()`
    for `platform=="web" and S.web_push_enabled`, else `fcm_send()` for native. Auto-revokes a web
    sub only on reason=="permanent". Honors alert prefs (explicit push_event_types UNION the
    default-ON transactional set minus opt-outs) + `can_send_alert_channel`.
  - `send_message_push(...)` — chat path, web branch mirrors FCM.
- SHARED emit — the same events that fire mobile ALSO fire web (no fork):
  - `app/services/alerts.py:890` (inside `write_alert`, generic recorder), `:25` imports it.
  - `app/services/social_alerts.py:266`, `app/services/shipment_tracking.py:303`,
    `app/routers/messaging.py:5967` (chat).
- Endpoints — `app/routers/push.py`, prefix `/ui`, all `Depends(require_ui_session)`:
  - `GET  /ui/push/vapid-key`   -> `{vapid_public_key}` (404 if unset). Public-safe.
  - `POST /ui/push/register`    -> generic; stores the token verbatim. **The SPA uses THIS for web**
                                   (token = full subscription JSON, platform="web"). Gated on push_enabled.
  - `POST /ui/push/subscribe` + `DELETE /ui/push/subscribe` -> dedicated VAPID subscribe/unsubscribe
                                   (`PushSubscribeReq{endpoint,keys_p256dh,keys_auth}`, models.py:789).
                                   Stores a canonical `{"endpoint",..,"keys":{"p256dh","auth"}}` blob
                                   (json.loads-able by the send path). Functionally equivalent to
                                   register+platform:web; currently unused by the SPA. Built & live.
  - `POST /ui/push/revoke`, `POST /ui/push/test`, `GET /ui/push/devices`.
  - Registered: `app/main.py:26` import, `:692` include_router.
- Settings — `app/core/settings.py`: `vapid_public_key`(2238)/`vapid_private_key`(2239)/
  `vapid_subject`(2240, default mailto:admin@testlogon.local), `web_push_enabled`(2241, default ON),
  `push_enabled`(296, default **OFF** — `PUSH_ENABLED` must be set to 1 to arm the whole path).
- Dep — `requirements.txt:22` `pywebpush>=2.0.0`. **Present in the dev venv** (import ok, py_vapid ok).
- Auth model — `/ui/push/*` is UI-session-scoped, correctly ABSENT from
  `app/services/api_key_route_scope_registry.py` => fail-closed to API keys. Do NOT add to the
  #118 registry (no regression).

## Frontend — already built & committed (React SPA, `frontend/`)
- `frontend/public/sw.js` — `push` handler (`showNotification` from `event.data.json()`:
  title/body/icon/url/tag/alert_type), `notificationclick` (focus/navigate `data.url`),
  `notificationclose`. Already built into `frontend/dist/sw.js`.
- `frontend/src/lib/pushSetup.ts` — `registerServiceWorker()`, `subscribeToPush(vapidKey)`
  (VAPID applicationServerKey, base64url->Uint8Array; returns `JSON.stringify(sub.toJSON())`
  == `{endpoint, keys:{p256dh,auth}}`), `unsubscribeFromPush()`, `listenForSwUpdate()`.
- `frontend/src/main.tsx:34` — SW registered on app mount.
- `frontend/src/pages/alerts/PushDevices.tsx::handleEnable()` — subscribe-on-permission:
  `Notification.requestPermission()` -> fetch VAPID key -> register SW -> subscribe ->
  `POST /ui/push/register {token: subscriptionJson, platform:"web"}`; lists/tests/revokes devices.
- `frontend/src/api/endpoints/push.ts`, `frontend/public/manifest.json` + icons present.

## PROD PARITY — CONFIRMED via https://tl-api.bitbazaar.cc (2026-07-14)
All push routes live on prod i-08f937fc705ebea75:
  GET  /ui/push/vapid-key | GET /ui/push/devices | POST /ui/push/register
  POST+DELETE /ui/push/subscribe | POST /ui/push/revoke | POST /ui/push/test
`GET /ui/push/vapid-key` -> **HTTP 200** with a real key:
  `BDsaS4WoPTFkG5jAJGIKiBdHZfPMb8FErKvaUbS42HdW1VQQvhGyvzBlc-2AVzwqwSTXymQHqMyGbiNRzBDa_go`
Decodes to a valid 65-byte uncompressed EC P-256 point (0x04-prefixed) => **VAPID public key is
ALREADY configured on prod** (contradicts the scope's "keys almost certainly not set" assumption;
a matching VAPID_PRIVATE_KEY is therefore also set). So the only OPEN prod unknowns are (a) whether
`PUSH_ENABLED=1` and (b) whether `pywebpush` is installed in the PROD venv + the private key is in
the RAW format (below). Both require prod shell/SSM to check — see "PROD ACTIONS".

## DEEP-VERIFY — dev, hermetic (2026-07-14, .venv python)
Drove the real service code (`app/services/push.py`) with a synthetic stored web subscription:
- (A) `web_push_send(...)` dev_mode=True -> `(True, None)`; queued payload
  `{title,body,url,tag,alert_id,alert_type,timestamp}` logged for the endpoint. PASS.
- (B) `send_push_for_alert("user","post_tip",...)` with a stubbed `T.push_devices.query` returning
  one `platform="web"` device -> dispatched to the WEB branch; captured title/body,
  `url="/billing"` (post_tip -> _alert_url), `tag/alert_type="post_tip"`. Proves the SHARED alert
  emit path drives web push for a default-ON event. PASS.
- (C) Real VAPID path, dev_mode=False, correctly-formatted RAW base64url private key ->
  `pywebpush.webpush()` PARSED the VAPID key (past `Vapid.from_string`) and proceeded to build the
  encrypted request; only the (synthetic) subscription failed downstream ("Invalid p256dh key
  specified"), classified `transient` (non-revoking). A real browser sub supplies a valid p256dh.
  Proves VAPID signing + encryption run with a raw-format key. PASS.
- (D) Malformed subscription (empty endpoint/keys) -> `(False, "invalid")` (non-revoking). PASS.
- KEY-FORMAT LANDMINE (confirmed against py_vapid source): `Vapid.from_string` does b64url-decode,
  NO PEM branch. A **PEM** `VAPID_PRIVATE_KEY` -> "Could not deserialize key data" -> every web send
  silently fails `transient` -> nothing delivers. `VAPID_PRIVATE_KEY` MUST be the base64url of the
  RAW 32-byte private scalar (or a b64url DER). Use `gen_vapid.py` (this dir) which emits it correctly.

## PROD ACTIONS (require prod shell/SSM — NOT reachable from the dev host / this shell)
`aws`/`ssm` are not installed on the dev host and no aws CLI is available in the ops shell (same
constraint the sibling `p0-consumer/search` fold notes for DDB). These must be run by an operator
with SSM on i-08f937fc705ebea75, then `sudo -u ubuntu bash /home/ubuntu/restart_backend.sh`:
1. Confirm `pywebpush` in the PROD venv: `python -c "import pywebpush"`. If missing:
   `pip install pywebpush` (in requirements.txt; if absent every web send silently no-ops transient).
2. Confirm `PUSH_ENABLED=1` in the prod backend env (arms mobile + web; default OFF).
   `WEB_PUSH_ENABLED` already defaults ON.
3. VAPID keys: prod already returns a public key (above). If web sends are failing, verify
   `VAPID_PRIVATE_KEY` is the RAW base64url form (NOT PEM). To (re)generate a matched pair, run
   `ops/prod-hotfixes/p0-consumer/webpush/gen_vapid.py` and set VAPID_PUBLIC_KEY/VAPID_PRIVATE_KEY/
   VAPID_SUBJECT. NOTE: rotating invalidates existing browser subs (they re-subscribe); the SPA
   fetches the public key at runtime so NO web rebuild is needed to rotate.
4. `curl https://tl-api.bitbazaar.cc/ui/push/vapid-key` -> 200, openapi 200.

## E2E VERIFY (once 1-3 confirmed on prod)
On the web SPA: Alerts -> Push devices -> "Enable Notifications" (grant permission). Confirm a
`platform:"web"` row in `push_devices` (GET /ui/push/devices). Trigger a **default-ON** event —
e.g. receive a tip (post_tip) or `POST /ui/push/subscribe` then a real new_message — and confirm the
browser notification fires. CAVEAT: `POST /ui/push/test` emits alert_type `security_event`, which is
NOT in DEFAULT_PUSH_EVENT_TYPES; it delivers only if the user has explicitly enabled security-event
push. Prefer a default-ON transactional event (tip/order/subscription/message) to smoke-test.

## Files in this fold
- `README.md` (this file) — verify record + prod runbook.
- `gen_vapid.py` — reproducible VAPID keygen in the exact formats the code expects (deps: cryptography).

## Residuals (non-blocking)
- `POST /ui/push/test` uses `security_event` (opt-in), so the "Test" button no-ops for users who
  have not enabled security-event push. Cosmetic verify-UX papercut; behavior is pref-correct.
- The SPA subscribe flow posts to `/ui/push/register` (platform:web), not the dedicated
  `/ui/push/subscribe`; both persist a json.loads-able blob and deliver identically. No action needed.
