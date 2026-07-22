# TestLogon — Production Go-Live Runbook

**Status of the world:** the *running* prod (EC2 `i-08f937fc705ebea75`, us-east-2) is a **DEV_MODE=1 demo** — in-process **moto S3**, **DDB-Local** (:8001), **stripe-mock**, app-managed registration/login (no Cognito), no real vendor keys. Every "real-AWS / real-vendor" code path across the platform is **written, tested, and prod-mirrored, but LATENT** until this environment is switched to real infrastructure + credentials. "prod-live + verified" in the program history means *the code path is deployed and works when its environment is real* — it does NOT mean the demo is moving real money today.

This runbook is the single checklist to flip the demo into a real production service. Flags/paths verified against `app/core/settings.py` on 2026-07-22.

---

## 0. THE #1 TRAP — prod-hotfixes are not in prod's git source
The running prod carries **dozens of live hotfixes/patches under `ops/prod-hotfixes/`** (messaging call-fanout, ghost-call suppression, broadcast rich-chat, the sessions x-session-id fix, MediaMTX/Go-Live infra, plus every smoothing/dispute/ecom/contacts fold) that are **NOT on prod's deployed git branch**. **Any redeploy from git MUST first re-apply `ops/prod-hotfixes/` or shipped features regress.** Before go-live, reconcile these INTO the source branch (the ecom/contacts folds already did this pattern) so a clean deploy == the running prod. Treat this as a blocking prerequisite, not a footnote.

---

## 1. Master switch
| Setting | Now | Set to | Effect |
|---|---|---|---|
| `DEV_MODE` | `1` | `0` | Cascades: disables moto/DDB-Local defaults, stripe-mock, dev email-code readback, and flips the DEV_MODE-defaulted flags below. Nothing works after this until sections 2-3 are real. |

Flags that DEFAULT to DEV_MODE (become OFF at DEV_MODE=0 — set explicitly if you want them on): `ccbill_mock_enabled`, `broadcast_devtools_enabled`, `broadcast_recording_worker_inline`, `group_calls_enabled`, `ec2_mock_enabled`, `k8s_mock_enabled`, `transcode_worker_enabled` (defaults to DEV_MODE=0 → **set `TRANSCODE_WORKER_ENABLED=1`** so VOD download-MP4 + ABR run), `broadcast_scheduler_enabled`.

## 2. AWS infrastructure (replace moto/DDB-Local)
| Env | Now | Set |
|---|---|---|
| `AWS_REGION` | `us-east-1` (code) / instance in us-east-2 | real region + IAM role/keys with S3+DynamoDB perms |
| DynamoDB | DDB-Local :8001 | real DynamoDB tables (migrate the single-table schema; the `users` table is real-Cognito-backed at go-live) |
| S3 buckets | moto / `local-uploads` etc. | real buckets: `VIDEO_UPLOAD_BUCKET`, `VOD_OUTPUT_BUCKET`, `PRIVACY_EXPORT_S3_BUCKET`/`AUDIT_EXPORT_S3_BUCKET`/`LEGAL_EXPORT_S3_BUCKET` (data-exports), `TICKET_ATTACHMENTS_S3_BUCKET`, `EMAIL_BODIES_S3_BUCKET`, `BANKING_S3_BUCKET`, `CRM_NOTES_S3_BUCKET` |

## 3. Auth — Cognito (real user pool)
In DEV_MODE prod self-manages registration/login (email codes in the backend log). At go-live wire real Cognito: `COGNITO_USER_POOL_ID`, `COGNITO_APP_CLIENT_ID`, `COGNITO_REGION`, `COGNITO_ISSUER_URL`, `COGNITO_JWKS_URL` (+ `COGNITO_EXPECTED_TOKEN_USE`). The web SPA needs the matching `VITE_COGNITO_*` (see section 11).

## 4. Payments — Stripe (drop stripe-mock)
| Env | Set |
|---|---|
| `STRIPE_SECRET_KEY` / `STRIPE_PUBLISHABLE_KEY` | real keys |
| `STRIPE_API_BASE` | empty (real Stripe) — was pointed at stripe-mock in dev |
| `STRIPE_WEBHOOK_SECRET` | real endpoint secret (billing webhooks — distinct from the subscription webhook secret) |
| `CCBILL_MOCK_ENABLED` | `0` (if CCBill is a real processor) |
Covers: subscriptions, ads deposits, tips, e-commerce checkout, VOD purchases — all currently on stripe-mock.

## 5. Payouts (money-OUT) + real transfer rail
Gate + runner already default ON (`payout_verification_gate_enabled`, `payout_runner_enabled`). The actual **transfer is honest-mock-until-keyed** — flip the Stripe Connect go-live flags + install Connect keys (see `ops/plans/payouts-plan.md` / the payouts-program memory). `PAYOUT_MAX_TRANSFER_ATTEMPTS=4`. Verify: a real withdrawal debits balance → KYC/W-9 gate → real transfer → 1099 accrual.

## 6. Disputes (processor track)
`PAYMENT_INCIDENTS_ROLLOUT_ENABLED=1` (default on) + `PAYMENT_INCIDENTS_ROLLOUT_PROVIDERS=stripe,paypal,ccbill`; run **shadow → live per provider** (`payment_incidents_rollout_shadow_mode`). `DISPUTE_CHARGEBACK_RECONCILE_ENABLED=1`. Needs `STRIPE_WEBHOOK_SECRET` (section 4) for real chargeback events. See the payment-disputes-program memory.

## 7. Shipping — EasyPost
`EASYPOST_API_KEY` + `EASYPOST_WEBHOOK_SECRET` (`EASYPOST_API_BASE` default real). `SHIPMENT_PROGRESSION_ENABLED=true` (default false) to run the tracking runner. Until keyed it is honest-mock-that-progresses.

## 8. Push — Firebase / FCM
Real `google-services.json` is already on-disk (gitignored, carries a real API key — confirm App Check restrictions / rotate if warranted). Install the FCM server credential (service account) for backend sends.

## 9. Realtime + calls — LiveKit + TURN
- **LiveKit** (audio rooms already use a deployed server): `LIVEKIT_URL` / `LIVEKIT_API_KEY` / `LIVEKIT_API_SECRET`. Setting these also enables **group-call SFU media** (the group-call token seam) and is required for group video. `GROUP_CALLS_ENABLED` (defaults to DEV_MODE → set `1`).
- **1:1 WebRTC calls**: `MESSAGING_WEBRTC_DIRECT_CALL_ENABLED=1` (default false) + TURN: `MESSAGING_WEBRTC_TURN_ENABLED=1`, `MESSAGING_WEBRTC_TURN_URLS` (prod coturn `18.222.237.167` is deployed), `MESSAGING_WEBRTC_TURN_SECRET`, `..._TTL_SECONDS=600`. (Dev now has its own coturn — see `ops/dev-turn/README.md`.)
- App-side residual: **video-call PiP keep-alive fix `9763d010` (android-impl) is build-verified but on-device float proof is PENDING** — verify + merge before relying on call PiP (see the contacts-pip-program memory).

## 10. Media / VOD, Contacts, NCMEC
- **VOD**: `TRANSCODE_WORKER_ENABLED=1` (ffmpeg present on prod) → real download-MP4 transcode + ABR (see the prod-is-devmode-demo memory).
- **Contacts sync**: **ROTATE `APP_CONTACT_MATCH_SALT`** from the dev default `tl_contact_match_v1` before public + rebuild the app (BuildConfig.CONTACT_MATCH_SALT) + run `ops/backfill_contact_match.py` against the real users table.
- **NCMEC (safety/legal)**: `NCMEC_REPORTING_ENABLED=true` + `NCMEC_API_BASE` + `NCMEC_API_KEY` + `NCMEC_ORG_ID` — **requires a real CyberTipline ESP account + legal sign-off on report content/retention** (owner + counsel). Until then it honest-records intent (nothing lost).

## 11. Web SPA deploy (never deployed)
`cd frontend && npm ci && npm run build` (Node 20) → deploy `dist/` to **CloudFront/S3** (per DEPLOYMENT.md) with prod `VITE_COGNITO_USER_POOL_ID/APP_CLIENT_ID/REGION/ISSUER_URL/JWKS_URL` (leave `VITE_API_BASE_URL` empty for cookie/SSE auth). Apply section 0 prod-hotfixes to the backend first. Needs owner's CloudFront distribution id / S3 bucket + deploy creds.

## 12. Security must-dos BEFORE public (see ops/ci-security-groups.md)
- **Close the plaintext exposure**: API `:8000` + SPA `:3000` are externally reachable bypassing Caddy TLS (`http://18.222.237.167:8000/openapi.json` → 200) — restrict to localhost/dev-host. Also close the world-open duplicate SSH + stale `:5173`. Reversible `aws ec2` commands documented.
- **HLS cutover**: `BROADCAST_LOCAL_CACHE_PUBLIC_BASE_URL` off cleartext `:8888` → the Caddy `https://…/hls-live` route (transport already applied); reconcile the `mint_local_playback_url` path shape vs MediaMTX; verify against a live stream.
- **LiveKit `:7880`** carries client signaling AND the RoomService admin API on one port → wss-front + split the admin API before CIDR-restricting.
- **Keep world-open (WebRTC needs it)**: coturn `udp/3478`+relay range, LiveKit `udp/7882`/`tcp/7881`, MediaMTX `udp/8189`/`tcp/8889`, Caddy `80/443`.
- **Rotate** the LAN-dev coturn secret (`tlturnsecret123`) before any non-LAN use; review/rotate the Firebase key.

## 13. Recommended ordering
1. Reconcile `ops/prod-hotfixes/` into the source branch (section 0) — blocking.
2. Stand up real AWS (S3+DynamoDB) + Cognito in a **staging** clone; flip `DEV_MODE=0` there and smoke every subsystem.
3. Providers in **shadow** first where supported (disputes; Stripe test keys → live keys).
4. Security lockdown (section 12) before any public DNS.
5. Deploy web SPA (section 11). 6. Flip prod `DEV_MODE=0` + real keys. 7. NCMEC last (needs legal).

## 14. Owner-only (cannot be done from the repo host)
Real AWS account/IAM + S3/DynamoDB, real Cognito pool, Stripe/EasyPost/LiveKit/Firebase/NCMEC credentials, CloudFront/S3 deploy creds + DNS, and legal sign-off (NCMEC content/retention, ToS/privacy for contact matching). Everything else in this doc is a code path already built and waiting on these.

_See memories: prod-is-devmode-demo, payouts-program, payment-disputes-program, subscriptions-smoothing, advertising-smoothing, ecommerce-smoothing, tipping-rough-edges-plan, moderation-smoothing, contacts-pip-program, close-incomplete-program, web-build-status, android-unit-tests._
