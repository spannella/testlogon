# Security Audit — 2026-06-04

Static, code-level audit across 8 attack surfaces. Findings are **calibrated by
who can exploit them**: 🌐 unauthenticated/any-user, 👤 any logged-in user,
🛡️ admin-abuse/over-privilege, ⚙️ config-dependent (only a hole if a prod env
var is unset/weak). Severities are the auditor's, re-calibrated for real-world
exploitability.

---

## TOP PRIORITY (fix first)

### 1. 🌐 SSRF via message link-preview — **Critical**
`app/routers/messaging.py:~4844` `_fetch_link_preview()` does `requests.get(url)`
on a URL extracted from message text with **no SSRF guard**. Any user sends a
message containing `http://169.254.169.254/latest/meta-data/iam/security-credentials/`
(or `http://localhost:8001`, internal services) → server fetches it → **cloud
credential / internal-service exfiltration**. A guard already exists
(`app/services/webhook_ssrf.py validate_webhook_url`) and is used elsewhere — just
not here. **Fix:** call `validate_webhook_url(url, skip_dns=S.dev_mode)` before fetch.

### 2. ⚙️🌐 Forged webhooks → unpaid entitlements — **Critical (if prod secrets unset)**
Several inbound webhooks fall back to **hardcoded default secrets** when env is
unset, letting an attacker forge "payment succeeded / subscription active / KYC
approved":
- CCBill: `billing_ccbill.py:159-172` default `"local-ccbill-webhook-secret"` (local mode = dev default).
- KYC eIDV callback: `kyc_eidv.py:202` default `"dev-mock-eid-signing-key"` → forge identity verification / tier upgrade.
- CCBill IP policy "monitor" mode lets bad IPs through (`billing_ccbill.py:515`).
- Webhook-registration SSRF validation only runs when `webhooks_v2_enabled` and swallows errors in dev (`webhook_service.py:225`).
- Stripe dedupe vs PayPal `custom_id`-parsed user → replay/double-credit edge cases.
**Fix:** require strong secrets (fail-closed; no hardcoded fallback), enforce
`ip+sig` in prod, always run SSRF validation, store user↔order server-side.

### 3. 🛡️ Wallet deposit/withdraw IDOR via `user_sub` override — **High**
`app/routers/billing.py:2316` (deposit) & `:2398` (withdraw) accept an optional
`user_sub`; a `billing_support` admin can **credit any user** (charge own card →
credit victim = laundering) or **drain any user's wallet**. **Fix:** remove the
`user_sub` override (operate on the authenticated user only), or move admin-initiated
adjustments to a separate, audited, two-person endpoint.

### 4. 🌐 Mock S3 endpoint has zero auth + registered unconditionally — **High**
`app/routers/s3_mock.py` `GET /mock/s3/{bucket}/{key}` has **no auth**; in dev,
file downloads use these URLs, so anyone who knows/guesses a key
(`{user}/objects/{id}`) downloads any file. Worse, the router is `include_router`'d
**unconditionally** in `app/main.py:450` (only moto init is dev-gated) → in prod it
could hit real S3. **Fix:** register the router only when `S.dev_mode`; add an
owner/key check.

### 5. ⚙️ Hardcoded secret fallbacks (forgeable tokens) — **High (if prod env unset)**
`os.environ.get(..., "<dev-default>")` for security-critical secrets:
- `cursor.py:22/36` `"dev-cursor-secret"` → **forge pagination cursors → IDOR over records**.
- DRM: `drm_production_provider.py:155` salt, `broadcast_local_drm.py:35/42-44` token + **static `"dev-token"` bypass**, `broadcast_playback.py:38` (MD5-signed URLs).
- `API_KEY_PEPPER`, `WS_TOKEN_SECRET`, `UI_ACCESS_TOKEN_SECRET` accept empty.
**Fix:** fail-closed at startup if any security secret is empty/default in non-dev;
remove static DRM token; upgrade MD5→HMAC-SHA256.

### 6. 👤 Stored XSS via file preview & rich-text fallback — **High**
- `app/routers/filemanager.py` preview serves `text/html` / `image/svg+xml` with
  `Content-Disposition: inline` → upload `malicious.html`, open preview/shared-preview
  → JS runs in app origin (session theft). **Fix:** force `attachment` for non-safe
  types; exclude html/xml/svg from `is_previewable`.
- `frontend/.../MarkdownComposer.tsx:134` `richDocToHtml` interpolates `body_plain`
  fallback unescaped → `dangerouslySetInnerHTML`. **Fix:** escape the fallback.
- Aggravator: the access token is mirrored into `localStorage["auth-store"]`, so any
  XSS = token theft (consider not persisting it).

---

## HIGH — broken access control (IDOR / scoping)

- 👤 **Activity-feed forgery** `activity_feed.py:148` — `POST /feed/record` takes
  `user_id` from the body; any user can inject feed entries for anyone. Force to `ctx.user_sub`.
- 🛡️ **KYC masked-PII unscoped** `kyc_cases.py:1557` — *any* admin reads masked PII
  for *any* case (decrypt path is scoped, masked path isn't). Apply `_is_scoped_admin_for_case`.
- 🛡️ **Impersonation audit scan** `admin_impersonation.py:192` — any `auth_support`
  admin scans **all** impersonations platform-wide. Scope to self or ROOT.
- 🛡️ **Admin compute quotas / invoices / job-retry** (`admin_compute.py:158`,
  `invoices.py:97`, `admin_jobs.py:90`) — any admin reads/acts on any user by id, some
  **unaudited**. Add scoping + audit events.
- 👤 **Achievements read** `achievements.py:228` — read any user's badges/points by id.
- **Signature packet final-PDF** `signature_packets.py:858` — a signer who hasn't
  signed can download the completed PDF; no completion check + no download rate limit.

## HIGH/MEDIUM — config & exposure

- 🌐 **FastAPI `/docs` + `/openapi.json` exposed in prod** (`main.py:384`) — full API
  schema to anyone. Disable when not dev.
- 🌐 **`/internal/ffmpeg-status` unauthenticated** (`main.py:395`) — version/path
  disclosure. Gate dev/root.
- ⚙️ **Mock routers registered unconditionally** (`main.py:443-449`) — ccbill/google/
  jira/paypal/caldav; safe only via per-request `_ensure_mock_enabled()`; register
  conditionally as defense-in-depth.
- **Cookie `secure` defaults false** (`settings.py:92`) — ensure prod sets it true.
- **CORS** wildcard+credentials echoes Origin (`main.py:364`) — tighten to known origins.
- 🛡️ **`dev_add_charge`** can fabricate `settled` debt (`billing.py:2238`); restrict to webhook path.

## MEDIUM / LOW (hardening)
- Tip ledger best-effort (non-atomic) debit/credit → money integrity (`tip_ledger.py`).
- UPS webhook **no replay/timestamp** check; UPS `/emit` SSRF (`ups.py:207`, dev).
- Unlock price unbounded; payout/deposit positive-amount defensive checks.
- Password hashing PBKDF2-260k (fine, non-adaptive → consider Argon2id).
- Webhook rotate-secret returns plaintext (`webhooks.py:173`).
- Share-link TOCTOU + timing; CSV export no rate limit; `DocConfigIn` `extra="allow"`.
- Stripe webhook dedupe race (`billing.py:1261`).

## Confirmed-good (not gaps)
CSRF enforced on cookie-auth mutations; require_admin_scope IS enforced; account
closure requires MFA; file lists capped at 500; CalDAV + registered-webhook SSRF
guards present; rich-node type allowlist rejects html/script; password reset/login/MFA
rate-limited; uuid4 link tokens are strong.

## Already ticketed (separate)
Root finalize network-gate bypass (ROOT-AUTH-001), rootctl no-auth (ROOTCTL-001),
admin scopes-vs-capabilities (ADMIN-PERMS-001), rate-limit dev inflation (dev-only).

---

## Cross-cutting themes
1. **IDOR by `user_sub`/`id` from the request** is the most repeated pattern — many
   admin and a few user endpoints trust an id instead of the authenticated subject.
2. **Hardcoded `dev-*` secret fallbacks** create a "secure-only-if-env-set" trap.
3. **SSRF guard exists but isn't applied uniformly** (link preview, UPS emit, webhook v1 path).
4. **Dev/mock surfaces** rely on runtime gates rather than not-registering in prod.

---

# Wave 2 (deeper surfaces) — additional findings

## New high-impact
- 🌐 **XFF IP spoofing** — `app/core/normalize.py:client_ip_from_request` trusts the
  first `X-Forwarded-For` with **no trusted-proxy check**. Used by rate-limit
  middleware, audit logs, login-anomaly, device-trust, magic-link IP check → an
  attacker rotates `X-Forwarded-For` to **bypass per-IP rate limits / brute-force
  login+MFA**, **evade the IP blocklist**, **poison audit/forensics**, and bypass the
  magic-link IP-match. (Root gate `root_network.py` is OK — it uses trusted-proxy
  resolution; the generic helper does not. → **SEC-008**, Critical.)
- 🌐 **SAML RelayState open redirect** — `app/routers/sso_saml.py:78,212` redirects to
  the IdP-supplied `RelayState` unvalidated → post-auth phishing/token theft.
  Host-header → eID callback URL (`kyc_eidv.py:87`). → **SEC-011**, High.
- 🌐/👤 **Account-takeover via auth weaknesses** — OTP brute force (per-IP only +
  `mfa/sms/begin` resets the per-challenge counter → unlimited 6-digit guesses,
  `ui_mfa.py`/`rate_limit.py`); **device-trust cookie is an unbound random token**
  (not HMAC(server_secret,user+device)) → stolen cookie = permanent MFA skip and
  attacker can self-trust a device (`device_trust.py`); non-constant-time `!=` on
  email/recovery codes; password reset **silently ignores** session-revocation
  failures; **email/phone change doesn't verify the new address** before it becomes a
  login/reset identity; recovery-code brute force (48-bit, no global lockout). →
  **SEC-009**, Critical.
- 🌐/👤 **Realtime-stream IDOR (SSE/WS)** — `GET /broadcast/sessions/{id}/stream` and
  `/chat/stream` (`broadcast.py:717,1763`) and `watch_party/{id}/stream`
  (`watch_party.py:262`) authenticate but **don't check the subscriber is a
  participant** → stream another user's private broadcast/chat/party in real time;
  chat stream calls `_chat_msg_out` **without `viewer_user_id`** → **locked/expired
  message text leaks**. `mint_ws_token`/`verify_ws_token` minted but never verified.
  → **SEC-010**, Critical.
- 🌐 **Media pipeline SSRF/local-file-read** — ffmpeg inputs lack
  `-protocol_whitelist`; `video_concatenator.py:338` uses `concat -safe 0` (allows
  `file://`); watermark download accepts arbitrary `http(s)` (`169.254.169.254`).
  → **SEC-012**, High.
- 💸 **Economic/business-logic abuse** — affiliate commission **replay** (no
  idempotency on `transaction_id`, `referrals.py:289`); **free-trial unlimited
  re-subscribe** (`subscription_server.py:817`); promo per-user limit **race/TOCTOU**
  (`promo_codes.py`); referral attribution **race** (no ConditionExpression);
  view-once **re-read race**. → **SEC-013**, Critical/High.

## Confirmed-good (wave 2)
Mass-assignment privesc NOT found — profile/address/media updates use allowlisted
models (`normalize_profile_payload`/`AddressIn`/`MediaPreferencesIn`); `extra="allow"`
only on response models. Self-referral & self-tip blocked; cancelled subscriptions
grant no access; image decompression-bomb limit + SVG reject present; browser-SSH WS
authorizes per session owner; root network gate uses trusted-proxy IP resolution.

## Note
API keys created before scoped-capabilities default to **full scope** when
`capabilities is None` (`api_keys.py:125`) — migrate legacy keys (tracked under SEC-005).

---

# Wave 3 (remaining surfaces) — additional findings

## New high-impact
- 🌐 **Security-headers middleware defined but NEVER registered** — `app/main.py:348-356`
  defines `_security_headers_middleware` (X-Frame-Options/CSP/nosniff/Referrer-Policy)
  but it's not added to the app → **no clickjacking/CSP/MIME protection** site-wide.
  Plus client-side: SW `postMessage` handler with no origin check, `target=_blank`
  without `noopener` (reverse tabnabbing), `RichContentRenderer` trusts backend
  `bodyMarkdownHtml`, client SSO-URL assignment unvalidated. → **SEC-016**, High.
- 👤/🌐 **SMS toll-fraud / email phishing relay** — `app/routers/mfa_devices.py`
  SMS/email device "begin" send a code to an **attacker-supplied** phone/email
  **before** ownership is proven (`:108-142`, `:230-267`); removal-challenge spam;
  registration SMS to arbitrary phone (`register.py:273`); Twilio Verify bypasses the
  per-number daily cap (`mfa.py`); no per-recipient caps → cost + harassment + your
  domain as a phishing/spam relay. → **SEC-014**, Critical.
- 🔑 **WebAuthn passkey register/remove without step-up MFA** —
  `app/routers/webauthn.py:28-46` only `require_ui_session` → a hijacked session lets
  an attacker **register their own passkey** (persistent takeover) and remove the
  victim's → lockout. → **SEC-017**, Critical.
- 🛡️ **Org/tenant isolation & lifecycle** — `add_org_payment_method`
  (`orgs.py:219`) skips `assert_org_membership` (lower-role member acts); **invite
  token not bound to email** (`org_service.py:236` — any user accepts a leaked
  invite); member-removal/org-archival **don't revoke sessions**
  (`org_service.py:323,178`). → **SEC-015**, High.
- ⏱️ **Account-state revocation lag (TOCTOU)** — ban check isn't applied on the
  **API-key** auth path, and **role downgrade is cached in the JWT** so it isn't
  effective until token refresh (`sessions.py:291-310`); account **deletion request
  doesn't revoke sessions** during the grace period (`account_deletion.py:175`);
  soft-deleted **email can be re-registered** and inherit data; deletion-cancel lacks
  step-up. → **SEC-018**, High.
- 🧩 **DynamoDB expression injection (pattern)** — `commerce_entitlement_orchestrator.py:105`
  builds `KeyConditionExpression` with an f-string (input currently internal, but
  unsafe pattern); use `Key().eq()`. → **SEC-019**, Medium.

## Confirmed-good (wave 3)
Repo secret hygiene clean (.env gitignored, only dummy test values, no committed
keys); dependencies reasonably pinned with no obvious known-CVE versions; CI has no
`pull_request_target`/secret-echo; cursor HMAC is verified BEFORE decode; temp files
use `NamedTemporaryFile`/`TemporaryDirectory` (no `mktemp`); transcode scratch dirs
are UUID-scoped; provider cache keys include `user_sub`; CSV import validates+caps;
API-key revocation IS checked per-request; impersonation revocation/expiry per-request.

---

# Wave 4 (feature-deep surfaces) — additional findings

## New high-impact
- 🌐 **Browser-SSH/SFTP destination SSRF — default allow-all** —
  `app/routers/browser_ssh_terminal.py:408-488` (and `sftp_destination_policy.py:84`)
  only block a host if `BROWSER_SSH_ALLOWED_HOSTS`/denied (or the SFTP policy) is
  **configured**; default = empty = **allow any host:port**. An authed user opens the
  WS terminal / SFTP mount to `169.254.169.254` (cloud metadata → IAM creds),
  `127.0.0.1`, or internal services → SSRF/pivot + credential theft. No hardcoded
  metadata/loopback denylist. → **SEC-020**, Critical.
- 🔐 **Stored credentials returned via API** — refresh-token ciphertext exposed in
  `provider_oauth.py:314` → `projects.py:352` metadata; **S3 `secret_access_key`
  returned in plaintext** by `provider_credentials.py:533-543` auth-context; SFTP
  secrets decrypted into memory with no scrub. (SSH keys, LLM keys, OAuth access
  tokens are correctly encrypted+stripped — good.) → **SEC-022**, High.
- 📆 **iCal injection + public-event enumeration + booking abuse** — `calendar.py:2048`
  builds `SUMMARY`/`DESCRIPTION` without RFC-5545 escaping → CRLF/property injection
  (ATTACH/VALARM) into `.ics`; public event endpoints (`:2079`) have **no auth/rate
  limit** → id-enumeration of events; public booking has no rate limit and a
  **`ctx` NameError at `:2043`** (500/DoS). → **SEC-023**, High.
- 💳 **E-commerce price/quantity tampering** — add-to-cart trusts client
  `unit_price_cents` (`shoppingcart.py:346`) → buy for $0; **refund/cancel doesn't
  revoke entitlements** (`purchase_history.py:501-535`) → buy digital good, refund,
  keep access. (Cart/txn/invoice IDOR, promo cap, stock race are correctly handled.)
  → **SEC-024**, Critical.
- 📡 **Broadcast/scheduler/moderation abuse** — broadcast session start/stop/delete
  check operator-role but **not ownership** (`broadcast.py:495-575`) → any operator
  hijacks another's session; moderation **report-flood** auto-takedown (per-user 8/min,
  per-IP 20/IP — multi-account/proxy bypass, `moderation.py:174-222`); Q&A upvote
  TOCTOU (`broadcast_qa.py:214`). (admin job-retry IDOR already in SEC-005; push
  subscription + stream-key handling are correctly scoped — good.) → **SEC-025**, High.
- ⚙️ **Agent worker / coder command-injection pattern** — `repo_url`/`branch`
  interpolated into shell `git clone` in `agent_coder.py`/`agent_architect.py`
  (**gated** by `AGENT_CODER_EXECUTE_COMMANDS`/`ARCHITECT_EXECUTE_COMMANDS`, default
  off); `custom_install_commands`/`custom_verify_command` accepted but currently dead
  code; LLM key-test echoes provider error body. Use `shlex.quote`/`shell=False`
  before these are ever enabled. → **SEC-021**, Medium (latent).

## Confirmed-good (wave 4)
SSH private keys, LLM API keys, OAuth access tokens, GitHub/GitLab tokens, Apple CalDAV
passwords are KMS-encrypted at rest and stripped from API responses; all credential
reads enforce owner scoping (no IDOR). EC2/k8s instance lifecycle is owner-scoped; k8s
image allowlist enforced. Cart/transaction/invoice reads are user-PK-scoped (no IDOR);
promo discount capped at item price; stock decrement is atomic (no oversell). Message/
post/catalog search is properly authz-scoped. Push register/revoke owner-scoped; stream
keys stored as Secrets-Manager refs (never returned).

---

# SECOPS — Security Detection & Response (defensive build-out)

Follow-on to the audit: instrument every suspicious event, then monitor + block
(IP/CIDR/ASN/datacenter/geo) and deploy honeypots. Filed as a build-it ticket set
(implement after E2E is green). Builds on existing infra: `geoip.py` (country lookups —
add ASN), `geo_check.py`/`geo_rules.py` (content geofencing), `rate_limit*`, `alerts.py`,
`metrics.py`, RiskDashboard/RateLimitDashboard. Hard prerequisite: **SEC-008** (trusted,
non-spoofable client IP) — every detection/block depends on accurate source attribution.

- **SECOPS-001** — Unified security-event telemetry pipeline (emitter + taxonomy +
  IP/ASN/geo enrichment + `security_events` table). Foundation.
- **SECOPS-002** — Network blocklist & auto-ban (IP / CIDR / ASN / Geo) enforcement
  middleware + escalation; extends geoip.py with a GeoLite2-ASN reader + datacenter ASN list.
- **SECOPS-003** — Honeypots & honeytokens (decoy routes, canary records/tokens, traps).
- **SECOPS-004** — Detection/correlation/alerting + admin SecurityMonitoring dashboard.
