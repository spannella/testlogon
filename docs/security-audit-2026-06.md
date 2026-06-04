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
