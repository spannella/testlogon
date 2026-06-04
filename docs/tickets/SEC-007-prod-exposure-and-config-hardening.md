# SEC-007: Production Exposure & Config Hardening (dev/mock surfaces, headers)

**Ticket**: SEC-007 · **Status**: Open · **Priority**: Medium-High · **Date**: 2026-06-04
**Source**: `docs/security-audit-2026-06.md` (HIGH/MEDIUM config & exposure)

## Problem
Dev/mock surfaces and defaults rely on runtime gates rather than not existing in prod:
- 🌐 **Unauthenticated mock S3** `app/routers/s3_mock.py` — `GET /mock/s3/{bucket}/{key}`
  has **no auth**; registered **unconditionally** (`main.py:450`, only moto init is
  dev-gated). In dev, file downloads use these URLs → anyone guessing
  `{user}/objects/{id}` reads files; in prod the route exists and could hit real S3.
- 🌐 **`/docs` + `/openapi.json` exposed in prod** (`main.py:384`) — full API schema.
- 🌐 **`/internal/ffmpeg-status` unauthenticated** (`main.py:395`) — version/path disclosure.
- **Mock routers registered unconditionally** (`main.py:443-449`: ccbill/google/jira/
  paypal/caldav) — safe only via per-request `_ensure_mock_enabled()`.
- **Cookie `secure` defaults false** (`settings.py:92`); **CORS** wildcard+credentials
  echoes Origin (`main.py:364`).
- **Mass assignment**: `DocConfigIn` `extra="allow"` (`models.py:7371`) → unexpected
  fields persisted; audit other `extra="allow"` models.
- **CSV export** (`csv_export.py`) no rate limit (bulk contact/billing exfil);
  **share-link** TOCTOU/timing (`file_share_links.py:318`); webhook **rotate-secret
  returns plaintext** (`webhooks.py:173`).

## Fix
- Register `s3_mock_router` **and all mock routers only when `S.dev_mode`**; add an
  owner/key check to mock S3.
- `docs_url=None, openapi_url=None, redoc_url=None` when not dev; gate
  `/internal/*` dev/root-only (or network-restricted), incl. ffmpeg-status.
- Default cookie `secure=True` in prod; tighten CORS to explicit origins (no
  wildcard+credentials); add CSP/HSTS/X-Frame-Options/nosniff.
- `extra="ignore"`/`"forbid"` on request models; rate-limit CSV export; don't return
  webhook secret in the body (show-once at creation).

## Testing
pytest: with `dev_mode=False`, `/mock/*`, `/docs`, `/openapi.json`,
`/internal/ffmpeg-status` are 404/403; mock S3 requires owner; CORS rejects unknown
origin with credentials; CSV export is rate-limited; unknown body fields are dropped.
