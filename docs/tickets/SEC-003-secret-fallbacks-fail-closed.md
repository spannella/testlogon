# SEC-003: Eliminate Hardcoded dev-* Secret Fallbacks (fail-closed)

**Ticket**: SEC-003 · **Status**: Open · **Priority**: High · **Date**: 2026-06-04
**Source**: `docs/security-audit-2026-06.md` (item 5, + crypto findings)

## Problem
Security-critical secrets use `os.environ.get(..., "<dev-default>")` or accept
empty strings — "secure only if the env var is set." If a prod env is unset, these
become forgeable:
- `app/core/cursor.py:22,36` — `"dev-cursor-secret"` → **forge pagination cursors →
  IDOR over records**.
- `app/services/drm_production_provider.py:155` — `"dev-drm-rotation-salt"` (key-id prediction).
- `app/services/broadcast_local_drm.py:35` — `"local-drm-secret"`; `:42-44` **static
  `"dev-token"` DRM bypass** (accepts a fixed token for any stream key).
- `app/services/broadcast_playback.py:38` — `"local-cache-secret"` + **MD5**-signed
  playback URLs.
- Empty allowed: `API_KEY_PEPPER` (`settings.py:45` / `api_keys.py:32`),
  `WS_TOKEN_SECRET` (`settings.py:246`), `UI_ACCESS_TOKEN_SECRET` (`settings.py:98`),
  `CURSOR_SIGNING_SECRET`, CCBill/UPS/KYC webhook secrets (see SEC-002).
- Password hashing PBKDF2-SHA256 260k (`registration.py:32`) — adequate but
  non-adaptive (consider Argon2id + rehash-on-login).

## Fix
- **Startup secret validation:** a single check that fails app boot in non-dev
  (`not S.dev_mode`) if any of these secrets is empty or equals its dev default.
- Remove the hardcoded fallbacks (or scope them to `dev_mode` only).
- Remove the static DRM token bypass; upgrade MD5 URL signing → HMAC-SHA256.
- (Optional) migrate password hashing to Argon2id.

## Testing
pytest: boot fails when a required secret is empty/default and `dev_mode=False`;
cursor/DRM/playback tokens minted with a real secret verify, and a token signed
with the old default is rejected.
