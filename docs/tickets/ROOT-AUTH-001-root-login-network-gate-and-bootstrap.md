# ROOT-AUTH-001: Root Login Hardening — Finalize Network Re-Gate (B3) + Bootstrap (B2)

**Ticket**: ROOT-AUTH-001
**Author**: Engineering
**Status**: Open
**Priority**: High (B3 is a security hole)
**Date**: 2026-06-04
**Dependencies**: `app/routers/root_auth.py`, `app/routers/ui_session.py`, `app/auth/root_network.py`, `app/services/sessions.py`, `docs/root-admin-login-plan.md`

---

## 1. Overview

Three confirmed gaps in the root login/session lifecycle. B3 is an actual
security bypass; B2 makes a fresh production deploy un-bootstrappable.

### B3 (SECURITY HOLE) — root network gate not applied at session finalize
`POST /auth/root/login` enforces the network gate
(`enforce_root_network_gate(req)`, `root_auth.py:21`) and requires root MFA, then
returns a step-up `challenge_id`. **But the session is actually minted by the
shared `POST /ui/session/finalize`** (`ui_session.py:170-189`), which:
- does **not** call `enforce_root_network_gate`, and
- applies no root-specific check at all — it just `load_challenge_or_401` +
  `maybe_finalize` + `rotate_session_cookies`.

So a root step-up challenge created from an allowed IP can be **finalized (and the
root session minted) from any IP** — the network gate is bypassable. Same for B1:
finalize has no root-specific hardening even though login does.

### B2 — no root bootstrap (chicken-and-egg) on a fresh deploy
`/auth/root/login` refuses to proceed unless root MFA is already configured
(`root_auth.py:25-28`, `compute_required_factors` non-empty). But:
- `ROOT_USER_SUB` (`settings.py:29`) sets the root *identity* only — no user
  record, password, or MFA.
- There is **no enroll-MFA-for-root path**: `rootctl root reset-mfa` only
  **deletes** factors (`rootctl.py:_root_reset_mfa_command`), which makes login
  *more* blocked, not less. `reset-password` requires an existing root session.
- No bootstrap endpoint / seed exists.
- Confirmed: **fresh-deploy root bootstrap is not possible today.**

## 2. Proposed Fix

### B3 / B1 — re-gate root at finalize
- In `POST /ui/session/finalize`, when `user_sub == S.root_user_sub` (or the
  challenge is flagged as a root-login challenge), call
  `enforce_root_network_gate(req)` **before** minting the session, and apply the
  root MFA/short-TTL invariants. Best: **stamp the source IP / `root_login=true`
  on the challenge** at `/auth/root/login` and have finalize verify the finalizing
  IP matches the gate (or is in the allowlist) and that the challenge is a root
  challenge. Reject otherwise (audit `root_finalize_denied`).
- Consider a dedicated `POST /auth/root/finalize` so root never traverses the
  generic finalize path, keeping all root hardening in one place.

### B2 — first-run root bootstrap
- Add a one-time **`POST /auth/root/bootstrap`** gated by a single-use
  `ROOT_BOOTSTRAP_TOKEN` (env/secret), allowed only when no root record/MFA exists
  (and behind the root network gate): creates the root user, sets initial
  password, and **enrolls the first MFA factor** (TOTP enroll → returns the
  provisioning secret/QR), then self-disables. Alternatively a
  `rootctl root enroll-mfa` bootstrap mode that sets the first factor (paired with
  reset-password) — but the endpoint is cleaner and avoids needing DDB access.
- Document the exact procedure in `docs/run-deploy.md` / `root-admin-login-plan.md`.

### Design Principles
- Root session minting is gated by network + MFA **at the point of issuance**, not
  only at challenge creation.
- Bootstrap is one-time, token-gated, self-disabling, network-gated; no standing
  backdoor; root-role invariant preserved.

## 3. Testing
- pytest/E2E: root challenge created from allowed IP **cannot** be finalized from a
  different IP (B3); root finalize enforces MFA + short TTL; bootstrap creates root
  + enrolls MFA with a valid one-time token, is rejected once root exists / with a
  bad token, and is refused outside the network gate.

## 4. Out of Scope / Related
- **A3** (admin scopes vs rootctl capabilities mismatch) — separate ticket
  (ADMIN-PERMS); not part of root auth.
- rootctl break-glass auth — **ROOTCTL-001**.

## 5. Confirmed evidence
- Gate on login only: `app/routers/root_auth.py:21,25-28`.
- Finalize mints session with no root re-gate: `app/routers/ui_session.py:170-189`.
- reset-mfa deletes (doesn't enroll) factors; no enroll path: `app/cli/rootctl.py`.
- Root identity env only: `app/core/settings.py:29`.
