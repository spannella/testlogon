# AUTH-001: Registration Abandonment & Email-Lock Recovery

**Ticket**: AUTH-001
**Author**: Engineering
**Status**: Open
**Date**: 2026-06-04
**Priority**: High
**Estimated effort**: 3-5 days
**Dependencies**: Cognito integration (`app/services/cognito.py`), registration flow (`app/routers/register.py`, `app/services/registration.py`)

---

## 1. Overview & Motivation

### 1.1 Problem Statement

A user who **abandons registration before verifying** (lost connection, closed
the tab, walked away) has their **email persisted early** and then appears to be
**permanently blocked from re-registering**, with no obvious way back. This is a
real dead-end risk in the current flow.

**What gets written, and when** (multi-step flow: `start → confirm`):

- `POST /ui/register/start` (`app/routers/register.py:88-138`) immediately:
  1. In production, calls `cognito_sign_up()` → creates an **UNCONFIRMED** Cognito
     user holding the email (`app/services/cognito.py:70-101`; 409 `UsernameExists`
     on retry).
  2. Calls `create_user_record()` → writes the user to the DynamoDB `users` table
     keyed by email, with status `pending_verification`, **before** verification
     (`app/services/registration.py:58-95`; `put_item` with a duplicate-blocking
     ConditionExpression at lines 79-84).
  3. Sets `account_state` to `pending_verification` (`registration.py:93-94`).
  4. Stores a verification challenge in `sessions` **with a TTL** (this expires —
     but the user/account_state records do **not**).

**The block**: when the user returns and re-enters the same email,
`registerEmailCheck` → `is_email_available()` → `_user_exists()` returns
"not available", and the frontend shows **"An account with this email already
exists"** (`frontend/src/pages/Register.tsx:619`), so they can't proceed.

**Why it's a dead-end in practice**:
- The unverified user record **persists indefinitely** — there is **no TTL/sweep**
  that frees the email after abandonment (only the challenge expires).
- A recovery path technically exists (`POST /ui/register/resend`,
  `register.py:241-307`, which will issue a fresh code for an abandoned email and
  let them `confirm`), **but it is not surfaced** — the "email already exists"
  message gives no guidance, and re-running `/start` returns a generic "ok" (to
  avoid leaking email existence), which is confusing.
- Frontend resume only works if the **same browser** still has localStorage from
  the `/start` response (`Register.tsx:198-216`); a different device = stuck.

### 1.2 How It Works (proposed)

Make abandoned registrations recoverable and self-healing:

1. **Re-registration over an UNCONFIRMED/unverified account is allowed.** When
   `/register/start` is called for an email whose only record is
   `pending_verification` (not `active`), treat it as a **resume**: re-issue a
   verification code (idempotent overwrite of the pending record / fresh
   challenge) instead of 409-blocking. For Cognito, handle the UNCONFIRMED case
   (resend confirmation / admin-recreate) rather than aborting on
   `UsernameExists`.
2. **Clear frontend guidance.** When the email-availability check reports the
   address is taken **but unverified**, show: "You started registering with this
   email but didn't verify it — resend a code to finish" with a **Resend code**
   button wired to `/register/resend`, plus a "start over" option. (Add a safe
   `GET /ui/register/status?email=` style signal, or fold an
   `unverified: true` hint into the existing check, taking care not to leak
   verified-account existence.)
3. **TTL on abandoned registrations.** Give `pending_verification` user +
   `account_state` records a TTL (e.g. `REGISTRATION_PENDING_TTL_DAYS`, default
   7-14 days). After expiry a sweep (or DynamoDB TTL + Cognito cleanup of
   UNCONFIRMED users) frees the email entirely.
4. **Frontend resume across reloads** already partially works via localStorage;
   ensure reload mid-flow lands the user on the verify step with resend/confirm.

### 1.3 Design Principles

- **No email enumeration regression**: recovery messaging must distinguish
  "unverified pending" (safe to guide to resend) from "verified active" (generic
  response) without leaking which verified accounts exist.
- **Idempotent resume**: re-`start` on an unverified email re-issues a code; it
  must not create duplicates or error.
- **Self-healing**: TTL guarantees an abandoned email never stays locked forever
  even if the user never returns.

---

## 2. Implementation

### 2.1 Backend (`app/routers/register.py`, `app/services/registration.py`, `app/services/cognito.py`)

- In `/register/start`: if the existing record for the email is
  `pending_verification`, branch to a **resume** path (refresh/overwrite the
  pending user + issue a new challenge) instead of the duplicate-block 409.
- Handle Cognito UNCONFIRMED: resend confirmation (or admin delete+recreate)
  rather than returning generic-ok on `UsernameExists`.
- Add `pending_verification` TTL: set a TTL attribute on the `users` /
  `account_state` rows when status is `pending_verification`; clear it on
  `confirm` (status → `active`). Add a sweep or rely on DDB TTL + a Cognito
  UNCONFIRMED-cleanup job.
- Optionally expose an `unverified` hint from the email-availability check (or a
  dedicated status endpoint) for the frontend, gated to avoid enumeration of
  verified accounts.

### 2.2 Frontend (`frontend/src/pages/Register.tsx`)

- When email check returns "taken but unverified": render recovery guidance + a
  **Resend code** action (calls `/register/resend`) and a "start over" link.
- Ensure mid-registration reload restores the verify step from localStorage and
  offers resend/confirm.

### 2.3 Settings (`app/core/settings.py`)

- `REGISTRATION_PENDING_TTL_DAYS` (default 14).
- `REGISTRATION_ALLOW_RESUME_UNVERIFIED` (default true).

---

## 3. Testing

- **E2E** (`frontend/e2e/registration-recovery.spec.ts`, new):
  - start → abandon (don't confirm) → return with same email → UI offers resend →
    confirm → account active (no dead-end).
  - start → abandon → re-`start` with same email is treated as resume (new code),
    not a hard block.
  - resend works for an abandoned email; confirm completes.
  - (unit) pending record carries a TTL; confirm clears it.
- **pytest**: `/register/start` resume branch for `pending_verification`; no
  duplicate user created; Cognito UNCONFIRMED handling; TTL set/cleared.

## 4. Out of Scope

- The verified-account login/forgot-password flows (unchanged).
- Broader account-recovery (handled elsewhere).

---

## 5. Current-State Risk Summary

| Question | Finding |
|----------|---------|
| Does abandoned registration lock the email? | **Yes** — email written to Cognito (UNCONFIRMED) + DDB `users` (`pending_verification`) at `/register/start`, before verification. |
| Permanent? | Effectively yes today — **no TTL/cleanup** on the user/account_state records. |
| Recovery path exists? | Yes via `/register/resend`, but **not surfaced** to the user. |
| Cross-device resume? | No — frontend resume relies on same-browser localStorage. |
| Net effect | A user can be soft-locked out of their own email with a confusing "already exists" message and no guidance. **This ticket fixes it.** |
