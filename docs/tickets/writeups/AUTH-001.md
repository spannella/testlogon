# AUTH-001: Registration Abandonment & Email-Lock Recovery — Investigation & Implementation Write-up

## 1. Summary & Classification

A user who starts registration but does not complete the verification step has their email permanently locked out. The `/register/start` endpoint writes both a Cognito UNCONFIRMED user and a DynamoDB `users` record immediately, before any verification occurs. If the user never confirms, these records persist indefinitely with no TTL or cleanup sweep. When the user returns and types the same email, `is_email_available()` returns `false` and the frontend displays "An account with this email already exists" with no recovery guidance and no way to proceed without manually contacting support.

A recovery path technically exists (`POST /ui/register/resend`), but it is never surfaced to the user because the frontend only reaches the "verify" step from `localStorage` state written during the original `/start` call. On a different device, or after clearing storage, the user is permanently blocked.

- **Type**: Bug / UX dead-end (with security constraint: cannot leak verified account existence)
- **Priority**: High
- **Status**: Open (not yet implemented)
- **Persona**: 🌐 Any user who abandons registration — could be accidental (connection drop, closed tab) or a second registration attempt from a different device
- **Cross-references**: SECOPS-007 (dev/prod parity — Cognito path vs. direct DDB path), registration flow docs
- **Attacker class**: This is a self-inflicted lock-out, not an adversarial attack. However, the fix must not introduce an email enumeration vector (see §3.3)

---

## 2. Current-State Investigation

### 2.1 Registration flow (`app/routers/register.py:60–150`)

The `POST /ui/register/start` endpoint at line 60 follows two paths depending on `_cognito_available()` (line 54–57):

```python
def _cognito_available() -> bool:
    if S.dev_mode:
        return False   # Dev mode always bypasses Cognito (fix #144)
    return bool(S.cognito_app_client_id)
```

**Prod path** (Cognito available, `dev_mode=False`):
1. Line 88–111: `cognito_sign_up(username, body.password, body.full_name)` — creates an UNCONFIRMED Cognito user
2. If `UsernameExistsException` (409): Cognito raises, caught at `cognito.py:82–84`, re-raised as `HTTPException(409)`. The `register_start` router catches this at line 93–106 and returns `generic_response` (status="ok", `verification_required=True`, no delivery info). The user sees no error — but the DDB `create_user_record` step is **never reached** because the Cognito exception causes a `return generic_response` at line 106, before line 115.

Wait — re-reading: on the Cognito path, `create_user_record` is called **after** the Cognito `sign_up` succeeds. The first `try` block (lines 88–111) handles the Cognito call. If `UsernameExistsException`, it returns early with `generic_response`. So the DDB write at lines 114–124 only happens if Cognito sign_up succeeded.

**Dev path** (`dev_mode=True`, Cognito bypassed):
1. Line 114–124: `create_user_record(email, full_name, password, verification_required=True)`
2. `create_user_record` (`app/services/registration.py:58–95`):
   - Line 66: `_user_exists(user_sub)` → 409 if user record exists
   - Line 79–84: `T.users.put_item(ConditionExpression="attribute_not_exists(user_sub)")` — race-safe duplicate block
   - Line 93–94: `set_account_state(user_sub, "pending_verification", ...)` — writes `account_state` record
3. Line 130–138: `create_registration_challenge(...)` — writes challenge session with TTL (`expires_at = ts + S.session_challenge_ttl_seconds`)

### 2.2 What gets written and what has a TTL

| Record | Table | TTL? | Notes |
|--------|-------|------|-------|
| `T.users` item (`user_sub=email`) | `users` | **No TTL** | Written at line 79; persists forever |
| `T.account_state` item (`status=pending_verification`) | `account_state` | **No TTL** | Written at line 94 via `set_account_state`; persists forever |
| Challenge session | `T.sessions` | **Yes** (`expires_at`) | Written at `registration.py:137` via `with_ttl`; expires after `S.session_challenge_ttl_seconds` |
| Cognito UNCONFIRMED user | Cognito User Pool | **No TTL** (unless pool-level config) | Created by `cognito_sign_up` at `cognito.py:73` |
| Profile record | `T.profiles` (via `save_profile`) | **No TTL** | Written at `registration.py:91` |

**The structural problem**: the challenge (which expires) and the user records (which do not) have asymmetric lifetimes. After the challenge expires, `verify_registration_code` returns 400 "Registration verification not found", but the user record is still there blocking re-registration.

### 2.3 Email availability check (`app/services/registration.py:53–55`)

```python
def is_email_available(email: str) -> bool:
    normalized = normalize_email(email)
    return not _user_exists(normalized)
```

`_user_exists` (line 41) does a `T.users.get_item` — a binary yes/no with no status distinction. There is no way to tell from this function whether an existing record is `pending_verification` or `active`.

The router endpoint at `register.py:153–184`:
```python
async def register_check(req, body):
    ...
    available = await asyncio.wait_for(
        run_in_threadpool(is_email_available, body.email), ...
    )
    return {"status": "ok", "available": available}
```

The response is `{"available": true/false}` — no `unverified` flag.

### 2.4 Frontend handling (`frontend/src/pages/Register.tsx`)

- Line 247: `setEmailStatus(data.available ? "available" : "unavailable")`
- Lines 616–621: when `emailStatus === "unavailable"`:
  ```tsx
  <p className="text-xs text-destructive">
    An account with this email already exists.
  </p>
  ```
  No resend button. No recovery link. Dead end.

- Lines 178–179: the "Next" button is disabled when `emailStatus === "unavailable"` — the user cannot proceed past the email field.

- Lines 198–216: `localStorage.getItem(REGISTER_STORAGE_KEY)` restores `{email, enable_sms_mfa, phone}` from a previous `/start` call and skips straight to the verify step. This works only on the same browser; a different device has no state.

- Line 181–196: if `?email=` and `?code=` URL params are present, the page jumps directly to verify step. This is the "magic link to verify" path but requires the email to be passed in the URL (used by deep links from verification emails).

### 2.5 Resend endpoint (`app/routers/register.py:241–307`)

`POST /ui/register/resend` is fully functional. It calls `create_registration_challenge(user_sub=username, ...)` which overwrites the challenge pointer in `T.sessions` (the `REGISTRATION_LATEST_POINTER_ID` item). It does not check whether the user is `pending_verification` — it always issues a new challenge for the given email, regardless of account state. This means it will silently issue codes for verified active accounts too (though confirming with an already-confirmed account just fails at `verify_registration_code` → `mark_user_verified`).

The resend endpoint is never linked from the "An account with this email already exists" UI state.

### 2.6 Cognito path nuance

In prod (Cognito enabled), after an abandoned registration:
- Cognito: UNCONFIRMED user exists for the email
- DDB: **no** user record is written (because the Cognito path returns `generic_response` on `UsernameExistsException` without reaching `create_user_record`)
- Account state: **no** `pending_verification` record

So on the Cognito path, `is_email_available()` returns `true` (DDB user does not exist), and `/register/start` returns the generic "ok" response again — but Cognito silently does nothing because the user already exists as UNCONFIRMED. The user gets "we sent a code" but no code is actually delivered if Cognito's `UsernameExistsException` was swallowed. This is a separate silent-failure bug on the Cognito path.

In dev mode (`dev_mode=True`, Cognito bypassed), the DDB user + account_state records are written, and `is_email_available()` returns `false` on retry — this is the path that produces the hard "email already exists" block.

---

## 3. Gap / Threat Analysis

### 3.1 Primary impact

A user who:
1. Starts registration on device A (gets to verify step)
2. Abandons without confirming
3. Returns on device B (no localStorage)

…sees "An account with this email already exists" and has no path to recovery without support intervention. The email is permanently blocked.

In dev mode this happens for every abandoned registration. In prod (Cognito path), the block is softer (DDB record not written), but the Cognito UNCONFIRMED user can still cause issues — particularly if the user tries to log in later without completing the flow.

### 3.2 All code sites that must change

| File | Change needed |
|------|--------------|
| `app/services/registration.py:53–55` | `is_email_available` must return `{"available": bool, "unverified": bool}` or a separate function |
| `app/services/registration.py:58–95` | `create_user_record` resume path for existing `pending_verification` records |
| `app/services/registration.py:58–95` | Add TTL to `T.users` and `T.account_state` writes when `status=pending_verification` |
| `app/services/account_state.py:28–38` | `set_account_state` needs optional TTL parameter |
| `app/routers/register.py:153–184` | `/check` response must include `unverified` hint |
| `app/routers/register.py:88–150` | `/start` resume path: detect `pending_verification` and re-issue challenge |
| `app/services/cognito.py:70–101` | Cognito path: on `UsernameExistsException` check if UNCONFIRMED and resend confirmation |
| `app/core/settings.py` | Add `REGISTRATION_PENDING_TTL_DAYS`, `REGISTRATION_ALLOW_RESUME_UNVERIFIED` |
| `frontend/src/pages/Register.tsx:616–621` | When email is `unverified`, show "Resend code" button and "Start over" link |
| `frontend/src/api/endpoints/auth.ts` | `RegisterEmailCheckResp` type needs `unverified?: boolean` |

### 3.3 Email enumeration risk

The `/check` endpoint currently returns `{"available": true/false}`. Adding `{"available": false, "unverified": true}` creates a distinction between "taken by a verified account" and "taken by an unverified account". The requirement is:

- `unverified: true` → safe to expose (guidance: "you started but didn't finish")
- `unverified: false` + `available: false` → existing **verified** account; must stay generic ("email already in use") to avoid confirming account existence to a third party

This matches the ticket's Design Principles: "recovery messaging must distinguish 'unverified pending' from 'verified active' without leaking which verified accounts exist."

### 3.4 Cognito UNCONFIRMED handling

When Cognito raises `UsernameExistsException`:
- Call `cognito_client().admin_get_user(UserPoolId=pool_id, Username=email)` to check `UserStatus`
- If `UserStatus == "UNCONFIRMED"`: call `cognito_client().resend_confirmation_code(...)` to re-send the verification email
- If `UserStatus == "CONFIRMED"`: return generic response (don't surface that a confirmed account exists)

This requires `cognito:AdminGetUser` IAM permission on the backend role.

---

## 4. Proposed Design / Fix

### 4.1 New settings (`app/core/settings.py`)

```python
registration_pending_ttl_days: int = int(
    os.environ.get("REGISTRATION_PENDING_TTL_DAYS", "14")
)
registration_allow_resume_unverified: bool = os.environ.get(
    "REGISTRATION_ALLOW_RESUME_UNVERIFIED", "true"
).lower() in ("1", "true", "yes")
```

### 4.2 TTL on pending records (`app/services/registration.py`)

Modify `create_user_record` to set DDB TTL on users and account_state records when `verification_required=True`:

```python
# registration.py — in create_user_record
if verification_required:
    ttl_epoch = now_ts() + (S.registration_pending_ttl_days * 86400)
    item["registration_expires_at"] = ttl_epoch  # DDB TTL attribute
```

Modify `set_account_state` in `app/services/account_state.py` to accept an optional `ttl_epoch` argument:

```python
def set_account_state(user_sub, status, *, reason="", requested_by="",
                       ttl_epoch: int | None = None) -> dict:
    item = {...}
    if ttl_epoch:
        item["registration_expires_at"] = ttl_epoch  # DDB TTL
    T.account_state.put_item(Item=item)
```

On `mark_user_verified` (line 200–205), remove the TTL attribute:
```python
T.account_state.update_item(
    Key={"user_sub": normalized},
    UpdateExpression="REMOVE registration_expires_at SET ...",
    ...
)
```

**Note**: DDB TTL attribute name on `users` and `account_state` tables must be configured in `scripts/local-ddb-init.py` to enable TTL (table-level setting via `enable_ttl`). The TTL attribute name must be consistent.

### 4.3 Email check with unverified hint

New service function:

```python
# app/services/registration.py
def check_email_status(email: str) -> dict:
    """Returns {"available": bool, "unverified": bool}.

    unverified=True only when a pending_verification record exists.
    Never returns unverified=True for confirmed/active accounts.
    """
    normalized = normalize_email(email)
    item = T.users.get_item(Key={"user_sub": normalized}).get("Item")
    if not item:
        return {"available": True, "unverified": False}
    state = get_account_state(normalized)
    if state.get("status") == "pending_verification":
        return {"available": False, "unverified": True}
    return {"available": False, "unverified": False}
```

Update `register_check` router (line 153) to call `check_email_status` and include `unverified` in the response JSON. Update `RegisterEmailCheckResp` Pydantic model to add `unverified: bool = False`.

### 4.4 Resume path in `/register/start`

Add a branch before `create_user_record` for the dev (non-Cognito) path:

```python
# register_start, dev path (lines 114+)
# Check if existing record is pending_verification
status_check = check_email_status(username)
if not status_check["available"] and status_check["unverified"] and S.registration_allow_resume_unverified:
    # Resume: re-issue a new challenge for the abandoned registration
    if can_send_verification(username, "email"):
        code = create_registration_challenge(user_sub=username, channel="email",
                                              send_to=username, mfa_setup=mfa_setup,
                                              sms_phone=body.phone)
        send_email_code(username, "Registration", code)
    audit_event("register_start", username, req, outcome="success",
                verification_required=True, delivery_medium="email")
    clear_lockout(username, ip, "register_start")
    return generic_response   # same shape as normal start
elif not status_check["available"]:
    # Verified active account — return generic to avoid enumeration
    audit_event("register_start", username, req, outcome="failure",
                reason="duplicate_account")
    clear_lockout(username, ip, "register_start")
    return generic_response
# else: available — proceed with create_user_record as before
```

For the Cognito path, add UNCONFIRMED detection (§3.4 above) inside the `except HTTPException` block at line 93–106.

### 4.5 Frontend recovery UI (`frontend/src/pages/Register.tsx`)

When `emailStatus === "unavailable"` (which can now be split into `unavailable_verified` and `unavailable_unverified` based on the new `unverified` field):

```tsx
{emailStatus === "unavailable_unverified" && (
  <div className="text-xs text-muted-foreground">
    <p>You started registering with this email but didn't verify it.</p>
    <Button size="sm" variant="link" onClick={handleResendForAbandoned}>
      Resend verification code
    </Button>
    {" · "}
    <button onClick={handleClearAndRestart} className="underline">
      Start over
    </button>
  </div>
)}
{emailStatus === "unavailable_verified" && (
  <p className="text-xs text-destructive">
    An account with this email already exists.
  </p>
)}
```

`handleResendForAbandoned`: calls `POST /ui/register/resend` with the email, then sets `registeredEmail` and `step="verify"` so the user can complete verification.

`handleClearAndRestart`: calls a new `DELETE /ui/register/pending?email=...` endpoint (or relies on TTL expiry) that removes the `pending_verification` record, then resets the form.

### 4.6 Dev/Prod parity (SECOPS-007)

| Component | Dev | Prod | Gate |
|-----------|-----|------|------|
| TTL on pending records | DDB Local TTL (may not be enforced by DDB Local but attribute is set) | AWS DDB TTL; records auto-deleted after expiry | `REGISTRATION_PENDING_TTL_DAYS` env var |
| Resume path | `check_email_status` → re-issue challenge | Same code path | `REGISTRATION_ALLOW_RESUME_UNVERIFIED` |
| Cognito UNCONFIRMED resend | Not reached (dev_mode=True bypasses Cognito) | `cognito_client().resend_confirmation_code` | `_cognito_available()` |
| `unverified` hint in `/check` | Same DDB check; no Cognito call | Same DDB check | None |

The key invariant: all resume and TTL logic runs on the DDB path in both dev and prod. The Cognito-specific handling only fires in prod (when `_cognito_available()` returns True, which requires `dev_mode=False`).

---

## 5. Testing, Verification & Rollout

### 5.1 Pytest unit tests (`tests/test_registration_recovery.py`)

All runnable offline with moto (no Cognito needed):

| Test | Assertion |
|------|-----------|
| `test_pending_record_has_ttl` | After `create_user_record(..., verification_required=True)`, `T.users` item has `registration_expires_at` set |
| `test_ttl_cleared_on_verify` | After `mark_user_verified`, `registration_expires_at` attribute removed |
| `test_check_email_status_available` | Non-existent email → `{"available": True, "unverified": False}` |
| `test_check_email_status_unverified` | Seeded `pending_verification` record → `{"available": False, "unverified": True}` |
| `test_check_email_status_verified` | Seeded `active` record → `{"available": False, "unverified": False}` |
| `test_register_start_resume_unverified` | POST `/start` for existing `pending_verification` email → `status="ok"`, new challenge written |
| `test_register_start_resume_no_duplicate` | Resume does NOT create second user record |
| `test_register_start_blocked_for_active` | POST `/start` for active account → generic ok, no second record |
| `test_resend_works_for_abandoned` | `/resend` for `pending_verification` email → 200, new challenge |

### 5.2 Playwright E2E (`frontend/e2e/registration-recovery.spec.ts`)

Per ticket §3 test plan:

| # | Scenario | Assertion |
|---|----------|-----------|
| 1 | Start → abandon → return same browser | localStorage restores; verify step shows; confirm completes registration |
| 2 | Start → abandon → clear localStorage → return | email check shows `unverified` message; "Resend code" button visible |
| 3 | Click "Resend code" | `POST /register/resend` called; page moves to verify step |
| 4 | Resend → confirm | Account becomes `active`; session set; redirect to dashboard |
| 5 | Start → abandon → re-`start` same email API | `POST /register/start` returns 200 `{status:"ok"}`; new challenge in sessions DDB |
| 6 | Active account → check email | Still shows "An account with this email already exists" (no unverified hint) |

**Auth for tests**: no session needed for `/start`, `/check`, `/resend`, `/confirm` — these are pre-auth endpoints. Use the global `request` fixture (Bearer-auth bypass) for API-level assertions.

### 5.3 Manual/QA steps

1. In dev mode: submit the registration form with a new email → close tab before confirming
2. Return and type same email → verify the "Resend code" guidance appears (not just "already exists")
3. Click "Resend code" → check console for verification code (dev mode logs it) → enter code → verify account is now active
4. Verify `T.users` item has `registration_expires_at` attribute via DDB admin UI

### 5.4 Security checklist

- [ ] `unverified: true` hint is only returned for `pending_verification` accounts — never for `active`
- [ ] No way to use `unverified` hint to enumerate verified account existence
- [ ] Resume path does not allow changing `full_name` or `password` mid-resume (use original values or require original password)
- [ ] Rate limits on `/check` and `/resend` remain in effect (existing `enforce_lockout` + `rate_limit_password_recovery` calls)
- [ ] TTL is set at write time; `mark_user_verified` clears it — no race window where an active account has an expiry

### 5.5 Rollout

**New settings** (add to `.env.local.example`):
```
REGISTRATION_PENDING_TTL_DAYS=14
REGISTRATION_ALLOW_RESUME_UNVERIFIED=true
```

**Phase order**:
1. Add TTL to pending records (safe, additive — no behavioural change until TTL elapses)
2. Expose `unverified` hint in `/check` + frontend recovery UI
3. Add resume branch in `/start`
4. (Prod) Add Cognito UNCONFIRMED resend handling

**Rollback**: disable `REGISTRATION_ALLOW_RESUME_UNVERIFIED=false` → resume path is bypassed; frontend falls back to existing "already exists" message. TTL attributes on existing records are harmless.

### 5.6 Effort estimate

- Settings + TTL on pending records: **S** (1 day)
- `check_email_status` + router + model changes: **S** (1 day)
- Frontend recovery UI: **S** (1 day)
- Resume path in `/start`: **S** (1 day)
- Cognito UNCONFIRMED handling: **S** (1 day, prod-only)
- E2E tests: **S** (1-2 days)
- **Total**: **S–M** (5-7 days end-to-end)
