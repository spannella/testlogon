---
id: AND-055
title: "Registration: email availability check"
milestone: M2
epic: E08
priority: P2
size: S
status: reviewed
reviewed_on: 2026-06-06
depends_on: [AND-053]
blocks: []
---

# AND-055 — Registration: email availability check

## 1. Overview & Goal

This ticket adds an inline, debounced *email availability* check to the registration
flow built in AND-053. As the user types an email address in the Register screen, the
app asynchronously queries `POST /ui/register/check` and surfaces — *before the user
submits the form* — whether that email is already taken. The goal is to give early,
non-blocking feedback so a user who reuses an existing account address learns it at
the field level instead of failing the `POST /ui/register/start` submit (AND-053).

Concretely this ticket delivers: (a) a debounce-and-cancel coroutine pipeline keyed
on the trimmed, syntactically-valid email; (b) a thin API method on the existing
registration API surface and a repository method returning a typed
`EmailAvailability`; (c) ViewModel state additions (`emailAvailability`,
`emailChecking`) wired into the existing `RegisterUiState` from AND-053; and (d) a
small inline status indicator in the email field's supporting text. The check is
*advisory*: it never blocks typing, and a `Taken` result disables submit while a
`Checking`/`Error`/`Unknown` result does **not** block submit (the server remains the
source of truth at `register/start`).

Module: `feature-auth`. Package:
`com.testlogon.android.feature.auth.register`. This ticket extends the existing
`RegisterViewModel`/`RegisterUiState`/`RegisterScreen` created by AND-053 rather than
introducing a new screen.

## 2. Context & References

- **AND-053** `Registration: start` (hard dependency) — owns `RegisterScreen`,
  `RegisterViewModel`, `RegisterUiState`, the email `TextField`, the
  `RegistrationApi` Retrofit interface, the `RegistrationRepository`, and the
  `POST /ui/register/start` call + `RegisterStartResp` mapping. This ticket adds
  fields/methods to those existing types; it does not recreate them.
- **AND-054** `Registration: confirm + resend` — sibling, no direct coupling; both
  depend on AND-053. No shared state with this ticket.
- **AND-015** `API error model + detail mapping` — provides `ApiError` and the FastAPI
  `detail` mapper (`string | [{msg}] | {code,...}`) used to classify failures.
- **AND-016** `Retry/backoff for idempotent GETs` — *not* applicable: `register/check`
  is a POST and must not be auto-retried (see §7).
- **AND-018** `ApiResult types` — `ApiResult<T>` is the repository return type.
- **AND-020** `Core input composables` — the email field composable whose
  `supportingText`/`isError`/trailing slot this ticket drives.
- **AND-009** `OkHttp client timeouts` — ~20s call timeout applies; the dev backend
  `http://18.222.237.167:8000` is plaintext and unreliable.
- Web reference (verified): `frontend/src/api/endpoints/auth.ts` (`registerEmailCheck` →
  `api.post<RegisterEmailCheckResp>("/ui/register/check", body)`), `frontend/src/api/types.ts`
  (`RegisterEmailCheckReq` / `RegisterEmailCheckResp`), and `frontend/src/pages/Register.tsx`
  (the 400 ms debounced `useEffect` that drives `emailStatus`). Response shape confirmed
  against `/openapi.json` (`RegisterEmailCheckResp`); see §13 R1 (resolved) and §16.

## 3. Functional Requirements

FR-1. Extend `RegisterUiState` (AND-053) with email-availability fields:
`emailAvailability: EmailAvailability` and a derived `emailChecking: Boolean`.

FR-2. On every `onEmailChange(value)` (already defined by AND-053), reset
`emailAvailability = Unknown` and clear any prior availability error, then schedule a
**debounced** check.

FR-3. Debounce window is **400 ms** of input inactivity. Rapid typing must collapse to
at most one in-flight request; a new keystroke cancels any pending/in-flight check.

FR-4. A check is only dispatched when the trimmed email is **syntactically plausible**
(`EmailValidator.isPlausible`, from core-ui per AND-031). Blank or invalid emails set
`emailAvailability = Unknown` and dispatch nothing (no wasted network calls).

FR-5. While a check is in flight, `emailChecking == true` (drives a small inline
spinner in the field's trailing slot). It returns to `false` on result, cancel, or
error.

FR-6. Map results: server "available" → `Available`; "taken"/"exists" → `Taken`;
transport/parse failure → `Error` (advisory only). The email value at result time must
still equal the value that was checked; a stale response for an out-of-date email is
discarded (guard on the checked email string).

FR-7. When `emailAvailability == Taken`, the email field shows an inline error
(`isError = true`) with supporting text "This email is already registered." and
**submit is disabled** even if all other validation passes.

FR-8. `Checking`, `Error`, and `Unknown` states **must not** disable submit. Submit
remains gated only by the AND-053 field-level validation plus the `Taken` rule above.

FR-9. The check never throws into the UI: failures are swallowed into `Error`/`Unknown`
and the form remains submittable, deferring to `register/start` as source of truth.

FR-10. On a successful `Available` result the field shows a subtle positive supporting
text/icon ("Email available"); this is optional polish but must be locale-resolved
`UiText` if present.

## 4. Technical Design

A `MutableStateFlow<String>` of the current email feeds a single long-lived collector
in `init {}` that applies `debounce`, filters to valid emails, maps with
`flatMapLatest` (which auto-cancels the previous request), and updates state. Using
`flatMapLatest` gives FR-3 cancellation for free.

```kotlin
package com.testlogon.android.feature.auth.register

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.data.register.RegistrationRepository
import com.testlogon.android.core.ui.validation.EmailValidator
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.FlowPreview
import kotlinx.coroutines.flow.*
import kotlinx.coroutines.launch
import javax.inject.Inject

@OptIn(FlowPreview::class)
@HiltViewModel
class RegisterViewModel @Inject constructor(
    private val repository: RegistrationRepository,
    // ...other deps from AND-053
) : ViewModel() {

    private val _uiState = MutableStateFlow(RegisterUiState())
    val uiState: StateFlow<RegisterUiState> = _uiState.asStateFlow()

    /** Raw email keystrokes; drives the debounced availability pipeline. */
    private val emailQuery = MutableStateFlow("")

    init {
        viewModelScope.launch {
            emailQuery
                .map { it.trim() }
                .debounce(EMAIL_DEBOUNCE_MS)
                .distinctUntilChanged()
                .flatMapLatest { email ->
                    if (!EmailValidator.isPlausible(email)) {
                        flowOf(CheckOutcome(email, EmailAvailability.Unknown))
                    } else {
                        flow {
                            emit(CheckOutcome(email, EmailAvailability.Checking))
                            emit(CheckOutcome(email, repository.checkEmail(email).toAvailability()))
                        }
                    }
                }
                .collect { (checkedEmail, availability) ->
                    // FR-6 stale guard: ignore if the field moved on.
                    if (_uiState.value.email.trim() == checkedEmail) {
                        _uiState.update { it.copy(emailAvailability = availability) }
                    }
                }
        }
    }

    fun onEmailChange(value: String) {
        _uiState.update {
            it.copy(email = value, emailAvailability = EmailAvailability.Unknown, emailError = null)
        }
        emailQuery.value = value
    }

    private data class CheckOutcome(val email: String, val availability: EmailAvailability)

    companion object { const val EMAIL_DEBOUNCE_MS = 400L }
}

private fun ApiResult<Boolean>.toAvailability(): EmailAvailability = when (this) {
    is ApiResult.Success -> if (data) EmailAvailability.Available else EmailAvailability.Taken
    is ApiResult.Failure -> EmailAvailability.Error   // advisory; never blocks submit
}
```

Design notes:

- **`flatMapLatest` for cancellation.** A new email value cancels the prior inner flow
  (and thus the in-flight Retrofit call when the coroutine is cancelled), satisfying
  FR-3 without manual `Job` tracking.
- **Emitting `Checking` from inside the inner flow** means `emailChecking` flips on
  only *after* debounce + validity gates pass, so a spinner never flashes for invalid
  input.
- **Stale guard.** Because results arrive asynchronously, we re-check that the live
  `email` still matches the email that was queried before committing `availability`
  (defense-in-depth on top of `flatMapLatest`).
- **`distinctUntilChanged`** prevents a redundant check when the trimmed value is
  unchanged (e.g. cursor moves, trailing whitespace toggles).
- Repository performs the IO-dispatcher switch (core-data convention); the ViewModel
  stays on `viewModelScope` (main).

## 5. API Contract

New call on the existing `RegistrationApi` (AND-053):

> **Verified against OpenAPI (`POST /ui/register/check`, schemas `RegisterEmailCheckReq`
> / `RegisterEmailCheckResp`) and `frontend/src/api/types.ts` + `endpoints/auth.ts`.**
> Corrections applied below: the backend request/response schemas are named
> `RegisterEmailCheckReq` / `RegisterEmailCheckResp` (not `RegisterCheck*`); the response
> has **two required** fields `{ available: boolean, status: string }` — there is **no**
> `email` field on the response (that was an unverified invention in the original draft).

```kotlin
interface RegistrationApi {
    // ...register/start, register/confirm, register/resend (other tickets)
    @POST("ui/register/check")
    suspend fun checkEmail(@Body body: RegisterEmailCheckReq): RegisterEmailCheckResp
}

@JsonClass(generateAdapter = true)
data class RegisterEmailCheckReq(val email: String)

@JsonClass(generateAdapter = true)
data class RegisterEmailCheckResp(
    val available: Boolean,          // required (verified)
    val status: String,              // required (verified) — free-form server status string
)
```

Endpoint: `POST /ui/register/check` (op `register_check_ui_register_check_post`).

Request body (schema `RegisterEmailCheckReq`, `email` required):
```json
{ "email": "user@example.com" }
```

Response (200, schema `RegisterEmailCheckResp`, both fields required):
```json
{ "available": false, "status": "taken" }
```
- `available == true` → email is free → `EmailAvailability.Available`.
- `available == false` → email is taken → `EmailAvailability.Taken`.
- `status` is a free-form server string. The web client (`Register.tsx`) **ignores it**
  and branches solely on `data.available`; this ticket mirrors that — `status` is parsed
  (it is required, so omitting it would break Moshi non-null parsing) but not currently
  used for UI branching. It is retained as a hook for future granularity.

Error responses use the standard FastAPI `detail` envelope, mapped by AND-015. The
documented validation error is **422** (`HTTPValidationError`):
```json
{ "detail": [{ "loc": ["body", "email"], "msg": "value is not a valid email address" }] }
```
**However, the web reference (`Register.tsx`) also handles `400` (→ "invalid") and `429`
(→ "rate_limited") for this endpoint** — i.e. the backend rate-limits availability checks.
For this ticket all non-2xx responses (400 / 422 / 429 / 5xx / transport) collapse to the
advisory `EmailAvailability.Error`, which never blocks submit (see §7). The field is also
gated locally by `EmailValidator`, so a 422 should be rare in practice.

CSRF/cookie handling — **verified** against `frontend/src/api/client.ts`: the call carries
the `ui_csrf` cookie value as the `X-CSRF-Token` header (`credentials: "include"`) via the
core-network interceptors (AND-012/AND-011). The OpenAPI index lists **no auth params**
(`params=` is empty — no `X-SESSION-ID`/`user_sub`), confirming **no auth session is
required** to call `register/check`. The Moshi DTOs and `toAvailability()` are the only
places to adjust if the contract changes (see §13 R1, now resolved).

## 6. Data & State Management

```kotlin
enum class EmailAvailability { Unknown, Checking, Available, Taken, Error }

// Additive changes to AND-053's RegisterUiState:
data class RegisterUiState(
    val email: String = "",
    // ...fullName, password, confirm, deliveryMethod, mfaOptIn, status, error (AND-053)
    val emailAvailability: EmailAvailability = EmailAvailability.Unknown,
    val emailError: UiText? = null,
) {
    val emailChecking: Boolean get() = emailAvailability == EmailAvailability.Checking
    val emailTaken: Boolean get() = emailAvailability == EmailAvailability.Taken

    // Extend AND-053's submitEnabled with the Taken gate (FR-7/FR-8):
    val submitEnabled: Boolean
        get() = /* AND-053 base field validation */ baseFieldsValid && !emailTaken
}
```

State rules:

- `Checking` is folded into the enum rather than a separate boolean to keep a single
  authoritative availability value; `emailChecking` is derived.
- `emailQuery` (the debounce source) is **not** part of `RegisterUiState` and is not
  rendered; it mirrors `email` for pipeline purposes only.
- All updates go through `MutableStateFlow.update { }` to avoid lost updates between
  `onEmailChange` and the async collector.
- **No persistence.** Availability is transient and never written to
  `SavedStateHandle`/DataStore; on process death it resets to `Unknown` and re-checks
  on next keystroke. The email itself follows AND-053's persistence policy.
- Submit gate: `submitEnabled` adds `&& !emailTaken` on top of AND-053's base
  validation. `Checking`/`Error`/`Unknown` deliberately do not gate submit (FR-8).

## 7. Error Handling & Resilience

- **Advisory failure model.** Any `ApiResult.Failure` from `checkEmail` maps to
  `EmailAvailability.Error`, which renders no blocking error and leaves submit enabled.
  The authoritative duplicate-email rejection still happens at
  `POST /ui/register/start` (AND-053), so a failed availability check degrades
  gracefully to "submit and let the server decide."
- **Timeouts.** OkHttp ~20s call timeout (AND-009). A timeout → `ApiError.Timeout` →
  `Error`. Because `flatMapLatest` cancels superseded calls, a slow request for an old
  email cannot clobber a newer state.
- **No auto-retry.** `register/check` is a POST; the AND-016 backoff policy applies only
  to idempotent GETs. We perform exactly one attempt per debounced query; the next
  keystroke (or re-typing the same address after editing) naturally re-triggers. This also
  means a **429 rate-limit** response (the backend rate-limits this endpoint — see §5/R2)
  is **not** retried; it collapses to advisory `Error` and the 400 ms debounce already
  throttles request volume, mitigating further rate-limiting.
- **Stale-response guard** (FR-6): the collector discards a result whose checked email
  no longer matches the live field, preventing a flicker to `Taken`/`Available` for a
  value the user has since changed.
- **Offline.** If connectivity is down, the check fails fast to `Error`; no banner is
  raised by this ticket (the form-level offline UX is owned by AND-053/AND-045).
- **Cancellation.** All work runs in `viewModelScope`; clearing the ViewModel cancels
  the pipeline. No manual lifecycle handling required.

## 8. Security & Privacy

- The email address is PII. Telemetry and logs must **never** record the raw email;
  log only `email_domain` and/or `email_len` (§10), consistent with AND-052's redaction
  rules.
- `register/check` is an **unauthenticated email-enumeration surface** by design (it
  exists to tell clients whether an email is taken). This ticket does not change that
  server behavior, but: the client must not cache availability results to disk, must
  not log full emails, and the feature must be a thin pass-through. Note the
  enumeration concern in §13 (R2) for backend follow-up — it is a backend policy
  decision (e.g. rate limiting), not an Android one.
- CSRF token + cookies are attached by core-network interceptors; the ViewModel holds
  no tokens.
- No new permissions; the call uses the existing cleartext-permitted dev host config.

## 9. Accessibility & i18n

- All availability strings are `UiText`/string resources, never hard-coded:
  `register_email_taken` ("This email is already registered."),
  `register_email_available` ("Email available"),
  `register_email_checking` ("Checking availability…").
- The email field's supporting text uses `Modifier.semantics { liveRegion = Polite }`
  so TalkBack announces the result without stealing focus while typing.
- The inline spinner (`emailChecking`) carries a `contentDescription` resolving to
  `register_email_checking`; when not checking, the trailing slot is empty/decorative.
- `isError`/`Taken` state sets the field's `error` semantics so assistive tech reads
  the field as invalid; the disabled submit button reflects `disabled()` semantics
  (button itself owned by AND-053).
- No locale-specific email parsing beyond `trim()`; `EmailValidator` is locale-neutral.

## 10. Telemetry & Logging

Events via the core-data analytics abstraction (no PII):

| Event | When | Properties |
|-------|------|-----------|
| `register_email_check` | a check is dispatched (after debounce+valid) | `email_domain`, `email_len` |
| `register_email_check_result` | result committed | `availability` (`available`/`taken`/`error`), `latency_ms` |

- Debug `Timber` logs record `email_domain` only; release strips verbose logs.
- The raw email never appears in any event, log line, or `RegisterUiState.toString()`
  (override/exclude `email` from `toString` per AND-053's privacy convention).
- `latency_ms` helps quantify the unreliable dev backend's effect on the check.

## 11. Testing Strategy

Pure-JVM unit tests (no Robolectric) under
`feature-auth/src/test/.../register/RegisterEmailCheckTest.kt`, using
`kotlinx-coroutines-test` (`StandardTestDispatcher`, `advanceTimeBy`, `runTest`) and
Turbine, with a fake `RegistrationRepository` from core-testing:

```kotlin
class FakeRegistrationRepository(
    var checkResult: ApiResult<Boolean> = ApiResult.Success(true),
) : RegistrationRepository {
    var checkCalls = 0
    val checkedEmails = mutableListOf<String>()
    override suspend fun checkEmail(email: String): ApiResult<Boolean> {
        checkCalls++; checkedEmails += email; return checkResult
    }
    // ...register/start etc.
}
```

Required cases (assert state transitions / call counts using virtual time):

1. Typing a valid email and advancing past 400 ms dispatches exactly one check
   (`checkCalls == 1`); the checked value is trimmed.
2. Rapid keystrokes within the debounce window dispatch **zero** checks until idle,
   then exactly one for the final value (`checkCalls == 1`).
3. Invalid email (`"foo"`) advances past debounce → no check (`checkCalls == 0`),
   `emailAvailability == Unknown`.
4. Blank email → no check; `Unknown`.
5. While the request is suspended, `emailChecking == true`; after completion it is
   `false`.
6. `available == true` → `Available`; `submitEnabled` unaffected by availability.
7. `available == false` → `Taken`; `submitEnabled == false` even with all other fields
   valid (the core acceptance criterion: **taken surfaces before submit**).
8. `ApiResult.Failure` (timeout/network/server) → `Error`; submit remains enabled.
9. Stale guard: change email after a check is dispatched but before it resolves; the
   resolved result for the old email is discarded (state stays `Unknown`/reflects new
   value), verified via `flatMapLatest` cancellation + email match.
10. `distinctUntilChanged`: re-emitting the same trimmed email does not dispatch a
    second check.
11. `onEmailChange` immediately resets `emailAvailability` to `Unknown` (no stale
    `Taken`/`Available` shown while re-typing).
12. `toAvailability()` mapping table is fully covered.

Coverage gate: 100% branches of the debounce pipeline collector and `toAvailability`.

Optional Compose UI test (AND-049 harness): typing a known-taken email shows the
inline error and disables the submit button — covers the acceptance "tested" clause at
the UI layer if the instrumented suite (AND-051) is available; otherwise the unit test
in case 7 is the authoritative coverage.

## 12. Dependencies & Sequencing

- **Hard dep (must merge first):** AND-053 — provides `RegisterScreen`,
  `RegisterViewModel`, `RegisterUiState`, `RegistrationApi`, `RegistrationRepository`,
  `onEmailChange`, and `submitEnabled`, all of which this ticket extends.
- **Transitive:** AND-015 (`ApiError`/detail mapper), AND-018 (`ApiResult`), AND-009
  (timeouts), AND-011/AND-012 (cookie jar + CSRF), AND-020 (input composables),
  AND-031 (`EmailValidator`) — all arrive via AND-053 or core-* and are consumed here.
- **Blocks:** none. AND-054 (confirm/resend) is independent.
- Develop directly on top of AND-053; the diff is additive (new enum, two state fields,
  one API method, one repository method, one init pipeline, supporting-text wiring).

## 13. Risks & Open Questions

- **R1 — Response field name. [RESOLVED 2026-06-06.]** Verified against
  `/openapi.json` (`RegisterEmailCheckResp`) and `frontend/src/api/types.ts`: the response
  is `{ available: boolean, status: string }` — **both required**, and there is **no**
  `email` field (the draft's optional `email` was wrong and has been removed in §5). The
  Moshi DTO + `toAvailability()` remain the single point of change.
- **R2 — Email enumeration.** An unauthenticated availability endpoint leaks which
  emails are registered. This is a backend concern; **note the backend already rate-limits
  this endpoint** — the web reference (`Register.tsx`) explicitly handles **HTTP 429** as
  `rate_limited`. The Android client should still not log/persist results (§8). No Android
  action beyond §8 and treating 429 as advisory `Error` (§5/§7).
- **R3 — Debounce tuning.** 400 ms is a starting value balancing responsiveness against
  load on the unreliable dev host. Make `EMAIL_DEBOUNCE_MS` a constant for easy tuning;
  revisit if check latency is high.
- **R4 — Race with submit.** If the user submits while a `Checking` is in flight, submit
  proceeds (FR-8) and `register/start` adjudicates. Confirm this is acceptable UX vs.
  briefly disabling submit during `Checking`. Current decision: do **not** block on
  `Checking` to keep the form responsive.
- **R5 — Endpoint existence. [RESOLVED 2026-06-06.]** `POST /ui/register/check` exists
  in the backend OpenAPI index (op `register_check_ui_register_check_post`,
  `req=RegisterEmailCheckReq`, `resp=200:RegisterEmailCheckResp;422:HTTPValidationError`).
  No degradation path needed for absence; the advisory `Error` fallback (§7) still covers
  transient outages.

## 14. Acceptance Criteria

- AC-1. Typing a syntactically valid email triggers at most one `POST /ui/register/check`
  after 400 ms of inactivity; rapid typing does not produce multiple concurrent calls.
  (unit-tested, cases 1–2)
- AC-2. **A taken email is surfaced inline before submit:** when the server reports the
  email is taken, the field shows `register_email_taken` and `submitEnabled == false`
  while other fields are valid. (unit-tested, case 7 — the source acceptance bullet)
- AC-3. Invalid or blank emails dispatch no network call and show no availability
  status. (unit-tested, cases 3–4)
- AC-4. While a check is in flight, `emailChecking == true` and an accessible inline
  spinner is shown; it clears on result/cancel/error. (unit-tested, case 5)
- AC-5. A failed/timeout check maps to `Error` (advisory) and does **not** block submit;
  the form defers to `register/start`. (unit-tested, case 8)
- AC-6. Editing the email cancels/discards any superseded check; no stale
  `Taken`/`Available` is shown for an outdated value. (unit-tested, cases 9, 11)
- AC-7. No raw email appears in logs, analytics, or `RegisterUiState.toString()`.
- AC-8. All pipeline branches and the `toAvailability` mapper have 100% unit-test branch
  coverage.

## 15. Definition of Done

- Code merged to `android-port` under
  `feature-auth/src/main/java/com/testlogon/android/feature/auth/register/` adding the
  `EmailAvailability` enum, the debounce pipeline in `RegisterViewModel.init`,
  `onEmailChange` reset behavior, the `submitEnabled` `Taken` gate, and the email-field
  supporting-text/spinner wiring in `RegisterScreen`.
- `RegistrationApi.checkEmail` + `RegisterEmailCheckReq`/`RegisterEmailCheckResp` DTOs
  (names matching the backend OpenAPI schemas; response carries required `available` +
  `status`) and `RegistrationRepository.checkEmail(): ApiResult<Boolean>` added and
  Hilt-wired (KSP).
- `RegisterEmailCheckTest` (cases 1–12) green in CI; branch-coverage gate met.
- Strings `register_email_taken`, `register_email_available`,
  `register_email_checking` added to `strings.xml`; field uses polite `liveRegion`
  semantics.
- No raw email in any log/`toString`/analytics payload (verified by test).
- ktlint/detekt clean; the only `core-*` change (if any) is the validated DTO name from
  R1; everything else lives in `feature-auth`.
- Manual smoke against the dev backend: typing a known-existing email shows the inline
  "already registered" message and disables submit; a fresh email shows available/no
  block; airplane mode degrades to no-block with the form still submittable.
- Open questions R1 and R5 (response shape + endpoint existence) resolved against
  `/openapi.json` before merge.

## 16. Citations & Assumption Audit

Each key technical claim with VERDICT (Verified / Corrected / Unverified-assumption) and
an exact SOURCE pointer.

1. **Endpoint is `POST /ui/register/check`.** VERDICT: Verified.
   SOURCE: OpenAPI `POST /ui/register/check` (op `register_check_ui_register_check_post`);
   `src/api/endpoints/auth.ts: registerEmailCheck` (`api.post("/ui/register/check", body)`).
2. **HTTP method is POST (not GET).** VERDICT: Verified.
   SOURCE: OpenAPI `POST /ui/register/check`; `src/api/endpoints/auth.ts: registerEmailCheck`.
3. **Request body is `{ email: string }` (email required).** VERDICT: Verified.
   SOURCE: OpenAPI schema `RegisterEmailCheckReq` (`properties.email: string`, `required:[email]`);
   `src/api/types.ts: RegisterEmailCheckReq`.
4. **Request/response DTO names.** VERDICT: Corrected. Draft used `RegisterCheckRequest` /
   `RegisterCheckResponse`; canonical names are `RegisterEmailCheckReq` / `RegisterEmailCheckResp`.
   SOURCE: OpenAPI `components.schemas.RegisterEmailCheckReq` / `RegisterEmailCheckResp`;
   `src/api/types.ts: RegisterEmailCheckReq`, `RegisterEmailCheckResp`.
5. **Response field `available: Boolean` drives free/taken.** VERDICT: Verified.
   SOURCE: OpenAPI `RegisterEmailCheckResp.properties.available: boolean` (required);
   `src/api/types.ts: RegisterEmailCheckResp`; `src/pages/Register.tsx:247`
   (`setEmailStatus(data.available ? "available" : "unavailable")`).
6. **Response also has a required `status: string` field; there is NO `email` field on the
   response.** VERDICT: Corrected. Draft declared an optional `email` field (does not exist)
   and omitted the required `status` field.
   SOURCE: OpenAPI `RegisterEmailCheckResp.properties` = `{available, status}`, `required:[status, available]`;
   `src/api/types.ts: RegisterEmailCheckResp` (`status: string; available: boolean;`).
7. **`status` is unused for UI branching (mirrors web).** VERDICT: Verified.
   SOURCE: `src/pages/Register.tsx:247` branches only on `data.available`; `status` is never read.
8. **Debounce window is 400 ms.** VERDICT: Verified.
   SOURCE: `src/pages/Register.tsx:262` (`setTimeout(..., 400)` keyed on `emailValue`).
9. **A new keystroke cancels the prior pending/in-flight check.** VERDICT: Verified
   (web parity; Android uses `flatMapLatest`).
   SOURCE: `src/pages/Register.tsx:229,263-266` (`isActive=false`, `clearTimeout` in effect cleanup);
   Android approach is a framework choice — `kotlinx.coroutines.flow.flatMapLatest`
   (framework ref: https://kotlinlang.org/api/kotlinx.coroutines/kotlinx-coroutines-core/kotlinx.coroutines.flow/flat-map-latest.html).
10. **Only syntactically valid emails are dispatched; invalid/blank dispatch nothing.**
    VERDICT: Verified (web parity).
    SOURCE: `src/pages/Register.tsx:219-228` (blank → `idle`; `z.string().email()` invalid → `invalid`, returns early).
11. **CSRF: `ui_csrf` cookie sent as `X-CSRF-Token` header.** VERDICT: Verified.
    SOURCE: `src/api/client.ts:168-170` (`getCookie("ui_csrf")` → `headers.set("X-CSRF-Token", csrf)`),
    `client.ts:124,183` (`credentials: "include"`).
12. **No auth session required for `register/check`.** VERDICT: Verified.
    SOURCE: OpenAPI index line for `POST /ui/register/check` has empty `params=` (no
    `X-SESSION-ID` / `user_sub` / impersonation), unlike authed `/ui/*` routes; web sends no
    Authorization for this call (`client.ts:158` only sets it when an access token exists).
13. **Validation error envelope is FastAPI `detail` (422 `HTTPValidationError`).**
    VERDICT: Verified.
    SOURCE: OpenAPI `resp=...;422:HTTPValidationError` for `POST /ui/register/check`;
    error classification owned by AND-015.
14. **Backend rate-limits this endpoint (HTTP 429) and may return 400 for invalid input.**
    VERDICT: Verified (behavior present in web client; advisory-collapsed on Android).
    SOURCE: `src/pages/Register.tsx:254-257` (`err.status === 429` → `rate_limited`;
    `err.status === 400` → `invalid`).
15. **Web reference lives in `Register.tsx` extending an existing screen (no new screen);
    advisory inline status under the email field.** VERDICT: Verified.
    SOURCE: `src/pages/Register.tsx:607-631` (inline `checking`/`available`/`unavailable`/
    `rate_limited`/`error` supporting text under the email input).
16. **~20s OkHttp call timeout (AND-009) and ViewModel/coroutine cancellation model.**
    VERDICT: Unverified-assumption (Android-internal cross-ticket convention; not derivable
    from backend/web sources). SOURCE: AND-009 / AND-018 internal specs (not in this review's
    authoritative source set).
17. **Web uses i18n resource keys for these availability strings.** VERDICT: Corrected /
    Unverified — the web reference uses **hard-coded inline literals**, not i18n keys (no
    matching keys in `src/i18n/locales/en.json`). The Android plan to use `strings.xml`
    resources is a deliberate, valid platform improvement, not a mirror of web.
    SOURCE: `src/pages/Register.tsx:607-631` (literal strings); `src/i18n/locales/en.json`
    (no `available`/`already exists`/`Checking email` keys found).

### Corrections made

- §5 / §15 / §16: DTO names changed `RegisterCheckRequest`/`RegisterCheckResponse` →
  `RegisterEmailCheckReq`/`RegisterEmailCheckResp` to match the backend OpenAPI schemas
  (claims 4).
- §5: Removed the invented optional response `email` field and **added the required
  `status: String` field**; documented that `status` is parsed but unused for branching
  (mirrors web), and that omitting a required field would break Moshi non-null parsing
  (claims 6, 7).
- §5 / §7 / §13-R2: Documented that the backend **rate-limits** this endpoint and the web
  client handles **429 (rate_limited)** and **400 (invalid)** distinctly; clarified that
  Android collapses 400/422/429/5xx/transport to advisory `Error` and does not retry 429
  (claims 13, 14).
- §5: Strengthened CSRF/no-auth claims from "assumed via interceptors" to verified against
  `client.ts` and the empty OpenAPI `params=` list (claims 11, 12).
- §2: Corrected the web reference path from the non-existent
  `frontend/src/api/endpoints/register.ts` to the actual `endpoints/auth.ts`
  (`registerEmailCheck`), `types.ts`, and `pages/Register.tsx`.
- §13-R1 and §13-R5 marked **RESOLVED** with verified evidence; §13-R2 augmented with the
  429 rate-limit evidence.

### Open assumptions

- **OkHttp ~20s call timeout** (claim 16): an AND-009 cross-ticket convention; not present
  in the backend/web sources provided, so it cannot be verified here. Treated as inherited.
- **`EmailValidator.isPlausible` semantics** (AND-031): the exact validity rule is an
  Android-internal core-ui contract not in the authoritative source set; the web uses Zod
  `z.string().email()` (`Register.tsx:224`) as its analog, but the two need not be identical.
- **Analytics event/property names** (`register_email_check*`, `email_domain`, `email_len`):
  Android-internal telemetry convention (AND-052); not derivable from backend/web sources.
- **`status` string vocabulary** (e.g. is it exactly `"taken"`/`"available"`?): the OpenAPI
  schema types it only as a free-form `string` with no enum; the precise values are not
  specified, which is why this ticket (like the web client) does not branch on it.

## 17. Test Plan

Test-target legend: **JVM** = JVM unit/Robolectric (local, no device); **Emulator** =
headless AVD `test35` (x86_64, API 35); **Device** = physical Samsung Galaxy A15 5G
(SM-A156U, serial R5CX821TA9R, API 34, arm64-v8a). This ticket is pure logic + a small
Compose surface with **no** camera/biometrics/push/WebRTC/Telecom hardware needs, so the
emulator is sufficient for instrumented/UI cases; one ABI/API-parity case is pinned to the
physical device.

- **TC-AND-055-01** — Debounced single dispatch (happy path).
  Type: unit (JVM, `kotlinx-coroutines-test` virtual time + Turbine).
  Target: JVM. Preconditions: `FakeRegistrationRepository(checkResult=Success(true))`.
  Steps: call `onEmailChange("a@b.com")`; `advanceTimeBy(401ms)`; settle.
  Expected: `repo.checkCalls == 1`; checked value is trimmed `"a@b.com"`; final
  `emailAvailability == Available`. Traces: AC-1.
- **TC-AND-055-02** — Rapid typing collapses to one request.
  Type: unit (JVM). Target: JVM. Preconditions: fake repo.
  Steps: emit `onEmailChange` for `"a@"`, `"a@b"`, `"a@b.c"`, `"a@b.com"` within < 400 ms
  each; then `advanceTimeBy(401ms)`.
  Expected: `checkCalls == 1`, dispatched only for the final value; no concurrent calls.
  Traces: AC-1.
- **TC-AND-055-03** — Invalid email dispatches nothing.
  Type: unit (JVM). Target: JVM. Preconditions: fake repo.
  Steps: `onEmailChange("foo")`; `advanceTimeBy(401ms)`.
  Expected: `checkCalls == 0`; `emailAvailability == Unknown`. Traces: AC-3.
- **TC-AND-055-04** — Blank email dispatches nothing.
  Type: unit (JVM). Target: JVM. Steps: `onEmailChange("")`; `advanceTimeBy(401ms)`.
  Expected: `checkCalls == 0`; `emailAvailability == Unknown`. Traces: AC-3.
- **TC-AND-055-05** — In-flight `Checking` then clears.
  Type: unit (JVM). Target: JVM. Preconditions: fake repo with a suspendable/gated result.
  Steps: dispatch a valid email; assert `emailChecking == true` while suspended; release;
  assert `emailChecking == false` after result. Traces: AC-4.
- **TC-AND-055-06** — `available == true` → `Available`, submit unaffected.
  Type: unit (JVM). Target: JVM. Preconditions: `checkResult=Success(true)`, all other
  fields valid. Steps: dispatch valid email; settle. Expected: `Available`;
  `submitEnabled == true`. Traces: AC-2 (negative side), AC-5-adjacent.
- **TC-AND-055-07** — `available == false` → `Taken`, submit blocked (core AC).
  Type: unit (JVM). Target: JVM. Preconditions: `checkResult=Success(false)`, all other
  fields valid. Steps: dispatch valid email; settle.
  Expected: `emailAvailability == Taken`; `submitEnabled == false`; supporting text resolves
  `register_email_taken`. Traces: AC-2.
- **TC-AND-055-08** — Contract test against the real response shape (MockWebServer).
  Type: contract/MockWebServer (JVM or Robolectric). Target: JVM/Emulator.
  Preconditions: MockWebServer enqueues `200 {"available": false, "status": "taken"}`.
  Steps: call `RegistrationApi.checkEmail(RegisterEmailCheckReq("x@y.com"))`.
  Expected: request is `POST /ui/register/check` with JSON body `{"email":"x@y.com"}` and
  header `X-CSRF-Token` present; Moshi parses both required fields (`available=false`,
  `status="taken"`) with no failure; repository maps to `Taken`. Also enqueue
  `{"available": true, "status": "ok"}` and assert `Available`. Traces: AC-2, AC-7-adjacent.
- **TC-AND-055-09** — Error responses collapse to advisory `Error`, submit stays enabled.
  Type: contract/MockWebServer + unit. Target: JVM/Emulator.
  Preconditions: enqueue, across sub-cases, `422 HTTPValidationError`, `400`, `429`, `500`,
  and a transport failure/timeout. Steps: dispatch a valid email per sub-case; settle.
  Expected: each maps to `EmailAvailability.Error`; `submitEnabled` remains as base-field
  validation dictates (not blocked by the check). Traces: AC-5.
- **TC-AND-055-10** — Flaky-dev-host / offline path.
  Type: integration (MockWebServer with throttled/dropped connection) + manual on Device.
  Target: JVM/Emulator for automated; **Device** for the manual airplane-mode smoke.
  Preconditions: airplane mode ON (Device) or MockWebServer set to no-response/timeout.
  Steps: type a valid email; wait past the ~20s call timeout.
  Expected: `emailAvailability == Error`; no crash, no blocking banner; form still
  submittable; deferral to `register/start`. Traces: AC-5.
- **TC-AND-055-11** — Stale-response guard (race).
  Type: unit (JVM). Target: JVM. Preconditions: gated fake repo.
  Steps: dispatch check for `"old@x.com"`; before it resolves, `onEmailChange("new@x.com")`;
  resolve the old call. Expected: the old result is discarded (no `Taken`/`Available` shown
  for `old@x.com`); state reflects the new value's pipeline; verified via `flatMapLatest`
  cancellation + email-match guard. Traces: AC-6.
- **TC-AND-055-12** — `onEmailChange` immediately resets to `Unknown`.
  Type: unit (JVM). Target: JVM. Preconditions: prior state `Taken`.
  Steps: `onEmailChange("z@z.com")`. Expected: `emailAvailability == Unknown` synchronously
  (no stale `Taken`/`Available` shown while re-typing). Traces: AC-6.
- **TC-AND-055-13** — No raw email in logs / analytics / `toString` (security/privacy).
  Type: unit (JVM). Target: JVM. Preconditions: fake analytics sink + captured logs.
  Steps: drive a full check cycle with `"secret@corp.com"`.
  Expected: emitted events contain only `email_domain`/`email_len`/`availability`/`latency_ms`;
  the raw local-part never appears in any event, log line, or `RegisterUiState.toString()`.
  Traces: AC-7.
- **TC-AND-055-14** — Compose-UI: taken email shows inline error, disables submit, is
  accessible.
  Type: Compose-UI / instrumented. Target: Emulator (AVD `test35`).
  Preconditions: test ViewModel/fake repo returning `available=false`; all other fields valid.
  Steps: type a known-taken email; advance debounce; assert node with `register_email_taken`
  text and `error` semantics; assert submit button has `disabled()` semantics; assert the
  email field's supporting text node uses `liveRegion = Polite`; while checking, assert the
  spinner exposes a `contentDescription` resolving `register_email_checking`.
  Expected: all assertions pass (TalkBack-compatible). Traces: AC-2, AC-4, AC-7.
- **TC-AND-055-15** — ABI/API parity smoke on physical hardware.
  Type: instrumented/e2e. Target: **Device (MUST run on physical SM-A156U, arm64-v8a,
  API 34)** to catch arm64-vs-x86 / API-34-vs-35 differences vs the x86_64 API-35 emulator.
  Preconditions: app installed on the device; reachable via adb (serial R5CX821TA9R).
  Steps: launch Register; type a known-taken then a fresh email against the dev backend
  (or MockWebServer over adb-reverse). Expected: inline taken message + disabled submit for
  taken; available/no-block for fresh; no ABI-specific crash. Traces: AC-2, AC-3.

### Coverage matrix

| Acceptance criterion (§14) | Covered by |
|---|---|
| AC-1 (debounce: ≤1 call/400 ms, no concurrency) | TC-01, TC-02 |
| AC-2 (taken surfaced inline before submit; submit disabled) | TC-07, TC-08, TC-14, TC-15 |
| AC-3 (invalid/blank → no call, no status) | TC-03, TC-04, TC-15 |
| AC-4 (`emailChecking` spinner shown then cleared, accessible) | TC-05, TC-14 |
| AC-5 (failed/timeout → advisory `Error`, submit not blocked) | TC-06, TC-09, TC-10 |
| AC-6 (edit cancels/discards stale; no stale status) | TC-11, TC-12 |
| AC-7 (no raw email in logs/analytics/`toString`) | TC-13, TC-08, TC-14 |
| AC-8 (100% branch coverage of pipeline + `toAvailability`) | TC-01..TC-13 (the JVM/contract suite) |
