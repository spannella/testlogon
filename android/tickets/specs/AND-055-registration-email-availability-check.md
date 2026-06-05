---
id: AND-055
title: "Registration: email availability check"
milestone: M2
epic: E08
priority: P2
size: S
status: draft
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
- Web reference: `frontend/src/api/endpoints/register.ts` (the `checkEmail` call) and
  `frontend/src/api/types.ts` (`RegisterCheckResponse`). Confirm the exact response
  shape against `/openapi.json` before implementation (see §13 R1).

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

```kotlin
interface RegistrationApi {
    // ...register/start, register/confirm, register/resend (other tickets)
    @POST("ui/register/check")
    suspend fun checkEmail(@Body body: RegisterCheckRequest): RegisterCheckResponse
}

@JsonClass(generateAdapter = true)
data class RegisterCheckRequest(val email: String)

@JsonClass(generateAdapter = true)
data class RegisterCheckResponse(
    val available: Boolean,
    @Json(name = "email") val email: String? = null,
)
```

Endpoint: `POST /ui/register/check`

Request body:
```json
{ "email": "user@example.com" }
```

Response (200):
```json
{ "available": false, "email": "user@example.com" }
```
- `available == true` → email is free → `EmailAvailability.Available`.
- `available == false` → email is taken → `EmailAvailability.Taken`.

Error responses use the standard FastAPI `detail` envelope, mapped by AND-015:
```json
{ "detail": [{ "loc": ["body", "email"], "msg": "value is not a valid email address" }] }
```
A 422 (validation) or any non-2xx is treated as advisory `Error` here (the field is
already gated locally by `EmailValidator`, so a 422 should be rare).

CSRF/cookie handling: the call carries the `ui_csrf` → `X-CSRF-Token` header and cookie
jar automatically via the core-network interceptors (AND-012/AND-011); no auth session
is required to call `register/check`. **Confirm the exact field name (`available` vs
`exists`/`taken`) against `/openapi.json` and `frontend/src/api/types.ts` — see §13 R1**;
the Moshi DTO and `toAvailability()` are the only places to adjust if it differs.

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
  keystroke (or re-typing the same address after editing) naturally re-triggers.
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

- **R1 — Response field name.** The exact `register/check` response shape
  (`{available}` vs `{exists}`/`{taken}`) must be verified against `/openapi.json` and
  `frontend/src/api/types.ts`. The Moshi DTO + `toAvailability()` are the single point
  of change; default assumption is `available: Boolean`.
- **R2 — Email enumeration.** An unauthenticated availability endpoint leaks which
  emails are registered. This is a backend concern (rate limiting / generic responses);
  the Android client should not log/persist results. Flag to backend owners; no Android
  action beyond §8.
- **R3 — Debounce tuning.** 400 ms is a starting value balancing responsiveness against
  load on the unreliable dev host. Make `EMAIL_DEBOUNCE_MS` a constant for easy tuning;
  revisit if check latency is high.
- **R4 — Race with submit.** If the user submits while a `Checking` is in flight, submit
  proceeds (FR-8) and `register/start` adjudicates. Confirm this is acceptable UX vs.
  briefly disabling submit during `Checking`. Current decision: do **not** block on
  `Checking` to keep the form responsive.
- **R5 — Endpoint existence.** If `POST /ui/register/check` is absent from the backend,
  the feature degrades to `Error`/no-op and submit relies on `register/start`. Confirm
  the route exists before sizing as done.

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
- `RegistrationApi.checkEmail` + `RegisterCheckRequest`/`RegisterCheckResponse` DTOs and
  `RegistrationRepository.checkEmail(): ApiResult<Boolean>` added and Hilt-wired (KSP).
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
