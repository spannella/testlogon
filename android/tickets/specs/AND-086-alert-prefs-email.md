---
id: AND-086
title: "Alert prefs: email"
milestone: M2
epic: E12
priority: P1
size: M
status: reviewed
reviewed_on: 2026-06-06
depends_on: [AND-078]
blocks: []
---

# AND-086 — Alert prefs: email

## 1. Overview & Goal

Implement the email alert-target management surface for the TestLogon native Android
app. Users must be able to add an email address as an alert delivery target, verify it
via a one-time confirmation code (double opt-in), remove an existing target, and view
their current email alert preferences. This ticket owns the full vertical slice:
Retrofit endpoints, Moshi DTOs, repository methods, a Hilt-injected `ViewModel`
exposing a `StateFlow<UiState>`, and the Compose UI under
`com.testlogon.android.feature.alerts`.

The feature wraps four backend endpoints:
`POST /ui/alerts/emails/begin`, `POST /ui/alerts/emails/confirm`,
`POST /ui/alerts/emails/remove`, and `GET /ui/alerts/email_prefs`. The "begin → confirm"
pair is a verification handshake: `begin` triggers a confirmation email containing a
6-digit code and returns a `challenge_id`; `confirm` validates `{challenge_id, code}` and
activates the target. `email_prefs` returns the user's `AlertPreferences`, whose `emails`
field is a flat list of *already-verified* address strings (CORRECTED: the backend does
NOT return per-target objects, ids, or a per-row `verified`/`pending` flag — verified
addresses simply appear in `emails`; an in-progress add lives only as client-side
challenge state). `remove` deletes a target by its email address (CORRECTED: keyed by
`email`, not by an id).

Verified against OpenAPI index lines 1118-1122 and `src/api/endpoints/alerts.ts`
(`alertEmailBegin/Confirm/Remove`, `getEmailPrefs`) and `src/api/types.ts:AlertPreferences`.

Goal: a tested, production-quality screen where a TestLogon user can manage which email
addresses receive alerts, with correct handling of the unreliable dev backend
(20s timeouts, single-retry-on-401 refresh, offline/stale states) and FastAPI `detail`
error mapping.

## 2. Context & References

- **Module:** `feature-alerts` (this ticket creates the email sub-feature within it).
- **Layering:** `app -> feature-alerts -> core-network, core-model, core-data, core-ui, core-testing`.
- **Depends on AND-078 (Preferences API + DTOs):** AND-078 establishes the
  `preferences.ts`-equivalent endpoint/DTO conventions, the `PreferencesRepository`
  pattern, the shared `ApiResult<T>` type, and the FastAPI `detail` error-mapping
  helper. AND-086 reuses those conventions and the persistent cookie jar / CSRF
  interceptor from core-network; it does not re-implement them.
- **Web reference:** `frontend/src/api/endpoints/alerts.ts` (or `preferences.ts` if alerts
  email lives there) and shared types in `frontend/src/api/types.ts`. Mirror request/
  response shapes from those files; confirm exact field names against
  `http://18.222.237.167:8000/openapi.json` before freezing DTOs.
- **Auth:** session established earlier in the flow (AND-027 session work).
  All four endpoints require an authenticated session. CORRECTED/CLARIFIED per
  `src/api/client.ts`: the web client sends multiple credentials on every call — an
  `Authorization: Bearer <accessToken>` header, the `X-CSRF-Token` header echoed from the
  `ui_csrf` cookie, session cookies (`credentials: "include"`), and (when impersonating)
  `X-IMPERSONATION-TOKEN`. The OpenAPI declares header params `X-SESSION-ID`,
  `X-IMPERSONATION-TOKEN` and a `user_sub` param on these routes (index lines 1118-1122).
  The Android client must replicate whichever of these the core-network/AND-027 transport
  uses; this ticket does not own that transport. The 401 → `POST /ui/session/refresh`
  → retry-once behavior is handled by the shared OkHttp authenticator from core-network
  (verified: `src/api/client.ts:refreshSession` retries exactly once then logs out).
- **Stack:** Kotlin 2.0.21, Compose + Material 3, Hilt (KSP), Coroutines/Flow,
  Retrofit 2.11 / OkHttp 4.12 / Moshi 1.15. minSdk 24, compileSdk/targetSdk 35.

## 3. Functional Requirements

FR-1. **List email targets.** On screen entry, load `GET /ui/alerts/email_prefs` and
render each configured address. CORRECTED: the response (`AlertPreferences.emails`) is a
flat `string[]` of *already-verified* addresses — there is no per-target `id` and no
per-row `verified`/`pending` flag returned by the backend. Every listed address is, by
definition, verified. (Web reference `src/pages/alerts/AlertPrefs.tsx` renders
`emailPrefs.data?.emails` directly as bare address strings.)

FR-2. **Add target.** User enters an email address and taps "Add". The app POSTs
`{email}` to `/ui/alerts/emails/begin`. On success it receives `{challenge_id, sent_to}`;
the UI stores this as client-side "pending add" state and reveals a code-entry field
prompting for the code sent to `sent_to`. CORRECTED: there is no new list row at this
stage — the pending address is NOT in `emails` until confirmed.

FR-3. **Confirm target.** User enters the 6-digit confirmation code received by
email and taps "Verify". The app POSTs `{challenge_id, code}` (CORRECTED: keyed by
`challenge_id`, NOT a target id) to `/ui/alerts/emails/confirm`. The response is the
updated `AlertPreferences`; on success the pending state is cleared and the list reflects
the newly verified address. Web reference gates Verify on `code.length >= 6`
(`NumberPassword`).

FR-4. **Resend / re-begin.** While an add is pending, the user may re-trigger `begin`
to resend the code (re-calling begin produces a new `challenge_id`). UNVERIFIED-ASSUMPTION:
the web reference implements NO resend control, NO client cooldown, and NO `429`/
`rate_limited` handling, and the backend documents only `422` for begin (index line 1120).
There is no `resend_available_in` field in any response. The 30s client cooldown and
rate-limit handling are net-new Android conveniences and must be treated as assumptions
pending backend confirmation (see R3/R5).

FR-5. **Remove target.** User taps "Remove" on a configured (verified) address,
confirms via a dialog, and the app POSTs `{email}` (CORRECTED: keyed by the address, NOT
an id) to `/ui/alerts/emails/remove`. The response is the updated `AlertPreferences`; the
list reflects the removal on success.

FR-6. **Validation.** Client-side email format validation (`android.util.Patterns.EMAIL_ADDRESS`)
before enabling "Add"; confirmation code restricted to expected length/charset before
enabling "Verify". Server-side validation errors are surfaced inline.

FR-7. **Offline/stale.** If the list load fails and a cached copy exists (Room via
core-data), show the cached list with a "stale" banner and a retry affordance. Mutations
are not performed offline; "Add/Verify/Remove" are disabled when no connectivity and no
in-flight session.

FR-8. **Idempotency.** Only the GET (`email_prefs`) is retried with bounded backoff. The
three POSTs are never auto-retried (except the single session-refresh retry on 401).

## 4. Technical Design

**Package:** `com.testlogon.android.feature.alerts.email`

### 4.1 API service (core-network)

```kotlin
interface EmailAlertApi {
    // CORRECTED: response is AlertPreferences (emails: List<String>), not a {emails:[{id,verified}]} shape.
    @GET("ui/alerts/email_prefs")
    suspend fun getEmailPrefs(): AlertPrefsDto

    // CORRECTED: begin returns {challenge_id, sent_to}.
    @POST("ui/alerts/emails/begin")
    suspend fun beginEmail(@Body body: EmailBeginRequest): EmailBeginResponse

    // CORRECTED: confirm body is {challenge_id, code}; response is the updated AlertPreferences.
    @POST("ui/alerts/emails/confirm")
    suspend fun confirmEmail(@Body body: EmailConfirmRequest): AlertPrefsDto

    // CORRECTED: remove body is {email}; response is the updated AlertPreferences.
    @POST("ui/alerts/emails/remove")
    suspend fun removeEmail(@Body body: EmailRemoveRequest): AlertPrefsDto
}
```

Verified against OpenAPI index lines 1118-1122 (req schemas `AlertEmailBeginReq`,
`AlertEmailConfirmReq`, `AlertEmailRemoveReq`) and `src/api/endpoints/alerts.ts`.

The `X-CSRF-Token` header is injected by the shared OkHttp interceptor (core-network), so
it is not declared per-method here.

### 4.2 Repository (core-data)

```kotlin
// CORRECTED: targets are keyed by email address, not by an id. confirm keys off the
// challengeId returned by begin; remove keys off the email string.
interface EmailAlertRepository {
    fun observeEmailTargets(): Flow<DataState<List<EmailTarget>>>
    suspend fun refreshEmailPrefs(): ApiResult<List<EmailTarget>>
    suspend fun beginEmail(email: String): ApiResult<EmailBeginResult>   // -> {challengeId, sentTo}
    suspend fun confirmEmail(challengeId: String, code: String): ApiResult<List<EmailTarget>>
    suspend fun removeEmail(email: String): ApiResult<List<EmailTarget>>
}

@Singleton
class DefaultEmailAlertRepository @Inject constructor(
    private val api: EmailAlertApi,
    private val dao: EmailTargetDao,            // Room, core-data
    private val errorMapper: ApiErrorMapper,    // shared from AND-078
    @IoDispatcher private val io: CoroutineDispatcher,
) : EmailAlertRepository
```

- `observeEmailTargets()` emits from Room (`Flow`), giving offline/stale reads.
- `refreshEmailPrefs()` calls the GET with bounded backoff (max 2 retries, 250ms→1s,
  jitter) on transient I/O / 5xx only, then upserts into Room.
- Mutations call the API, and on success upsert/delete the Room rows and return the
  updated domain list/object. On failure they map `detail` and leave Room untouched.

### 4.3 ViewModel (feature-alerts)

```kotlin
@HiltViewModel
class EmailAlertViewModel @Inject constructor(
    private val repo: EmailAlertRepository,
) : ViewModel() {

    private val _uiState = MutableStateFlow(EmailAlertUiState())
    val uiState: StateFlow<EmailAlertUiState> = _uiState.asStateFlow()

    fun onEmailChanged(value: String)
    fun onCodeChanged(value: String)
    fun add()                         // begin -> stores challengeId + sentTo
    fun verify()                      // confirm with the stored challengeId + code
    fun resend()                      // begin again (new challengeId), client 30s cooldown (assumption)
    fun remove(email: String)         // confirm dialog -> remove by address
    fun retryLoad()
    fun consumeMessage()              // clears one-shot snackbar message
}

data class EmailAlertUiState(
    val targets: List<EmailTargetUi> = emptyList(),
    val isLoading: Boolean = false,
    val isStale: Boolean = false,
    val emailInput: String = "",
    val emailError: String? = null,
    val codeInput: String = "",
    val codeError: String? = null,
    // CORRECTED: pending add is challenge-scoped, not a list-row id. Holds begin's response.
    val pendingChallengeId: String? = null,
    val pendingSentTo: String? = null,
    val inFlight: Set<EmailAction> = emptySet(),  // ADD, VERIFY, REMOVE, RESEND
    val resendCooldownUntilMs: Long? = null,
    val transientMessage: UiText? = null,         // snackbar
)

enum class EmailAction { ADD, VERIFY, REMOVE, RESEND, LOAD }
```

`init` collects `repo.observeEmailTargets()` into `targets`/`isStale` and triggers
`refreshEmailPrefs()`. Per-action booleans are tracked in `inFlight` so multiple targets'
spinners are independent.

### 4.4 UI (Compose, core-ui components)

- `EmailAlertRoute(viewModel: EmailAlertViewModel = hiltViewModel())` — collects state
  with `collectAsStateWithLifecycle()` and forwards callbacks.
- `EmailAlertScreen(state, callbacks)` — stateless. A `LazyColumn` of `EmailTargetRow`s
  (each a verified address with a Remove action), an add-email `OutlinedTextField` +
  button, a code-entry section gated on `pendingChallengeId` (prompting for the code sent
  to `pendingSentTo`), a `RemoveConfirmDialog`, and a `SnackbarHost` for `transientMessage`.
- Navigation entry registered in the app `NavHost` at route `alerts/email`.

## 5. API Contract

Base URL (dev): `http://18.222.237.167:8000/`. Confirm field names against
`/openapi.json` before merge; shapes below reflect the web reference.

CORRECTED throughout. The OpenAPI declares request schemas but leaves the `200` response
bodies untyped (index lines 1118-1122 show `resp=200:` with no schema). The shapes below
are taken from the frontend reference, which is the de-facto contract:
`src/api/endpoints/alerts.ts` + `src/api/types.ts:AlertPreferences`.

**GET `/ui/alerts/email_prefs`** → `200` `AlertPreferences`
```json
{
  "emails": ["user@example.com", "alt@example.com"],
  "email_event_types": ["payout", "login"]
}
```
CORRECTED: `emails` is a flat array of address strings. There is NO `id`, NO per-row
`verified`, and NO `created_at`. All listed addresses are already verified.

**POST `/ui/alerts/emails/begin`** (req schema `AlertEmailBeginReq`)
```json
// request
{ "email": "alt@example.com" }
// 200 response  (CORRECTED: {challenge_id, sent_to}; no id/status/resend_available_in)
{ "challenge_id": "chal_...", "sent_to": "alt@example.com" }
```

**POST `/ui/alerts/emails/confirm`** (req schema `AlertEmailConfirmReq`)
```json
// request  (CORRECTED: keyed by challenge_id, not id)
{ "challenge_id": "chal_...", "code": "483920" }
// 200 response: updated AlertPreferences (same shape as email_prefs)
```

**POST `/ui/alerts/emails/remove`** (req schema `AlertEmailRemoveReq`)
```json
// request  (CORRECTED: keyed by email address, not id)
{ "email": "alt@example.com" }
// 200 response: updated AlertPreferences (same shape as email_prefs)
```

**Headers:** per `src/api/client.ts`, every call sends session cookies +
`Authorization: Bearer <accessToken>` + `X-CSRF-Token: <ui_csrf>`; POST bodies are JSON
(`Content-Type: application/json`). (Web sets `X-CSRF-Token` on GET too, not only POSTs.)

**Error envelope (FastAPI `detail`):** mapped via the shared helper from AND-078. The
ONLY error response documented in OpenAPI for all four routes is `422 HTTPValidationError`
(the array shape). The string and object `detail` shapes are handled defensively (the web
`normalizeErrorDetail` in `src/api/client.ts` handles string, array-of-`{msg}`, and
object-with-`code`/`msg` forms), but the specific 409/429/object shapes below are
UNVERIFIED-ASSUMPTIONS not present in the spec sources:
```json
// VERIFIED shape (422, HTTPValidationError) — documented for begin/confirm/remove/prefs:
{ "detail": [ { "loc": ["body","email"], "msg": "value is not a valid email", "type": "value_error" } ] }
// DEFENSIVELY HANDLED by web normalizeErrorDetail, but not documented for these routes:
{ "detail": "Email already verified" }
{ "detail": { "code": "rate_limited", "retry_after": 30 } }
```

### DTOs (Moshi)  — CORRECTED to match AlertPreferences + the actual req/resp shapes
```kotlin
// GET email_prefs, and confirm/remove responses all return this.
@JsonClass(generateAdapter = true)
data class AlertPrefsDto(
    val emails: List<String> = emptyList(),
    @Json(name = "email_event_types") val emailEventTypes: List<String> = emptyList(),
    // other AlertPreferences fields (sms_numbers, push_event_types, webhook_urls, ...)
    // exist but are out of scope for this ticket.
)

@JsonClass(generateAdapter = true)
data class EmailBeginRequest(val email: String)

@JsonClass(generateAdapter = true)
data class EmailBeginResponse(
    @Json(name = "challenge_id") val challengeId: String,
    @Json(name = "sent_to") val sentTo: String,
)

@JsonClass(generateAdapter = true)
data class EmailConfirmRequest(
    @Json(name = "challenge_id") val challengeId: String,
    val code: String,
)

// CORRECTED: confirm returns the updated AlertPrefsDto, not a per-target object.

@JsonClass(generateAdapter = true)
data class EmailRemoveRequest(val email: String)
```

Mapper `AlertPrefsDto.toEmailTargets()` (List<String> -> List<EmailTarget>) lives in
core-data. Since the backend exposes no id/verified per address, the domain `EmailTarget`
is derived from the address string (every listed address is verified).

## 6. Data & State Management

- **Domain model:** CORRECTED — the backend has no per-target id/verified/createdAt, so
  `EmailTarget(email: String, verified: Boolean = true)` in core-model (verified is always
  true for listed addresses; the field is kept only to make UI intent explicit). The
  pending-add is not an `EmailTarget` — it is transient `{challengeId, sentTo}` ViewModel
  state.
- **Room (core-data):** `EmailTargetEntity` (PK `email`, `updatedAtLocal`) with
  `EmailTargetDao` exposing `observeAll(): Flow<List<EmailTargetEntity>>`, `upsertAll(...)`,
  `deleteByEmail(email)`, `replaceAll(...)`. CORRECTED: PK is `email`, not an id; there is
  no `verified`/`createdAt` column to persist. Room is the single source of truth for
  reads, enabling stale/offline display per FR-7.
- **DataStore:** stores only the last successful `email_prefs` sync timestamp (for the
  stale banner) under key `alerts_email_last_sync_ms`. No PII beyond what Room already
  holds.
- **State derivation:** `isStale = (now - lastSync) > 5 min` OR last refresh failed while
  cache present. CORRECTED: there is no `verified == false` list row; the pending add is
  the transient `pendingChallengeId`/`pendingSentTo` state, to which the code-entry section
  binds.
- **One-shot events:** `transientMessage: UiText?` cleared by `consumeMessage()` after the
  snackbar shows, avoiding re-emission on recomposition/rotation. `StateFlow` survives
  config changes via the ViewModel.

## 7. Error Handling & Resilience

- **Timeouts:** OkHttp call timeout 20s (core-network default for the dev host).
- **Retry policy:** only `refreshEmailPrefs()` (GET) retries — max 2 attempts, exponential
  backoff 250ms→1s with full jitter, on `IOException`/timeout/HTTP 5xx. POSTs never
  auto-retry beyond the single 401-refresh retry.
- **401 handling:** delegated to the shared OkHttp authenticator: one `POST /ui/session/refresh`
  then retry; if still 401, surface a re-login required state and stop.
- **Error mapping** (shared `ApiErrorMapper` from AND-078) → `ApiResult.Error` subtypes.
  CORRECTED: only `422` is documented (index lines 1118-1122); the other status mappings
  are defensive/assumed (see §16):
  - `422` validation array → field-level `emailError` (for begin/remove) / `codeError` (for
    confirm), matched on `loc` (VERIFIED shape: HTTPValidationError).
  - `400 / "invalid or expired code"` → `codeError`, keep code field focused
    (ASSUMPTION; web simply toasts "Invalid or expired code" on any confirm error).
  - `409 / "Email already verified"` → inline message under the add field (ASSUMPTION).
  - `429 / rate_limited` (or `detail.retry_after`) → set `resendCooldownUntilMs`, disable
    Resend (ASSUMPTION — no backend rate-limit doc, no web handling).
  - `404` on confirm/remove (challenge expired / address already gone) → toast + force
    `email_prefs` refresh to reconcile (ASSUMPTION).
  - Network/timeout → snackbar "Couldn't reach server", keep cached list, allow retry.
- **Optimistic vs. pessimistic:** removals are pessimistic (wait for `200` then update
  Room) to avoid resurrecting a target on failure. Add/verify update Room from the server
  response only.
- **Cooldown:** `resendCooldownUntilMs` enforced client-side (30s) even absent a backend
  `retry_after`, preventing accidental email spam against the flaky dev host.

## 8. Security & Privacy

- Email addresses are user PII. They are stored only in app-private Room/DataStore
  (default app sandbox); not written to logs (see §10) and not exported.
- All mutations require the `X-CSRF-Token` header (echoed from `ui_csrf`); requests rely on
  the persistent cookie jar from core-network. No tokens are stored in plain SharedPreferences.
- Confirmation codes are never persisted; held only in transient `codeInput` and cleared
  on success, navigation away, or screen disposal.
- The dev backend is **plaintext HTTP**; production must enforce HTTPS. A
  `network_security_config.xml` cleartext exception is scoped to the dev host
  `18.222.237.167` only (owned by core-network/AND-027); this ticket does not widen it.
- Double opt-in (begin→confirm) is enforced server-side; the client never marks an address
  verified without a `confirm` success response.

## 9. Accessibility & i18n

- All controls have `contentDescription` / `Modifier.semantics`: "Add email alert target",
  "Confirmation code", "Verify email", "Remove <email>".
- Touch targets ≥ 48dp; Material 3 dynamic color and dark theme via core-ui.
- TextFields: `KeyboardType.Email` for address, `KeyboardType.NumberPassword` for the code;
  `imeAction` Next/Done wired for keyboard flow.
- Errors announced via `liveRegion` semantics; the stale banner is focusable and announced.
- All user-facing strings in `res/values/strings.xml` with placeholders
  (e.g., `alert_email_pending_for = "Pending verification for %1$s"`); no hardcoded text.
  RTL-safe layouts (use start/end paddings). Dates rendered with locale-aware formatter.

## 10. Telemetry & Logging

- Analytics events (via core-ui/core-data analytics facade): `alerts_email_add_started`,
  `alerts_email_add_succeeded`, `alerts_email_confirm_succeeded`, `alerts_email_removed`,
  `alerts_email_resend`, `alerts_email_error` (with mapped `error_code`, never the address).
- **Never log PII:** email addresses and confirmation codes must not appear in Logcat,
  crash reports, or analytics payloads. OkHttp `HttpLoggingInterceptor` is at `BASIC` (or
  redacted `HEADERS`) in debug only and stripped in release; request bodies for these
  endpoints are not logged.
- Structured debug logs use target `id` (opaque) rather than email for correlation.

## 11. Testing Strategy

**Acceptance mandate (source ticket): "Add/verify/remove email alert target (tested)."**

- **Repository unit tests** (core-testing, JUnit5 + MockWebServer):
  - `refreshEmailPrefs` parses `email_prefs`, upserts Room, returns `Success`.
  - `beginEmail` success → pending result; `422` → mapped field error.
  - `confirmEmail(challengeId, code)` success returns updated prefs and upserts Room;
    `422`/assumed `400 invalid code` → error.
  - `removeEmail(email)` success deletes the Room row by address; assumed `404` → error and
    Room untouched.
  - Backoff: GET retries on 503 then succeeds; POSTs do **not** retry on 503.
  - 401 → refresh-once path retried (fake authenticator).
- **ViewModel tests** (Turbine + coroutines-test): state transitions for add → pending →
  verify → verified; resend cooldown disables control for 30s; remove confirm flow;
  stale banner when refresh fails with cache present; one-shot message consumed once.
- **DTO/JSON tests:** Moshi adapters parse `AlertPrefsDto` (`emails: List<String>`),
  `EmailBeginResponse` (`challenge_id`/`sent_to`), and the `422` HTTPValidationError array
  via the shared mapper; unknown/extra `AlertPreferences` fields tolerated.
- **Compose UI tests** (`createAndroidComposeRule`): "Add" disabled until valid email;
  "Verify" disabled until 6-digit code entered; remove dialog confirm path; error text shown
  via semantics; pending-add state (after begin) reveals the code-entry field for `sent_to`.
- **MockWebServer integration:** end-to-end begin→confirm→prefs happy path against scripted
  responses, including a 20s-timeout simulation surfacing the offline snackbar.

## 12. Dependencies & Sequencing

- **Depends on AND-078** (Preferences API + DTOs): reuses `ApiResult<T>`, `ApiErrorMapper`,
  the repository pattern, and Room/DataStore wiring. Must merge first.
- **Transitively depends on AND-027** (session/cookie + CSRF + 401-refresh authenticator)
  via AND-078; this ticket assumes that core-network infrastructure exists.
- **Sequencing:** (1) add DTOs + `EmailAlertApi` to core-network; (2) Room entity/DAO +
  repository in core-data; (3) ViewModel + Compose UI in feature-alerts; (4) NavHost route +
  Hilt module bindings in app; (5) tests throughout.
- **Blocks:** none recorded in the source backlog. Other E12 alert-target tickets (SMS,
  push) may reuse this pattern but are not declared blocked here.

## 13. Risks & Open Questions

- **R1 — Field-name drift:** RESOLVED during this review. Verified against
  `src/api/types.ts:AlertPreferences`: the field is `emails` (a `string[]`), with sibling
  `email_event_types`. No `is_verified`/`email_targets`. DTOs frozen accordingly; keep
  `@Json(name=...)` for `challenge_id`/`sent_to`/`email_event_types`.
- **R2 — Begin response shape:** RESOLVED. `begin` returns `{challenge_id, sent_to}` (no
  target id). `confirm` keys off `challenge_id`; `remove` keys off the email address.
  Verified in `src/api/endpoints/alerts.ts` and OpenAPI `AlertEmailConfirmReq`/
  `AlertEmailRemoveReq`.
- **R3 — Resend semantics:** STILL OPEN. The web reference has no resend control, so the
  re-`begin`-for-pending behavior is unobserved. Assumed re-issue (new `challenge_id`);
  confirm with backend. The client 30s cooldown is a net-new convenience (see §16).
- **R4 — Flaky dev host:** intermittent 5xx/timeouts may make confirm appear to fail after
  the code was actually consumed. *Mitigation:* on ambiguous failure, force an
  `email_prefs` refresh before showing an error.
- **R5 — Rate limiting:** exact `429` body shape (`retry_after` vs `detail.retry_after`)
  unconfirmed; handle both.

## 14. Acceptance Criteria

- AC-1. A user can add an email target: entering a valid address and tapping "Add" calls
  `POST /ui/alerts/emails/begin` with `{email}`, and the UI enters the pending-add state
  (code-entry field revealed for the `sent_to` address). (No new list row yet — see §6.)
- AC-2. A user can verify a target: entering the emailed 6-digit code and tapping "Verify"
  calls `POST /ui/alerts/emails/confirm` with `{challenge_id, code}`; on `200` the returned
  `AlertPreferences` includes the address in `emails` and it appears as a verified row.
- AC-3. A user can remove a target: confirming the dialog calls
  `POST /ui/alerts/emails/remove` with `{email}`; on `200` the address is gone from the
  returned `emails` and Room is updated.
- AC-4. The list loads from `GET /ui/alerts/email_prefs` on entry and renders each
  configured (verified) address; there is no per-row pending state from the server.
- AC-5. Invalid email is rejected client-side (Add disabled); server `422` validation
  (HTTPValidationError array) maps to inline `emailError` (begin/remove) or `codeError`
  (confirm), matched on `loc`.
- AC-6. The GET retries with bounded backoff on transient failure; the three POSTs are not
  auto-retried; 401 triggers exactly one session refresh + retry.
- AC-7. When refresh fails with a cached list present, the stale banner shows and the cached
  list remains visible with a working retry.
- AC-8. Resend is disabled for 30s after a begin/resend and respects backend rate limits.
- AC-9. No email address or confirmation code appears in Logcat, analytics, or crash logs.
- AC-10. Repository, ViewModel, DTO, and Compose UI tests covering add/verify/remove pass
  in CI (satisfying the "(tested)" acceptance).

## 15. Definition of Done

- All four endpoints integrated via `EmailAlertApi` with Moshi DTOs verified against
  `/openapi.json`.
- `EmailAlertRepository` (Room-backed, ApiResult-returning) and `EmailAlertViewModel`
  (`StateFlow<EmailAlertUiState>`) implemented in the correct modules with Hilt bindings.
- Compose `EmailAlertScreen` wired into the app `NavHost` at `alerts/email`, fully
  accessible and localized (no hardcoded strings).
- Error mapping covers all three FastAPI `detail` shapes plus 401/404/409/422/429 and
  network/timeout, with offline/stale UI.
- Unit, ViewModel, DTO, and Compose tests pass in CI; ktlint/detekt clean; no PII in logs.
- Code reviewed and merged to `android-port`; package namespace
  `com.testlogon.android.feature.alerts.email` throughout.
- AND-078 confirmed merged; open questions R3/R5 resolved with backend or documented as
  follow-ups before release (R1/R2 resolved during the 2026-06-06 review).

## 16. Citations & Assumption Audit

Each key technical claim, its verdict, and an exact source pointer. Sources: OpenAPI
index (`reference/openapi.index.txt`), OpenAPI spec (`reference/openapi.pretty.json`
`components.schemas.*`), and frontend (`reference/src/...`).

1. **Endpoints exist as `GET /ui/alerts/email_prefs`, `POST /ui/alerts/emails/begin|confirm|remove`.**
   VERIFIED. OpenAPI index lines 1118-1122 (`GET /ui/alerts/email_prefs`,
   `POST /ui/alerts/emails/begin|confirm|remove`).
2. **HTTP methods: GET for prefs, POST for begin/confirm/remove.** VERIFIED.
   Same index lines; mirrored in `src/api/endpoints/alerts.ts` (`api.get`/`api.post`).
3. **`begin` request body = `{email}`.** VERIFIED. Schema `AlertEmailBeginReq`
   (`openapi.pretty.json` line 4536, required `email`); `src/api/endpoints/alerts.ts:alertEmailBegin`.
4. **`begin` response = `{challenge_id, sent_to}`.** CORRECTED (spec said
   `{id,email,status,resend_available_in}`). `src/api/endpoints/alerts.ts:alertEmailBegin`
   types the response `{ challenge_id: string; sent_to: string }`; OpenAPI leaves the 200
   body untyped (index line 1120 `resp=200:`).
5. **`confirm` request body = `{challenge_id, code}`.** CORRECTED (spec said `{id, code}`).
   Schema `AlertEmailConfirmReq` (`openapi.pretty.json` line 4549, required
   `challenge_id`, `code`); `src/api/endpoints/alerts.ts:alertEmailConfirm`.
6. **`confirm` response = updated `AlertPreferences`.** CORRECTED (spec said
   `{id,email,verified}`). `alertEmailConfirm` returns `AlertPreferences`;
   `src/api/types.ts:AlertPreferences` (line 446).
7. **`remove` request body = `{email}`.** CORRECTED (spec said `{id}`). Schema
   `AlertEmailRemoveReq` (`openapi.pretty.json` line 4580, required `email`);
   `src/api/endpoints/alerts.ts:alertEmailRemove`.
8. **`remove` response = updated `AlertPreferences`.** VERIFIED. `alertEmailRemove`
   returns `AlertPreferences`.
9. **`email_prefs` response = `AlertPreferences` with `emails: string[]`.** CORRECTED
   (spec said list of `{id,email,verified,created_at}` objects). `src/api/types.ts:AlertPreferences`
   line 446-455: `emails?: string[]`, `email_event_types?: string[]`. No id/verified/created_at.
10. **No per-target id; no per-row verified flag; remove keyed by address; confirm keyed
    by challenge.** CORRECTED. Established by items 4-9 plus
    `src/pages/alerts/AlertPrefs.tsx` (renders bare `addr` strings; `emailRemoveMut.mutate(addr)`;
    `emailConfirmMut.mutate({ id: emailPending.challengeId, code })`).
11. **Confirmation code is 6 digits.** VERIFIED. `src/pages/alerts/AlertPrefs.tsx`
    gates Verify on `emailCode.length < 6` and prompts "Enter the 6-digit code".
12. **CSRF: `X-CSRF-Token` echoed from `ui_csrf` cookie.** VERIFIED. `src/api/client.ts`
    lines 167-171 (`getCookie("ui_csrf")` -> `headers.set("X-CSRF-Token", csrf)`).
13. **Auth also sends `Authorization: Bearer <accessToken>` and cookies; impersonation via
    `X-IMPERSONATION-TOKEN`.** CORRECTED/CLARIFIED (spec said cookie-only). `src/api/client.ts`
    lines 156-165, 183 (`credentials: "include"`); OpenAPI params `X-SESSION-ID`,
    `X-IMPERSONATION-TOKEN`, `user_sub` (index lines 1118-1122).
14. **401 → single `POST /ui/session/refresh` then retry once, else logout.** VERIFIED.
    `src/api/client.ts:refreshSession` (lines 121-130) + retry block lines 194-237.
15. **Only documented error response is `422 HTTPValidationError` (array shape).** VERIFIED.
    Index lines 1118-1122 (`resp=...;422:HTTPValidationError`). `normalizeErrorDetail`
    (`src/api/client.ts` lines 66-102) additionally tolerates string and object `detail`.
16. **`409 "Email already verified"`, `400 invalid code`, `404 target gone`,
    `429 rate_limited`/`retry_after` mappings.** UNVERIFIED-ASSUMPTION. None documented in
    OpenAPI for these routes; not implemented in the web client (which just toasts a generic
    message on confirm error — `AlertPrefs.tsx` lines 119/129). Defensive only.
17. **Resend control + 30s client cooldown + backend rate-limit handling.**
    UNVERIFIED-ASSUMPTION. The web reference has no resend control, no cooldown, no
    `resend_available_in`/`retry_after` field anywhere. Net-new Android behavior.
18. **Stale/offline + Room single-source-of-truth + DataStore last-sync.**
    UNVERIFIED-ASSUMPTION (Android architecture choice; depends on AND-078). The web client
    has no offline cache (it shows a network-error toast and stops — `src/api/client.ts`
    lines 185-189).
19. **Stack: Compose/Material3, Hilt, Retrofit/OkHttp/Moshi, Coroutines/Flow.**
    Framework choice — not verifiable from backend/web sources. framework ref:
    https://developer.android.com/jetpack/compose and https://developer.android.com/training/dependency-injection/hilt-android
20. **`android.util.Patterns.EMAIL_ADDRESS` for client email validation.** framework ref:
    https://developer.android.com/reference/android/util/Patterns#EMAIL_ADDRESS

### Corrections made
- begin response shape: `{id,email,status,resend_available_in}` → `{challenge_id, sent_to}` (§1, §3 FR-2, §4.1, §5, DTOs).
- confirm request: `{id, code}` → `{challenge_id, code}`; response: per-target object → `AlertPreferences` (§3 FR-3, §4.1-4.3, §5, DTOs).
- remove request: `{id}` → `{email}` (§3 FR-5, §4.1-4.3, §5, DTOs).
- email_prefs / list model: list of `{id,email,verified,created_at}` → flat `emails: string[]` of already-verified addresses; removed per-row pending/verified state (§1, §3 FR-1/FR-4, §4.3, §5, §6, §14 AC-1/AC-2/AC-4).
- Domain/Room model: id-keyed entity with verified/createdAt → email-keyed, no verified/createdAt columns (§6).
- ViewModel: `pendingTargetId`/`verify(targetId)`/`remove(targetId)` → `pendingChallengeId`+`pendingSentTo`/`verify()`/`remove(email)` (§4.3).
- Auth: "cookie-based only" → cookies + Bearer + CSRF (+ impersonation) (§2, §5).
- Error mapping: marked 409/400/404/429 as assumptions; only 422 is documented (§5, §7).
- Risks R1/R2 reclassified RESOLVED with citations (§13).

### Open assumptions
- OA-1. All non-422 error mappings (409/400/404/429 and string/object `detail` shapes for these routes). Why: not in OpenAPI (only `422`) and not exercised by the web client. Verify with backend or treat defensively.
- OA-2. Resend semantics (does re-`begin` on a pending address re-issue or error?) and the existence/shape of any rate-limit response. Why: no resend control exists in the web reference (R3/R5).
- OA-3. The 30s resend cooldown, Room-backed offline/stale UI, and DataStore last-sync. Why: net-new Android conveniences with no web/back-end analogue.
- OA-4. Whether `confirm`/`remove` truly return the *full updated* `AlertPreferences` synchronously vs. requiring a follow-up `email_prefs` GET. Why: web invalidates the query cache after mutation rather than relying solely on the response body (`AlertPrefs.tsx` lines 124/134); the Android client should defensively refresh on ambiguity (R4).
- OA-5. Android framework/architecture choices (Compose/Hilt/Retrofit/Room/DataStore) and `Patterns.EMAIL_ADDRESS`. Why: not derivable from backend/web sources; standard platform choices.

## 17. Test Plan

Test targets: JVM = local JVM/Robolectric unit; MWS = MockWebServer contract; EMU =
headless emulator AVD `test35` (x86_64, API 35); DEV = physical Samsung Galaxy A15 5G
(SM-A156U, API 34, arm64-v8a). This feature is pure REST + Compose UI with no
camera/biometric/WebRTC/FCM hardware dependency, so most cases run on JVM/EMU; one ABI
parity case is pinned to the physical device.

- **TC-AND-086-01 — Load prefs happy path (contract).** Type: contract/MockWebServer
  (JVM). Target: `DefaultEmailAlertRepository.refreshEmailPrefs`. Preconditions: MWS scripted
  to return `200 {"emails":["a@x.com","b@y.com"],"email_event_types":[...]}`. Steps: call
  `refreshEmailPrefs()`. Expected: returns `Success` with two `EmailTarget`s (both
  verified), Room upserted with PK=email, request was `GET /ui/alerts/email_prefs` with
  `X-CSRF-Token` header. Traces: AC-4.
- **TC-AND-086-02 — Begin add happy path (contract).** Type: MWS (JVM). Target:
  `repository.beginEmail`. Preconditions: MWS returns `200 {"challenge_id":"chal_1","sent_to":"new@x.com"}`.
  Steps: `beginEmail("new@x.com")`. Expected: request body is exactly `{"email":"new@x.com"}`
  to `POST /ui/alerts/emails/begin`; result carries `challengeId="chal_1"`, `sentTo="new@x.com"`;
  Room NOT modified (no row added yet). Traces: AC-1.
- **TC-AND-086-03 — Confirm happy path (contract).** Type: MWS (JVM). Target:
  `repository.confirmEmail`. Preconditions: MWS returns `200` with updated
  `{"emails":["a@x.com","new@x.com"]}`. Steps: `confirmEmail("chal_1","483920")`. Expected:
  request body is exactly `{"challenge_id":"chal_1","code":"483920"}`; result list contains
  `new@x.com`; Room upserted to include it. Traces: AC-2.
- **TC-AND-086-04 — Remove happy path (contract).** Type: MWS (JVM). Target:
  `repository.removeEmail`. Preconditions: MWS returns `200 {"emails":["a@x.com"]}`. Steps:
  `removeEmail("new@x.com")`. Expected: request body is exactly `{"email":"new@x.com"}` to
  `POST /ui/alerts/emails/remove`; Room row for `new@x.com` deleted; returned list excludes it.
  Traces: AC-3.
- **TC-AND-086-05 — 422 validation maps to field error (contract).** Type: MWS (JVM).
  Target: `repository.beginEmail` + `ApiErrorMapper`. Preconditions: MWS returns
  `422 {"detail":[{"loc":["body","email"],"msg":"value is not a valid email","type":"value_error"}]}`.
  Steps: `beginEmail("bad")`. Expected: `ApiResult.Error` mapped to a field error keyed on
  `loc=["body","email"]` (surfaced as `emailError`); Room untouched. Traces: AC-5.
- **TC-AND-086-06 — Confirm wrong/expired code error (contract).** Type: MWS (JVM).
  Target: `repository.confirmEmail`. Preconditions: MWS returns `422` (documented) and,
  in a second scripted run, `400 {"detail":"invalid or expired code"}` (assumption path).
  Steps: confirm with a bad code. Expected: both map to a `codeError`; code field retained;
  Room untouched; no auto-retry of the POST. Traces: AC-2, AC-5, AC-6.
- **TC-AND-086-07 — GET backoff retry vs POST no-retry (contract).** Type: MWS (JVM).
  Target: repository retry policy. Preconditions: MWS queues `503` then `200` for the GET;
  separately queues `503` for a begin POST. Steps: `refreshEmailPrefs()` then `beginEmail()`.
  Expected: GET retried (≤2 retries, backoff) and ultimately `Success`; the POST is NOT
  auto-retried and returns `Error` after the single `503`. Traces: AC-6.
- **TC-AND-086-08 — 401 triggers exactly one session refresh + retry (contract).** Type:
  MWS (JVM) with fake authenticator. Target: core-network authenticator integration on
  these calls. Preconditions: MWS returns `401` for `email_prefs`, `200` for
  `POST /ui/session/refresh`, then `200` for the retried `email_prefs`. Steps:
  `refreshEmailPrefs()`. Expected: exactly one `/ui/session/refresh` call, original request
  retried once, final `Success`; a persistent `401` surfaces a re-login state and does NOT
  loop. Traces: AC-6.
- **TC-AND-086-09 — Offline/stale banner with cache present (unit/ViewModel).** Type: unit
  (Turbine, JVM). Target: `EmailAlertViewModel`. Preconditions: Room seeded with one
  address; refresh fails with `IOException`. Steps: init VM, let refresh fail. Expected:
  cached list still emitted, `isStale=true`, retry affordance enabled, mutations gated off
  while offline. Traces: AC-7.
- **TC-AND-086-10 — Resend cooldown disables control 30s (unit/ViewModel).** Type: unit
  (coroutines-test virtual clock, JVM). Target: `EmailAlertViewModel.resend`. Preconditions:
  a pending add exists. Steps: call `resend()`, advance clock < 30s then ≥ 30s. Expected:
  `resendCooldownUntilMs` set; Resend disabled until 30s elapse, then re-enabled. NOTE:
  exercises an UNVERIFIED-ASSUMPTION (OA-2/OA-3) — keep isolated from backend contract.
  Traces: AC-8.
- **TC-AND-086-11 — No PII in logs (unit/instrumented).** Type: unit (JVM) + spot-check
  instrumented (EMU). Target: logging/analytics facade + OkHttp logging config. Steps:
  run begin/confirm/remove against MWS with a captured logger; assert no email address and
  no code appears in any log line or analytics payload (only opaque correlators / mapped
  `error_code`). Expected: zero PII occurrences. Traces: AC-9.
- **TC-AND-086-12 — Compose: Add/Verify gating + remove dialog + a11y (Compose-UI).**
  Type: Compose-UI instrumented (EMU). Target: `EmailAlertScreen`. Preconditions: fake VM
  state. Steps: type invalid then valid email (Add enabled only when valid via
  `Patterns.EMAIL_ADDRESS`); enter < 6 then 6 digits (Verify enabled only at 6); open
  remove dialog and confirm; assert error text and stale banner are exposed via
  `liveRegion`/semantics and all controls have contentDescription and ≥48dp targets.
  Expected: gating, dialog confirm callback, and accessibility assertions pass. Traces:
  AC-1, AC-2, AC-3, AC-5, AC-9.
- **TC-AND-086-13 — End-to-end begin→confirm→prefs + 20s timeout (integration).** Type:
  integration/MockWebServer (EMU). Target: full VM+repo+UI stack. Preconditions: MWS scripts
  begin `200`, confirm `200` (updated prefs), and a separate `email_prefs` call delayed > 20s
  to trip the OkHttp call timeout. Steps: drive add→verify happy path, then trigger a load
  that times out. Expected: address appears verified after confirm; the timeout surfaces the
  "Couldn't reach server" snackbar while the cached list remains visible. Traces: AC-2,
  AC-4, AC-7, AC-10.
- **TC-AND-086-14 — ABI/API parity smoke on physical device (instrumented/e2e).** Type:
  instrumented (DEV — MUST run on the physical Galaxy A15, arm64-v8a, API 34; the rest of
  the suite runs on the x86_64/API-35 emulator). Target: packaged feature module against a
  stub/MWS backend. Steps: run the begin→confirm→remove instrumented flow on-device.
  Expected: identical behavior to EMU (no arm64-vs-x86 Moshi/codegen or API-34-vs-35
  Compose regressions). Traces: AC-10.

### Coverage matrix
| AC | Covered by |
| --- | --- |
| AC-1 (add → pending state) | TC-01-ish entry, TC-02, TC-12 |
| AC-2 (verify → verified) | TC-03, TC-06, TC-12, TC-13 |
| AC-3 (remove) | TC-04, TC-12 |
| AC-4 (list load + render) | TC-01, TC-13 |
| AC-5 (client + 422 validation) | TC-05, TC-06, TC-12 |
| AC-6 (GET backoff / POST no-retry / 401 once) | TC-06, TC-07, TC-08 |
| AC-7 (stale banner + cached list + retry) | TC-09, TC-13 |
| AC-8 (resend 30s cooldown / rate limit) | TC-10 |
| AC-9 (no PII in logs/analytics) | TC-11, TC-12 |
| AC-10 ((tested): repo+VM+DTO+Compose in CI) | TC-01..TC-14 (esp. TC-13, TC-14) |
