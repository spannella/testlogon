---
id: AND-086
title: "Alert prefs: email"
milestone: M2
epic: E12
priority: P1
size: M
status: draft
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
code; `confirm` validates that code and activates the target. `email_prefs` returns the
list of configured targets and their verification state; `remove` deletes a target.

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
- **Auth:** cookie-based session established earlier in the flow (AND-027 session work).
  All four endpoints require an authenticated session; mutating POSTs require the
  `X-CSRF-Token` header echoed from the `ui_csrf` cookie. The 401 → `POST /ui/session/refresh`
  → retry-once behavior is handled by the shared OkHttp authenticator from core-network.
- **Stack:** Kotlin 2.0.21, Compose + Material 3, Hilt (KSP), Coroutines/Flow,
  Retrofit 2.11 / OkHttp 4.12 / Moshi 1.15. minSdk 24, compileSdk/targetSdk 35.

## 3. Functional Requirements

FR-1. **List email targets.** On screen entry, load `GET /ui/alerts/email_prefs` and
render each target with its address and verification status (`verified` / `pending`).

FR-2. **Add target.** User enters an email address and taps "Add". The app POSTs to
`/ui/alerts/emails/begin`. On success, the UI transitions the target into a
"pending verification" state and reveals a code-entry field.

FR-3. **Confirm target.** User enters the 6-character confirmation code received by
email and taps "Verify". The app POSTs to `/ui/alerts/emails/confirm`. On success, the
target is marked verified and the list refreshes.

FR-4. **Resend / re-begin.** While a target is pending, the user may re-trigger `begin`
to resend the code; the "Resend" control is rate-limited client-side (30s cooldown) and
respects backend `429`/`rate_limited` responses.

FR-5. **Remove target.** User taps "Remove" on any target (verified or pending),
confirms via a dialog, and the app POSTs to `/ui/alerts/emails/remove`. The list
refreshes on success.

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
    @GET("ui/alerts/email_prefs")
    suspend fun getEmailPrefs(): EmailPrefsDto

    @POST("ui/alerts/emails/begin")
    suspend fun beginEmail(@Body body: EmailBeginRequest): EmailBeginResponse

    @POST("ui/alerts/emails/confirm")
    suspend fun confirmEmail(@Body body: EmailConfirmRequest): EmailConfirmResponse

    @POST("ui/alerts/emails/remove")
    suspend fun removeEmail(@Body body: EmailRemoveRequest): EmailPrefsDto
}
```

The `X-CSRF-Token` header is injected by the shared OkHttp interceptor (core-network), so
it is not declared per-method here.

### 4.2 Repository (core-data)

```kotlin
interface EmailAlertRepository {
    fun observeEmailTargets(): Flow<DataState<List<EmailTarget>>>
    suspend fun refreshEmailPrefs(): ApiResult<List<EmailTarget>>
    suspend fun beginEmail(email: String): ApiResult<EmailBeginResult>
    suspend fun confirmEmail(targetId: String, code: String): ApiResult<EmailTarget>
    suspend fun removeEmail(targetId: String): ApiResult<List<EmailTarget>>
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
    fun add()                         // begin
    fun verify(targetId: String)      // confirm
    fun resend(targetId: String)      // begin again, 30s cooldown
    fun remove(targetId: String)      // confirm dialog -> remove
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
    val pendingTargetId: String? = null,
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
- `EmailAlertScreen(state, callbacks)` — stateless. A `LazyColumn` of `EmailTargetRow`s,
  an add-email `OutlinedTextField` + button, a code-entry section gated on
  `pendingTargetId`, a `RemoveConfirmDialog`, and a `SnackbarHost` for `transientMessage`.
- Navigation entry registered in the app `NavHost` at route `alerts/email`.

## 5. API Contract

Base URL (dev): `http://18.222.237.167:8000/`. Confirm field names against
`/openapi.json` before merge; shapes below reflect the web reference.

**GET `/ui/alerts/email_prefs`** → `200`
```json
{
  "emails": [
    { "id": "em_01H...", "email": "user@example.com", "verified": true,  "created_at": "2026-06-01T10:22:00Z" },
    { "id": "em_02H...", "email": "alt@example.com",  "verified": false, "created_at": "2026-06-05T09:00:00Z" }
  ]
}
```

**POST `/ui/alerts/emails/begin`**
```json
// request
{ "email": "alt@example.com" }
// 200 response
{ "id": "em_02H...", "email": "alt@example.com", "status": "pending", "resend_available_in": 30 }
```

**POST `/ui/alerts/emails/confirm`**
```json
// request
{ "id": "em_02H...", "code": "483920" }
// 200 response
{ "id": "em_02H...", "email": "alt@example.com", "verified": true }
```

**POST `/ui/alerts/emails/remove`**
```json
// request
{ "id": "em_02H..." }
// 200 response: updated EmailPrefsDto (same shape as email_prefs)
```

**Headers:** all four send session cookies; the three POSTs send
`X-CSRF-Token: <ui_csrf>` and `Content-Type: application/json`.

**Error envelope (FastAPI `detail`):** mapped via the shared helper from AND-078,
handling all three shapes:
```json
{ "detail": "Email already verified" }
{ "detail": [ { "loc": ["body","email"], "msg": "value is not a valid email", "type": "value_error" } ] }
{ "detail": { "code": "rate_limited", "retry_after": 30 } }
```

### DTOs (Moshi)
```kotlin
@JsonClass(generateAdapter = true)
data class EmailPrefsDto(val emails: List<EmailTargetDto>)

@JsonClass(generateAdapter = true)
data class EmailTargetDto(
    val id: String,
    val email: String,
    val verified: Boolean,
    @Json(name = "created_at") val createdAt: String? = null,
)

@JsonClass(generateAdapter = true)
data class EmailBeginRequest(val email: String)

@JsonClass(generateAdapter = true)
data class EmailBeginResponse(
    val id: String,
    val email: String,
    val status: String,
    @Json(name = "resend_available_in") val resendAvailableIn: Int? = null,
)

@JsonClass(generateAdapter = true)
data class EmailConfirmRequest(val id: String, val code: String)

@JsonClass(generateAdapter = true)
data class EmailConfirmResponse(val id: String, val email: String, val verified: Boolean)

@JsonClass(generateAdapter = true)
data class EmailRemoveRequest(val id: String)
```

Mappers `EmailTargetDto.toDomain()` / `toEntity()` live in core-data.

## 6. Data & State Management

- **Domain model:** `EmailTarget(id: String, email: String, verified: Boolean, createdAt: Instant?)`
  in core-model.
- **Room (core-data):** `EmailTargetEntity` (PK `id`, `email`, `verified`, `createdAt`,
  `updatedAtLocal`) with `EmailTargetDao` exposing `observeAll(): Flow<List<EmailTargetEntity>>`,
  `upsertAll(...)`, `deleteById(id)`, `replaceAll(...)`. Room is the single source of
  truth for reads, enabling stale/offline display per FR-7.
- **DataStore:** stores only the last successful `email_prefs` sync timestamp (for the
  stale banner) under key `alerts_email_last_sync_ms`. No PII beyond what Room already
  holds.
- **State derivation:** `isStale = (now - lastSync) > 5 min` OR last refresh failed while
  cache present. The pending-verification target is derived from `verified == false`; the
  code-entry section binds to `pendingTargetId`.
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
- **Error mapping** (shared `ApiErrorMapper` from AND-078) → `ApiResult.Error` subtypes:
  - `409 / "Email already verified"` → inline message on the row.
  - `422` validation array → field-level `emailError` / `codeError` (match on `loc`).
  - `400 / "invalid code"` or `"code expired"` → `codeError`, keep code field focused.
  - `429 / rate_limited` (or `detail.retry_after`) → set `resendCooldownUntilMs`, disable Resend.
  - `404` on confirm/remove (target gone) → toast + force refresh to reconcile.
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
  - `confirmEmail` success marks verified and upserts Room; `400 invalid code` → error.
  - `removeEmail` success deletes Room row; `404` → error and Room untouched.
  - Backoff: GET retries on 503 then succeeds; POSTs do **not** retry on 503.
  - 401 → refresh-once path retried (fake authenticator).
- **ViewModel tests** (Turbine + coroutines-test): state transitions for add → pending →
  verify → verified; resend cooldown disables control for 30s; remove confirm flow;
  stale banner when refresh fails with cache present; one-shot message consumed once.
- **DTO/JSON tests:** Moshi adapters round-trip all three `detail` error shapes via the
  shared mapper; `created_at` absent tolerated.
- **Compose UI tests** (`createAndroidComposeRule`): "Add" disabled until valid email;
  "Verify" disabled until code length met; remove dialog confirm path; error text shown via
  semantics; pending row reveals code field.
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

- **R1 — Field-name drift:** the web reference may name fields differently (e.g.,
  `email_targets` vs `emails`, `is_verified` vs `verified`). *Mitigation:* freeze DTOs only
  after diffing `/openapi.json`; isolate via `@Json(name=...)`.
- **R2 — Begin response shape:** unclear whether `begin` returns a target `id` or only
  `status`. If no `id` is returned, `confirm` must key off the email address instead.
  *Open question for backend owner.*
- **R3 — Resend semantics:** does re-calling `begin` for a pending address re-issue a code
  or error? Assumed re-issue; confirm with backend.
- **R4 — Flaky dev host:** intermittent 5xx/timeouts may make confirm appear to fail after
  the code was actually consumed. *Mitigation:* on ambiguous failure, force an
  `email_prefs` refresh before showing an error.
- **R5 — Rate limiting:** exact `429` body shape (`retry_after` vs `detail.retry_after`)
  unconfirmed; handle both.

## 14. Acceptance Criteria

- AC-1. A user can add an email target: entering a valid address and tapping "Add" calls
  `POST /ui/alerts/emails/begin` and the row appears as "pending verification".
- AC-2. A user can verify a target: entering the emailed code and tapping "Verify" calls
  `POST /ui/alerts/emails/confirm`; on `200` the row becomes "verified" and the list
  reflects it after refresh.
- AC-3. A user can remove a target: confirming the dialog calls
  `POST /ui/alerts/emails/remove`; on `200` the row disappears and Room is updated.
- AC-4. The list loads from `GET /ui/alerts/email_prefs` on entry and renders verified vs.
  pending state correctly.
- AC-5. Invalid email is rejected client-side (Add disabled); server `422` validation maps
  to inline `emailError`/`codeError`.
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
- AND-078 confirmed merged; open questions R2/R3/R5 resolved with backend or documented as
  follow-ups before release.
