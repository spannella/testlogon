---
id: AND-178
title: Tips on posts
milestone: M4
epic: E24
priority: P1
size: M
status: draft
depends_on: [AND-031]
blocks: []
---

# AND-178 — Tips on posts

## 1. Overview & Goal

Implement a **tip** action on a post in the TestLogon native Android app. From a
post (in the feed list or on the post detail screen), an authenticated user can
open a tip sheet, choose or enter a tip amount, optionally attach a short
message, confirm, and receive an explicit success confirmation. The deliverable
is the full vertical slice for tipping a single post: the network service and
DTOs, the repository mutation with idempotent submission, the ViewModel intent
state machine that drives the bottom sheet (amount entry -> submitting ->
confirmed | error), and the Compose tip UI wired into the existing `PostItem`
(AND-099) / post detail (AND-100) surfaces.

A tip is a **money-moving, non-idempotent** mutation. The spec therefore treats
correctness and double-submit protection as first-class: the submit control is
disabled while in-flight, an idempotency key is sent so a retried request cannot
charge twice, and the user only sees a "tip sent" confirmation after the server
returns a 2xx with a confirmed tip record. There is **no optimistic UI** for
tips (unlike likes in AND-173): money must not appear sent until the server
confirms.

This ticket owns only the tip action and its confirmation flow on posts. It does
not own post rendering (AND-099), the post detail container (AND-100), the
generic paywall/unlock flows (AND-101), nor message tips (AND-139) or chat tips
(AND-282), which are sibling tickets with their own endpoints. Wallet/balance
top-up, payment-method selection, and the underlying billing/session
prerequisites are provided by the dependency (AND-031) and are **stubbed/faked**
in this ticket's tests where not yet available.

## 2. Context & References

- **Stack:** Kotlin 2.0.21, Compose + Material 3, Hilt (KSP), Coroutines/Flow,
  Retrofit 2.11 + OkHttp 4.12 + Moshi 1.15, Room 2.6, DataStore, Paging 3.
  minSdk 24, compileSdk/targetSdk 35, JDK 17, AGP 8.7.3, Gradle 8.9.
- **Modules:** `feature-feed` (ViewModel + tip sheet Compose), `core-data`
  (repository), `core-network` (Retrofit service, `ApiResult`, FastAPI `detail`
  mapper), `core-model` (domain types), `core-ui` (tip button + reusable
  amount-input visuals), `core-testing` (fakes, Turbine, MockWebServer harness).
  Layering: `app -> feature-* -> core-*`.
- **Package base:** `com.testlogon.android` everywhere.
- **Dependency AND-031 (billing/session prerequisite):** AND-178's backlog dep
  is recorded as `AND-031`; in the tips backlog family this id is used as the
  billing/payment prerequisite (`AND-031(billing)`). This ticket consumes that
  prerequisite for an authenticated, billing-capable session and treats the
  payment instrument / balance as already established. Where the billing surface
  is not yet merged, its inputs are injected behind an interface and faked in
  tests.
- **Post surfaces AND-099 / AND-100:** provide
  `com.testlogon.android.core.ui.post.PostItem(...)` and the post detail screen.
  This ticket adds a tip affordance + `onTip` callback to those surfaces without
  regressing their existing render contract. The domain `Post` already exposes
  `id: String` and `creatorId: String`.
- **Auth:** cookie-based session; `ui_csrf` cookie echoed as `X-CSRF-Token`
  (required on this mutating request); persistent cookie jar; on 401 the shared
  network layer calls `POST /ui/session/refresh` once then retries. A tip is a
  mutating request and is **NOT** eligible for the idempotent-GET backoff-retry
  policy (AND-016).
- **Backend:** FastAPI + DynamoDB, dev host `http://18.222.237.167:8000`
  (plaintext HTTP, unreliable; ~20s call timeouts). OpenAPI at `/openapi.json`.
  Web reference for tip endpoints: `frontend/src/api/endpoints/*.ts`, shared
  types `frontend/src/api/types.ts`. The exact tip endpoint path/fields below
  MUST be validated against `/openapi.json` before implementation (OQ-1).

## 3. Functional Requirements

FR-1. Each rendered post exposes a **tip** affordance (icon + label) on the post
action row (feed item and detail). Tapping it opens a modal tip bottom sheet for
that post id.

FR-2. The tip sheet shows the creator/recipient context, a set of **preset
amounts** (e.g. configurable list, default `[1, 5, 10, 20, 50]` in the app's
minor-unit currency), and a **custom amount** field. Exactly one amount is
"selected" at a time; selecting a preset clears the custom field and vice versa.

FR-3. Amount validation: the selected amount MUST be a positive integer in the
allowed range `[minTip, maxTip]` (defaults `min = 1`, `max = 500`, confirmed via
config/OpenAPI). The **Send tip** button is disabled until a valid amount is
selected.

FR-4. An optional **message** field (max 200 chars) may accompany the tip. The
remaining character count is shown; exceeding the limit blocks submission.

FR-5. On **Send tip**, the button enters a non-cancelable submitting state
(button shows a spinner and is disabled; the amount/message inputs are disabled).
A single POST is sent carrying a client-generated **idempotency key**.

FR-6. On a 2xx confirmed response, the sheet transitions to a **confirmed**
state showing "Tip sent" with the confirmed amount (server-returned), then
auto-dismisses after a short delay or on user dismiss. A snackbar confirmation
is also surfaced on the host screen.

FR-7. On failure (validation rejected by server, insufficient balance, network,
timeout, non-2xx after a single auth refresh retry), the sheet returns to the
amount-entry state with an inline, actionable error message; **no tip is
recorded** and the user may retry. A retry reuses the **same idempotency key**
for the same intended tip so a previously-succeeded-but-lost response cannot
double-charge.

FR-8. Double-submit protection: while a tip request is in flight for a post,
further taps on **Send tip** are ignored; the action is **never optimistic** and
the confirmation never shows before the server confirms.

FR-9. Self-tipping and tipping when unauthenticated/billing-incapable are
prevented: the tip affordance is hidden/disabled when `post.creatorId ==
currentUserId`, and a billing-required state routes to the billing prerequisite
(AND-031) rather than silently failing.

FR-10. Dismissing the sheet (back, scrim tap, drag-down) while not submitting
cancels the flow with no side effects. Dismiss is blocked during the submitting
state to avoid ambiguity about whether the charge occurred.

## 4. Technical Design

### 4.1 Domain model (core-model)

```kotlin
/** Whole minor-currency-unit amount; currency carried separately. */
@JvmInline value class TipAmount(val value: Int) {
    init { require(value > 0) { "tip amount must be positive" } }
}

data class TipRequest(
    val postId: String,
    val amount: TipAmount,
    val message: String?,        // <= 200 chars, nullable
    val idempotencyKey: String,  // UUID v4, stable across retries of same intent
)

data class TipReceipt(
    val tipId: String,
    val postId: String,
    val amount: TipAmount,
    val currency: String,        // ISO-4217, e.g. "USD"
    val createdAt: Instant,
)

data class TipConfig(
    val presets: List<Int>,
    val minTip: Int,
    val maxTip: Int,
    val currency: String,
)
```

### 4.2 Network service (core-network)

```kotlin
interface TipApiService {
    @POST("ui/posts/{id}/tip")
    suspend fun tipPost(
        @Path("id") postId: String,
        @Header("Idempotency-Key") idempotencyKey: String,
        @Body body: TipRequestDto,
    ): Response<TipReceiptDto>
}

@JsonClass(generateAdapter = true)
data class TipRequestDto(
    @Json(name = "amount") val amount: Int,
    @Json(name = "message") val message: String?,
)

@JsonClass(generateAdapter = true)
data class TipReceiptDto(
    @Json(name = "tip_id") val tipId: String,
    @Json(name = "post_id") val postId: String,
    @Json(name = "amount") val amount: Int,
    @Json(name = "currency") val currency: String,
    @Json(name = "created_at") val createdAt: String, // ISO-8601 -> Instant adapter
)
```

The `X-CSRF-Token` header and cookie jar are applied by the shared OkHttp
interceptors; only the per-request `Idempotency-Key` is supplied here. The call
returns raw `Response<…>` so the repository can branch on 401/4xx/5xx and map to
`ApiResult<TipReceipt>`.

### 4.3 Repository (core-data)

```kotlin
interface TipRepository {
    suspend fun tip(request: TipRequest): ApiResult<TipReceipt>
    fun tipConfig(): TipConfig   // from remote config / sane defaults
}

@Singleton
class TipRepositoryImpl @Inject constructor(
    private val api: TipApiService,
    private val toDomain: TipReceiptMapper,
    @IoDispatcher private val io: CoroutineDispatcher,
) : TipRepository {

    override suspend fun tip(request: TipRequest): ApiResult<TipReceipt> =
        withContext(io) {
            val resp = api.tipPost(
                postId = request.postId,
                idempotencyKey = request.idempotencyKey,
                body = TipRequestDto(request.amount.value, request.message?.takeIf { it.isNotBlank() }),
            )
            when {
                resp.isSuccessful && resp.body() != null ->
                    ApiResult.Success(toDomain(resp.body()!!))
                else -> ApiResult.Error(resp.toApiError())
            }
        }
}
```

No retry, no caching of tips (a tip is a fire-and-confirm action, not list
state). Reconciliation of any visible "tips count"/"goal progress" is out of
scope here (owned by AND-282 tips summary).

### 4.4 ViewModel (feature-feed)

The tip sheet is driven by its own scoped state, separate from feed paging.

```kotlin
sealed interface TipSheetState {
    data object Hidden : TipSheetState
    data class Entry(
        val postId: String,
        val recipient: String,
        val config: TipConfig,
        val selectedAmount: Int?,     // null until chosen
        val customAmountText: String,
        val message: String,
        val canSend: Boolean,         // derived: valid amount && message within limit
        val error: String? = null,    // inline error after a failed attempt
    ) : TipSheetState
    data class Submitting(val postId: String, val amount: Int) : TipSheetState
    data class Confirmed(val receipt: TipReceipt) : TipSheetState
}

sealed interface TipEffect {
    data class ShowSnackbar(val message: String) : TipEffect
    data object NavigateToBilling : TipEffect      // FR-9 billing-required (AND-031)
}

@HiltViewModel
class TipViewModel @Inject constructor(
    private val tips: TipRepository,
    private val authState: AuthStateStore,         // currentUserId (AND-029)
    private val keys: IdempotencyKeyProvider,
) : ViewModel() {

    val state: StateFlow<TipSheetState>
    val effects: SharedFlow<TipEffect>

    fun open(postId: String, creatorId: String, recipient: String)  // FR-1, FR-9 self-tip guard
    fun selectPreset(amount: Int)                                   // FR-2
    fun setCustomAmount(text: String)                              // FR-2/FR-3
    fun setMessage(text: String)                                  // FR-4
    fun send()                                                   // FR-5/FR-8 (no-op if Submitting)
    fun dismiss()                                                // FR-10 (no-op if Submitting)
}
```

`send()` snapshots the current `Entry`, generates (or reuses) an idempotency key
held on the in-flight intent, transitions to `Submitting`, launches the
repository call in `viewModelScope`, and on completion transitions to
`Confirmed` (success) or back to `Entry(error = …)` (failure). A failure keeps
the same key on the cached intent so the next `send()` reuses it (FR-7). The key
is rotated only when the amount/message changes after a confirmed send or on a
fresh `open()`.

### 4.5 UI (core-ui + feature-feed)

`PostItem` (AND-099) and the detail action row (AND-100) gain a tip control:

```kotlin
@Composable
fun TipButton(onTip: () -> Unit, enabled: Boolean = true, modifier: Modifier = Modifier)
```

Icon `Icons.Outlined.Paid` (or `VolunteerActivism`) with a "Tip" label. The
sheet is a Material 3 `ModalBottomSheet`:

```kotlin
@Composable
fun TipSheet(state: TipSheetState, actions: TipSheetActions, onDismiss: () -> Unit)
```

Layout: recipient header, a horizontally laid-out preset chip row
(`FilterChip` per preset), a custom amount `OutlinedTextField`
(`KeyboardType.Number`, currency prefix), an optional message field with live
char counter, and a primary **Send tip** `Button` whose content swaps to a
`CircularProgressIndicator` in `Submitting`. The `Confirmed` state replaces the
body with a success check + "Tip sent · {amount} {currency}" and auto-dismisses
after ~1.5s. `ModalBottomSheet` dismissal is gated: in `Submitting` the
`sheetState` confirms `false` to drag-down and back is consumed.

## 5. API Contract

One mutating endpoint (path/fields to be confirmed against `/openapi.json`,
OQ-1):

**Tip a post**
```
POST /ui/posts/{id}/tip
Headers:
  X-CSRF-Token: <ui_csrf>
  Idempotency-Key: <uuid-v4>
  Cookie: <session>
  Content-Type: application/json
Body:
  { "amount": 10, "message": "great post!" }   // message optional/nullable

201 Created (or 200 OK)
{
  "tip_id": "tip_8f2c…",
  "post_id": "post_123",
  "amount": 10,
  "currency": "USD",
  "created_at": "2026-06-05T14:03:11Z"
}
```

Notable responses:
- `400 / 422 Unprocessable Entity` — invalid amount / out of range / bad body;
  FastAPI `detail` (`string | [{msg}] | {code,...}`) mapped to an inline error.
- `401 Unauthorized` — shared interceptor performs one `POST /ui/session/refresh`
  then a single retry; a second 401 surfaces as auth error -> `Entry(error)`.
- `402 Payment Required / 409` (insufficient balance / billing) — mapped to a
  "billing required" outcome -> `TipEffect.NavigateToBilling` (FR-9).
- `403` — self-tip or not permitted; surfaced as inline error (and the
  affordance should already be hidden for self, FR-9).
- `404` — post deleted/unavailable; inline error, no retry.
- `5xx` / timeout — generic retriable error; same idempotency key on retry.

Because the request carries an `Idempotency-Key`, a retry after an ambiguous
failure (timeout, lost response) MUST return the original receipt rather than
charging again; the client relies on this for safe FR-7 retries. If
`/openapi.json` shows a different path (e.g. a generic `POST /ui/tips` with a
`{post_id}` body) or omits idempotency support, the repository contract
(`tip(TipRequest)`) is unaffected but OQ-1/OQ-3 must be resolved before merge.

## 6. Data & State Management

- **No Room caching:** a tip is a transactional action; its receipt is not list
  state and is not persisted by this ticket. Any visible aggregate (tips total,
  goal progress) is owned by AND-282 and re-fetched there.
- **In-flight intent:** the idempotency key + snapshot live in the ViewModel for
  the lifetime of one tip attempt (survives recomposition via the ViewModel,
  scoped to the host screen). It is **not** persisted across process death; a
  process kill mid-submit drops the key (acceptable: server idempotency only
  matters across explicit retries, see OQ-3).
- **Source of truth:** the server `TipReceiptDto` is the only source for the
  confirmed amount shown in `Confirmed`; the client never claims success from
  local arithmetic.
- **TipConfig:** read from remote config/DataStore if available, otherwise
  hardcoded defaults (`presets [1,5,10,20,50]`, `min 1`, `max 500`, `currency`
  from session/locale). DataStore is read-only here; no new keys are written.
- **Sheet state** is a `StateFlow<TipSheetState>`; `Hidden` is the resting
  state. State is screen-scoped so an open sheet on the feed does not leak to
  detail and vice versa.

## 7. Error Handling & Resilience

- Tips are **not** auto-retried with backoff (idempotent-GET-only policy,
  AND-016). The only automatic retry is the single auth refresh-then-retry in
  the shared interceptor (AND-013).
- Timeouts: ~20s OkHttp call timeout (slow dev host). A timeout is an
  `ApiResult.Error` -> `Entry(error = "Couldn't send tip. Check your connection
  and try again.")`, with the same idempotency key preserved for a safe retry.
- Offline: request fails fast -> `Entry(error = "You're offline.")`; no deferred
  queue (a queued/offline tip is explicitly out of scope — money must not be
  silently deferred).
- Ambiguous success (response lost after server committed): the idempotency key
  guarantees the next retry returns the same receipt rather than double-charging;
  this is the primary resilience mechanism (FR-7).
- Submit-state lock (FR-5/FR-8): the `Submitting` state ignores further `send()`
  and blocks dismiss, eliminating client-side double submits independent of the
  network.
- Cancellation: `CancellationException` from ViewModel scope teardown is
  swallowed and never shown as an error; an unconfirmed tip simply ends in
  `Hidden`/`Entry` with no false success.

## 8. Security & Privacy

- The tip call rides the cookie session and MUST send the `X-CSRF-Token` header
  (mutating request); requests without it are rejected by the backend. CSRF/
  cookie wiring is owned by the network/auth tickets (AND-011/AND-012); this
  ticket only asserts the request flows through the shared authenticated OkHttp
  client.
- **Idempotency-Key** is a random UUID v4 with no PII; it is logged at DEBUG only
  (debug builds) for QA correlation, never in release.
- Money amounts and the optional message are user content: the message is **not**
  logged; amounts are logged only as DEBUG, never at INFO/WARN in release.
- Self-tip prevention (FR-9) is enforced client-side as UX, but the server is the
  authority (403 handled defensively).
- Dev backend is plaintext HTTP; the existing network security config already
  permits the dev host cleartext. No new cleartext exception is introduced.
- No new permissions, no new stored credentials, no payment-card data handled in
  this ticket (billing is AND-031's responsibility).

## 9. Accessibility & i18n

- `TipButton` exposes `Modifier.semantics { role = Role.Button;
  contentDescription = "Tip this post" }`; min touch target 48x48dp.
- The bottom sheet is a focus-trapping dialog; on open, focus moves to the sheet
  title; preset chips expose `selected` state via `semantics { selected = … }`;
  the Send button exposes a disabled state and, in `Submitting`, a
  `stateDescription = "Sending"` so TalkBack announces progress.
- `Confirmed` announces "Tip sent" via a `liveRegion = LiveRegionMode.Polite`.
- All strings ("Tip", "Send tip", "Add a message", presets are numeric,
  errors, "Tip sent", "%d characters left") live in `strings.xml`; the char
  counter uses `<plurals>`. No hardcoded UI strings.
- Amounts are formatted with `NumberFormat.getCurrencyInstance(locale)` using the
  config currency; the custom amount field accepts locale-appropriate digits.
- Color is never the sole signal (disabled Send button also has a state
  description; selected chips show a check). Contrast meets WCAG AA.

## 10. Telemetry & Logging

- Emit `post_tip_opened` `{ post_id, recipient_id, source: "feed"|"detail" }` on
  sheet open; `post_tip_submitted` `{ post_id, amount, has_message }` on send;
  and `post_tip_result` `{ post_id, success: Boolean, amount, error_code? }` on
  completion. Events route through the existing analytics abstraction (no raw
  vendor SDK here). Amounts may be included; the message body MUST NOT be.
- Logging via the shared `Logger`: INFO on confirmed tip (post_id + amount, no
  message), WARN on failure with the mapped error code (no body, no PII), DEBUG
  for state transitions (Entry -> Submitting -> Confirmed/Error) and the
  idempotency key in debug builds only. No request/response bodies logged in
  release.

## 11. Testing Strategy

Acceptance is "Tip submits + confirms", so tests are mandatory.

**Unit — repository (`core-data`, MockWebServer or fake `TipApiService`):**
- 201/200 with body -> `ApiResult.Success(TipReceipt)`, amount/currency mapped
  from server body (not the request).
- The `Idempotency-Key` header is sent and equals the request's key
  (RecordedRequest assertion).
- 422 -> `ApiResult.Error` with mapped `detail` message; no success emitted.
- 402/409 -> error classified as billing-required.
- timeout/5xx -> `ApiResult.Error`.

**Unit — ViewModel (Turbine over `state`/`effects`, `MainDispatcherRule`):**
- `open()` for a non-self post -> `Entry` with config presets; `open()` for
  `creatorId == currentUserId` -> sheet not shown / disabled (FR-9).
- amount validation: invalid/empty/out-of-range custom amount -> `canSend=false`;
  valid preset -> `canSend=true` (FR-3).
- message > 200 chars -> `canSend=false` (FR-4).
- `send()` -> `Submitting` then `Confirmed(receipt)` on success; snackbar effect
  emitted (FR-5/FR-6).
- double `send()` while `Submitting` -> only one repository call (FR-8),
  verified via fake call count.
- failure -> `Entry(error=…)`, no `Confirmed`; a subsequent `send()` reuses the
  **same idempotency key** (FR-7), verified via captured `TipRequest`.
- billing-required outcome -> `TipEffect.NavigateToBilling` (FR-9).
- `dismiss()` during `Submitting` -> ignored (FR-10); during `Entry` ->
  `Hidden`.

**Instrumented / Compose (`createAndroidComposeRule`):**
- `TipSheet` renders presets, custom field, message counter; Send disabled until
  valid amount.
- clicking Send shows progress + disables inputs (Submitting); Confirmed shows
  "Tip sent" and auto-dismisses.
- semantics: chip `selected`, Send `stateDescription`, `Confirmed` live region;
  touch targets >= 48dp.

Coverage target for new repository + ViewModel logic >= 85% lines.

## 12. Dependencies & Sequencing

- **Depends on AND-031** (recorded backlog dep; the billing/session prerequisite
  for the tips family). Provides the authenticated, billing-capable session this
  ticket assumes. Until merged, billing inputs (`AuthStateStore.currentUserId`,
  any balance/payment capability) are injected behind interfaces and faked in
  tests; the `NavigateToBilling` effect targets the billing route owned there.
- **Implicitly relies on** the cookie/CSRF auth + shared OkHttp client and the
  `ApiResult` / FastAPI `detail` mapper (AND-011/012/013/015/018). If not yet
  merged, `TipApiService` and interceptor wiring are stubbed behind the existing
  `core-network` client; no new auth code is written here.
- **Relies on** the post surfaces AND-099 (feed `PostItem`) and AND-100 (detail)
  to host the `TipButton`/`onTip` callback. The visual slot must be added
  without regressing their existing render tests.
- **Sibling, non-blocking:** AND-139 (message tips), AND-282 (chat tips & goals),
  AND-315 (tips config & private shows). They share the tip *concept* but use
  different endpoints/surfaces; any shared `TipSheet`/`TipAmount` primitives in
  `core-ui`/`core-model` introduced here SHOULD be reused by them.
- **Blocks:** none recorded.

## 13. Risks & Open Questions

- **OQ-1 (endpoint shape):** Confirm against `/openapi.json` and
  `frontend/src/api/endpoints/*.ts` the exact tip path (`POST /ui/posts/{id}/tip`
  vs a generic `POST /ui/tips` with a body `post_id`), the request field names
  (`amount` units — whole units vs cents), and the receipt field names
  (`tip_id`/`amount`/`currency`/`created_at`). Adapter + service paths depend on
  this; the repository contract does not.
- **OQ-2 (amount units & currency):** Is `amount` an integer minor unit (cents)
  or a whole-currency integer? Are presets/min/max server-driven (config
  endpoint) or client constants? This affects validation and display formatting.
- **OQ-3 (idempotency support):** Does the backend honor an `Idempotency-Key`
  header for `/tip`? If not, FR-7 safe-retry guarantees weaken to client-side
  submit locking only; product must accept the residual double-charge risk on an
  ambiguous timeout, or the retry affordance must be removed.
- **OQ-4 (balance/billing prerequisite):** Confirm how insufficient balance is
  signaled (402 vs 409 vs `detail.code`) and the billing route AND-031 exposes
  for `NavigateToBilling`.
- **Risk:** unreliable dev host makes manual QA of confirm/retry flaky; mitigate
  by treating MockWebServer-driven tests as the authoritative signal.
- **Risk:** without idempotency support, a slow dev host increasing timeout
  frequency raises double-charge exposure; mitigate with strict submit locking
  and conservative retry copy until OQ-3 resolves.

## 14. Acceptance Criteria

AC-1. A tip affordance appears on a post (feed + detail); tapping it opens a
modal tip sheet scoped to that post id (FR-1), verified by Compose test.

AC-2. Presets + custom amount are selectable with single-selection semantics;
the Send button is disabled until a valid in-range amount is chosen, and an
out-of-range/empty amount keeps it disabled (FR-2/FR-3), verified by test.

AC-3. An optional message up to 200 chars is accepted with a live counter;
exceeding the limit blocks submission (FR-4), verified by test.

AC-4. Tapping Send disables inputs and shows a non-cancelable submitting state;
exactly one POST is sent even on repeated taps, carrying an `Idempotency-Key`
header (FR-5/FR-8), verified by repository + ViewModel tests.

AC-5. On a 2xx confirmed response the sheet shows "Tip sent" with the
**server-returned** amount and a host snackbar appears, then auto-dismisses
(FR-6), verified by test.

AC-6. On failure the sheet returns to amount entry with an inline error and no
tip is recorded; a retry of the same intent reuses the same idempotency key
(FR-7), verified by test.

AC-7. A billing-required response routes to the billing prerequisite (AND-031)
and self-tip is prevented (FR-9), verified by test.

AC-8. Sheet a11y: focus trap, chip `selected` state, Send disabled/`Submitting`
state description, `Confirmed` polite live region, >= 48dp touch targets, all
strings localized with plurals (section 9), verified by Compose semantics test.

AC-9. All requests use `com.testlogon.android` package code, the shared
authenticated OkHttp client, and send `X-CSRF-Token`; no new cleartext config;
no message body or PII logged in release.

## 15. Definition of Done

- [ ] `TipRepository` + `Impl`, `TipApiService.tipPost`, `TipRequestDto`,
      `TipReceiptDto`/mapper, `TipAmount`/`TipRequest`/`TipReceipt`/`TipConfig`
      implemented in the correct modules under `com.testlogon.android`.
- [ ] `TipViewModel` with `TipSheetState` machine (Hidden -> Entry -> Submitting
      -> Confirmed | Entry(error)), submit locking, idempotency-key reuse on
      retry, and self-tip/billing guards implemented.
- [ ] `TipButton` added to `PostItem` (AND-099) and detail action row (AND-100)
      with no regression to existing render tests; `TipSheet` `ModalBottomSheet`
      with presets/custom/message/confirm per sections 4 and 9.
- [ ] Idempotency-Key header + `X-CSRF-Token` flow through the shared client;
      no optimistic success path exists.
- [ ] Unit (repository + MockWebServer), ViewModel (Turbine), and Compose tests
      for AC-1..AC-8 pass; new logic coverage >= 85%.
- [ ] Telemetry events `post_tip_opened` / `post_tip_submitted` /
      `post_tip_result` emitted; message body excluded from logs/telemetry.
- [ ] `/openapi.json` verified for endpoint path/fields, amount units, and
      idempotency support (OQ-1/OQ-2/OQ-3); deviations reflected in service +
      adapter before merge.
- [ ] Lint, detekt, ktlint, and `./gradlew :feature-feed:test :core-data:test`
      green on the `android-port` branch.
- [ ] PR reviewed; spec acceptance criteria checked off; no hardcoded strings or
      logged PII/message content.
