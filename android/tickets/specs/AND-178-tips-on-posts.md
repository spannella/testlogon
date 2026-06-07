---
id: AND-178
title: Tips on posts
milestone: M4
epic: E24
priority: P1
size: M
status: reviewed
reviewed_on: 2026-06-06
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
  types `frontend/src/api/types.ts`. **[Verified 2026-06-06]** The endpoint is
  `POST /posts/{post_id}/tip` (no `/ui` prefix) with request schema
  `PostTipRequest`; see §5 for the corrected contract.

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
    val amount: TipAmount,                 // minor units (cents)
    val paymentMethodId: String? = null,   // optional; default PM used server-side if null
    // [Corrected 2026-06-06] message is NOT supported by the backend tip schema
    // (PostTipRequest has no message field). Kept only as a client-side note;
    // if product still wants it, FR-4 must be cut or backed by a new endpoint (OQ-5).
    val message: String? = null,
    val idempotencyKey: String,  // UUID v4; see OQ-3 (server support unconfirmed)
)

// [Corrected 2026-06-06] The backend tip response is an empty body (OpenAPI) /
// { ok, tip_total_cents } (web client). It does NOT return tip_id, currency, or
// created_at. The receipt below carries only what is actually available; the
// confirmed amount shown to the user is the REQUEST amount echoed back locally
// (the server does not return a per-tip amount), and tipTotalCents is the new
// running post total when present.
data class TipReceipt(
    val postId: String,
    val amount: TipAmount,           // the amount that was submitted (cents)
    val tipTotalCents: Int?,         // server-reported running total, if returned
)

data class TipConfig(
    val presets: List<Int>,
    val minTip: Int,
    val maxTip: Int,
    val currency: String,
)
```

### 4.2 Network service (core-network)

**[Corrected 2026-06-06]** The path is `posts/{id}/tip` (no `ui/` prefix). The
backend request schema is `PostTipRequest` with fields `amount_cents` (int,
minimum 1), optional `currency` (default `"usd"`), and optional
`payment_method_id`. There is **no `message` field** in the backend schema — see
the §5 note and OQ-5. The backend does **not** document an `Idempotency-Key`
header (OQ-3); it is shown below as a client-side-only header pending OQ-3.

```kotlin
interface TipApiService {
    @POST("posts/{id}/tip")
    suspend fun tipPost(
        @Path("id") postId: String,
        // NOTE (OQ-3): Idempotency-Key is NOT in the backend OpenAPI; keep only
        // if the server is confirmed to honor it, else drop and rely on submit lock.
        @Header("Idempotency-Key") idempotencyKey: String,
        @Body body: TipRequestDto,
    ): Response<TipResultDto>
}

@JsonClass(generateAdapter = true)
data class TipRequestDto(
    @Json(name = "amount_cents") val amountCents: Int,        // minor units, >= 1
    @Json(name = "currency") val currency: String? = "usd",   // default usd
    @Json(name = "payment_method_id") val paymentMethodId: String? = null,
)

// Response: OpenAPI documents 200 with an EMPTY body schema ({}). The web client
// (newsfeed.ts: tipPostDirect) types it as { ok, tip_total_cents }. Both fields
// are therefore nullable/optional; do NOT assume a tip_id/created_at receipt.
@JsonClass(generateAdapter = true)
data class TipResultDto(
    @Json(name = "ok") val ok: Boolean? = null,
    @Json(name = "tip_total_cents") val tipTotalCents: Int? = null,
)
```

The `X-CSRF-Token` header (echoed from the `ui_csrf` cookie) and cookie jar are
applied by the shared OkHttp interceptors (verified in web `src/api/client.ts`).
The call returns raw `Response<…>` so the repository can branch on 401/4xx/5xx
and map to `ApiResult<TipReceipt>`.

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
                idempotencyKey = request.idempotencyKey,  // see OQ-3
                // [Corrected] body carries amount_cents + optional payment_method_id;
                // no message field exists in the backend schema (OQ-5).
                body = TipRequestDto(
                    amountCents = request.amount.value,
                    paymentMethodId = request.paymentMethodId,
                ),
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

One mutating endpoint. **[Verified/Corrected 2026-06-06 against
`POST /posts/{post_id}/tip` (op `tip_post_posts__post_id__tip_post`), schema
`PostTipRequest`, and web `src/api/endpoints/newsfeed.ts: tipPostDirect`.]**

**Tip a post**
```
POST /posts/{post_id}/tip          # CORRECTED: no /ui prefix, path param is post_id
Headers:
  X-CSRF-Token: <ui_csrf>          # verified: client.ts echoes ui_csrf cookie
  Cookie: <session>                # credentials: include
  Content-Type: application/json
  # Idempotency-Key: NOT in the OpenAPI contract (OQ-3) — do not assume support
Body (PostTipRequest):
  {
    "amount_cents": 1000,                 // CORRECTED: integer minor units, minimum 1
    "currency": "usd",                    // optional, default "usd"
    "payment_method_id": "pm_..."         // optional; default PM used if omitted
  }

200 OK
{}                                        # OpenAPI: empty body schema ({})
# Web client (tipPostDirect) types the body as:
#   { "ok": true, "tip_total_cents": 12345 }
# CORRECTED: there is NO tip_id / currency / created_at receipt.
```

Notable responses:
- `422 Unprocessable Entity` — invalid/missing `amount_cents` (e.g. < 1) or bad
  body; FastAPI `HTTPValidationError` (`detail: [{loc, msg, type}]`) mapped to an
  inline error. (Verified: only `422` and `200` are documented for this op.)
- `401 Unauthorized` — shared interceptor performs one `POST /ui/session/refresh`
  then a single retry; a second 401 surfaces as auth error -> `Entry(error)`.
  (Verified: `client.ts` refresh-once-then-retry, refresh path `/ui/session/refresh`.)
- `402 / 409` (insufficient balance / billing) — **assumption (OQ-4):** not in the
  documented responses for this op; if returned, map to a "billing required"
  outcome -> `TipEffect.NavigateToBilling` (FR-9). Treat as best-effort until OQ-4.
- `403` — self-tip or not permitted; the web client surfaces a toast. Map to inline
  error; the affordance should already be hidden for self (FR-9). (Assumption: not
  documented for this op.)
- `404` — post deleted/unavailable; inline error, no retry. (Assumption.)
- `5xx` / timeout — generic retriable error.

**[Corrected]** The backend does not document `Idempotency-Key` support (OQ-3),
so safe-retry against ambiguous timeouts cannot be guaranteed at the contract
level; until OQ-3 resolves, the only firm double-submit protection is the
client-side `Submitting` lock (FR-8). The repository contract (`tip(TipRequest)`)
is unaffected by these corrections.

## 6. Data & State Management

- **No Room caching:** a tip is a transactional action; its receipt is not list
  state and is not persisted by this ticket. Any visible aggregate (tips total,
  goal progress) is owned by AND-282 and re-fetched there.
- **In-flight intent:** the idempotency key + snapshot live in the ViewModel for
  the lifetime of one tip attempt (survives recomposition via the ViewModel,
  scoped to the host screen). It is **not** persisted across process death; a
  process kill mid-submit drops the key (acceptable: server idempotency only
  matters across explicit retries, see OQ-3).
- **Source of truth:** success is gated on a 2xx from the server; the client
  never claims success from local arithmetic. **[Corrected]** Because the tip
  response does not return a per-tip amount (empty body / `{ ok, tip_total_cents }`),
  the `Confirmed` amount is the **submitted** `amount_cents` echoed locally, and
  `tip_total_cents` (when present) is the new running post total, not the tip.
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

- **OQ-1 (endpoint shape) — RESOLVED 2026-06-06:** Path is `POST /posts/{post_id}/tip`
  (no `/ui` prefix), request schema `PostTipRequest`
  = `{ amount_cents (int, min 1), currency? (default "usd"), payment_method_id? }`.
  Response is an empty body in OpenAPI; web client types it `{ ok, tip_total_cents }`.
  There is **no `tip_id`/`created_at`/per-tip amount** in the response. Service +
  adapters in §4.2 corrected accordingly.
- **OQ-2 (amount units & currency) — RESOLVED:** `amount_cents` is an integer
  **minor unit (cents)**, minimum 1; `currency` defaults to `"usd"`. The web app's
  presets are `[100, 500, 1000]` cents (`TipDialog.tsx`). No tip-config endpoint
  exists for posts (the `/broadcast/.../tips/config` endpoints are broadcast-only),
  so post presets/min/max are **client constants** here — recommend aligning the
  app defaults with the web `[100, 500, 1000]` cents rather than `[1,5,10,20,50]`.
- **OQ-3 (idempotency support):** The OpenAPI contract for
  `POST /posts/{post_id}/tip` does **not** document an `Idempotency-Key` header,
  and the web client does not send one. **Current evidence says it is NOT
  supported.** Therefore FR-7's safe-retry guarantee is unproven: until confirmed
  with the backend team, rely on the client-side submit lock (FR-8) only, and
  product must accept the residual double-charge risk on an ambiguous timeout (or
  the auto-retry affordance must be removed).
- **OQ-5 (message field) — NEW:** FR-4 specifies an optional 200-char message, but
  the backend `PostTipRequest` schema has **no message field** (only
  `amount_cents`, `currency`, `payment_method_id`); the web `TipDialog` also has no
  message input. FR-4 as written is **unimplementable against the current API**.
  Either cut FR-4 for posts or add a backend field before building it. The §4 types
  retain `message` only as a client-local placeholder and never send it.
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

## 16. Citations & Assumption Audit

Each key technical claim, its verdict, and the exact source pointer.

1. **Tip endpoint is `POST /posts/{post_id}/tip`** (no `/ui` prefix). VERDICT:
   Corrected (spec said `POST /ui/posts/{id}/tip`). SOURCE: OpenAPI
   `POST /posts/{post_id}/tip` (op `tip_post_posts__post_id__tip_post`);
   `src/api/endpoints/newsfeed.ts: tipPostDirect`.
2. **Request schema is `PostTipRequest` = `{ amount_cents (int, min 1),
   currency? (default "usd"), payment_method_id? }`.** VERDICT: Corrected (spec
   said body `{ amount, message }`). SOURCE: OpenAPI
   `components.schemas.PostTipRequest`; `src/api/types.ts: TipReq`;
   `src/pages/feed/TipDialog.tsx` (sends `amount_cents` + `payment_method_id`).
3. **Amount is an integer minor unit (cents), minimum 1.** VERDICT: Verified
   (spec's intent was right but field name was `amount`; now `amount_cents`).
   SOURCE: OpenAPI `PostTipRequest.amount_cents.minimum = 1`;
   `TipDialog.tsx` `PRESETS = [100, 500, 1000] // cents`.
4. **No `message` field exists for post tips.** VERDICT: Corrected (FR-4
   unimplementable as written — see OQ-5). SOURCE: OpenAPI `PostTipRequest`
   (only 3 fields); `src/api/types.ts: TipReq`; `TipDialog.tsx` (no message input).
5. **Response has no `tip_id`/`currency`/`created_at` receipt.** VERDICT:
   Corrected (spec defined a `TipReceiptDto` with those fields). SOURCE: OpenAPI
   op response `200: { "schema": {} }` (empty); web typed
   `{ ok: boolean; tip_total_cents: number }` in `newsfeed.ts: tipPostDirect`.
6. **`payment_method_id` is an accepted (optional) request field; default PM is
   used server-side if omitted.** VERDICT: Verified (spec omitted it entirely).
   SOURCE: OpenAPI `PostTipRequest.payment_method_id`; `TipDialog.tsx`
   (`effectivePm` -> body `payment_method_id`).
7. **Mutating tip request must carry `X-CSRF-Token` echoed from the `ui_csrf`
   cookie, over a credentialed (cookie) session.** VERDICT: Verified. SOURCE:
   `src/api/client.ts:168-170` (`getCookie("ui_csrf")` -> `X-CSRF-Token`),
   `client.ts:183` (`credentials: "include"`).
8. **On 401, the shared layer refreshes once via `POST /ui/session/refresh` then
   retries the original request a single time.** VERDICT: Verified. SOURCE:
   `src/api/client.ts:194-237` (single retry); `client.ts:122` /
   `src/api/endpoints/auth.ts:59-60` (`/ui/session/refresh`).
9. **Only `200` and `422` (HTTPValidationError) are documented responses for the
   tip op.** VERDICT: Verified. SOURCE: OpenAPI op
   `resp=200:;422:HTTPValidationError`; `components.schemas.HTTPValidationError`
   (`detail: [{loc,msg,type}]`).
10. **`Idempotency-Key` header support for tips.** VERDICT: Unverified-assumption
    (evidence leans NO). SOURCE: header absent from OpenAPI op parameters and
    from `newsfeed.ts: tipPostDirect`. See OQ-3.
11. **`402`/`409` billing / insufficient-balance signaling and a
    `NavigateToBilling` route.** VERDICT: Unverified-assumption. SOURCE: not in
    the documented tip-op responses; AND-031 billing route not present in this
    reference. See OQ-4.
12. **`403` self-tip / not-permitted handling.** VERDICT: Unverified-assumption
    (not documented for this op; web shows a generic toast). SOURCE: OpenAPI op
    (no 403 documented); `TipDialog.tsx onError` -> toast.
13. **Web preset amounts are `[100, 500, 1000]` cents (vs the spec's
    `[1,5,10,20,50]`).** VERDICT: Corrected/Verified. SOURCE:
    `src/pages/feed/TipDialog.tsx:19`.
14. **No tip-config endpoint exists for posts (broadcast tips config is
    broadcast-only).** VERDICT: Verified. SOURCE: OpenAPI only exposes
    `PATCH /broadcast/sessions/{session_id}/tips/config` and
    `GET .../tips/summary`; no `/posts` tip-config op. So §6 `TipConfig` is
    client-side constants.
15. **Compose Material 3 `ModalBottomSheet` and dismissal-gating via
    `confirmValueChange`/`sheetState` are appropriate for the sheet.** VERDICT:
    Unverified-assumption (framework choice). SOURCE: framework ref —
    developer.android.com Material 3 `ModalBottomSheet` API. Not verifiable from
    the backend/web sources.
16. **`Icons.Outlined.Paid` / `VolunteerActivism` for the tip affordance.**
    VERDICT: Unverified-assumption (UI/icon choice). SOURCE: framework ref —
    Material Icons. The web uses `DollarSign` (`TipDialog.tsx:3`), so a money/
    dollar glyph is the closest reference.

### Corrections made

- §2/§4.2/§5: endpoint path `POST /ui/posts/{id}/tip` -> `POST /posts/{post_id}/tip`.
- §4.1/§4.2/§4.3/§5/§6: request body `{ amount, message }` ->
  `PostTipRequest { amount_cents, currency?, payment_method_id? }`; field
  `amount` -> `amount_cents`; added `payment_method_id`.
- §4.1/§4.2/§5/§6: response receipt `TipReceiptDto { tip_id, post_id, amount,
  currency, created_at }` -> empty body / `{ ok, tip_total_cents }`; renamed DTO
  to `TipResultDto`; `TipReceipt` reduced to `{ postId, amount, tipTotalCents? }`
  with the confirmed amount being the locally-echoed submitted amount.
- §4 domain: added `paymentMethodId` to `TipRequest`; demoted `message` to a
  non-transmitted client-local placeholder (no backend field).
- §13: OQ-1 and OQ-2 marked RESOLVED with the verified contract; OQ-3 updated to
  reflect that idempotency is not in the contract; added OQ-5 (no message field).
- §5 response list: reclassified 402/409/403/404 as undocumented assumptions for
  this op rather than asserted contract behavior.

### Open assumptions

- **Idempotency-Key (OQ-3):** not in the OpenAPI op or web client; cannot confirm
  the server dedupes retries. Why unverifiable: no header in any authoritative
  source and no backend access here.
- **Billing/insufficient-balance status codes & route (OQ-4):** only 200/422 are
  documented; 402/409 mapping and the AND-031 `NavigateToBilling` target are not
  present in these references.
- **403 self-tip semantics:** not documented; client self-tip guard (FR-9) is UX
  only, server authority unverified.
- **`message` field for posts (OQ-5):** absent from the backend schema; FR-4 is
  unimplementable against the current API and is flagged for product.
- **Framework/UI choices** (`ModalBottomSheet`, icon, plurals, telemetry event
  names): design decisions, not derivable from backend/web sources.
- **Response richness mismatch:** OpenAPI documents an empty body while the web
  client reads `{ ok, tip_total_cents }`; the Android DTO treats both as optional.
  The true runtime shape cannot be confirmed without hitting the live backend.

## 17. Test Plan

Test IDs `TC-AND-178-NN`. Targets: JVM = JVM/Robolectric unit (no device);
EMU = headless emulator AVD `test35` (x86_64, API 35); DEV = physical Samsung
Galaxy A15 5G (SM-A156U, API 34, arm64-v8a) on the build host. Most cases are
JVM/MockWebServer or Compose-UI and do **not** require hardware; the physical
device is reserved for the real-network flaky-dev-host path.

- **TC-AND-178-01 — Happy-path tip submit + confirm (repository contract).**
  Type: contract/MockWebServer (JVM). Target: JVM. Preconditions: MockWebServer
  enqueues `200` with body `{ "ok": true, "tip_total_cents": 12345 }`.
  Steps: call `TipRepository.tip(TipRequest(postId="post_123",
  amount=TipAmount(1000), paymentMethodId="pm_1", idempotencyKey=K))`. Expected:
  recorded request is `POST /posts/post_123/tip`, JSON body has
  `amount_cents=1000` and `payment_method_id="pm_1"` (no `message` key); result is
  `ApiResult.Success` with `amount=1000 cents` and `tipTotalCents=12345`.
  Traces: AC-4, AC-5, AC-9.

- **TC-AND-178-02 — Empty-body 200 still succeeds.** Type: contract/MockWebServer
  (JVM). Target: JVM. Preconditions: MockWebServer enqueues `200` with body `{}`.
  Steps: call `tip(...)`. Expected: `ApiResult.Success`; `tipTotalCents == null`;
  confirmed amount equals the **submitted** amount (1000 cents) echoed locally.
  Traces: AC-5.

- **TC-AND-178-03 — 422 validation error maps to inline error.** Type:
  contract/MockWebServer (JVM). Target: JVM. Preconditions: enqueue `422` with
  `{"detail":[{"loc":["body","amount_cents"],"msg":"ensure this value is greater
  than or equal to 1","type":"value_error"}]}`. Steps: call `tip(...)` with an
  out-of-range amount. Expected: `ApiResult.Error` carrying the mapped `detail`
  message; no success. Traces: AC-2, AC-6.

- **TC-AND-178-04 — CSRF header present on mutating tip.** Type:
  contract/MockWebServer (JVM). Target: JVM. Preconditions: cookie jar seeded with
  a `ui_csrf` cookie; enqueue `200`. Steps: call `tip(...)`. Expected: recorded
  request contains header `X-CSRF-Token` equal to the `ui_csrf` value and the
  session cookie. Traces: AC-9.

- **TC-AND-178-05 — 401 triggers single refresh-then-retry.** Type:
  contract/MockWebServer (JVM). Target: JVM. Preconditions: enqueue `401`, then a
  `200` for `POST /ui/session/refresh`, then `200` for the retried tip; auth state
  = authenticated. Steps: call `tip(...)`. Expected: exactly one refresh call to
  `/ui/session/refresh` and exactly one retry of the tip; final `ApiResult.Success`.
  Second-401 variant: enqueue `401`,`refresh 200`,`401` -> `ApiResult.Error` (auth),
  no further retry. Traces: AC-6, AC-9.

- **TC-AND-178-06 — Idempotency-Key behavior (OQ-3 guard).** Type:
  contract/MockWebServer (JVM). Target: JVM. Preconditions: enqueue `200`. Steps:
  call `tip(...)` with key K. Expected: IF the service is built to send
  `Idempotency-Key`, the recorded request carries header `Idempotency-Key == K`;
  a repository-level retry of the same intent reuses K. NOTE: header support is an
  unverified backend assumption (OQ-3) — if dropped, this case asserts the header
  is absent and relies on the submit lock (TC-08) instead. Traces: AC-4, AC-6.

- **TC-AND-178-07 — Timeout/offline maps to retriable error (slow dev host).**
  Type: contract/MockWebServer (JVM) for timeout simulation; the real-network
  variant is integration. Target: JVM for the simulated case;
  **DEV (physical device) MUST run the real-network variant** against the flaky
  dev host `http://18.222.237.167:8000` to exercise the ~20s call timeout and
  cleartext path on real radio/Wi-Fi. Preconditions (JVM): MockWebServer with
  `SocketPolicy.NO_RESPONSE` / throttled body; (DEV): device online to dev host.
  Steps: call `tip(...)`. Expected: `ApiResult.Error` (timeout/offline class), no
  success, same idempotency key preserved for a manual retry; no crash on
  cleartext HTTP. Traces: AC-6.

- **TC-AND-178-08 — ViewModel submit lock: double `send()` -> one call.** Type:
  unit (Turbine, `MainDispatcherRule`) (JVM). Target: JVM. Preconditions: fake
  `TipRepository` with a suspending/delayed `tip`. Steps: `open()` non-self post,
  select preset, call `send()` twice rapidly. Expected: state goes
  `Entry -> Submitting`; the fake repository is invoked exactly once; second
  `send()` is a no-op while `Submitting`. Traces: AC-4.

- **TC-AND-178-09 — ViewModel happy path: Submitting -> Confirmed + snackbar.**
  Type: unit (Turbine) (JVM). Target: JVM. Preconditions: fake repo returns
  `Success`. Steps: `open()`, select preset 1000, `send()`. Expected: emissions
  `Entry -> Submitting(amount=1000) -> Confirmed`; a `TipEffect.ShowSnackbar`
  effect is emitted; confirmed amount = submitted amount. Traces: AC-5.

- **TC-AND-178-10 — ViewModel failure path + idempotency-key reuse.** Type: unit
  (Turbine) (JVM). Target: JVM. Preconditions: fake repo returns `Error` first,
  capturing the `TipRequest`. Steps: `send()` (fails) then `send()` again.
  Expected: state returns to `Entry(error=…)`, no `Confirmed`; the captured
  `idempotencyKey` is identical across both attempts; key rotates only on a fresh
  `open()` or amount change. Traces: AC-6.

- **TC-AND-178-11 — Validation + self-tip + billing-required guards.** Type: unit
  (Turbine) (JVM). Target: JVM. Preconditions: `AuthStateStore.currentUserId` set;
  fake repo. Steps: (a) `open()` where `creatorId == currentUserId` -> sheet not
  shown/disabled; (b) custom amount empty / `< minTip` / `> maxTip` -> `canSend=false`,
  valid preset -> `canSend=true`; (c) fake repo returns the billing-required
  outcome -> `TipEffect.NavigateToBilling`. NOTE: (c) depends on OQ-4 status-code
  mapping. Traces: AC-2, AC-7.

- **TC-AND-178-12 — Compose: sheet renders + Send gating + submit/confirm UI.**
  Type: Compose-UI (`createAndroidComposeRule`). Target: EMU (`test35`).
  Preconditions: fake ViewModel feeding `Entry`/`Submitting`/`Confirmed`. Steps:
  render `TipSheet`; assert preset chips, custom field, single-selection; Send
  disabled until a valid amount; on Send show `CircularProgressIndicator` and
  disabled inputs; `Confirmed` shows "Tip sent" and auto-dismisses (~1.5s).
  Expected: all assertions pass; dismiss is blocked during `Submitting`.
  Traces: AC-1, AC-2, AC-4, AC-5.

- **TC-AND-178-13 — Compose accessibility semantics.** Type: Compose-UI
  (semantics). Target: EMU (`test35`). Preconditions: rendered `TipSheet` +
  `TipButton`. Steps: assert `TipButton` role=Button with content description and
  >= 48dp touch target; preset chips expose `selected`; Send exposes disabled and
  `stateDescription="Sending"` in `Submitting`; `Confirmed` uses a polite live
  region; char-counter strings come from `<plurals>`. Expected: all semantics
  present. Traces: AC-8.

- **TC-AND-178-14 — Release build: no PII/message/body logging, no new cleartext
  config.** Type: instrumented/e2e + manual review. Target: DEV (physical device,
  to confirm real release behavior over the network) plus a JVM Logcat/asserting
  check. Preconditions: release-type build/logger config. Steps: perform a tip and
  capture logs; inspect network security config. Expected: no message content, no
  request/response bodies, and no raw amounts at INFO/WARN in release; the
  idempotency key (if used) appears only in debug; no new cleartext-permitted host
  beyond the existing dev-host exception. Traces: AC-9.

### Coverage matrix

| AC | Covered by |
|----|------------|
| AC-1 | TC-12 |
| AC-2 | TC-03, TC-11, TC-12 |
| AC-3 | (FR-4/message is unimplementable per OQ-5 — no API field; covered only if FR-4 is retained as client-local: TC-12 char counter. Flag for product.) |
| AC-4 | TC-01, TC-06, TC-08, TC-12 |
| AC-5 | TC-01, TC-02, TC-09, TC-12 |
| AC-6 | TC-03, TC-05, TC-06, TC-07, TC-10 |
| AC-7 | TC-11 |
| AC-8 | TC-13 |
| AC-9 | TC-01, TC-04, TC-05, TC-14 |
