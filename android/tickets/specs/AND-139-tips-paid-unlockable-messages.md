---
id: AND-139
title: Tips & paid/unlockable messages
milestone: M3
epic: E19
priority: P1
size: L
status: draft
depends_on: [AND-124, AND-031]
blocks: []
---

# AND-139 — Tips & paid/unlockable messages

## 1. Overview & Goal

Add monetized-message support to the messaging surface: **paid/unlockable messages** (a message whose body/media is gated behind a price and only revealed after purchase), **tipping** an individual message, and the **lottery unlock** variant (an unlock whose price is resolved by a server-side lottery/draw rather than a fixed amount). The defining requirement is a clean separation of two concerns: (1) the **locked-message UI** — rendering a gated message as a teaser with price, lock affordance, and post-unlock reveal — and (2) the **purchase flows** that drive `POST /messages/{id}/tip` and `POST /messages/{id}/unlock`, with the underlying *payment authorization* delegated to the billing dependency (AND-031), which in this ticket is **stubbed behind an interface and fully tested** rather than wired to a live payment processor.

Goal, restated as a testable outcome: a user viewing a locked message sees a teaser with the price and an "Unlock" affordance; tapping it runs the billing-authorize → server-unlock sequence and, on success, reconciles the row in place to its revealed (unlocked) content. Separately, a user can tip any eligible message via a tip sheet (preset/custom amounts), driving `POST /messages/{id}/tip`. The lottery unlock resolves its price from the server before charging. All flows degrade safely on payment failure, server failure, and offline. The deliverables are the locked-message Composables, the tip sheet, the `MonetizationViewModel` action surface, the repository + DTOs for the two endpoints, and the `BillingAuthorizer` seam that AND-031 will later satisfy.

## 2. Context & References

- **Module:** `feature-messaging` (Gradle module `:feature:messaging`), package `com.testlogon.android.feature.messaging.monetization`. The locked-message item and tip sheet extend the Thread (message list) screen delivered by AND-123 and the send path from AND-124; this ticket adds the monetization read/teaser rendering and the two write flows.
- **Layering:** `:feature:messaging` -> `:core:network` (Retrofit service, `ApiResult<T>`, `apiCall { }`, `DetailErrorAdapter`), `:core:model` (DTO/domain + mappers), `:core:data` (Room cache + repository, analytics facade), `:core:ui` (Compose components, theme, state composables). No backward dependencies. The `BillingAuthorizer` interface is declared in `:core:model` (a pure contract) and implemented by the billing module under AND-031; a `FakeBillingAuthorizer` for this ticket lives in `:core:testing`.
- **Backend:** FastAPI + DynamoDB. Dev host `http://18.222.237.167:8000` (plaintext HTTP, unreliable; ~20s timeouts). OpenAPI at `/openapi.json`. Cookie-based auth: session cookies + `ui_csrf` cookie echoed as `X-CSRF-Token`; on `401` the OkHttp authenticator calls `POST /ui/session/refresh` once and retries. Persistent cookie jar required (core-network).
- **Web reference:** `frontend/src/api/endpoints/messages.ts` (the `tipMessage` / `unlockMessage` calls and the lottery variant) and `frontend/src/api/types.ts` (`Message`, `MessageMonetization`, `TipRequest`, `UnlockRequest`, `UnlockResult`). The Android DTOs here must mirror those shapes; confirm exact field names against `/openapi.json` before implementation.
- **Dependency AND-124** supplies the message domain model (`Message`), the Room `MessageEntity`/`MessageDao`, the thread render loop, `ApiResult`, and the `apiCall { }`/`DetailErrorAdapter` plumbing. AND-139 extends `Message` with monetization fields and adds the unlock/tip write paths.
- **Dependency AND-031 (billing)** owns real payment authorization (payment-method selection, processor charge, receipt). This ticket consumes it only through `BillingAuthorizer` and ships with a stub/fake so the unlock/tip flows are independently testable.
- **Stack:** Kotlin 2.0.21, Compose + Material 3, Hilt (KSP), Coroutines/Flow, Retrofit 2.11 + OkHttp 4.12 + Moshi 1.15, Room 2.6, Paging 3. minSdk 24 / compileSdk/targetSdk 35, JDK 17.

## 3. Functional Requirements

FR-1. A message may carry monetization metadata. The thread item Composable (from AND-124) branches on `Message.monetization`: a `null` monetization renders a normal message; a non-null one with `unlocked == false` renders the **locked teaser**; `unlocked == true` renders the revealed content.

FR-2. The **locked teaser** shows: a lock glyph, an optional preview (blurred/placeholder image or truncated caption supplied by the server as `teaser`), the formatted **price** (currency-aware), the unlock type label (Fixed price vs **Lottery**), and a primary **Unlock** button. It never renders the gated `body`/media until unlock succeeds.

FR-3. Tapping **Unlock** on a fixed-price message runs: `BillingAuthorizer.authorize(amount, currency)` -> on success `POST /messages/{id}/unlock` with the returned `payment_token` -> on success, reconcile the row to `unlocked = true` with the server-returned revealed `body`/media. The button shows an in-progress state and is disabled during the flow.

FR-4. **Lottery unlock**: when `monetization.type == LOTTERY`, the displayed price is a *range or "draw"* hint, not a final number. Tapping Unlock first calls `POST /messages/{id}/unlock` (or the lottery resolve step) to obtain the **resolved price**, presents a confirmation ("You drew $X — confirm?") , then runs `BillingAuthorizer.authorize(resolvedAmount)` and finalizes the unlock. The user must explicitly confirm the drawn amount before any charge. (Exact endpoint shape is OQ-2.)

FR-5. **Tip**: any tip-eligible message exposes a tip affordance (overflow action / long-press). Tapping opens a **tip sheet** (Material 3 `ModalBottomSheet`) with preset amounts (e.g., 1/5/10/20) and a custom-amount field, plus an optional short note (max 200 chars). Confirming runs `BillingAuthorizer.authorize(amount)` -> `POST /messages/{id}/tip` -> on success, a confirmation (snackbar) and optional inline "tipped" indicator on the row.

FR-6. Amount validation: tip/unlock amounts are positive, within `[min, max]` bounds (defaults min = smallest currency unit, max = 500.00 of the message currency unless the server supplies bounds), parsed locale-aware, and never sent as a free-form string. Custom amount under min / over max is blocked with an inline error; the confirm button is disabled.

FR-7. Idempotency: each unlock/tip carries a client-generated `client_id` (UUID). A repeated `client_id` for the same message is treated by the server as the same logical transaction (no double charge). Manual retry after an *uncertain* failure reuses the same `client_id`.

FR-8. The flows are **non-destructive** on failure: a failed unlock leaves the message locked and shows a retryable error; a failed tip leaves the sheet open with the amount preserved and a retry affordance. Payment-declined and server errors are distinguished in the message shown.

FR-9. Already-unlocked messages (server says `unlocked == true`, e.g., re-fetched after a prior purchase) render revealed with no purchase prompt. Unlock state persists across app restarts (sourced from the message cache / server, not from local-only flags).

FR-10. The user's **own** messages (authored by the current `GET /ui/me` user) are not offered tip/unlock affordances against themselves; tip is offered only on other users' eligible messages, and a creator's own paid message renders revealed.

## 4. Technical Design

### 4.1 Domain model additions (`:core:model`)

`Message` (from AND-124) gains an optional monetization block:

```kotlin
enum class UnlockType { FIXED, LOTTERY }

data class MessageMonetization(
    val type: UnlockType,
    val unlocked: Boolean,
    val priceMinor: Long?,        // price in minor units (cents); null for unresolved lottery
    val currency: String,         // ISO-4217, e.g. "USD"
    val teaser: String?,          // safe preview text; never the gated body
    val teaserImageUrl: String?,  // blurred/placeholder; never the gated media
    val tipEligible: Boolean,
)

data class Message(
    val id: String?,
    val clientId: String,
    val conversationId: String,
    val authorId: String,
    val body: String,                 // empty/placeholder while locked
    val createdAt: Instant,
    val sendStatus: SendStatus = SendStatus.SENT,
    val monetization: MessageMonetization? = null,   // null = ordinary message
)
```

### 4.2 Billing seam (`:core:model` contract; AND-031 supplies real impl)

```kotlin
data class BillingAuthorization(val paymentToken: String, val authorizedMinor: Long)

sealed interface BillingResult {
    data class Authorized(val auth: BillingAuthorization) : BillingResult
    data object Cancelled : BillingResult                 // user dismissed the payment sheet
    data class Declined(val reason: String) : BillingResult
    data class Failed(val cause: Throwable) : BillingResult
}

interface BillingAuthorizer {
    /** Obtain a payment token for [amountMinor] in [currency]. No network charge to TestLogon. */
    suspend fun authorize(amountMinor: Long, currency: String, memo: String? = null): BillingResult
}
```

A `@Provides @Singleton` Hilt binding selects `FakeBillingAuthorizer` (from `:core:testing`, also used as the default debug stub) until AND-031 lands the real implementation. The fake returns `Authorized` (configurable to `Declined`/`Cancelled`/`Failed` for tests).

### 4.3 UI state

```kotlin
enum class UnlockPhase { IDLE, AUTHORIZING, RESOLVING, UNLOCKING, FAILED }

data class UnlockUiState(
    val messageId: String,
    val phase: UnlockPhase = UnlockPhase.IDLE,
    val resolvedPriceMinor: Long? = null,   // populated for lottery before confirm
    val error: UiError? = null,
)

data class TipSheetState(
    val messageId: String? = null,          // non-null = sheet open
    val presetsMinor: List<Long> = listOf(100, 500, 1000, 2000),
    val selectedMinor: Long? = null,
    val customInput: String = "",
    val note: String = "",
    val amountError: UiError? = null,
    val submitting: Boolean = false,
)
```

Per-message unlock phases are held in a `Map<String, UnlockUiState>` within the messaging UI state so concurrent unlocks on different rows are independent; the merged message list from AND-124 is unchanged except for the new `monetization` field on rows.

### 4.4 ViewModel actions

```kotlin
class MonetizationViewModel @Inject constructor(
    private val repo: MonetizationRepository,
    private val billing: BillingAuthorizer,
    private val me: AuthStateStore,          // current user id (AND-029)
    private val analytics: Analytics,
) : ViewModel() {
    fun onUnlockClick(messageId: String)     // FIXED or LOTTERY entry point
    fun onLotteryConfirm(messageId: String)  // confirm drawn price -> charge
    fun onUnlockDismiss(messageId: String)

    fun onTipOpen(messageId: String)
    fun onTipPresetSelect(amountMinor: Long)
    fun onTipCustomChange(text: String)
    fun onTipNoteChange(text: String)
    fun onTipConfirm()
    fun onTipDismiss()
}
```

`onUnlockClick(messageId)` (FIXED):
1. Set phase `AUTHORIZING`; `val m = currentMessage(messageId)`.
2. `when (billing.authorize(m.priceMinor!!, m.currency))`:
   - `Authorized(auth)` -> phase `UNLOCKING`; `repo.unlock(messageId, auth.paymentToken, clientId)`.
   - `Cancelled` -> phase `IDLE` (no error toast).
   - `Declined(reason)` -> phase `FAILED`, `UiError.PaymentDeclined(reason)`.
   - `Failed(t)` -> phase `FAILED`, `UiError.from(t)`.
3. On `repo.unlock` `ApiResult.Success(revealed)` -> `messageDao.upsert(revealed.toEntity())` (reconcile row to `unlocked = true`), phase `IDLE`; on `Error` -> phase `FAILED`.

`onUnlockClick` (LOTTERY) sets phase `RESOLVING`, calls `repo.resolveLottery(messageId, clientId)` to obtain `resolvedPriceMinor`, stores it, and stops (awaiting `onLotteryConfirm`). `onLotteryConfirm` runs the same authorize → finalize as steps 2–3 using the resolved amount.

`onTipConfirm`: validate amount in bounds; `submitting = true`; `billing.authorize(amount)` -> `repo.tip(messageId, auth.paymentToken, amountMinor, note, clientId)` -> success: close sheet, emit confirmation, mark row tipped; error: keep sheet open, surface error, preserve amount.

### 4.5 Repository (`:core:data`)

```kotlin
interface MonetizationRepository {
    suspend fun unlock(messageId: String, paymentToken: String, clientId: String): ApiResult<Message>
    suspend fun resolveLottery(messageId: String, clientId: String): ApiResult<LotteryDraw>   // OQ-2
    suspend fun tip(
        messageId: String, paymentToken: String,
        amountMinor: Long, note: String?, clientId: String,
    ): ApiResult<TipReceipt>
}
```

Implementation builds the request DTOs, calls the Retrofit service, maps `MessageDto.toDomain(...)` / receipt DTOs via the shared `apiCall { }` helper (exceptions/non-2xx → `ApiResult.Error`, FastAPI `detail` decoded by `DetailErrorAdapter`), and writes revealed messages back to `MessageDao` so unlock state persists.

### 4.6 Composables (`:feature:messaging.monetization`)

```kotlin
@Composable
fun LockedMessageItem(
    monetization: MessageMonetization,
    phase: UnlockPhase,
    onUnlock: () -> Unit,
    onConfirmDraw: () -> Unit,
    modifier: Modifier = Modifier,
)

@Composable
fun TipSheet(
    state: TipSheetState,
    onPreset: (Long) -> Unit,
    onCustomChange: (String) -> Unit,
    onNoteChange: (String) -> Unit,
    onConfirm: () -> Unit,
    onDismiss: () -> Unit,
)
```

`LockedMessageItem` replaces the body branch in the AND-124 message item when `monetization != null && !unlocked`. The lottery confirm step is a Material 3 `AlertDialog` triggered when `resolvedPriceMinor != null`. Currency is formatted with a `MoneyFormatter` (`java.text.NumberFormat.getCurrencyInstance(locale)` driven by minor units + ISO code) shared in `:core:ui`.

## 5. API Contract

**Unlock — `POST /messages/{id}/unlock`** (path `id` = messageId).
Request headers: session cookies (cookie jar) + `X-CSRF-Token` (CSRF interceptor) + `Content-Type: application/json`.

Request body:
```json
{ "payment_token": "tok_stub_...", "client_id": "7c1f...-uuid" }
```
Success `200` returns the revealed message:
```json
{
  "id": "msg_01H...",
  "conversation_id": "conv_01H...",
  "author_id": "usr_01H...",
  "body": "the now-revealed gated text",
  "client_id": null,
  "created_at": "2026-06-05T14:22:31.004Z",
  "monetization": { "type": "fixed", "unlocked": true, "price_minor": 500, "currency": "USD",
                    "teaser": null, "teaser_image_url": null, "tip_eligible": true }
}
```

**Lottery resolve (variant of unlock)** — `POST /messages/{id}/unlock` with `{ "mode": "lottery_draw", "client_id": "..." }` (or a dedicated `/messages/{id}/unlock/lottery` step — **OQ-2**). Returns the drawn price:
```json
{ "draw_id": "draw_01H...", "price_minor": 350, "currency": "USD", "expires_at": "2026-06-05T14:25:00Z" }
```
The follow-up finalize sends `{ "payment_token": "...", "draw_id": "draw_01H...", "client_id": "..." }`.

**Tip — `POST /messages/{id}/tip`**.
Request body:
```json
{ "payment_token": "tok_stub_...", "amount_minor": 500, "currency": "USD",
  "note": "great post", "client_id": "9a2e...-uuid" }
```
Success `200`/`201`:
```json
{ "tip_id": "tip_01H...", "message_id": "msg_01H...", "amount_minor": 500,
  "currency": "USD", "created_at": "2026-06-05T14:22:31.004Z" }
```

**Moshi DTOs + Retrofit:**
```kotlin
@JsonClass(generateAdapter = true)
data class UnlockRequest(
    @Json(name = "payment_token") val paymentToken: String,
    @Json(name = "draw_id") val drawId: String? = null,
    @Json(name = "mode") val mode: String? = null,
    @Json(name = "client_id") val clientId: String,
)

@JsonClass(generateAdapter = true)
data class LotteryDrawDto(
    @Json(name = "draw_id") val drawId: String,
    @Json(name = "price_minor") val priceMinor: Long,
    @Json(name = "currency") val currency: String,
    @Json(name = "expires_at") val expiresAt: String?,
)

@JsonClass(generateAdapter = true)
data class TipRequest(
    @Json(name = "payment_token") val paymentToken: String,
    @Json(name = "amount_minor") val amountMinor: Long,
    @Json(name = "currency") val currency: String,
    @Json(name = "note") val note: String?,
    @Json(name = "client_id") val clientId: String,
)

@JsonClass(generateAdapter = true)
data class TipReceiptDto(
    @Json(name = "tip_id") val tipId: String,
    @Json(name = "message_id") val messageId: String,
    @Json(name = "amount_minor") val amountMinor: Long,
    @Json(name = "currency") val currency: String,
    @Json(name = "created_at") val createdAt: String,
)

@JsonClass(generateAdapter = true)
data class MonetizationDto(
    @Json(name = "type") val type: String,            // "fixed" | "lottery"
    @Json(name = "unlocked") val unlocked: Boolean,
    @Json(name = "price_minor") val priceMinor: Long?,
    @Json(name = "currency") val currency: String,
    @Json(name = "teaser") val teaser: String?,
    @Json(name = "teaser_image_url") val teaserImageUrl: String?,
    @Json(name = "tip_eligible") val tipEligible: Boolean,
)

interface MessageMonetizationApi {
    @POST("messages/{id}/unlock")
    suspend fun unlock(@Path("id") id: String, @Body req: UnlockRequest): Response<MessageDto>

    @POST("messages/{id}/unlock")
    suspend fun resolveLottery(@Path("id") id: String, @Body req: UnlockRequest): Response<LotteryDrawDto>

    @POST("messages/{id}/tip")
    suspend fun tip(@Path("id") id: String, @Body req: TipRequest): Response<TipReceiptDto>
}
```

**Error responses** (FastAPI `detail` → `UiError` via `DetailErrorAdapter`; `detail` may be `string | [{msg,...}] | {code,...}`):
- `401` -> authenticator runs `POST /ui/session/refresh` once + retry; second `401` -> `UiError.Unauthorized` (flow FAILED, surface re-auth).
- `402` (payment required / insufficient) or `{code:"payment_*"}` -> `UiError.PaymentDeclined` (non-retryable without re-authorizing).
- `403` -> CSRF/permission/own-message; non-retryable hint.
- `404` -> message gone; FAILED "message unavailable".
- `409` -> already unlocked / duplicate transaction -> treat as success: re-fetch/reveal the message (idempotent outcome).
- `410` (lottery draw expired) -> clear resolved price, re-resolve.
- `422` -> `[{msg, loc}]`; show first `msg` (e.g., amount out of range).
- `5xx` / timeout / `IOException` -> FAILED, retryable with same `client_id`.

## 6. Data & State Management

- **Source of truth for unlock state:** Room `MessageEntity` (AND-124) extended with embedded monetization columns; `unlocked` is server-authoritative and written on successful unlock so reveal persists across restarts (FR-9). No local-only "unlocked" boolean.
- **Per-message transient phase:** `Map<String, UnlockUiState>` in the messaging `StateFlow<UiState>`, not persisted (transient purchase progress).
- **Tip sheet state:** held in the ViewModel; the draft amount/note backed by `SavedStateHandle` (`tip_amount_<messageId>`, `tip_note_<messageId>`) so rotation/process recreation does not lose typing.
- **Idempotency keys:** `client_id` per attempt generated once per logical purchase and reused on manual retry; for lottery, `draw_id` ties the finalize to the resolved price.
- **Currency:** all amounts stored and transported in **minor units** (`Long`); formatting to display is a UI concern via `MoneyFormatter`. No floating-point money.
- **Threading:** DB writes on `Dispatchers.IO`; billing/network suspend functions on `viewModelScope`; state exposed via `stateIn(SharingStarted.WhileSubscribed(5_000))`.
- **Dedup:** a `409 already-unlocked` or a history refresh delivering `unlocked == true` reconciles by `id`; the row collapses to revealed exactly once.

## 7. Error Handling & Resilience

- **Two-stage failure isolation:** billing-authorize failures (`Declined`/`Cancelled`/`Failed`) never call the unlock/tip endpoint; server failures occur only after a payment token exists. The UI message distinguishes "payment declined" from "couldn't reach server" so the user knows whether they were charged.
- **Charged-but-uncertain:** if authorize succeeded but the unlock/tip POST timed out, the row stays locked and shows "Couldn't confirm — Retry"; retry reuses `client_id` (and `draw_id`) so the server dedupes and a second charge is impossible. A `409` on retry is treated as success.
- **Timeouts:** OkHttp call timeout ~20s (dev-host policy); a stuck request becomes FAILED, never a spinner that hangs.
- **Offline:** unlock/tip are disabled (or fail fast to `FAILED` with "No connection") since they are non-idempotent writes requiring a fresh payment token; nothing is queued/auto-retried.
- **Lottery draw expiry:** a `410`/`expires_at` in the past clears the resolved price and forces a fresh draw before charging (no charging against a stale draw).
- **Refresh-on-401:** handled by the OkHttp authenticator centrally; the flow sees only the post-refresh outcome; double-401 → FAILED + re-auth.
- **Concurrent unlocks:** independent per-`messageId` phase entries; one failure never affects another row.
- **No auto-retry of charges:** all retries are user-initiated (consistent with AND-124's manual-retry stance for non-idempotent writes).

## 8. Security & Privacy

- **No card data in this module.** Payment instrument selection, PAN, and processor interaction are entirely inside the billing module (AND-031); this ticket only ever holds an opaque `payment_token` and amounts. The `payment_token` is single-use and is **never** logged or persisted.
- Auth/CSRF/cookies are transport concerns from core-network; this ticket adds no auth code and must not bypass the cookie jar, `X-CSRF-Token` interceptor, or refresh authenticator.
- **Gated content confidentiality:** the locked teaser must render only server-supplied `teaser`/`teaser_image_url`; the gated `body`/media must not be present in the locked DTO/cache (the server must not ship gated content to a non-purchaser). If the API returns gated content alongside the locked flag (server bug), the client still must not render it while `unlocked == false` — and this is flagged as a security defect (OQ-3).
- The dev backend is plaintext HTTP (known dev-only); release builds use HTTPS with cleartext forbidden via network-security-config (owned by network/build tickets; inherited here). Payment flows in production must be HTTPS-only.
- Amounts are sent as integer minor units via Moshi (no string interpolation); no injection surface. Notes render via Compose `Text` (no HTML), no XSS surface; notes are length-capped and trimmed.
- Tip notes are user content: not written to logcat or telemetry payloads.

## 9. Accessibility & i18n

- **Currency & numbers:** all amounts formatted with locale-aware `NumberFormat.getCurrencyInstance` from minor units + ISO code; no hardcoded "$". Presets and custom field display localized currency.
- The **Unlock** button exposes `contentDescription` including the price ("Unlock for $5.00"); progress state announced via `Modifier.semantics { stateDescription = ... }` ("Authorizing payment", "Unlocking") so it is not color/spinner-only.
- The **lottery** confirm dialog states the drawn amount in text and is fully screen-reader navigable; the confirm action is explicit (no auto-charge).
- Tip sheet: preset chips and custom field are labeled; selected preset has `selected` semantics; the note field has a label and counter; confirm announces enabled/disabled.
- All strings in `strings.xml` (no literals), including price-bearing strings via formatted resources. RTL-safe (start/end, `imePadding`). Minimum 48dp touch targets for Unlock, presets, custom-confirm, and retry.

## 10. Telemetry & Logging

- Events via the core-data analytics facade (no PII, no notes, no token, no raw amount value as currency string — minor-unit integer is acceptable, hashed messageId):
  - `paid_msg_unlock_attempt` { messageId (hashed), type (fixed|lottery) }
  - `paid_msg_unlock_billing_result` { result (authorized|cancelled|declined|failed) }
  - `paid_msg_unlock_success` { latencyMs }
  - `paid_msg_unlock_failed` { stage (billing|resolve|unlock), errorClass, httpStatus }
  - `paid_msg_lottery_draw` { priceMinor }
  - `tip_attempt` { messageId (hashed), amountMinor } / `tip_success` { latencyMs } / `tip_failed` { errorClass, httpStatus }
- Logging: `Timber.d/w` for flow lifecycle keyed by `messageId`/`client_id` only — **never** `payment_token`, note text, or cookies. Network logging interceptor stays at `BASIC` in release (no bodies) per project policy, which keeps tokens out of logs.

## 11. Testing Strategy

- **Unit — ViewModel (core-testing, `MainDispatcherRule`, Turbine, `FakeBillingAuthorizer`, MockWebServer-backed repo):**
  - Fixed unlock happy path: authorize `Authorized` -> `POST /unlock` 200 -> row reconciles to `unlocked = true`, phase returns IDLE, `MessageEntity` updated. *(covers "unlock flow works")*
  - Billing `Cancelled` -> no unlock call, phase IDLE, row still locked.
  - Billing `Declined` -> phase FAILED with `PaymentDeclined`, no unlock call.
  - Unlock POST 5xx/timeout after authorize -> phase FAILED, retry reuses same `client_id`; `409` on retry treated as success.
  - Lottery: `RESOLVING` -> draw price stored -> confirm -> authorize(resolved) -> finalize success; expired draw (`410`) clears resolved price and forces re-resolve; charge never fires before explicit confirm. *(covers "lottery unlock")*
  - Tip happy path: authorize -> `POST /tip` 200 -> sheet closes, confirmation emitted; amount/bounds validation toggles confirm; out-of-range custom amount blocked; failure keeps sheet open with amount preserved.
  - Own-message: tip/unlock affordances not offered for current user's authored message (FR-10).
  - Concurrent unlocks on two messages are independent.
- **Repository tests:** MockWebServer returns 200/402/409/410/422/500/timeout for `/unlock` and `/tip`; assert correct `ApiResult`, request body JSON (`payment_token`, `amount_minor`, `currency`, `client_id`, `note`), and `X-CSRF-Token` header presence; assert revealed message written to DAO.
- **DAO tests:** Room in-memory — monetization columns round-trip; `unlocked` persists; reveal supersedes locked row by `id`.
- **Compose UI tests:** locked teaser shows price + Unlock and does **not** render gated body; tapping Unlock shows progress; lottery confirm dialog shows drawn amount and requires confirm; tip sheet preset/custom selection + confirm; failure shows retry; accessibility content/state descriptions asserted; gated body never appears in semantics tree while locked.
- **Billing-stub contract test:** `FakeBillingAuthorizer` honors configured outcomes; no network charge issued.
- All async tests deterministic (`runTest`, injected `TestDispatcher`); MockWebServer for network; no live dev-host or live payment calls in CI.

## 12. Dependencies & Sequencing

- **Depends on AND-124** (send text message / messaging foundation): provides the `Message` domain model, Room `MessageEntity`/`MessageDao`, the thread render loop and item Composable this ticket branches on, `ApiResult`, `apiCall { }`, and `DetailErrorAdapter`. Must merge after AND-124. (Transitively: AND-120/AND-123 messaging foundation and the core-network auth/CSRF/cookie-jar/refresh tickets.)
- **Depends on AND-031 (billing)** for the real `BillingAuthorizer` implementation. Per the source acceptance ("with payment dependency stubbed/tested"), this ticket ships and tests against `FakeBillingAuthorizer`; the `BillingAuthorizer` contract (in `:core:model`) is the integration seam AND-031 must satisfy. AND-139 can merge before AND-031's real impl lands, defaulting to the stub binding, but production monetization is not enabled until AND-031 provides the real authorizer.
- **Current-user identity** from the auth-state store (AND-029) is consumed for FR-10.
- **Blocks:** none recorded in the source bullets.

## 13. Risks & Open Questions

- **OQ-1 (must resolve before merge):** Exact request/response shapes for `POST /messages/{id}/tip` and `POST /messages/{id}/unlock` — field names (`payment_token` vs `payment_method_id`), whether `client_id` is accepted/deduped, and the `409 already-unlocked` behavior. Verify against `/openapi.json` and `frontend/src/api/endpoints/messages.ts`. If `client_id` dedupe is unsupported, retry-after-uncertain-failure is unsafe and must be disabled.
- **OQ-2 (must resolve before merge):** Lottery unlock protocol — is it a two-step `resolve` then `finalize` (as designed), a single endpoint that draws-and-charges atomically, or a dedicated path `/messages/{id}/unlock/lottery`? Confirm `draw_id`/`expires_at` semantics. The two-step design here is the safe assumption (explicit confirm before charge) and may need to collapse to one call.
- **OQ-3 (security):** Does the locked DTO ever contain the gated `body`/media before purchase? It must not. If the server ships gated content with `unlocked == false`, raise as a backend security defect; the client must still refuse to render it.
- **OQ-4:** Billing contract (AND-031) — does `authorize` return a reusable `payment_token`, and is the amount captured at authorize or at server confirm? This affects whether `409` retries can re-use the token. The `BillingAuthorizer` interface must be agreed with the AND-031 owner.
- **Risk:** double-charge on retry if idempotency is incomplete (token + `client_id` + `draw_id`). Mitigation: reuse all idempotency keys, treat `409` as success, and gate retry behind explicit user action.
- **Risk:** unreliable dev host produces frequent FAILED states in manual QA. Mitigation: clear distinct error copy (declined vs server) + retry; deterministic MockWebServer tests.

## 14. Acceptance Criteria

AC-1. A locked message renders as a teaser showing the formatted price and an Unlock affordance, and **does not** display the gated body/media; an already-unlocked message renders revealed with no prompt. *(source: "locked message UI")*

AC-2. Tapping Unlock on a fixed-price message runs billing-authorize then `POST /messages/{id}/unlock`, and on success reconciles the row in place to `unlocked = true` with the server-revealed content; unlock state persists across app restart. *(source: "unlock flow works", "stubbed/tested")* — verified by automated ViewModel + DAO tests.

AC-3. Lottery unlock resolves a drawn price from the server, requires explicit user confirmation of that amount, then authorizes and finalizes; no charge occurs before confirmation, and an expired draw forces a re-draw. *(source: "lottery unlock")*

AC-4. Tipping a message via the tip sheet (preset or validated custom amount, optional note) runs billing-authorize then `POST /messages/{id}/tip` and shows a confirmation on success; out-of-range amounts are blocked. *(source: "`/messages/{id}/tip`")*

AC-5. Billing failures (`Cancelled`/`Declined`/`Failed`) never call the server endpoint and are surfaced distinctly from server failures; server failures leave the message locked / tip sheet preserved with a retry that reuses `client_id` (no double charge). *(source: "tip flows work … stubbed/tested")*

AC-6. Users are not offered tip/unlock affordances against their own authored messages.

AC-7. Automated tests cover fixed unlock, lottery resolve+confirm, tip happy path + validation, billing-cancel/decline isolation, uncertain-failure retry with `409`-as-success, and locked-body-not-rendered, all against `FakeBillingAuthorizer` and MockWebServer with no live host/payment calls. *(source: "stubbed/tested")*

## 15. Definition of Done

- `LockedMessageItem`, `TipSheet`, the lottery confirm dialog, `MonetizationViewModel` (unlock/lottery/tip actions), `MonetizationRepository`, the `MessageMonetizationApi` Retrofit service, and the monetization/tip/unlock Moshi DTOs implemented in `:feature:messaging` / `:core:network` / `:core:model` / `:core:data` under `com.testlogon.android.feature.messaging.monetization`.
- `BillingAuthorizer` contract declared in `:core:model`; `FakeBillingAuthorizer` in `:core:testing`; Hilt binding defaults to the stub until AND-031 supplies the real implementation; no card data or `payment_token` is logged or persisted.
- Fixed unlock, lottery unlock (resolve + confirm), and tip flows functional against MockWebServer and the `FakeBillingAuthorizer`, and manually verified against the dev host where the endpoints exist.
- All §11 unit, repository, DAO, and Compose UI tests pass in CI; no live-host or live-payment calls in CI; gated content provably never rendered while locked.
- Amounts handled in integer minor units; currency formatted locale-aware; strings externalized; accessibility content/state descriptions present; touch targets >= 48dp.
- `X-CSRF-Token` and cookie-jar paths verified on both endpoints; Detekt/ktlint clean; KSP builds.
- OQ-1, OQ-2, and OQ-3 confirmed against `/openapi.json` and the web reference, and reflected in code, before merge.
- All ACs in §14 demonstrably met. PR targets the `android-port` branch and references AND-139, AND-124, and AND-031.
