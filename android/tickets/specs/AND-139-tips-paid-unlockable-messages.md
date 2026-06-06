---
id: AND-139
title: Tips & paid/unlockable messages
milestone: M3
epic: E19
priority: P1
size: L
status: reviewed
reviewed_on: 2026-06-06
depends_on: [AND-124, AND-031]
blocks: []
---

# AND-139 — Tips & paid/unlockable messages

## 1. Overview & Goal

Add monetized-message support to the messaging surface: **paid/unlockable messages** (a message whose body/media is gated behind a price and only revealed after purchase), **tipping** an individual message, and the **lottery unlock** variant (an unlock whose price is resolved by a server-side lottery/draw rather than a fixed amount). The defining requirement is a clean separation of two concerns: (1) the **locked-message UI** — rendering a gated message as a teaser with price, lock affordance, and post-unlock reveal — and (2) the **purchase flows** that drive `POST /messaging/conversations/{conversation_id}/messages/{message_id}/tip` and `.../unlock` (**CORRECTED** — the real backend paths are conversation-scoped, not the flat `/messages/{id}/tip` the source ticket scoped; see §5 and §16), with the underlying *payment authorization* delegated to the billing dependency (AND-031), which in this ticket is **stubbed behind an interface and fully tested** rather than wired to a live payment processor.

Goal, restated as a testable outcome: a user viewing a locked message sees a teaser with the price and an "Unlock" affordance; tapping it runs the billing-authorize → server-unlock sequence and, on success, reconciles the row in place to its revealed (unlocked) content. Separately, a user can tip any eligible message via a tip sheet (preset/custom amounts), driving `POST /messaging/conversations/{conversation_id}/messages/{message_id}/tip`. The **lottery unlock is a distinct, separate message type** (`lottery_dm`) with its own single-call endpoint `POST /messaging/messages/{message_id}/lottery/unlock` that draws-and-reveals atomically server-side (**CORRECTED** — there is no two-step price-resolve-then-confirm protocol, and the web client performs no client-side billing-authorize for lottery; see FR-4 and §16). All flows degrade safely on payment failure, server failure, and offline. The deliverables are the locked-message Composables, the tip sheet, the `MonetizationViewModel` action surface, the repository + DTOs for the two endpoints, and the `BillingAuthorizer` seam that AND-031 will later satisfy.

## 2. Context & References

- **Module:** `feature-messaging` (Gradle module `:feature:messaging`), package `com.testlogon.android.feature.messaging.monetization`. The locked-message item and tip sheet extend the Thread (message list) screen delivered by AND-123 and the send path from AND-124; this ticket adds the monetization read/teaser rendering and the two write flows.
- **Layering:** `:feature:messaging` -> `:core:network` (Retrofit service, `ApiResult<T>`, `apiCall { }`, `DetailErrorAdapter`), `:core:model` (DTO/domain + mappers), `:core:data` (Room cache + repository, analytics facade), `:core:ui` (Compose components, theme, state composables). No backward dependencies. The `BillingAuthorizer` interface is declared in `:core:model` (a pure contract) and implemented by the billing module under AND-031; a `FakeBillingAuthorizer` for this ticket lives in `:core:testing`.
- **Backend:** FastAPI + DynamoDB. Dev host `http://18.222.237.167:8000` (plaintext HTTP, unreliable; ~20s timeouts). OpenAPI at `/openapi.json`. Auth (**CORRECTED/CLARIFIED** vs. "cookie-based" only): the web client sends an **`Authorization: Bearer <accessToken>` header** (from the auth store) **plus** the `ui_csrf` cookie echoed as `X-CSRF-Token`, with `credentials: include` so session cookies are also sent; on `401` it calls `POST /ui/session/refresh` once and retries (verified in `src/api/client.ts`). The messaging endpoints additionally accept an `X-SESSION-ID` parameter (per OpenAPI index). On Android this maps to: persistent cookie jar **and** the Bearer-token/header path from core-network's auth tickets (AND-029); a `401` authenticator that refreshes once. Do not assume pure cookie-session.
- **Web reference (CORRECTED file/symbol names):** `src/api/endpoints/messaging.ts` (functions `sendMessageTip(conversationId, messageId, body)`, `unlockMessage(conversationId, messageId, paymentMethodId?)`, and the separate `unlockLotteryMessage(messageId)` / `getLotteryMessage(messageId)` / `createLotteryMessage(body)`) and `src/api/types.ts` (`Message` with flat fields `lock_price_cents`/`lock_description`/`is_unlocked`/`locked`/`tip_amount_cents`/`tip_currency` and a separate `lottery` sub-object; `SendTipReq`; `LotteryMessage`; `LotteryUnlockResp`; `LotterySelectedOutcome`; `CreateLotteryMessageReq`). **There is no `MessageMonetization`, `TipRequest`, `UnlockRequest`, or `UnlockResult` type in the reference** — those names in the original draft were invented. The Android DTOs must mirror the real shapes (`SendTipIn`/`TipOut`, `UnlockMessageIn`/`UnlockOut`, `LotteryUnlockOut`) confirmed against `/openapi.json`. See §5 and §16.
- **Dependency AND-124** supplies the message domain model (`Message`), the Room `MessageEntity`/`MessageDao`, the thread render loop, `ApiResult`, and the `apiCall { }`/`DetailErrorAdapter` plumbing. AND-139 extends `Message` with monetization fields and adds the unlock/tip write paths.
- **Dependency AND-031 (billing)** owns real payment authorization (payment-method selection, processor charge, receipt). This ticket consumes it only through `BillingAuthorizer` and ships with a stub/fake so the unlock/tip flows are independently testable.
- **Stack:** Kotlin 2.0.21, Compose + Material 3, Hilt (KSP), Coroutines/Flow, Retrofit 2.11 + OkHttp 4.12 + Moshi 1.15, Room 2.6, Paging 3. minSdk 24 / compileSdk/targetSdk 35, JDK 17.

## 3. Functional Requirements

FR-1. A message may carry paid-message metadata. **(CORRECTED shape)** The backend `Message` does **not** nest a single `monetization` object; instead a fixed-price locked message carries flat fields `lock_price_cents` (Long, cents), `lock_description` (String, the teaser caption), `locked`/`is_unlocked` (Booleans). A lottery message is a **separate message type** carried in a distinct `lottery` sub-object (`{ message_type: "lottery_dm", lock_state: "locked"|"unlocked", selected_outcome? }`). The thread item Composable (from AND-124) branches: no lock fields and no `lottery` block -> normal message; `locked == true && is_unlocked == false` -> **fixed-price locked teaser**; `lottery.lock_state == "locked"` -> **lottery locked teaser**; otherwise revealed. The Android domain `MessageMonetization` model (§4.1) is an internal mapping convenience, **not** a wire shape.

FR-2. The **fixed-price locked teaser** shows: a lock glyph, an optional preview (the server-supplied `lock_description` caption and/or a blurred preview attachment), the formatted **price** from `lock_price_cents` (currency-aware), and a primary **Unlock** button. **(CORRECTED)** There is no server `teaser`/`teaser_image_url` field on the message JSON — use `lock_description`; blurred media previews are delivered via the gallery/attachment preview path (`preview_key`), not an inline `teaser_image_url`. The teaser never renders the gated `body`/media until unlock succeeds.

FR-3. Tapping **Unlock** on a fixed-price message runs: `BillingAuthorizer.authorize(amount, currency)` -> on success `POST /messaging/conversations/{conversation_id}/messages/{message_id}/unlock` with body `{ "payment_method_id": "<id>" }` -> on success (`UnlockOut` = `{ ok, conversation_id, message_id, unlock_payment_id, amount_cents }`). **(CORRECTED)** The unlock response does **NOT** contain the revealed `body`/media — `UnlockOut` returns only the receipt. The client must **re-fetch the message/thread** (the web reference invalidates the `["messages", conversationId]` query on success) to obtain the revealed content, then reconcile the row to `is_unlocked = true`. The button shows an in-progress state and is disabled during the flow. **Also note:** the billing seam supplies a `payment_method_id` (an opaque selected-payment-method identifier), not a `payment_token`; the web client requires a selected payment method before unlock.

FR-4. **Lottery unlock (CORRECTED — single atomic call, no price-confirm step):** the lottery is its own `lottery_dm` message. There is **no** two-step "resolve price -> confirm -> authorize -> finalize" protocol and **no** drawn-price confirmation dialog in the real contract. Tapping Unlock calls `POST /messaging/messages/{message_id}/lottery/unlock` with an **empty body** (no `payment_method_id`, no `client_id`, no `mode`/`draw_id`); the server **draws and reveals atomically**, returning `LotteryUnlockOut` = `{ message_id, lock_state: "unlocked", selected_outcome, unlocked_at }`. The web client performs **no client-side `BillingAuthorizer.authorize` for lottery** — pricing/charging (if any) is server-side and gated by feature flag `messaging_dm_lottery`. On success the client reveals `selected_outcome` (text or media) with a reveal animation (respecting reduced-motion) and re-fetches via `getLotteryMessage(messageId)` for hydration. The Android design should therefore drop the `resolveLottery`/confirm-draw steps; the `LotteryDraw`/`onLotteryConfirm` surfaces below are an **unverified, non-matching assumption** retained only as a note (see §13/§16) and MUST be removed before implementation unless a separate priced-lottery endpoint is confirmed.

FR-5. **Tip**: any tip-eligible message authored by another user exposes a tip affordance (overflow action / long-press). Tapping opens a **tip sheet** (Material 3 `ModalBottomSheet`) with preset amounts (e.g., 1/5/10/20) and a custom-amount field, plus an optional short note (**max 500 chars** per `SendTipIn.note` maxLength — **CORRECTED** from 200). Confirming runs `BillingAuthorizer.authorize(amount)` to obtain a `payment_method_id` -> `POST /messaging/conversations/{conversation_id}/messages/{message_id}/tip` with `SendTipIn` = `{ amount_cents, currency, note?, payment_method_id? }` -> on success (`TipOut` = `{ ok, conversation_id, message_id, tip_payment_id, amount_cents, currency }`) a confirmation (snackbar) and optional inline "tipped" indicator on the row.

FR-6. Amount validation: tip/unlock amounts are positive integers in **cents**, within `[min, max]` bounds. **(CORRECTED bounds)** `SendTipIn.amount_cents` is constrained server-side to `minimum: 1` (1 cent) and `maximum: 100000` (i.e. **$1000.00**, not $500.00). The client mirrors min 1 / max 100000 cents unless the server supplies tighter bounds; the web client computes `cents = Math.round(parseFloat(input) * 100)` and rejects `cents < 1`. Amounts are parsed locale-aware and sent as integer cents, never as a free-form string. Out-of-range custom amount is blocked with an inline error and the confirm button disabled.

FR-7. Idempotency **(CORRECTED — no `client_id` on tip/unlock):** the real `SendTipIn`/`UnlockMessageIn` request bodies have **no `client_id` field**, and `unlockMessage`/`sendMessageTip` send no idempotency header. The only message endpoint that uses idempotency is lottery **create** (`Idempotency-Key` header on `POST /messaging/messages/lottery`), which is out of scope here. Therefore client-side dedupe of tip/unlock via `client_id` is **not supported by the contract**; per OQ-1, retry-after-uncertain-failure cannot be assumed safe and must be treated as a known gap (see §7, §13, §16). Any Android idempotency must be coordinated with the backend (e.g. adding an `Idempotency-Key` header) before relying on retries.

FR-8. The flows are **non-destructive** on failure: a failed unlock leaves the message locked and shows a retryable error; a failed tip leaves the sheet open with the amount preserved and a retry affordance. Payment-declined and server errors are distinguished in the message shown.

FR-9. Already-unlocked messages (server says `unlocked == true`, e.g., re-fetched after a prior purchase) render revealed with no purchase prompt. Unlock state persists across app restarts (sourced from the message cache / server, not from local-only flags).

FR-10. The user's **own** messages (authored by the current user) are not offered tip/unlock affordances against themselves; tip is offered only on other users' eligible messages, and a creator's own paid message renders revealed. **(VERIFIED)** The web reference enforces this via `isOwn` (e.g., payment-methods query is `enabled: !isOwn` in `MessageBubble.tsx`, gating Send-Tip/Unlock to recipient bubbles). Current-user identity for Android comes from the auth-state store (AND-029).

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
3. On `repo.unlock` `ApiResult.Success(UnlockOut)` -> **(CORRECTED)** the unlock response is only a receipt, so the repo must then **re-fetch the message** (or thread page) to get the revealed `body`/media, write it to `messageDao` (reconcile row to `is_unlocked = true`), phase `IDLE`; on `Error` -> phase `FAILED`. Do not expect the revealed body in the unlock response.

`onUnlockClick` (LOTTERY) **(CORRECTED — no resolve/confirm step):** sets phase `UNLOCKING`, calls `repo.unlockLottery(messageId)` (empty body), and on success writes the revealed `selected_outcome` to the row (`lock_state = "unlocked"`). The `RESOLVING` phase, `resolveLottery`, `onLotteryConfirm`, and the drawn-price confirmation dialog do **not** correspond to any endpoint and should be removed unless a separate priced-lottery flow is confirmed with the backend (OQ-2). No client-side `BillingAuthorizer.authorize` is invoked for lottery per the web reference.

`onTipConfirm`: validate amount in bounds; `submitting = true`; `billing.authorize(amount)` -> `repo.tip(messageId, auth.paymentToken, amountMinor, note, clientId)` -> success: close sheet, emit confirmation, mark row tipped; error: keep sheet open, surface error, preserve amount.

### 4.5 Repository (`:core:data`)

```kotlin
// CORRECTED to match the verified contract: conversation-scoped paths, payment_method_id (not
// payment_token), amount_cents (not amount_minor), no client_id, unlock returns a receipt so the
// repo re-fetches the message, and lottery is a single empty-body call.
interface MonetizationRepository {
    suspend fun unlock(
        conversationId: String, messageId: String, paymentMethodId: String?,
    ): ApiResult<Message>            // calls /unlock (UnlockOut receipt) then re-fetches the message
    suspend fun unlockLottery(messageId: String): ApiResult<Message>   // single atomic draw+reveal
    suspend fun tip(
        conversationId: String, messageId: String, paymentMethodId: String?,
        amountCents: Long, currency: String, note: String?,
    ): ApiResult<TipOut>
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

> **This section has been substantially corrected against `/openapi.json` and `src/api/endpoints/messaging.ts`.** All three endpoints were wrong in the original draft (flat `/messages/{id}/...` paths, `payment_token`, `amount_minor`, `client_id`, a nested `monetization` response, and an unlock that returns the revealed body). The verified contract follows.

**Unlock — `POST /messaging/conversations/{conversation_id}/messages/{message_id}/unlock`** (op `unlock_message_...`).
Path params: `conversation_id`, `message_id`. Headers: `Authorization: Bearer <token>` + `X-CSRF-Token` + cookies (`credentials: include`) + `X-SESSION-ID` + `Content-Type: application/json`.

Request body (`UnlockMessageIn` — every field optional):
```json
{ "payment_method_id": "pm_123" }
```
Success `200` returns **only a receipt** (`UnlockOut`), NOT the revealed message:
```json
{ "ok": true, "conversation_id": "conv_...", "message_id": "msg_...",
  "unlock_payment_id": "upay_...", "amount_cents": 500 }
```
The revealed `body`/media is obtained by **re-fetching the message/thread** after success (web invalidates `["messages", conversationId]`).

**Lottery unlock — `POST /messaging/messages/{message_id}/lottery/unlock`** (op `unlock_lottery_message_...`). **No conversation in path. Empty request body (no schema). Single atomic draw+reveal.** Success `200` (`LotteryUnlockOut`):
```json
{ "message_id": "msg_...", "lock_state": "unlocked",
  "selected_outcome": { "outcome_id": "o_1", "payload_type": "text", "text_content": "..." },
  "unlocked_at": 1717600000 }
```
Related: `GET /messaging/messages/{message_id}/lottery` -> `LotteryMessageOut` (for hydration/state); `POST /messaging/messages/lottery` (create, `Idempotency-Key` header) is creator-side and out of scope. There is **no** `draw_id`/`expires_at`/price-resolve step in the contract.

**Tip — `POST /messaging/conversations/{conversation_id}/messages/{message_id}/tip`** (op `send_message_tip_...`).
Request body (`SendTipIn`):
```json
{ "amount_cents": 500, "currency": "USD", "note": "great post", "payment_method_id": "pm_123" }
```
`amount_cents` required (`min 1`, `max 100000`); `currency` defaults `"USD"`; `note` max 500; `payment_method_id` optional/nullable. Success `200` (`TipOut`):
```json
{ "ok": true, "conversation_id": "conv_...", "message_id": "msg_...",
  "tip_payment_id": "tpay_...", "amount_cents": 500, "currency": "USD" }
```

**Moshi DTOs + Retrofit (corrected to match the verified wire shapes):**
```kotlin
@JsonClass(generateAdapter = true)
data class UnlockMessageIn(
    @Json(name = "payment_method_id") val paymentMethodId: String? = null,
)

@JsonClass(generateAdapter = true)
data class UnlockOut(
    @Json(name = "ok") val ok: Boolean,
    @Json(name = "conversation_id") val conversationId: String,
    @Json(name = "message_id") val messageId: String,
    @Json(name = "unlock_payment_id") val unlockPaymentId: String,
    @Json(name = "amount_cents") val amountCents: Long,
)

@JsonClass(generateAdapter = true)
data class SendTipIn(
    @Json(name = "amount_cents") val amountCents: Long,           // min 1, max 100000
    @Json(name = "currency") val currency: String = "USD",
    @Json(name = "note") val note: String? = null,               // max 500
    @Json(name = "payment_method_id") val paymentMethodId: String? = null,
)

@JsonClass(generateAdapter = true)
data class TipOut(
    @Json(name = "ok") val ok: Boolean,
    @Json(name = "conversation_id") val conversationId: String,
    @Json(name = "message_id") val messageId: String,
    @Json(name = "tip_payment_id") val tipPaymentId: String,
    @Json(name = "amount_cents") val amountCents: Long,
    @Json(name = "currency") val currency: String,
)

// Lottery (separate message type). selected_outcome carries the revealed payload.
@JsonClass(generateAdapter = true)
data class LotterySelectedOutcomeDto(
    @Json(name = "outcome_id") val outcomeId: String,
    @Json(name = "payload_type") val payloadType: String,        // "text" | "image" | "video"
    @Json(name = "text_content") val textContent: String? = null,
    @Json(name = "media_asset_id") val mediaAssetId: String? = null,
)

@JsonClass(generateAdapter = true)
data class LotteryUnlockOut(
    @Json(name = "message_id") val messageId: String,
    @Json(name = "lock_state") val lockState: String,            // "unlocked"
    @Json(name = "selected_outcome") val selectedOutcome: LotterySelectedOutcomeDto,
    @Json(name = "unlocked_at") val unlockedAt: Long,            // epoch seconds (integer)
)

// Fixed-price paid-message fields live FLAT on MessageDto (no nested "monetization"):
//   lock_price_cents: Long?, lock_description: String?, locked: Boolean?, is_unlocked: Boolean?,
//   tip_amount_cents: Long?, tip_currency: String?, and a separate `lottery` sub-object.

interface MessageMonetizationApi {
    @POST("messaging/conversations/{cid}/messages/{mid}/unlock")
    suspend fun unlock(
        @Path("cid") conversationId: String,
        @Path("mid") messageId: String,
        @Body req: UnlockMessageIn,
    ): Response<UnlockOut>

    @POST("messaging/messages/{mid}/lottery/unlock")
    suspend fun unlockLottery(@Path("mid") messageId: String): Response<LotteryUnlockOut>

    @POST("messaging/conversations/{cid}/messages/{mid}/tip")
    suspend fun tip(
        @Path("cid") conversationId: String,
        @Path("mid") messageId: String,
        @Body req: SendTipIn,
    ): Response<TipOut>
}
```

**Error responses (CORRECTED).** Per `/openapi.json`, the documented responses for `/unlock`, `/tip`, and `/lottery/unlock` are **only `200` and `422:HTTPValidationError`**; the sibling messaging control endpoints additionally document `400/401/403/429`. The original draft's `402/409/410` codes are **not in the contract** and must be treated as unverified assumptions, not relied upon. FastAPI `detail` → `UiError` via `DetailErrorAdapter`; `detail` is `string | [{msg, loc, ...}] | {code, ...}` (`normalizeErrorDetail` in `src/api/client.ts` confirms all three shapes, including a `{code}` authorization map).
- `401` -> authenticator runs `POST /ui/session/refresh` once + retry; second `401` -> `UiError.Unauthorized` (flow FAILED, surface re-auth). *(Verified in client.ts.)*
- `403` -> CSRF/permission/own-message or geo-block (`{code:"geo_blocked"}`); non-retryable hint. *(Verified.)*
- `404` -> message gone; FAILED "message unavailable". *(Plausible but not documented for these ops — unverified.)*
- `422` -> body `{ detail: [{msg, loc}] }`; show first `msg` (e.g., amount out of range, `amount_cents` < 1 or > 100000). *(Verified — only documented error besides 401/403.)*
- `429` -> rate-limited; FAILED, retryable after backoff. *(Documented on sibling messaging endpoints.)*
- `5xx` / timeout / `IOException` -> FAILED, retryable. **Caveat:** with no `client_id`/`Idempotency-Key` on the contract (FR-7), a retry after an *uncertain* failure is NOT guaranteed dedupe-safe and risks a double charge; gate retry behind explicit user action and coordinate idempotency with the backend (OQ-1).
- **Payment-declined / already-unlocked / lottery-expired** codes (`402`/`409`/`410`) are **assumed, not contractually defined**; if the backend returns them, map declined->`PaymentDeclined`, `409`->treat as already-unlocked (re-fetch), but do not design around them as guaranteed (OQ-1/OQ-2).

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

- **OQ-1 (RESOLVED for shapes; one gap remains).** Verified against `/openapi.json` + `src/api/endpoints/messaging.ts`: the fields are `payment_method_id` (not `payment_token`) and `amount_cents` (not `amount_minor`); paths are conversation-scoped. **There is no `client_id` and no `Idempotency-Key` on `/unlock` or `/tip`**, and no documented `409 already-unlocked`. **Remaining gap:** because the contract offers no client idempotency key for these two writes, retry-after-uncertain-failure is **not dedupe-safe** — this MUST be coordinated with the backend (add an `Idempotency-Key` header, as lottery-create already supports) before any auto/one-tap retry is enabled.
- **OQ-2 (RESOLVED).** Lottery unlock is a **single atomic draw-and-reveal** call: `POST /messaging/messages/{message_id}/lottery/unlock` with an **empty body**, returning `LotteryUnlockOut` (`selected_outcome`, `unlocked_at`). There is **no** two-step resolve/finalize, **no** `draw_id`/`expires_at`, and **no** client-side billing-authorize or drawn-price confirmation in the web reference (confirmed by `MessageBubble.lottery.test.tsx`). The Android design's two-step lottery flow is incorrect and is being corrected to the single call. Whether the lottery carries a charge at all is server-side/feature-flagged (`messaging_dm_lottery`); if a *priced* lottery confirmation is later required, it needs a new backend endpoint (not present today).
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

## 16. Citations & Assumption Audit

Each key technical claim with its VERDICT (Verified / Corrected / Unverified-assumption) and exact SOURCE pointer.

1. **Unlock endpoint path/method.** Claim (orig): `POST /messages/{id}/unlock`. VERDICT: **Corrected** to `POST /messaging/conversations/{conversation_id}/messages/{message_id}/unlock`. SOURCE: OpenAPI `POST /messaging/conversations/{conversation_id}/messages/{message_id}/unlock` (op `unlock_message_messaging_...`); `src/api/endpoints/messaging.ts: unlockMessage`.
2. **Unlock request body.** Claim (orig): `{ payment_token, client_id }`. VERDICT: **Corrected** to `UnlockMessageIn { payment_method_id?: string|null }` (only field; no `client_id`). SOURCE: OpenAPI schema `UnlockMessageIn`; `src/api/endpoints/messaging.ts: unlockMessage` (`{ payment_method_id: paymentMethodId ?? null }`).
3. **Unlock response = revealed message.** Claim (orig): returns the revealed `Message` with `monetization.unlocked=true` and `body`. VERDICT: **Corrected** — returns receipt only (`UnlockOut { ok, conversation_id, message_id, unlock_payment_id, amount_cents }`); client must re-fetch to reveal. SOURCE: OpenAPI schema `UnlockOut`; `src/pages/messages/MessageBubble.tsx: unlockMut.onSuccess` invalidates `["messages", conversationId]`.
4. **Tip endpoint path/method.** Claim (orig): `POST /messages/{id}/tip`. VERDICT: **Corrected** to `POST /messaging/conversations/{conversation_id}/messages/{message_id}/tip`. SOURCE: OpenAPI `POST /messaging/conversations/{conversation_id}/messages/{message_id}/tip` (op `send_message_tip_messaging_...`); `src/api/endpoints/messaging.ts: sendMessageTip`.
5. **Tip request body.** Claim (orig): `{ payment_token, amount_minor, currency, note, client_id }`. VERDICT: **Corrected** to `SendTipIn { amount_cents (required, 1..100000), currency (default "USD"), note? (max 500), payment_method_id? }`; no `client_id`. SOURCE: OpenAPI schema `SendTipIn`; `src/api/types.ts: SendTipReq`.
6. **Tip response.** Claim (orig): `{ tip_id, message_id, amount_minor, currency, created_at }`. VERDICT: **Corrected** to `TipOut { ok, conversation_id, message_id, tip_payment_id, amount_cents, currency }` (no `tip_id`, no `created_at`, uses `amount_cents`). SOURCE: OpenAPI schema `TipOut`; `src/api/endpoints/messaging.ts: sendMessageTip` return type.
7. **Tip note max length.** Claim (orig): 200 chars. VERDICT: **Corrected** to 500. SOURCE: OpenAPI `SendTipIn.note` `maxLength: 500`.
8. **Tip amount bounds.** Claim (orig): max 500.00. VERDICT: **Corrected** to min 1 cent / max 100000 cents ($1000.00). SOURCE: OpenAPI `SendTipIn.amount_cents` `minimum:1, maximum:100000`; web `cents = Math.round(parseFloat(...)*100)` with `cents < 1` rejected (`MessageBubble.tsx`).
9. **Money field naming.** Claim (orig): `amount_minor`/`price_minor`. VERDICT: **Corrected** to `amount_cents`/`lock_price_cents` (wire); internal Android `*Cents`/minor-units modeling is fine. SOURCE: OpenAPI `SendTipIn`/`TipOut`/`UnlockOut`; `src/api/types.ts: Message.lock_price_cents`.
10. **Paid-message metadata shape.** Claim (orig): nested `Message.monetization { type, unlocked, price_minor, teaser, teaser_image_url, tip_eligible }`. VERDICT: **Corrected** — backend uses **flat** `Message` fields `lock_price_cents`, `lock_description`, `locked`, `is_unlocked`, `tip_amount_cents`, `tip_currency`, plus a separate `lottery` sub-object. No `monetization`, `teaser`, `teaser_image_url`, or `tip_eligible` fields exist. SOURCE: `src/api/types.ts: Message` (lines ~1171–1216).
11. **Billing seam token.** Claim (orig): opaque `payment_token`. VERDICT: **Corrected** — the seam is a `payment_method_id` (selected payment method), supplied by billing (`getPaymentMethods`). SOURCE: `src/api/endpoints/billing.ts: getPaymentMethods` (used in `MessageBubble.tsx`); request fields `payment_method_id`.
12. **Lottery unlock protocol.** Claim (orig): two-step resolve→confirm-drawn-price→authorize→finalize, with `draw_id`/`expires_at`. VERDICT: **Corrected** — single atomic `POST /messaging/messages/{message_id}/lottery/unlock` (empty body) → `LotteryUnlockOut { message_id, lock_state, selected_outcome, unlocked_at }`; no draw_id/expires_at, no client billing-authorize, no confirm dialog. SOURCE: OpenAPI `POST /messaging/messages/{message_id}/lottery/unlock` + schema `LotteryUnlockOut`; `src/api/endpoints/messaging.ts: unlockLotteryMessage`; `src/pages/messages/MessageBubble.lottery.test.tsx`.
13. **Lottery is a separate message type.** Claim (orig): a `monetization.type == LOTTERY` variant of the same unlock. VERDICT: **Corrected** — lottery is its own `lottery_dm` message (created via `POST /messaging/messages/lottery`, read via `GET /messaging/messages/{message_id}/lottery`), distinct from fixed-price locked messages. SOURCE: OpenAPI `LotteryMessageOut`, `CreateLotteryMessageIn`; `src/api/types.ts: LotteryMessage`, `Message.lottery`.
14. **`unlocked_at`/`created_at` types.** Claim (orig implied ISO-8601 strings, e.g. `created_at: "...Z"`). VERDICT: **Corrected** — lottery `unlocked_at`/`created_at` are **integer epoch** values. SOURCE: OpenAPI `LotteryUnlockOut.unlocked_at` (`type: integer`), `LotteryMessageOut.created_at` (`type: integer`).
15. **Auth/CSRF transport.** Claim (orig): "cookie-based auth: session cookies + `ui_csrf` echoed as `X-CSRF-Token`; 401→`POST /ui/session/refresh` once". VERDICT: **Corrected/clarified** — also sends `Authorization: Bearer <accessToken>` and `X-SESSION-ID`; `credentials: include` for cookies; single refresh-on-401 confirmed. SOURCE: `src/api/client.ts` (`Authorization` header, `getCookie("ui_csrf")` → `X-CSRF-Token`, `refreshSession()` → `/ui/session/refresh`); OpenAPI params `authorization, X-SESSION-ID` on the messaging endpoints.
16. **Own-message guard (FR-10).** Claim: own messages not offered tip/unlock. VERDICT: **Verified.** SOURCE: `src/pages/messages/MessageBubble.tsx` payment-methods query `enabled: !isOwn`; `isOwn` prop gating tip/unlock affordances.
17. **Error `detail` shapes.** Claim: `string | [{msg,...}] | {code,...}`. VERDICT: **Verified.** SOURCE: `src/api/client.ts: normalizeErrorDetail` (+ `mapAuthorizationError` `{code}` handling); OpenAPI `HTTPValidationError` (`detail: [{msg, loc, type}]`).
18. **Documented error codes for these ops.** Claim (orig): `402/409/410` handled. VERDICT: **Unverified-assumption** — OpenAPI documents only `200` + `422` for `/unlock`,`/tip`,`/lottery/unlock` (siblings add `400/401/403/429`). `402/409/410` are not in the contract. SOURCE: OpenAPI index lines for the three ops (`resp=200:...;422:HTTPValidationError`).
19. **Idempotency via `client_id`.** Claim (orig): client_id dedupes tip/unlock; retry reuses it. VERDICT: **Corrected/Unverified** — no `client_id`/`Idempotency-Key` exists on these two endpoints; only lottery-**create** uses `Idempotency-Key`. Safe retry requires backend coordination. SOURCE: OpenAPI `SendTipIn`/`UnlockMessageIn` (no such field); `POST /messaging/messages/lottery` `params=Idempotency-Key`; `src/api/endpoints/messaging.test` (`messaging.lottery.test.ts`) header assertions.
20. **Gated content never shipped while locked (OQ-3).** Claim: locked DTO must not include gated body/media. VERDICT: **Unverified-assumption** (security) — not provable from the static sources; the locked `Message` exposes `lock_description`/preview only and the revealed body arrives on re-fetch, which is consistent, but a live backend probe is needed to confirm the server never leaks gated `body`/media at `locked == true`. SOURCE: `src/api/types.ts: Message` (separate `lock_description` vs `text`); no contract field guarantees exclusion.
21. **Stack/Compose/Hilt/Retrofit choices.** VERDICT: **Unverified-assumption** (framework refs, not derivable from backend/web sources). Android Compose Material 3 `ModalBottomSheet`/`AlertDialog`, accessibility semantics, and 48dp targets follow framework guidance — framework ref: developer.android.com/jetpack/compose, developer.android.com/guide/topics/ui/accessibility.

### Corrections made
- Endpoints repathed from flat `/messages/{id}/{tip,unlock}` to conversation-scoped `/messaging/conversations/{conversation_id}/messages/{message_id}/{tip,unlock}` (items 1,4).
- Request fields: `payment_token`→`payment_method_id`; `amount_minor`→`amount_cents`; removed non-existent `client_id` (items 2,5,11,19).
- Unlock response: revealed-`Message` → receipt-only `UnlockOut`; added mandatory re-fetch to reveal (item 3); FR-3, §4.4, §4.5 updated.
- Tip response: invented `{tip_id, created_at, amount_minor}` → real `TipOut` (item 6).
- Note max 200→500 (item 7); amount max $500→$1000/100000 cents (item 8).
- Paid-message shape: nested `monetization` (+ `teaser`/`teaser_image_url`/`tip_eligible`/`type`) → flat `lock_*`/`is_unlocked`/`locked`/`tip_*` fields + separate `lottery` block (items 10,13); FR-1, FR-2 updated.
- Lottery: removed the two-step resolve/confirm/finalize, `draw_id`/`expires_at`, `RESOLVING` phase, `resolveLottery`, `onLotteryConfirm`, and the drawn-price `AlertDialog`; replaced with the single empty-body `lottery/unlock` call returning `selected_outcome` (item 12); FR-4, §4.4, §4.5, OQ-2 updated.
- Auth description expanded to include Bearer token + `X-SESSION-ID` (item 15).
- Error-code table: flagged `402/409/410` as undocumented assumptions; kept verified `401/403/422/429` (item 18).
- Moshi DTOs + Retrofit interface in §5 rewritten to the verified schemas; repository interface in §4.5 rewritten (`payment_method_id`, `amount_cents`, re-fetch, single lottery call).
- Frontmatter: `status: reviewed`, `reviewed_on: 2026-06-06`.

### Open assumptions
- **OQ-1 idempotency gap:** no `client_id`/`Idempotency-Key` on `/unlock` or `/tip` in the contract, so retry-after-uncertain-failure is not provably dedupe-safe. Unverifiable as safe without a backend change; item 19.
- **OQ-3 gated-content confidentiality:** cannot be proven from static OpenAPI/web sources that the server never returns gated `body`/media while `locked==true`; requires a live probe against the dev host (item 20). Treated as a security must-verify.
- **Undocumented error codes (`402/409/410`):** not in OpenAPI; behavior on payment-declined / already-unlocked / lottery-expired is unknown and assumed (item 18).
- **Whether lottery unlock charges the viewer at all** is server-side/feature-flagged and not exposed in the contract; if a priced/confirmed lottery is required, a new endpoint must be added (item 12, OQ-2).
- **Billing seam (AND-031) semantics** — whether `authorize` yields a reusable, capture-deferred `payment_method_id` — remains an AND-031 cross-team agreement (OQ-4); framework-internal, not in these sources.
- **Stack/framework choices** (Compose, Hilt, Retrofit/Moshi) are inherited project conventions; framework refs only (item 21).

## 17. Test Plan

IDs `TC-AND-139-NN`. "Traces" links to §14 Acceptance Criteria. Targets: JVM = local JVM/Robolectric; Emulator = headless AVD `test35` (x86_64, API 35); Device = physical Samsung Galaxy A15 5G (SM-A156U, API 34, arm64-v8a). MockWebServer + `FakeBillingAuthorizer`; no live dev-host or live-payment calls in CI.

- **TC-AND-139-01 — Fixed unlock happy path (re-fetch reveals body).** Type: unit + contract/MockWebServer. Target: JVM. Preconditions: locked `Message` (`locked=true,is_unlocked=false,lock_price_cents=500`); `FakeBillingAuthorizer` returns `Authorized(payment_method_id="pm_1")`; MockWebServer queues `200 UnlockOut {ok:true,...,amount_cents:500}` for `POST .../unlock` then `200` revealed message for the subsequent fetch. Steps: call `onUnlockClick(id)`; await phases. Expected: authorize called once; `POST .../unlock` body == `{"payment_method_id":"pm_1"}`; on receipt the repo issues the message re-fetch; row reconciles to `is_unlocked=true` with revealed body; phase returns IDLE; no revealed body assumed from the unlock response. Traces: AC-2.
- **TC-AND-139-02 — Unlock request transport headers.** Type: contract/MockWebServer. Target: JVM. Preconditions: authed session (Bearer token + `ui_csrf`). Steps: trigger unlock; inspect recorded request. Expected: request carries `Authorization: Bearer ...`, `X-CSRF-Token`, `X-SESSION-ID`, `Content-Type: application/json`; path is conversation-scoped. Traces: AC-2, AC-5.
- **TC-AND-139-03 — Billing Cancelled isolates server.** Type: unit. Target: JVM. Preconditions: `FakeBillingAuthorizer` → `Cancelled`. Steps: `onUnlockClick`. Expected: no `/unlock` request issued (MockWebServer records 0 calls); phase IDLE; row stays locked; no error toast. Traces: AC-5.
- **TC-AND-139-04 — Billing Declined surfaced distinctly.** Type: unit. Target: JVM. Preconditions: `FakeBillingAuthorizer` → `Declined("card_declined")`. Steps: `onUnlockClick`. Expected: no `/unlock` call; phase FAILED with `UiError.PaymentDeclined`, message distinct from server-error copy; row locked. Traces: AC-5.
- **TC-AND-139-05 — Unlock server 5xx/timeout after authorize (uncertain failure).** Type: contract/MockWebServer. Target: JVM. Preconditions: authorize Authorized; MockWebServer returns `500` (and a variant with socket timeout ~20s policy). Steps: `onUnlockClick`; observe. Expected: phase FAILED with retryable server-error copy ("couldn't reach server"), distinct from declined; row remains locked; **retry is user-gated** and the plan notes the no-`client_id` dedupe gap (no silent auto-retry). Traces: AC-5, AC-2.
- **TC-AND-139-06 — Tip happy path + receipt mapping.** Type: unit + contract/MockWebServer. Target: JVM. Preconditions: tip sheet open on another user's message; preset 500¢ selected; authorize Authorized("pm_1"); MockWebServer `200 TipOut`. Steps: `onTipConfirm`. Expected: `POST .../tip` body == `{"amount_cents":500,"currency":"USD","note":...,"payment_method_id":"pm_1"}`; on success sheet closes, confirmation emitted, row marked tipped; `TipOut` fields mapped (`tip_payment_id`, `amount_cents`). Traces: AC-4.
- **TC-AND-139-07 — Tip amount validation bounds.** Type: unit + Compose-UI. Target: JVM (logic) + Emulator (UI). Preconditions: tip sheet open. Steps: enter custom `0`, then `100001`¢-equivalent ($1000.01), then valid `750`¢; observe confirm enablement and inline error. Expected: `0`/over-max blocked with inline error and disabled confirm; valid amount enables confirm; `amount_cents` sent as integer (no float/string). Traces: AC-4.
- **TC-AND-139-08 — Tip failure preserves sheet + amount.** Type: unit. Target: JVM. Preconditions: authorize Authorized; MockWebServer `422 {detail:[{msg:"amount out of range",loc:[...]}]}`. Steps: `onTipConfirm`. Expected: sheet stays open, amount/note preserved, first `msg` shown; retry affordance present. Traces: AC-4, AC-5.
- **TC-AND-139-09 — Lottery single-call unlock + reveal.** Type: unit + contract/MockWebServer. Target: JVM. Preconditions: `lottery_dm` message `lock_state=locked`; MockWebServer `200 LotteryUnlockOut {selected_outcome:{payload_type:"text",text_content:"win"},unlocked_at:...}`. Steps: `onUnlockClick` (lottery). Expected: exactly one `POST /messaging/messages/{id}/lottery/unlock` with **empty body**; **no** `BillingAuthorizer.authorize` call; **no** resolve/confirm step or drawn-price dialog; row reveals `selected_outcome`; hydration re-fetch via `getLotteryMessage` reconciles. Traces: AC-3.
- **TC-AND-139-10 — Lottery unlock error + user retry.** Type: unit + Compose-UI. Target: JVM + Emulator. Preconditions: first `lottery/unlock` fails (`500`), second succeeds. Steps: tap Unlock → see error → tap Unlock again. Expected: "Unlock failed" shown; second tap re-issues the call; success reveals outcome; retry is explicit (mirrors `MessageBubble.lottery.test.tsx`). Traces: AC-3, AC-5.
- **TC-AND-139-11 — Own-message affordance suppression.** Type: unit + Compose-UI. Target: JVM + Emulator. Preconditions: message authored by current user (`isOwn`); paid + lottery variants. Steps: render row, open overflow. Expected: no Tip/Unlock affordance offered; own paid message renders revealed (no purchase prompt). Traces: AC-6.
- **TC-AND-139-12 — Locked teaser never renders gated body (UI + semantics).** Type: Compose-UI. Target: Emulator. Preconditions: locked message with `lock_price_cents=500`, `lock_description="preview"`, gated `body` absent. Steps: render `LockedMessageItem`; inspect node + semantics tree. Expected: shows formatted price ("$5.00") + Unlock button + `lock_description`; gated body/media not present in the rendered tree or semantics; in-progress state announced via `stateDescription` (not spinner-only). Traces: AC-1, AC-7.
- **TC-AND-139-13 — Unlock state persists across restart (DAO).** Type: integration (Room in-memory) + instrumented. Target: JVM (Room) / Emulator (process recreation). Preconditions: message unlocked & revealed body written to `MessageDao`. Steps: round-trip entity; simulate process death/reopen; re-read. Expected: monetization columns + `is_unlocked=true` and revealed body persist (server-authoritative, no local-only flag); reveal supersedes locked row by `id`. Traces: AC-2.
- **TC-AND-139-14 — Offline / flaky-dev-host write guard.** Type: integration. Target: Device (toggle airplane mode / real flaky network). Preconditions: no connectivity (or dev-host timeout). Steps: attempt unlock and tip. Expected: writes are disabled or fail-fast to FAILED with "No connection" (non-idempotent writes are never queued/auto-retried); on reconnect, user-initiated retry works. Best on the **physical device** for real radio/offline behavior. Traces: AC-5.
- **TC-AND-139-15 — Security: payment id / note never logged or persisted.** Type: unit + manual. Target: JVM + Device. Preconditions: BASIC logging in release; run a tip+unlock. Steps: capture logcat (device) and inspect DB/prefs. Expected: `payment_method_id`, tip note, and cookies absent from logcat/telemetry; no card data in this module; tip note not in analytics payloads. Device run confirms real release logging behavior. Traces: AC-5 (security), AC-7.
- **TC-AND-139-16 — Accessibility audit (Compose-UI).** Type: Compose-UI + manual TalkBack. Target: Emulator (automated) + Device (TalkBack). Preconditions: locked teaser + tip sheet rendered. Steps: assert `contentDescription` includes price ("Unlock for $5.00"); preset chips labeled with `selected` semantics; note field labeled with counter; touch targets ≥48dp; RTL render. Manual TalkBack pass on device for the unlock + tip + lottery-reveal flows. Expected: all semantics present; no color/spinner-only state. Traces: AC-1, AC-4.

### Coverage matrix
- **AC-1** (locked teaser shows price + Unlock, hides gated body; already-unlocked renders revealed): TC-12, TC-16.
- **AC-2** (fixed unlock → authorize → POST unlock → re-fetch reveal; persists across restart): TC-01, TC-02, TC-05, TC-13.
- **AC-3** (lottery single-call draw+reveal, no charge-before-confirm semantics): TC-09, TC-10.
- **AC-4** (tip via sheet, preset/validated custom, confirmation on success; out-of-range blocked): TC-06, TC-07, TC-08, TC-16.
- **AC-5** (billing failures isolate server; distinct error copy; server failure preserves state with user-gated retry): TC-02, TC-03, TC-04, TC-05, TC-08, TC-14, TC-15.
- **AC-6** (no tip/unlock on own messages): TC-11.
- **AC-7** (automated coverage of unlock, lottery, tip+validation, billing-cancel/decline isolation, uncertain-failure retry, locked-body-not-rendered, all against Fake + MockWebServer, no live calls): TC-01, TC-03, TC-04, TC-05, TC-06, TC-07, TC-09, TC-12, TC-15.
