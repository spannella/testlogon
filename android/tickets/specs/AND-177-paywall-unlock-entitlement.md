---
id: AND-177
title: Paywall unlock & entitlement
milestone: M4
epic: E24
priority: P0
size: L
status: draft
depends_on: [AND-101, AND-031]
blocks: []
---

# AND-177 — Paywall unlock & entitlement

## 1. Overview & Goal

AND-101 (M2) shipped the **locked-content display**: a post flagged `locked == true`
renders a paywall placeholder (blurred/redacted body, price chip, unlock CTA) instead of
its real media/body. This ticket (M4 / E24) implements the **action behind that CTA**:
purchasing/unlocking a single locked post, persisting the resulting **entitlement**, and
**revealing** the previously hidden content in place without a full screen reload.

Goal: when a signed-in user taps "Unlock" on a fixed-price locked post, the app calls the
backend `POST /posts/unlock` endpoint, processes the returned `payment_intent` through a
**pluggable payment provider** (a deterministic stub in this milestone — real CCBill/PayPal
is out of scope), confirms the entitlement, caches it durably (Room), and transitions the
post's UI from `Locked` → `Unlocking` → `Unlocked` so the genuine content appears. The
entitlement cache means a relaunch or a fresh feed fetch shows the post already unlocked
without re-charging.

Non-goals: real payment SDK integration, subscription/membership tiers, tip-lottery unlock
(`lock_type == "tip_lottery"`), message/broadcast unlock (`/messaging/.../unlock`,
`/broadcast/.../unlock`), refunds, and the payment-method management UI
(`/api/billing/payment-methods`). This ticket targets `lock_type == "fixed_price"` only and
consumes whatever default payment method the backend resolves server-side when
`payment_method_id` is omitted.

## 2. Context & References

- **Module:** `feature-paywall` (created in AND-101) with new use cases/repository methods
  in `core-data`; DTOs/models in `core-model`; Retrofit service in `core-network`.
- **Package base:** `com.testlogon.android` (e.g. `com.testlogon.android.feature.paywall`,
  `com.testlogon.android.core.data.paywall`).
- **Depends on:**
  - **AND-101 — Paywall / locked display:** owns `PaywallPlaceholder` composable, the
    `locked`/`unlock_price_cents`/`lock_type` post fields, and the unlock CTA hook this
    ticket binds to. AND-101 explicitly deferred unlock to "M4 E24" = this ticket.
  - **AND-031 — LoginViewModel:** establishes the cookie-based session + `ui_csrf`/
    `X-CSRF-Token` handling and the `ApiResult<T>` + FastAPI `detail` mapping conventions
    reused here. Unlock requires an authenticated session (the CSRF header is mandatory on
    this state-changing POST).
- **Backend reference:** FastAPI `unlock_post_posts_unlock_post` →
  `POST /posts/unlock`, schemas `UnlockPostRequest` / `UnlockPostResponse`; post lock fields
  live on `PostResponse`. Web reference: `frontend/src/api/endpoints/*.ts`,
  `frontend/src/api/types.ts`. Dev backend `http://18.222.237.167:8000` (plaintext, flaky).
- **Stack:** Kotlin 2.0.21, Compose + Material 3, Hilt (KSP), Retrofit 2.11 / OkHttp 4.12 /
  Moshi 1.15, Room 2.6, DataStore, Coroutines/Flow. minSdk 24 / target 35, JDK 17.

## 3. Functional Requirements

FR-1. On a `fixed_price` locked post, tapping the AND-101 unlock CTA invokes
`PaywallViewModel.unlock(postId)`. The CTA is disabled while `lock_type` is null/unsupported
or `unlock_price_cents == null`.

FR-2. The unlock flow has explicit, observable states:
`Locked → Unlocking(postId) → (Unlocked | UnlockFailed(reason) | AlreadyEntitled)`.
The CTA shows an inline spinner and is disabled during `Unlocking`; it is not globally
blocking (the rest of the feed stays scrollable).

FR-3. On success the post content is **revealed in place**: the same post item re-renders
with `locked = false` (real body + media via the existing Coil/Media3 paths). No navigation
push; the feed scroll position is preserved.

FR-4. The entitlement is **cached durably** keyed by `(userSub, postId)`. A subsequent feed
load, post detail open, process death + relaunch, or offline open of the same post shows it
**already unlocked** without calling `/posts/unlock` again.

FR-5. The unlock request is **idempotent**: the client generates a stable
`idempotency_key` per `(postId, attempt-session)` so retrying a timed-out request does not
double-charge. A second tap while `Unlocking` is a no-op.

FR-6. If the backend reports the post is already entitled (200 with an already-paid
`payment_intent.status`, or the refreshed post returns `locked == false`), the app treats it
as `AlreadyEntitled`, writes/refreshes the cache, and reveals content — no error shown.

FR-7. `unlock_limit_reached == true` (sold-out) disables the CTA and shows a non-error
"No longer available" affordance instead of attempting unlock.

FR-8. Payment is handled behind a `PaymentProcessor` abstraction. In M4 the bound
implementation is `StubPaymentProcessor` which deterministically "confirms" any
`payment_intent` (and can be forced to fail/timeout via test seams). The interface is shaped
so a real provider can replace it without touching the ViewModel/repository.

## 4. Technical Design

**Layering:** `feature-paywall` (UI + ViewModel) → `core-data` (`PaywallRepository`,
`PaymentProcessor`, Room DAO) → `core-network` (`PaywallApi`) and `core-model` (DTO/domain).

**UI state (feature-paywall):**

```kotlin
sealed interface UnlockState {
    data object Idle : UnlockState                       // locked, ready
    data class InProgress(val postId: String) : UnlockState
    data class Unlocked(val postId: String) : UnlockState
    data object SoldOut : UnlockState                     // unlock_limit_reached
    data class Failed(val postId: String, val message: String, val retryable: Boolean) : UnlockState
}

data class PaywallUiState(
    val unlock: UnlockState = UnlockState.Idle,
    val priceCents: Int? = null,
    val ctaEnabled: Boolean = false,
)
```

```kotlin
@HiltViewModel
class PaywallViewModel @Inject constructor(
    private val repo: PaywallRepository,
    @ApplicationScope private val appScope: CoroutineScope,
) : ViewModel() {
    private val _state = MutableStateFlow(PaywallUiState())
    val state: StateFlow<PaywallUiState> = _state.asStateFlow()

    fun bind(post: PostUi)            // seeds price/ctaEnabled from post lock fields
    fun unlock(postId: String)        // launches unlock flow; idempotent re-entry guard
    fun retry(postId: String)
}
```

**Repository + payment abstraction (core-data):**

```kotlin
interface PaymentProcessor {
    suspend fun confirm(intent: PaymentIntent): PaymentResult   // stub in M4
}

sealed interface UnlockOutcome {
    data class Success(val postId: String) : UnlockOutcome
    data object AlreadyEntitled : UnlockOutcome
    data class Failure(val message: String, val retryable: Boolean) : UnlockOutcome
}

class PaywallRepository @Inject constructor(
    private val api: PaywallApi,
    private val payments: PaymentProcessor,
    private val dao: EntitlementDao,
    private val session: SessionProvider,          // supplies current userSub
    private val idem: IdempotencyKeyStore,
) {
    fun isEntitled(postId: String): Flow<Boolean>   // observes Room
    suspend fun unlock(postId: String): UnlockOutcome
}
```

`PaywallRepository.unlock` sequence:
1. Short-circuit if `dao.find(userSub, postId)` already entitled → `AlreadyEntitled`.
2. `idem.keyFor(postId)` → stable `idempotency_key` (persisted in DataStore until success).
3. `api.unlock(UnlockPostRequest(postId, paymentMethodId = null, idempotencyKey))`.
4. Map `ApiResult`. On 200, run `payments.confirm(resp.paymentIntent)` (stub).
5. On confirmed/already-paid intent: `dao.upsert(EntitlementEntity(userSub, postId, now))`,
   clear the idempotency key, return `Success`.
6. Emit through `isEntitled(postId)` so the feed item recomposes to `locked = false`.

**Reveal mechanism:** the feed/detail item observes `repo.isEntitled(postId)` (combined with
the server `locked` flag). When entitled, the item renders the real content branch and skips
the AND-101 placeholder. No new screen; pure recomposition.

## 5. API Contract

**Unlock — `POST /posts/unlock`** (auth required; cookies + `X-CSRF-Token`).

Request (`UnlockPostRequest`):
```json
{ "post_id": "p_123", "payment_method_id": null, "idempotency_key": "unlock:p_123:8f2a" }
```
- `post_id` (string, required). `payment_method_id` (string|null) — omitted; server resolves
  default. `idempotency_key` (string|null, `^[A-Za-z0-9:_.-]+$`, 1–128 chars).

Response 200 (`UnlockPostResponse`):
```json
{ "post_id": "p_123", "payment_intent": { "status": "...", "...": "..." } }
```
- `payment_intent` is `additionalProperties: true` (opaque). The stub inspects `status`
  (e.g. `succeeded`/`requires_action`/`processing`) and otherwise treats a returned intent
  on a 200 as confirmable. Real provider would action `requires_action`.

Errors (FastAPI `detail`, mapped per AND-031 conventions): `401` → refresh-once-then-retry
via `POST /ui/session/refresh`; `402`/`409` (payment declined / already unlocked / sold-out)
→ map to friendly message, `409 already unlocked` → `AlreadyEntitled`; `422`
(`HTTPValidationError`, array of `{msg}`) → first `msg`. `detail` may be `string`,
`[{msg}]`, or `{code,...}`.

**Reveal/refresh — `GET /posts/{post_id}`** returns `PostResponse` whose lock fields drive
display: `locked` (bool), `lock_type` (`fixed_price|tip_lottery|null`), `unlock_price_cents`
(int|null), `unlock_count` (int), `unlock_limit` (int|null), `unlock_limit_reached` (bool).
After a successful unlock the client may re-GET the post to obtain `locked == false` with the
real body; the entitlement cache is the primary reveal trigger, this GET reconciles content.

`DELETE`/refund endpoints: N/A for this ticket.

## 6. Data & State Management

**Room (core-data, cache DB):**

```kotlin
@Entity(primaryKey-composite via @Entity(primaryKeys = ["userSub","postId"]))
data class EntitlementEntity(
    val userSub: String,
    val postId: String,
    val unlockedAtEpochMs: Long,
    val source: String = "purchase",   // purchase | already_entitled | sync
)

@Dao interface EntitlementDao {
    @Query("SELECT EXISTS(SELECT 1 FROM entitlement WHERE userSub=:u AND postId=:p)")
    fun isEntitled(u: String, p: String): Flow<Boolean>
    @Upsert suspend fun upsert(e: EntitlementEntity)
    @Query("DELETE FROM entitlement WHERE userSub=:u") suspend fun clearForUser(u: String)
}
```

- **Keying by `userSub`** prevents leaking one user's entitlements to another on the same
  device; `clearForUser` runs on logout/account switch.
- **DataStore** holds the per-post `idempotency_key` (cleared on success) and is the prefs
  store; entitlements themselves live in Room (queryable, joinable to cached posts).
- **Source of truth for display:** server `locked` flag AND/OR a local entitlement row.
  Effective `isUnlocked = !serverLocked || cachedEntitlement`. Server is authoritative when
  online; cache provides offline/stale reveal of content the user already paid for.
- All ViewModel state is a single `StateFlow<PaywallUiState>`; no mutable shared state.

## 7. Error Handling & Resilience

- **Timeouts:** unlock POST uses the standard ~20s OkHttp timeout. `POST /posts/unlock` is
  **not idempotent-by-method** (it is a POST), so the client does **not** auto-retry it on
  network failure; instead it surfaces `Failed(retryable=true)` and relies on the stable
  `idempotency_key` so a user-initiated retry is safe against double-charge.
- **401:** call `POST /ui/session/refresh` once then retry the original unlock once (AND-031
  pattern). A second 401 → `Failed(retryable=false)` with a "please sign in again" message.
- **Declined (402):** `Failed(retryable=true)`, message from `detail`.
- **Already unlocked / race (409):** resolve to `AlreadyEntitled`, write cache, reveal — no
  error toast.
- **Sold out (`unlock_limit_reached` or 409 sold-out):** `SoldOut`, CTA replaced by
  "No longer available".
- **Offline:** if entitlement is cached, content reveals normally. If not cached and offline,
  the unlock attempt fails fast with an offline message; CTA re-enables for retry.
- **Stub payment failure/timeout:** mapped to `Failed(retryable=true)`; idempotency key
  retained so retry reuses it.
- **Partial success (charged but reveal GET failed):** entitlement is still written on a
  confirmed intent; the reveal GET is best-effort and retried lazily on next view.

## 8. Security & Privacy

- Unlock is a **state-changing POST**: the persistent cookie jar + `X-CSRF-Token`
  (echoed from `ui_csrf`) are required; requests without CSRF must not be sent.
- No card/PAN data touches the app in M4 (stub only); `payment_method_id` is an opaque server
  token, never a raw instrument. No payment secrets are logged.
- Entitlement rows are partitioned by `userSub` and wiped on logout/account switch so a
  shared device cannot reveal another user's paid content.
- `idempotency_key` contains only the post id + a random nonce; no PII.
- Dev backend is **plaintext HTTP**; this is a known dev-only constraint. Production builds
  must use HTTPS (enforced by network-security config from the networking ticket); no payment
  flow ships against cleartext in release.

## 9. Accessibility & i18n

- CTA button has a `contentDescription`/semantics label including the localized price
  ("Unlock for $4.99"); the spinner state announces "Unlocking…" via `liveRegion`.
- Success reveal moves focus sensibly and announces "Content unlocked".
- Price formatting uses `unlock_price_cents` → locale currency via `NumberFormat`
  /`java.util.Currency` (no hard-coded `$`). Currency code TBD (see Open Questions).
- All strings (`paywall_unlock_cta`, `paywall_unlocking`, `paywall_sold_out`,
  `paywall_unlock_failed`, `paywall_already_owned`) live in `strings.xml`; no literals in
  Compose. Touch targets ≥ 48dp; states meet Material 3 contrast.

## 10. Telemetry & Logging

- Events (no PII, no payment detail): `paywall_unlock_tapped {postId, priceCents}`,
  `paywall_unlock_succeeded {postId, latencyMs, source}`,
  `paywall_unlock_failed {postId, reason, httpStatus}`,
  `paywall_already_entitled {postId}`.
- Logging via the project Timber-style wrapper at `DEBUG`; redact cookies, CSRF token, and
  the full `payment_intent` body (log only `status`).
- Counters: unlock success rate, decline rate, 401-refresh-then-retry rate to monitor the
  flaky dev host.

## 11. Testing Strategy

Acceptance is **"tested w/ payment stub"**, so the stub is the primary test seam.

- **Unit — `PaywallRepository` (core-testing + Turbine + MockWebServer):**
  - 200 + confirmable intent → `Success`, Room upserts, idempotency key cleared.
  - cached entitlement present → short-circuits, no HTTP call.
  - 409 already-unlocked → `AlreadyEntitled` + cache write, no error.
  - 402 declined → `Failure(retryable=true)`.
  - 401 → one refresh call then retry; second 401 → non-retryable failure.
  - stub forced-fail / forced-timeout → `Failure`, idempotency key retained.
  - same `idempotency_key` reused across retry of one post/session.
- **Unit — `PaywallViewModel`:** state machine `Idle→InProgress→Unlocked/Failed/SoldOut`;
  double-tap during `InProgress` is a no-op; `unlock_limit_reached` → `SoldOut`, CTA disabled.
- **Room:** `EntitlementDao` upsert/isEntitled/clearForUser; per-`userSub` isolation;
  in-memory DB.
- **Compose UI test:** locked item shows placeholder → tap CTA → spinner → real content
  renders, scroll position preserved; sold-out shows "No longer available".
- **Persistence test:** unlock, kill ViewModel/recreate (simulate process death) → post still
  unlocked from cache with no new `/posts/unlock` call.
- `StubPaymentProcessor` exposed as a Hilt test binding with `succeed/decline/timeout` modes.

## 12. Dependencies & Sequencing

- **Blocks on AND-101** (paywall placeholder + lock fields + CTA hook) and **AND-031**
  (session/CSRF + `ApiResult`/`detail` conventions). Also implicitly relies on the
  established `core-network` Retrofit/OkHttp cookie-jar + Room cache DB and the feed/post
  rendering tickets that own `PostResponse` mapping and Media3/Coil content rendering.
- **Sequencing:** (1) `PaywallApi` + DTOs in core-network/core-model; (2) `EntitlementDao` +
  Room migration; (3) `PaymentProcessor` + `StubPaymentProcessor` + Hilt module; (4)
  `PaywallRepository`; (5) `PaywallViewModel` + bind CTA in AND-101 composable; (6) reveal
  wiring via `isEntitled`; (7) tests.
- **Blocks:** none currently; a future real-payment-provider ticket (CCBill/PayPal) will
  replace `StubPaymentProcessor` and consume this interface.

## 13. Risks & Open Questions

- **Opaque `payment_intent`:** `additionalProperties: true` — exact `status` values and any
  `requires_action`/3DS shape are unknown. Q: confirm enum of `payment_intent.status` from a
  live `/posts/unlock` call before finalizing the stub's confirm logic.
- **Currency:** `unlock_price_cents` has no co-located currency code on `PostResponse`.
  Q: is price always a single tenant currency, or is there a `currency` field on
  `/ui/me`/tenant config? Affects i18n formatting.
- **Idempotency semantics:** confirm the backend honors `idempotency_key` for replays and
  returns the same outcome (200/409) rather than re-charging.
- **Default payment method:** when `payment_method_id` is null, confirm the backend resolves
  a default and what error it returns when none exists (likely 402/409) so we can route users
  to the (out-of-scope) payment-method UI in a later ticket.
- **Reveal data freshness:** whether the unlock 200 ever returns the unlocked post inline, or
  a follow-up `GET /posts/{id}` is always required.

## 14. Acceptance Criteria

- AC-1 (from backlog): Tapping unlock on a `fixed_price` locked post runs the unlock flow and,
  on success (via payment stub), **reveals the real content in place** with no navigation and
  preserved scroll position.
- AC-2 (from backlog): The entitlement is **cached** (Room, keyed by `userSub`+`postId`); after
  process death/relaunch or a fresh feed load the same post shows unlocked with **no** new
  `POST /posts/unlock` call. Verified by an instrumented/unit test using the payment stub.
- AC-3: Unlock uses `POST /posts/unlock` with `idempotency_key`; retry after a timeout reuses
  the key and does not double-charge (stub asserts single confirm per key).
- AC-4: State machine transitions (`Idle/InProgress/Unlocked/SoldOut/Failed`) and CTA
  enable/disable + spinner are covered by ViewModel unit tests; double-tap is a no-op.
- AC-5: 409 already-unlocked → content revealed with no error; `unlock_limit_reached` →
  "No longer available", CTA disabled.
- AC-6: 401 triggers a single `POST /ui/session/refresh` then one retry; CSRF header present
  on the POST; cookies/CSRF/payment intent body are not logged.
- AC-7: Logout/account switch clears entitlement cache for the previous user.

## 15. Definition of Done

- `feature-paywall` unlock + `core-data` entitlement caching + `core-network` `PaywallApi`
  implemented under `com.testlogon.android.*`; CTA from AND-101 wired to `PaywallViewModel`.
- `StubPaymentProcessor` bound by default in M4; `PaymentProcessor` interface documented for
  the future real provider.
- All AC verified; unit + Room + Compose UI + persistence tests green in CI; coverage on
  repository/ViewModel meets the project threshold.
- No new lint/detekt errors; strings externalized; a11y semantics present.
- Open Questions in §13 either resolved or filed as follow-up tickets; spec linked from the PR
  on branch `android-port`.
