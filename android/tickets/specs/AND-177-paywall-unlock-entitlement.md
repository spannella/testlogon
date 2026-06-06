---
id: AND-177
title: Paywall unlock & entitlement
milestone: M4
epic: E24
priority: P0
size: L
status: reviewed
reviewed_on: 2026-06-06
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
  default. `idempotency_key` (string|null, `^[A-Za-z0-9:_.-]+$`, 1–128 chars). All three field
  names/types/constraints VERIFIED against `components.schemas.UnlockPostRequest`.
- **Web nuance (VERIFIED):** the web client (`src/api/endpoints/newsfeed.ts: unlockPost`) sends
  only `post_id` (+ optional `payment_method_id`) and does **not** send `idempotency_key`. The
  field exists in the OpenAPI schema, so the Android client may send it, but its server-side
  honoring is unverified (see §13 / Open assumptions).

Response 200 (`UnlockPostResponse`): VERIFIED against `components.schemas.UnlockPostResponse`.
```json
{ "post_id": "p_123", "payment_intent": { "status": "...", "...": "..." } }
```
- Both `post_id` (string) and `payment_intent` (object) are **required** in the schema.
- `payment_intent` is `additionalProperties: true` (opaque, no declared inner fields). The stub
  inspects `status` (e.g. `succeeded`/`requires_action`/`processing`) and otherwise treats a
  returned intent on a 200 as confirmable. Real provider would action `requires_action`.
- **CORRECTION / web nuance:** the web reference client (`src/api/endpoints/newsfeed.ts:
  unlockPost`) types this response loosely as `{ ok: boolean }` and does **not** read
  `payment_intent`. The OpenAPI schema is authoritative for the Android port (use
  `UnlockPostResponse`); the `{ ok: boolean }` web typing is stale/loose and must not be copied.

Errors (FastAPI `detail`, mapped per AND-031 conventions): `401` → refresh-once-then-retry
via `POST /ui/session/refresh`; `402`/`409` (payment declined / already unlocked / sold-out)
→ map to friendly message, `409 already unlocked` → `AlreadyEntitled`; `422`
(`HTTPValidationError`, array of `{msg}`) → first `msg`. `detail` may be `string`,
`[{msg}]`, or `{code,...}`.
- **UNVERIFIED-ASSUMPTION:** OpenAPI for `POST /posts/unlock` declares **only** `200` and `422`
  responses. The `401`/`402`/`409` codes are **not** in the spec — they are assumed runtime
  behaviors inferred from the AND-031 transport (401 refresh) and FastAPI conventions. The
  exact status code for "declined"/"already unlocked"/"sold-out" must be confirmed against a
  live `/posts/unlock` call; treat the client mapping as defensive (handle any non-200 by code
  if present, else fall back to the friendly `detail` message). The `detail` shape handling
  (string / `[{msg}]` / `{code,...}`) is VERIFIED against `src/api/client.ts:
  normalizeErrorDetail`.

**Reveal/refresh — `GET /posts/{post_id}`** returns `PostResponse` whose lock fields drive
display: `locked` (bool, **required**), `lock_type` (`fixed_price|tip_lottery|null`),
`unlock_price_cents` (int|null), `unlock_count` (int, default 0), `unlock_limit` (int|null),
`unlock_limit_reached` (bool, default false). All field names/types VERIFIED against
`components.schemas.PostResponse`. Note: the OpenAPI index lists `GET /posts/{post_id}` with an
un-named `200` body, but the schema component `PostResponse` is the documented post shape and the
web client (`src/api/endpoints/newsfeed.ts: getPost`) deserializes it as `FeedPost`.
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

## 16. Citations & Assumption Audit

Each key technical claim, its verdict, and an exact source pointer (OpenAPI `METHOD /path`
and/or schema name; frontend `path: symbol`; or a framework ref).

1. **Unlock endpoint is `POST /posts/unlock`.** VERDICT: Verified. SOURCE: OpenAPI
   `POST /posts/unlock` (op=`unlock_post_posts_unlock_post`); frontend
   `src/api/endpoints/newsfeed.ts: unlockPost`.
2. **Request body is `UnlockPostRequest` with `post_id` (required string),
   `payment_method_id` (string|null), `idempotency_key` (string|null,
   `^[A-Za-z0-9:_.-]+$`, 1–128 chars).** VERDICT: Verified. SOURCE:
   `components.schemas.UnlockPostRequest` (`required: [post_id]`).
3. **Response 200 is `UnlockPostResponse` with `post_id` and `payment_intent`
   (`additionalProperties: true`), both required.** VERDICT: Verified. SOURCE:
   `components.schemas.UnlockPostResponse` (`required: [post_id, payment_intent]`).
4. **Web client types the unlock response as `{ ok: boolean }` and ignores `payment_intent`.**
   VERDICT: Verified (web nuance; OpenAPI is authoritative for Android). SOURCE:
   `src/api/endpoints/newsfeed.ts: unlockPost`.
5. **Web client does NOT send `idempotency_key` (only `post_id` + optional
   `payment_method_id`).** VERDICT: Verified. SOURCE: `src/api/endpoints/newsfeed.ts:
   unlockPost`. The Android client adding `idempotency_key` is schema-legal but server honoring
   is unverified (see Open assumptions).
6. **Reveal/refresh via `GET /posts/{post_id}` returning a post with lock fields
   (`locked` bool [required], `lock_type` `fixed_price|tip_lottery|null`,
   `unlock_price_cents` int|null, `unlock_count` int, `unlock_limit` int|null,
   `unlock_limit_reached` bool).** VERDICT: Verified. SOURCE: OpenAPI `GET /posts/{post_id}`
   (op=`get_post_posts__post_id__get`); `components.schemas.PostResponse`
   (`required` includes `locked`); frontend `src/api/endpoints/newsfeed.ts: getPost`
   (typed `FeedPost`).
7. **Auth/CSRF: state-changing POST uses cookie session + `X-CSRF-Token` echoed from the
   `ui_csrf` cookie; `credentials: include`.** VERDICT: Verified. SOURCE: `src/api/client.ts`
   (lines ~167–171 read `ui_csrf` cookie → set `X-CSRF-Token`; `credentials: "include"`).
8. **401 handling: refresh once via `POST /ui/session/refresh`, then retry the original
   request once; a second 401 logs the user out / surfaces "sign in again".** VERDICT:
   Verified. SOURCE: `src/api/client.ts` 401 branch (calls `refreshSession()`, single retry,
   `logout("session_expired")` on repeat 401); `src/api/endpoints/auth.ts: refreshSession` →
   `POST /ui/session/refresh`; OpenAPI `POST /ui/session/refresh`
   (op=`ui_session_refresh_ui_session_refresh_post`, `resp=200:`).
9. **FastAPI `detail` may be a `string`, an array of `{msg}`, or an object `{code,...}`, and
   the client flattens accordingly (first/joined `msg`).** VERDICT: Verified. SOURCE:
   `src/api/client.ts: normalizeErrorDetail`.
10. **422 validation errors use `HTTPValidationError`.** VERDICT: Verified. SOURCE: OpenAPI
    `POST /posts/unlock` `resp=...;422:HTTPValidationError`.
11. **`lock_type` enum is exactly `fixed_price` | `tip_lottery` (nullable); this ticket scopes
    `fixed_price` only.** VERDICT: Verified. SOURCE: `components.schemas.PostResponse.lock_type`
    (`enum: [fixed_price, tip_lottery]` | null); also frontend `src/api/types.ts` (FeedPost
    `lock_type?: "fixed_price" | "tip_lottery"`).
12. **Out-of-scope unlock endpoints exist separately (messaging / broadcast / lottery).**
    VERDICT: Verified (confirms non-goals point at real, distinct endpoints). SOURCE: OpenAPI
    `POST /messaging/conversations/{conversation_id}/messages/{message_id}/unlock`
    (`UnlockMessageIn`→`UnlockOut`), `POST /messaging/messages/{message_id}/lottery/unlock`
    (`LotteryUnlockOut`), `POST /broadcast/sessions/{session_id}/chat/{message_id}/unlock`
    (`BroadcastChatUnlockIn`).
13. **`401`/`402`/`409` are NOT declared responses for `POST /posts/unlock` (only `200`/`422`
    are).** VERDICT: Unverified-assumption (the codes are assumed, not documented). SOURCE:
    OpenAPI `POST /posts/unlock` (`resp=200:UnlockPostResponse;422:HTTPValidationError`).
14. **No `currency` field co-located with `unlock_price_cents` on `PostResponse`.** VERDICT:
    Verified (negative result, supports §13 currency open question). SOURCE:
    `components.schemas.PostResponse` (price is `unlock_price_cents` only; no `currency`).
15. **Android stack/tooling choices (Room for the entitlement cache, DataStore for the
    idempotency key, Hilt for the `PaymentProcessor` test binding, Coil/Media3 reveal paths,
    Compose Material 3, MockWebServer for contract tests).** VERDICT: Unverified-assumption
    (Android-side design decisions; not derivable from backend/web sources). SOURCE:
    framework ref — Room <https://developer.android.com/training/data-storage/room>,
    DataStore <https://developer.android.com/topic/libraries/architecture/datastore>,
    Hilt testing <https://developer.android.com/training/dependency-injection/hilt-testing>,
    Compose semantics/a11y
    <https://developer.android.com/jetpack/compose/accessibility>,
    OkHttp MockWebServer <https://square.github.io/okhttp/#mockwebserver>.

### Corrections made

- **§5 (response shape):** Added that the web client types the unlock response loosely as
  `{ ok: boolean }` and ignores `payment_intent`; clarified that the authoritative shape for
  Android is `UnlockPostResponse` and that both `post_id` and `payment_intent` are required.
- **§5 (idempotency_key):** Noted that the web client does not send `idempotency_key` (only
  `post_id` + optional `payment_method_id`); the field is schema-legal but server honoring is an
  open assumption.
- **§5 (error codes):** Flagged that `401`/`402`/`409` are not declared OpenAPI responses for
  `POST /posts/unlock` (only `200`/`422`); marked them as inferred runtime behavior and tied the
  `detail` flattening to the verified `normalizeErrorDetail` logic.
- **§5 (reveal/refresh):** Annotated `GET /posts/{post_id}` / `PostResponse` field types as
  verified (incl. required `locked`, default values) and noted the index's un-named 200 body vs.
  the documented `PostResponse` component / web `FeedPost` typing.
- No corrections were required for the auth/CSRF (§2/§8), 401-refresh (§7), or state-machine
  (§3/§4) claims — all verified as written.

### Open assumptions

- **`payment_intent.status` value set:** `additionalProperties: true` exposes no declared
  `status` enum; the stub's confirm logic (`succeeded`/`requires_action`/`processing`) is
  assumed. Why unverifiable: opaque object in OpenAPI, no live `/posts/unlock` capture available.
- **Server honoring of `idempotency_key` (replay returns same outcome, no double-charge):**
  assumed. Why: web client never sends it; no backend behavior documented in OpenAPI.
- **Status codes for declined / already-unlocked / sold-out (`402`/`409` mapping, incl.
  `409 → AlreadyEntitled`):** assumed. Why: not in the endpoint's declared responses; only
  `200`/`422` are documented.
- **Default payment-method resolution when `payment_method_id` is null (and the error when none
  exists):** assumed. Why: server-side behavior not described in the OpenAPI request/response.
- **Currency for `unlock_price_cents`:** no `currency` field on `PostResponse`; whether price is
  a single tenant currency or sourced elsewhere (e.g. `/ui/me`/tenant config) is unverified.
- **Android-layer design (Room/DataStore/Hilt/MockWebServer, module layout under
  `com.testlogon.android.*`):** assumed per project conventions; not derivable from
  backend/web sources (framework refs cited in item 15).

## 17. Test Plan

Test-target legend: **JVM** = JVM unit/Robolectric (local, no device); **emu35** = headless
emulator AVD `test35` (x86_64, API 35); **A15** = physical Samsung Galaxy A15 5G (SM-A156U,
serial R5CX821TA9R, API 34, arm64-v8a). Acceptance is "tested w/ payment stub", so
`StubPaymentProcessor` (succeed/decline/timeout seams) plus MockWebServer are the primary seams.
No case in this ticket requires real hardware (no camera/biometric/WebRTC/FCM/streaming), so the
UI/instrumented suite runs on **emu35**; one ABI-parity smoke is called out on **A15**.

- **TC-AND-177-01 — Happy path: unlock reveals content in place.**
  - Type: Compose-UI (instrumented). Target: emu35.
  - Preconditions: signed-in session; feed contains a `fixed_price` locked post
    (`locked=true`, `lock_type="fixed_price"`, `unlock_price_cents` set); `StubPaymentProcessor`
    in `succeed` mode; MockWebServer returns `200 UnlockPostResponse {post_id, payment_intent:{status:"succeeded"}}`.
  - Steps: render feed; assert placeholder shown; tap "Unlock" CTA; await state.
  - Expected: CTA shows spinner during `InProgress`, then the same item recomposes with real
    body/media (`locked=false`); no navigation push; scroll position preserved.
  - Traces: AC-1.

- **TC-AND-177-02 — Request contract: body + CSRF header.**
  - Type: contract/MockWebServer. Target: JVM.
  - Preconditions: `ui_csrf` cookie present; repository wired to `PaywallApi`.
  - Steps: call `PaywallRepository.unlock(postId)`; capture the recorded request.
  - Expected: `POST /posts/unlock`; JSON body has `post_id`, `payment_method_id` omitted/null,
    `idempotency_key` matching `^[A-Za-z0-9:_.-]+$` (1–128); `X-CSRF-Token` header equals the
    `ui_csrf` cookie value; `Content-Type: application/json`. Request is never sent if CSRF is
    absent.
  - Traces: AC-3, AC-6.

- **TC-AND-177-03 — Response parsing: UnlockPostResponse / confirmable intent.**
  - Type: unit (contract/MockWebServer). Target: JVM.
  - Preconditions: MockWebServer returns `200 {post_id, payment_intent:{status:"succeeded"}}`.
  - Steps: invoke `unlock`; assert outcome and side effects.
  - Expected: Moshi parses `UnlockPostResponse` (both fields required); `payments.confirm`
    runs once; `EntitlementDao.upsert` writes `(userSub, postId)`; idempotency key cleared;
    returns `Success`. (Guards against copying the stale web `{ ok: boolean }` typing.)
  - Traces: AC-1, AC-2.

- **TC-AND-177-04 — Entitlement cache short-circuit (already cached).**
  - Type: unit. Target: JVM (Room in-memory).
  - Preconditions: `EntitlementEntity(userSub, postId)` already present.
  - Steps: call `unlock(postId)`.
  - Expected: returns `AlreadyEntitled`; **no** HTTP request issued (MockWebServer records zero
    calls); `isEntitled(postId)` emits `true`.
  - Traces: AC-2, AC-5.

- **TC-AND-177-05 — Persistence across process death.**
  - Type: instrumented. Target: emu35.
  - Preconditions: successful unlock completed (cache row written to on-disk Room).
  - Steps: destroy/recreate the ViewModel and Activity (simulate process death); reopen the
    same post in feed/detail.
  - Expected: post renders unlocked from cache; **no** new `POST /posts/unlock` call observed.
  - Traces: AC-2.

- **TC-AND-177-06 — 409 already-unlocked → AlreadyEntitled, no error.**
  - Type: unit (contract/MockWebServer). Target: JVM.
  - Preconditions: MockWebServer returns `409` with `detail` (string or `[{msg}]`).
    (Status code is an inferred behavior — see §16 item 13.)
  - Steps: call `unlock`.
  - Expected: maps to `AlreadyEntitled`; cache row written; reveal proceeds; **no** error
    surface/toast.
  - Traces: AC-5.

- **TC-AND-177-07 — 402 declined → retryable failure, friendly message.**
  - Type: unit (contract/MockWebServer). Target: JVM.
  - Preconditions: MockWebServer returns `402` with `detail` (test all three shapes:
    `"declined"`, `[{msg:"declined"}]`, `{code:"card_declined"}`).
  - Steps: call `unlock`.
  - Expected: `Failure(retryable=true)`; message derived via `normalizeErrorDetail`-equivalent
    logic (string → as-is; array → first/joined `msg`; object → mapped/fallback); idempotency
    key retained for retry.
  - Traces: AC-5.

- **TC-AND-177-08 — 401 refresh-once-then-retry, then give up.**
  - Type: unit (contract/MockWebServer). Target: JVM.
  - Preconditions: MockWebServer scripts: unlock→`401`, then `POST /ui/session/refresh`→`200`,
    then unlock retry→(a) `200` success and (b) second `401`.
  - Steps: call `unlock` for both scenarios.
  - Expected: (a) exactly one `POST /ui/session/refresh` then one unlock retry → `Success`;
    (b) second `401` → `Failure(retryable=false)` with "sign in again"; no infinite loop.
  - Traces: AC-6.

- **TC-AND-177-09 — Stub payment forced fail/timeout.**
  - Type: unit. Target: JVM.
  - Preconditions: `StubPaymentProcessor` in `decline` and in `timeout` mode; MockWebServer
    returns `200` with a confirmable intent.
  - Steps: call `unlock` in each mode.
  - Expected: both map to `Failure(retryable=true)`; **no** entitlement row written; idempotency
    key retained so a subsequent retry reuses the same key.
  - Traces: AC-3, AC-4.

- **TC-AND-177-10 — Idempotency key stability + double-tap no-op.**
  - Type: unit. Target: JVM.
  - Preconditions: first attempt times out (key persisted in DataStore); ViewModel in
    `InProgress`.
  - Steps: trigger a second `unlock`/`retry` for the same post within the same attempt-session;
    inspect the key used on retry and the state transitions.
  - Expected: retry reuses the **same** `idempotency_key`; stub asserts a single `confirm` per
    key; a tap while `InProgress` is a no-op (no second HTTP call).
  - Traces: AC-3, AC-4.

- **TC-AND-177-11 — ViewModel state machine + CTA gating.**
  - Type: unit (Turbine). Target: JVM.
  - Preconditions: bound `PaywallUiState` from a locked post.
  - Steps: drive `bind` then `unlock`; also bind a post with `unlock_limit_reached=true` and a
    post with `unlock_price_cents=null`/null `lock_type`.
  - Expected: transitions `Idle→InProgress→Unlocked|Failed|SoldOut`; CTA disabled during
    `InProgress`, disabled when price/lock_type missing; `unlock_limit_reached=true` →
    `SoldOut` (CTA replaced by "No longer available", no unlock attempted).
  - Traces: AC-4, AC-5.

- **TC-AND-177-12 — Offline behavior (flaky/unreachable dev host).**
  - Type: integration. Target: emu35 (toggle airplane mode / kill MockWebServer).
  - Preconditions: scenario A — entitlement cached; scenario B — not cached, network down.
  - Steps: open the post offline (A); tap "Unlock" offline (B).
  - Expected: (A) content reveals from cache with no network call; (B) fast-fail with an offline
    message, `Failure(retryable=true)`, CTA re-enables; no crash; idempotency key retained.
  - Traces: AC-2, AC-5.

- **TC-AND-177-13 — Security: per-user cache isolation + logout wipe; no secret logging.**
  - Type: instrumented + unit. Target: emu35.
  - Preconditions: user A unlocks a post (cache row for A); a logcat capture around the unlock.
  - Steps: log out / switch to user B; query `isEntitled` for the same post as B; inspect logs.
  - Expected: `clearForUser(A)` ran on logout; user B sees the post **locked** (no cross-user
    leak); `unlock_price_cents` row keyed by `userSub`; logs contain no cookie, no
    `X-CSRF-Token`, and no full `payment_intent` body (only `status`).
  - Traces: AC-2, AC-6, AC-7.

- **TC-AND-177-14 — Accessibility of paywall CTA and reveal.**
  - Type: Compose-UI (instrumented, with semantics/TalkBack assertions). Target: emu35.
  - Preconditions: locked `fixed_price` post; locale with non-`$` currency to exercise
    `NumberFormat`.
  - Steps: inspect CTA semantics; tap; observe live-region announcements and focus after reveal.
  - Expected: CTA `contentDescription` includes the localized price (e.g. "Unlock for $4.99");
    `Unlocking…` announced via `liveRegion`; "Content unlocked" announced and focus moves
    sensibly on reveal; touch target ≥ 48dp; all strings from `strings.xml` (no literals).
  - Traces: AC-1, AC-4.

- **TC-AND-177-15 — ABI/API parity smoke on physical device.**
  - Type: instrumented/e2e. Target: **A15 (MUST run on physical device)** — arm64-v8a / API 34
    vs the emulator's x86_64 / API 35.
  - Preconditions: app installed on SM-A156U; `StubPaymentProcessor` succeed mode; reachable
    MockWebServer or dev host.
  - Steps: run the happy-path unlock + relaunch-from-cache flow on the device.
  - Expected: unlock succeeds, content reveals, and cache persists identically to emu35 (Room
    schema, Moshi parsing, and DataStore behave the same on arm64/API 34). No ABI- or
    API-level-specific failure.
  - Traces: AC-1, AC-2.

### Coverage matrix

| Acceptance criterion (§14) | Covered by |
| --- | --- |
| AC-1 (reveal in place, no nav, scroll preserved) | TC-01, TC-03, TC-14, TC-15 |
| AC-2 (entitlement cached; no re-charge after relaunch/feed reload) | TC-03, TC-04, TC-05, TC-12, TC-13, TC-15 |
| AC-3 (idempotency_key; retry no double-charge) | TC-02, TC-09, TC-10 |
| AC-4 (state machine + CTA gating + double-tap no-op) | TC-09, TC-10, TC-11, TC-14 |
| AC-5 (409 → revealed no error; sold-out → "No longer available") | TC-04, TC-06, TC-07, TC-11, TC-12 |
| AC-6 (401 refresh-then-retry; CSRF present; no secret logging) | TC-02, TC-08, TC-13 |
| AC-7 (logout/account switch clears prior user's cache) | TC-13 |
