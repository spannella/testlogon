---
id: AND-181
title: Feed interaction tests
milestone: M4
epic: E24
priority: P1
size: M
status: reviewed
reviewed_on: 2026-06-06
depends_on: [AND-173, AND-177]
blocks: []
---

# AND-181 — Feed interaction tests

## 1. Overview & Goal

This is a **test-only** ticket. It delivers automated repository (unit/integration)
and UI (Compose instrumentation) test coverage for the two interactive feed
behaviours shipped in M4: **like / unlike** (AND-173) and **paywall unlock &
entitlement** (AND-177). No production behaviour changes; the goal is a regression
net that pins the optimistic-update + server-reconciliation contract for likes and
the purchase-stub → entitlement-cache → content-reveal contract for unlocks.

Concretely the ticket must:

- Add JVM/Robolectric tests for the repository layer that own like state and
  entitlement state (`core-data`), asserting optimistic mutation, rollback on
  failure, and reconciliation with the authoritative server response.
- Add `androidTest` Compose UI tests for the feed item composables that drive the
  like toggle and the paywall unlock affordance, asserting visible state
  transitions and accessibility semantics.
- Run against a `MockWebServer`-backed network so tests are hermetic and never
  touch the unreliable dev backend at `http://18.222.237.167:8000`.

Success is binary and measurable: the new test sources compile and **all tests
pass** (`./gradlew :core-data:test :feature-feed:connectedDebugAndroidTest`),
with the like and unlock paths each exercising success, server-mismatch, and
network-failure branches.

## 2. Context & References

- **Repo:** `spannella/testlogon`, Android app under `android/`, branch
  `android-port`. Namespace/applicationId base `com.testlogon.android`.
- **Under test (AND-173 Like / unlike):** like toggle with optimistic update;
  acceptance "like persists + reconciles (tested)". Lives in `feature-feed` UI +
  `core-data` repository, backed by web reference
  `src/api/endpoints/newsfeed.ts` (`likePost`/`unlikePost`/`unlockPost`); transport
  in `src/api/client.ts`; DTOs in `src/api/types.ts` (`FeedPost`). (Corrected: there
  is no `feed.ts`/`interactions.ts`; the web client groups these in `newsfeed.ts`.)
- **Under test (AND-177 Paywall unlock & entitlement):** unlock paid content via
  purchase/entitlement, reveal on success, "entitlement cached (tested w/ payment
  stub)". The payment side is a **stub** — these tests assert the app-side
  contract around that stub, not a real payment SDK.
- **Stack:** Kotlin 2.0.21, Compose + Material 3, Hilt (KSP), Coroutines/Flow,
  Retrofit 2.11 + OkHttp 4.12 + Moshi 1.15, Room 2.6, DataStore, Paging 3.
  minSdk 24 / compileSdk 35, JDK 17, Gradle 8.9, AGP 8.7.3.
- **Test infra:** `core-testing` module supplies shared fakes, dispatcher rules,
  and `MockWebServer` helpers. JUnit4 + Robolectric for JVM, Compose
  `createAndroidComposeRule` + Espresso-Compose for instrumentation, Turbine for
  Flow assertions, MockK for collaborators, Truth for assertions.
- **Layering:** tests respect `app -> feature-* -> core-*`; UI tests live in
  `feature-feed`, repository tests in `core-data`, shared utilities in
  `core-testing`.

## 3. Functional Requirements

The deliverable is test code; "functional requirements" are the behaviours the
tests must lock down. Tests MUST assert, not merely execute, each item below.

**Like / unlike (FR-L):**
- FR-L1 Tapping like on an un-liked item flips UI to liked **immediately**
  (optimistic), before the network call resolves.
- FR-L2 On HTTP 200 with the server's authoritative `liked` + `like_count`, the
  repository reconciles to the server values (e.g. count corrected if a
  concurrent like landed).
- FR-L3 On network failure / non-2xx, the optimistic state **rolls back** to the
  pre-tap value and an error signal is surfaced.
- FR-L4 Rapid double-tap (like then unlike before first resolves) ends in a state
  consistent with the last user intent and a single in-flight reconciliation per
  item (debounce/last-write-wins as implemented in AND-173).
- FR-L5 Like state is keyed per `feed_item_id` and does not bleed across items.

**Paywall unlock & entitlement (FR-U):**
- FR-U1 A locked item renders the paywall affordance (price + unlock CTA) and
  hides the gated media/body.
- FR-U2 Successful purchase stub → `POST .../unlock` 200 → entitlement persisted →
  gated content revealed without a full reload.
- FR-U3 Entitlement is **cached** (Room): re-reading the item returns
  `entitled = true` from cache without a new unlock call.
- FR-U4 Failed/cancelled purchase stub leaves the item locked, no entitlement
  written, error surfaced.
- FR-U5 Unlock failure after a successful payment stub (server reject) does not
  reveal content and does not persist entitlement (no false-positive unlock).

**Accessibility (FR-A):**
- FR-A1 Like control exposes a toggleable role + content description that flips
  between "Like" / "Unlike".
- FR-A2 Unlock CTA exposes a button role with a descriptive label including price.

## 4. Technical Design

### 4.1 Test module placement

```
core-data/src/test/java/com/testlogon/android/core/data/
    feed/LikeRepositoryTest.kt
    feed/EntitlementRepositoryTest.kt
feature-feed/src/androidTest/java/com/testlogon/android/feature/feed/
    LikeToggleUiTest.kt
    PaywallUnlockUiTest.kt
core-testing/src/main/java/com/testlogon/android/core/testing/
    MockWebServerRule.kt        // existing/extended
    MainDispatcherRule.kt       // existing
    fixtures/FeedFixtures.kt    // JSON + model builders (new/extended)
```

### 4.2 Repository tests (JVM, `core-data`)

Subjects under test are the AND-173/AND-177 repositories. Expected SUT surface
(consumed, not redefined by this ticket):

```kotlin
interface LikeRepository {
    fun observeLike(feedItemId: String): Flow<LikeState>           // liked + count
    suspend fun toggleLike(feedItemId: String, like: Boolean): ApiResult<LikeState>
}

interface EntitlementRepository {
    fun observeEntitlement(feedItemId: String): Flow<EntitlementState>
    suspend fun unlock(feedItemId: String, receipt: PurchaseReceipt): ApiResult<EntitlementState>
}

data class LikeState(val liked: Boolean, val likeCount: Int)
data class EntitlementState(val entitled: Boolean, val unlockedAt: Instant?)
```

> CONTRACT NOTE (verified): the server unlock request is `UnlockPostRequest =
> { post_id, payment_method_id?, idempotency_key? }` — NOT a `{receipt:{provider,
> token,product_id}}` envelope. `PurchaseReceipt` here is an **Android-internal**
> shape produced by the payment stub (AND-101/AND-031); the repository is
> responsible for mapping it to `UnlockPostRequest` (e.g. `payment_method_id`).
> Likewise `EntitlementState.entitled` maps from the post DTO's `unlocked` boolean
> and `EntitlementState.unlockedAt` is a local cache timestamp (no server field).
> These data-class names are this ticket's local convention, confirmed not to clash
> with the wire contract; the wire contract is in §5.

Tests use a real Retrofit pointed at `MockWebServer`, an in-memory Room database
(`Room.inMemoryDatabaseBuilder(...).allowMainThreadQueries()`), and
`MainDispatcherRule` driving a `StandardTestDispatcher` so optimistic emissions can
be observed before the network call completes via `advanceUntilIdle()`.

```kotlin
@RunWith(RobolectricTestRunner::class)
class LikeRepositoryTest {
    @get:Rule val mainDispatcher = MainDispatcherRule()
    @get:Rule val server = MockWebServerRule()

    private lateinit var repo: LikeRepository

    @Test fun toggleLike_emitsOptimisticThenReconciles() = runTest {
        server.enqueueJson(200, FeedFixtures.likeResponse(liked = true, count = 43))
        repo.observeLike("f1").test {
            assertThat(awaitItem()).isEqualTo(LikeState(false, 42)) // seed
            val result = async { repo.toggleLike("f1", like = true) }
            assertThat(awaitItem()).isEqualTo(LikeState(true, 43))  // optimistic (+1)
            advanceUntilIdle()
            assertThat(awaitItem()).isEqualTo(LikeState(true, 43))  // reconciled (server authoritative)
            assertThat(result.await()).isInstanceOf(ApiResult.Success::class.java)
        }
    }

    @Test fun toggleLike_rollsBackOnError() { /* enqueue 503; assert revert to (false,42) + ApiResult.Error */ }
    @Test fun toggleLike_serverCountWins_onConcurrentMismatch() { /* optimistic +1=43, server says 50 -> 50 */ }
    @Test fun toggleLike_isolatedPerItem() { /* f1 toggle leaves f2 untouched */ }
}
```

`EntitlementRepositoryTest` mirrors this: `unlock_success_persistsAndReveals`,
`unlock_cachedHit_skipsNetwork` (assert `server.requestCount` unchanged on second
read), `unlock_serverReject_noPersist`, `unlock_paymentStubFailure_noNetworkCall`.

### 4.3 UI tests (instrumentation, `feature-feed`)

Compose tests render the feed item composables with a Hilt-injected **fake**
repository (via `@UninstallModules` + a test module binding) so UI transitions are
deterministic and decoupled from the network. Use `runComposeUiTest` /
`createAndroidComposeRule<HiltTestActivity>()`.

```kotlin
@HiltAndroidTest
class LikeToggleUiTest {
    @get:Rule(order = 0) val hilt = HiltAndroidRule(this)
    @get:Rule(order = 1) val compose = createAndroidComposeRule<HiltTestActivity>()

    @Test fun tappingLike_flipsToUnlikeSemantics() {
        compose.setContent { FeedItem(uiState = lockedLikeState(), onLike = {}) }
        compose.onNodeWithContentDescription("Like").performClick()
        compose.onNodeWithContentDescription("Unlike").assertIsDisplayed()
    }
}
```

Fakes live in `core-testing`; the UI tests assert *rendered* state for FR-L1/3 and
FR-U1/2/4 by feeding the fake's scripted `ApiResult` sequence and asserting node
state via `assertIsOn()/assertIsOff()` (toggleable) and content reveal via a test
tag `feedItemGatedContent`.

### 4.4 Build wiring

Add test deps to the two modules' `build.gradle.kts` if not already present:
`testImplementation(project(":core-testing"))`, `robolectric`, `turbine`,
`mockwebserver`, `mockk`, `truth`; `androidTestImplementation` for
`compose.ui.test.junit4`, `hilt.android.testing` (+ `kspAndroidTest` for Hilt),
`espresso.core`. Register the Hilt test runner
(`com.testlogon.android.core.testing.HiltTestRunner`) in `defaultConfig`.

## 5. API Contract

This ticket adds **no new endpoints**; it consumes the AND-173/AND-177 contracts
via `MockWebServer` and must encode their exact shapes as fixtures. Authoritative
paths/shapes (verified against `reference/openapi.index.txt`,
`reference/openapi.pretty.json`, and `src/api/endpoints/newsfeed.ts`):

> CORRECTION: the previously-documented `POST /ui/feed/{item_id}/like` (+`DELETE`)
> and `POST /ui/feed/{item_id}/unlock` paths and the `{feed_item_id, liked,
> like_count}` / `receipt`+`entitled`+`unlocked_at` bodies DO NOT exist in the
> backend or the web client. The corrected contracts are below.

**Like** — `POST /posts/{post_id}/like`
(`like_post_posts__post_id__like_post`). **Unlike** — `POST /posts/{post_id}/unlike`
(`unlike_post_posts__post_id__unlike_post`). Both are **POST** (there is no
`DELETE` for unlike). The mutating call carries the `X-CSRF-Token` header echoed
from the `ui_csrf` cookie (verified `src/api/client.ts`). The web client types the
response as `{ ok: boolean }` (`newsfeed.ts: likePost/unlikePost`); the backend
OpenAPI declares an empty 200 body for these two paths (`resp=200:;422:`). The
authoritative liked/count fields live on the **post DTO** itself
(`FeedPost.liked_by_me: boolean`, `FeedPost.like_count: number`), refetched/observed
rather than returned by the toggle call:
```json
// POST /posts/f1/like  → 200 (web client shape)
{ "ok": true }
```
> NOTE (unverified assumption): the spec's repository contract assumes the toggle
> returns an authoritative `LikeState{liked, like_count}` for inline reconciliation.
> The web endpoints do NOT return that. A `{liked, like_count}` body DOES exist but
> only for the **video** like endpoint `POST /ui/videos/{video_id}/like`
> (schema `LikeToggleOut = {liked: bool, like_count: int}`). If AND-173 reconciles
> the post like via a follow-up `GET /posts/{post_id}` (FeedPost) rather than the
> toggle body, the fixtures must enqueue a `FeedPost` JSON for the reconcile step.
> Treat the inline `LikeState` reconciliation as an AND-173 implementation choice to
> confirm at implementation time (see §13 R2).

**Unlock** — `POST /posts/unlock` (flat path, `unlock_post_posts_unlock_post`),
request schema `UnlockPostRequest`, response schema `UnlockPostResponse`:
```json
// request  (UnlockPostRequest — note: NOT a {receipt:{...}} envelope)
{ "post_id": "f9", "payment_method_id": "pm_stub_ok", "idempotency_key": "and181-f9-001" }
// 200 response (UnlockPostResponse)
{ "post_id": "f9", "payment_intent": { /* provider-specific, additionalProperties */ } }
```
`post_id` is the only required request field; `payment_method_id` and
`idempotency_key` are optional/nullable. The web client (`newsfeed.ts: unlockPost`)
sends `{ post_id, payment_method_id? }` and types the response as `{ ok: boolean }`.
Entitlement state is read from the **post DTO** after unlock: `FeedPost.unlocked:
boolean` and `FeedPost.locked: boolean` / `lock_expired`, with price in
`FeedPost.unlock_price_cents` (cents, not a formatted string). There is no
`entitled`/`unlocked_at` field on this contract — the Android `EntitlementState`
must map from `unlocked` (the `unlockedAt` timestamp is an Android-local cache
column, not a server field; mark as a local convention).

Error envelope (FastAPI `detail`) the tests must enqueue and the SUT must map —
`detail` may be `string | [{msg}] | {code,...}`:
```json
{ "detail": "payment_required" }
{ "detail": [ { "msg": "receipt invalid", "loc": ["body","receipt"] } ] }
{ "detail": { "code": "ENTITLEMENT_CONFLICT" } }
```
Tests enqueue all three forms to confirm `ApiResult.Error` carries the parsed
message and the optimistic/locked rollback occurs. A `401` fixture verifies the
single `POST /ui/session/refresh`-then-retry path is *not* re-triggered into an
infinite loop (one refresh, one retry, then surface).

## 6. Data & State Management

- **Optimistic like state:** repository emits an immediately-mutated `LikeState`
  on `toggleLike`, then a reconciled emission from the server body. Tests assert
  the three-step Flow sequence (seed → optimistic → reconciled) via Turbine.
- **Entitlement cache:** Room table `entitlement(feed_item_id PK, entitled,
  unlocked_at)`. Tests use an in-memory DB and assert (a) a row is written on
  unlock success and (b) `observeEntitlement` serves from cache with zero extra
  `MockWebServer` requests (`server.requestCount`).
- **No DataStore assertions** here beyond what AND-173/177 already persist; CSRF
  cookie handling is verified only indirectly (header presence on recorded
  request) since the cookie jar is owned by `core-network`.
- **UI state:** `FeedItemUiState` (liked, likeCount, locked, price, gatedVisible)
  is driven by the fake; tests assert it maps 1:1 to rendered semantics.

## 7. Error Handling & Resilience

Tests are the consumers of the resilience contract, so they must cover:
- **Network failure:** `server.enqueue(MockResponse().setSocketPolicy(DISCONNECT_AFTER_REQUEST))`
  → assert like rollback (FR-L3) and unlock-not-revealed (FR-U4).
- **Timeout posture:** a delayed response asserts the SUT honours its ~20s read
  timeout without hanging the test (use `setBodyDelay` small + assert no retry on
  the non-idempotent `POST` — only idempotent GETs retry per project policy).
- **Server mismatch:** like count divergence reconciles to server (FR-L2).
- **False-positive guard:** payment stub success + server unlock reject must NOT
  persist entitlement (FR-U5) — assert empty Room table + locked UI.
- Tests must be **hermetic and deterministic** (no real host, no Thread.sleep;
  use `StandardTestDispatcher` + `advanceUntilIdle`) to avoid flakiness on the
  unreliable dev backend.

## 8. Security & Privacy

- Tests MUST NOT embed real credentials, cookies, or payment tokens; use stub
  tokens (`stub-ok-001`, `stub-fail-001`).
- Verify the like/unlock requests carry the `X-CSRF-Token` header (recorded
  request assertion) — this guards against regressing CSRF echo on mutating calls.
- No PII in fixtures; usernames are synthetic. Tests never log response bodies to
  device logs (would risk leaking entitlement tokens in CI artifacts).
- `cleartextTrafficPermitted` is irrelevant — `MockWebServer` runs on loopback;
  tests do not contact the plaintext dev host.

## 9. Accessibility & i18n

- UI tests assert the like control is `Modifier.toggleable(role = Role.Switch/Checkbox)`
  with content descriptions "Like"/"Unlike" (FR-A1) via `onNodeWithContentDescription`
  and `assertIsOn()/assertIsOff()`.
- Unlock CTA asserted as `Role.Button` with a label containing the localized price
  (FR-A2).
- i18n: tests resolve strings through `composeRule.activity.getString(R.string.feed_like_cd)`
  rather than hardcoded literals, so they survive localization. No new strings are
  introduced by this ticket; missing string resources are an AND-173/177 defect to
  file, not fix here.

## 10. Telemetry & Logging

No production telemetry is added. Tests may assert that the existing analytics
interface (if the SUT emits `AnalyticsEvent.LikeToggled` / `UnlockCompleted`) is
invoked exactly once on success via a MockK relaxed spy — but this is **optional**
and gated on AND-173/177 already exposing the hook. Test logging uses standard
JUnit failure messages; no custom logger. CI surfaces results via the Gradle test
HTML/XML reports under `build/reports/tests` and
`build/outputs/androidTest-results`.

## 11. Testing Strategy

This ticket *is* the testing strategy for feed interactions.

- **Unit/integration (JVM, Robolectric) — `core-data`:** `LikeRepositoryTest`,
  `EntitlementRepositoryTest`. Coverage targets every branch in FR-L and FR-U
  (success, rollback, mismatch, cache-hit, false-positive guard). Tooling: JUnit4,
  Robolectric, Turbine, MockK, Truth, OkHttp `MockWebServer`, in-memory Room.
- **UI (instrumentation) — `feature-feed`:** `LikeToggleUiTest`,
  `PaywallUnlockUiTest` with Hilt test rule + fake repos. Coverage: FR-L1/L4,
  FR-U1/U2/U4, FR-A1/A2.
- **Determinism:** `MainDispatcherRule(StandardTestDispatcher())`,
  `advanceUntilIdle()`, no sleeps, loopback `MockWebServer`. Each test enqueues
  exactly the responses it consumes and asserts `requestCount`.
- **Commands:**
  `./gradlew :core-data:testDebugUnitTest`
  `./gradlew :feature-feed:connectedDebugAndroidTest` (or managed-device
  `:feature-feed:pixel6Api35DebugAndroidTest` if GMD is configured).
- **CI:** both gradle tasks added to the existing M4 verification job; failures
  block merge.

## 12. Dependencies & Sequencing

- **depends_on:** AND-173 (Like / unlike) and AND-177 (Paywall unlock &
  entitlement) — their production code must be merged on `android-port` first,
  since these tests bind to `LikeRepository`/`EntitlementRepository` and the feed
  composables. AND-173 transitively depends on AND-099 (feed list); AND-177 on
  AND-101 / AND-031 (payment stub + content gating).
- **Shared infra:** assumes `core-testing` provides `MainDispatcherRule`,
  `MockWebServerRule`, and `HiltTestRunner`; if absent, add them here (small) as a
  prerequisite within this ticket.
- **blocks:** nothing structurally, but this ticket is the regression gate for the
  M4 feed-interaction release sign-off.
- **Sequencing:** land after AND-173/177 are green; can be developed in parallel
  against their interfaces using fakes if the interfaces are stable.

## 13. Risks & Open Questions

- **R1 — Interface drift:** AND-173/177 may expose slightly different
  repository/UI signatures than assumed in §4. Mitigation: confirm the actual
  `LikeRepository`/`EntitlementRepository` and feed composable signatures at
  implementation time; the test shapes here are the contract, not a redefinition.
- **R2 — Optimistic-emission observability:** if the repository collapses
  optimistic + reconciled into a single emission (no intermediate state), FR-L1
  cannot be asserted at the repo layer. Open question: is the optimistic state
  emitted by the repository or only by the ViewModel? If ViewModel-only, move
  FR-L1 assertion into a `FeedViewModelTest`.
- **R3 — Payment stub contract:** exact `PurchaseReceipt` shape and the stub's
  success/failure tokens come from AND-101/AND-031. Open question: does the stub
  return synchronously or via callback? Affects whether unlock tests need a
  suspend boundary.
- **R4 — UI test flakiness on CI emulators:** mitigate with Gradle Managed
  Devices + `connectedCheck` retries (max 1) rather than `Thread.sleep`.
- **R5 — Double-tap semantics (FR-L4):** debounce vs last-write-wins is an
  AND-173 implementation choice; the test must match it. Confirm before writing.

## 14. Acceptance Criteria

- AC1 New test sources compile under JDK 17 / AGP 8.7.3 in `core-data`
  (`src/test`) and `feature-feed` (`src/androidTest`).
- AC2 `./gradlew :core-data:testDebugUnitTest` passes, including
  `toggleLike_emitsOptimisticThenReconciles`, `toggleLike_rollsBackOnError`,
  `toggleLike_serverCountWins_onConcurrentMismatch`, `toggleLike_isolatedPerItem`.
- AC3 `EntitlementRepositoryTest` passes, including `unlock_success_persistsAndReveals`,
  `unlock_cachedHit_skipsNetwork` (asserts zero additional `MockWebServer`
  requests), `unlock_serverReject_noPersist`, `unlock_paymentStubFailure_noNetworkCall`.
- AC4 `./gradlew :feature-feed:connectedDebugAndroidTest` passes, including
  `LikeToggleUiTest` (like→unlike semantics + rollback) and `PaywallUnlockUiTest`
  (locked render, reveal on success, stays locked on failure).
- AC5 Mutating requests recorded by `MockWebServer` carry the `X-CSRF-Token`
  header (asserted in at least one like and one unlock test).
- AC6 All three FastAPI `detail` error shapes are exercised and map to
  `ApiResult.Error` with a non-null message.
- AC7 No test contacts `http://18.222.237.167:8000`; all network is loopback
  `MockWebServer` (verified by absence of `INTERNET`-host config in test setup).
- AC8 Tests are deterministic: 20 consecutive CI runs of both tasks show zero
  flakes.

## 15. Definition of Done

- All §14 acceptance criteria met; both Gradle test tasks green locally and in CI.
- New tests added to the M4 verification CI job and gating merges to `android-port`.
- Fixtures (`FeedFixtures`) and any new shared rules live in `core-testing`, reused
  (not duplicated) by both modules.
- No production source under `feature-feed`/`core-data` main sets is modified
  except, if strictly necessary, adding `@VisibleForTesting` test tags / content
  descriptions — any such change is called out in the PR description and traced to
  an FR.
- Code reviewed and approved; PR references AND-181 and links AND-173 / AND-177.
- Open questions R2/R3/R5 resolved (or explicitly deferred with a follow-up
  ticket) before merge.
- No new lint or detekt violations introduced in test sources.

## 16. Citations & Assumption Audit

Each key technical claim below lists the claim, a VERDICT, and an exact source
pointer. Sources: OpenAPI index/spec under `reference/`, frontend under `src/`, or
labelled framework refs.

1. **Like endpoint is `POST /ui/feed/{item_id}/like`.** VERDICT: **Corrected** →
   actual is `POST /posts/{post_id}/like`. Source: OpenAPI `POST
   /posts/{post_id}/like` (op `like_post_posts__post_id__like_post`);
   `src/api/endpoints/newsfeed.ts: likePost` (`api.post(\`/posts/${postId}/like\`)`).
2. **Unlike uses HTTP `DELETE`.** VERDICT: **Corrected** → unlike is `POST
   /posts/{post_id}/unlike`; no `DELETE` exists. Source: OpenAPI `POST
   /posts/{post_id}/unlike` (op `unlike_post_posts__post_id__unlike_post`);
   `src/api/endpoints/newsfeed.ts: unlikePost`.
3. **Like 200 body is `{feed_item_id, liked, like_count}`.** VERDICT: **Corrected**
   → post like/unlike declare an empty 200 body in OpenAPI (`resp=200:;422:`); web
   client types it `{ ok: boolean }`. Authoritative liked/count are post-DTO fields
   `FeedPost.liked_by_me` + `FeedPost.like_count`. Source: OpenAPI index lines for
   `/posts/{post_id}/like` and `/unlike`; `src/api/types.ts: FeedPost` (`like_count`,
   `liked_by_me`); `src/api/endpoints/newsfeed.ts: likePost`.
4. **A `{liked, like_count}` toggle body exists.** VERDICT: **Verified but for a
   different endpoint** — it is the **video** like endpoint `POST
   /ui/videos/{video_id}/like` → `LikeToggleOut {liked: bool, like_count: int}`
   (and `GET .../like` → `LikeCheckOut {liked}`). Source: OpenAPI
   `POST /ui/videos/{video_id}/like` (op `toggle_like_endpoint_...`), schema
   `components.schemas.LikeToggleOut` / `LikeCheckOut` in `openapi.pretty.json`.
5. **Unlock endpoint is `POST /ui/feed/{item_id}/unlock`.** VERDICT: **Corrected**
   → actual is the flat `POST /posts/unlock`. Source: OpenAPI `POST /posts/unlock`
   (op `unlock_post_posts_unlock_post`, `req=UnlockPostRequest
   resp=200:UnlockPostResponse`); `src/api/endpoints/newsfeed.ts: unlockPost`.
6. **Unlock request body is `{receipt:{provider,token,product_id}}`.** VERDICT:
   **Corrected** → schema `UnlockPostRequest = { post_id (required),
   payment_method_id?, idempotency_key? }`; web sends `{ post_id,
   payment_method_id? }`. Source: `openapi.pretty.json:
   components.schemas.UnlockPostRequest`; `src/api/endpoints/newsfeed.ts: unlockPost`.
7. **Unlock 200 body is `{feed_item_id, entitled, unlocked_at}`.** VERDICT:
   **Corrected** → schema `UnlockPostResponse = { post_id, payment_intent (object,
   additionalProperties) }`; web types it `{ ok: boolean }`. No `entitled` /
   `unlocked_at` field. Source: `openapi.pretty.json:
   components.schemas.UnlockPostResponse`; `src/api/endpoints/newsfeed.ts: unlockPost`.
8. **Entitlement/lock state lives on the post DTO as `unlocked`/`locked`/price.**
   VERDICT: **Verified** → `FeedPost.unlocked: boolean`, `FeedPost.locked` (cf.
   `lock_expired`, `unlock_price_cents` in cents). Source: `src/api/types.ts:
   FeedPost` (lines ~2209–2225) and `src/api/types.ts: ProfilePostItem`
   (`locked`, `unlock_price_cents`, `like_count`).
9. **Mutating calls carry `X-CSRF-Token` echoed from the `ui_csrf` cookie.**
   VERDICT: **Verified.** Source: `src/api/client.ts` — `getCookie("ui_csrf")` then
   `headers.set("X-CSRF-Token", csrf)`.
10. **Auth is a `Bearer` token in the `Authorization` header.** VERDICT:
    **Verified** (relevant for fixtures/recorded-request assertions). Source:
    `src/api/client.ts` (`Authorization: Bearer ${accessToken}`). Note: backend
    OpenAPI also accepts `X-SESSION-ID` / `X-IMPERSONATION-TOKEN` params on these
    routes (OpenAPI index `params=...`).
11. **On 401 the client does exactly one `POST /ui/session/refresh` then one
    retry, no infinite loop.** VERDICT: **Verified.** Source: `src/api/client.ts`
    — `refreshSession()` calls `/ui/session/refresh`; `refreshPromise` single-flight
    guard; single retry; a second 401 calls `logout("session_expired")` instead of
    re-refreshing.
12. **Error envelope is FastAPI `detail` = `string | [{msg,...}] | {code,...}`.**
    VERDICT: **Verified.** Source: OpenAPI `HTTPValidationError` (422 on all these
    routes uses `detail: [{msg, loc, type}]`); `src/api/client.ts`
    `normalizeErrorDetail` handles string / array-of-`{msg}` / object forms.
13. **Web reference for these calls is `frontend/src/api/endpoints/feed.ts` /
    `interactions.ts`.** VERDICT: **Corrected** → those files do not exist; the
    calls are in `src/api/endpoints/newsfeed.ts`. Source: directory listing of
    `src/api/endpoints/` (no `feed.ts`/`interactions.ts`; `newsfeed.ts` present).
14. **Stack/tooling (Kotlin 2.0.21, Compose+M3, Hilt/KSP, Retrofit/OkHttp/Moshi,
    Room, Paging 3; Robolectric, Turbine, MockK, Truth, MockWebServer, Compose UI
    test).** VERDICT: **Unverified-assumption** (no Android module sources in this
    reference set to confirm). Framework refs for the testing approach:
    Compose testing (framework ref:
    https://developer.android.com/develop/ui/compose/testing),
    Hilt testing (framework ref: https://developer.android.com/training/dependency-injection/hilt-testing),
    OkHttp MockWebServer (framework ref: https://square.github.io/okhttp/features/testing/),
    Robolectric (framework ref: http://robolectric.org/),
    Room in-memory DB (framework ref:
    https://developer.android.com/training/data-storage/room/testing-db),
    coroutines `StandardTestDispatcher`/`advanceUntilIdle` (framework ref:
    https://developer.android.com/kotlin/coroutines/test).
15. **Inline repo reconciliation: `toggleLike` returns authoritative
    `LikeState{liked, like_count}` from the toggle body.** VERDICT:
    **Unverified-assumption** — the post like endpoints return no such body (claim 3);
    only the video endpoint does (claim 4). Whether AND-173 reconciles via a
    follow-up `GET /posts/{post_id}` (FeedPost) is undetermined from these sources.
    Source: same as claims 3–4; flagged in §13 R2.
16. **`PurchaseReceipt` shape and stub success/failure tokens.** VERDICT:
    **Unverified-assumption** — defined by AND-101/AND-031 (payment stub), not
    present in this reference set. Source: §13 R3 (open question).

### Corrections made

- §2: replaced non-existent `frontend/src/api/endpoints/feed.ts` /
  `interactions.ts` with the real `src/api/endpoints/newsfeed.ts` (+ `client.ts`,
  `types.ts`).
- §5 (Like): corrected path `POST /ui/feed/{item_id}/like` → `POST
  /posts/{post_id}/like`; corrected unlike from `DELETE` → `POST
  /posts/{post_id}/unlike`; corrected the 200 body from `{feed_item_id, liked,
  like_count}` to the real empty/`{ok}` body, noting authoritative fields live on
  `FeedPost` and that `{liked, like_count}` (`LikeToggleOut`) is the **video** like
  endpoint.
- §5 (Unlock): corrected path `POST /ui/feed/{item_id}/unlock` → `POST
  /posts/unlock`; corrected request from `{receipt:{provider,token,product_id}}` to
  `UnlockPostRequest {post_id, payment_method_id?, idempotency_key?}`; corrected
  response from `{feed_item_id, entitled, unlocked_at}` to `UnlockPostResponse
  {post_id, payment_intent}` (web `{ok}`), with entitlement read from
  `FeedPost.unlocked` and price `unlock_price_cents`.
- §4.2: added a contract note clarifying `PurchaseReceipt`/`EntitlementState` are
  Android-local shapes mapped to the wire `UnlockPostRequest`, and that
  `unlockedAt` is a local cache column (no server field).

### Open assumptions

- The exact Android repository/composable signatures (LikeRepository,
  EntitlementRepository, FeedItem) are unverifiable here — no Android module exists
  in the reference set; they are AND-173/AND-177 outputs (§13 R1/R2).
- Whether the like toggle reconciles inline (toggle body) or via a follow-up
  `GET /posts/{post_id}` is unverifiable (claim 15) — fixtures must adapt once
  AND-173 is merged.
- `PurchaseReceipt` shape + stub tokens come from AND-101/AND-031 (claim 16, §13 R3).
- Build-tool/version matrix (claim 14) cannot be confirmed against backend/frontend
  sources; treat as repo-config assumptions.
- The video-like `{liked, like_count}` body would let the spec's inline-`LikeState`
  reconciliation work as written only if AND-173 reused the **video** endpoint for
  feed-post likes — there is no evidence it does; do not assume it.

## 17. Test Plan

All cases below are hermetic: real network is `MockWebServer` on loopback; the dev
host `http://18.222.237.167:8000` is never contacted. Targets: **JVM/Robolectric**
(local, no device), **emulator AVD `test35`** (API 35, x86_64, KVM, CI), **physical
device** Samsung Galaxy A15 5G (SM-A156U, API 34, arm64-v8a, serial R5CX821TA9R).
Compose-UI / instrumented cases default to the emulator `test35`; the
ABI/API-skew case (TC-AND-181-13) MUST run on the physical device.

- **TC-AND-181-01 — Like happy path: optimistic then reconcile.**
  Type: contract/MockWebServer (JVM/Robolectric). Target: JVM (`core-data`).
  Preconditions: seed `LikeState(false, 42)` for `f1`; `MockWebServer` enqueues a
  200 for `POST /posts/f1/like` (empty/`{ok}` body, plus the reconcile source per
  §5 — FeedPost or LikeToggleOut as AND-173 implements).
  Steps: collect `observeLike("f1")` via Turbine; call `toggleLike("f1", true)`;
  `advanceUntilIdle()`. Expected: emissions seed `(false,42)` → optimistic
  `(true,43)` → reconciled to server-authoritative value; `ApiResult.Success`;
  recorded request method/path = `POST /posts/f1/like`. Traces: AC2, AC4 (path).

- **TC-AND-181-02 — Like rollback on non-2xx.**
  Type: contract/MockWebServer (JVM). Target: JVM (`core-data`).
  Preconditions: seed `(false,42)`; enqueue `503` with `{"detail":"service
  unavailable"}`. Steps: toggle like; `advanceUntilIdle()`. Expected: emissions
  seed → optimistic `(true,43)` → rolled back `(false,42)`; result
  `ApiResult.Error` with non-null message. Traces: AC2, AC6.

- **TC-AND-181-03 — Like rollback on network failure (offline / flaky host).**
  Type: contract/MockWebServer (JVM). Target: JVM (`core-data`).
  Preconditions: seed `(false,42)`; enqueue `MockResponse().setSocketPolicy(
  DISCONNECT_AFTER_REQUEST)`. Steps: toggle like; `advanceUntilIdle()`. Expected:
  optimistic then rollback to `(false,42)`; `ApiResult.Error`; **no retry** on the
  non-idempotent POST (assert `requestCount == 1`). Traces: AC2, AC7.

- **TC-AND-181-04 — Server count wins on concurrent mismatch.**
  Type: contract/MockWebServer (JVM). Target: JVM (`core-data`).
  Preconditions: seed `(false,42)`; enqueue 200 whose authoritative count is `50`.
  Steps: toggle like; `advanceUntilIdle()`. Expected: optimistic `(true,43)` →
  reconciled `(true,50)`. Traces: AC2.

- **TC-AND-181-05 — Like state isolated per `post_id`.**
  Type: unit (JVM). Target: JVM (`core-data`).
  Preconditions: seed `f1=(false,42)`, `f2=(false,7)`; enqueue 200 for `f1`.
  Steps: toggle `f1`; observe `f2`. Expected: `f2` unchanged `(false,7)`; only `f1`
  request recorded. Traces: AC2.

- **TC-AND-181-06 — CSRF header on mutating like request.**
  Type: contract/MockWebServer (JVM). Target: JVM (`core-data`).
  Preconditions: cookie jar holds `ui_csrf=test-csrf`; enqueue 200. Steps: toggle
  like; read `RecordedRequest`. Expected: header `X-CSRF-Token == test-csrf`
  present on `POST /posts/f1/like`. Traces: AC5.

- **TC-AND-181-07 — Unlock happy path persists + reveals.**
  Type: contract/MockWebServer (JVM). Target: JVM (`core-data`).
  Preconditions: in-memory Room; enqueue 200 `UnlockPostResponse {post_id:"f9",
  payment_intent:{}}` for `POST /posts/unlock`; stub receipt → `payment_method_id`.
  Steps: `unlock("f9", stubOk)`; `advanceUntilIdle()`; re-`observeEntitlement("f9")`.
  Expected: `ApiResult.Success`; recorded request body is `{"post_id":"f9",
  "payment_method_id":...}` (NO `receipt` envelope); Room row written;
  `EntitlementState.entitled == true`. Traces: AC3.

- **TC-AND-181-08 — Entitlement cache hit skips network.**
  Type: contract/MockWebServer (JVM). Target: JVM (`core-data`).
  Preconditions: from TC-07 state (one unlock already persisted). Steps: capture
  `server.requestCount`; call `observeEntitlement("f9")` again. Expected:
  `entitled == true` from Room; `requestCount` unchanged (zero additional unlock
  calls). Traces: AC3.

- **TC-AND-181-09 — Server reject after stub success: no false-positive unlock.**
  Type: contract/MockWebServer (JVM). Target: JVM (`core-data`).
  Preconditions: stub payment succeeds; enqueue `402` (or `409`) with
  `{"detail":{"code":"ENTITLEMENT_CONFLICT"}}`. Steps: `unlock("f9", stubOk)`;
  `advanceUntilIdle()`. Expected: `ApiResult.Error` (parsed code/message);
  **no Room row** written; `entitled == false` (content stays locked). Traces:
  AC3, AC6.

- **TC-AND-181-10 — Payment-stub failure: no network call at all.**
  Type: unit (JVM). Target: JVM (`core-data`).
  Preconditions: stub receipt = `stub-fail-001` (fails before the API call).
  Steps: `unlock("f9", stubFail)`. Expected: `ApiResult.Error`; `requestCount == 0`
  (unlock endpoint never hit); no Room row. Traces: AC3.

- **TC-AND-181-11 — All three `detail` error shapes map to `ApiResult.Error`.**
  Type: contract/MockWebServer (JVM). Target: JVM (`core-data`).
  Preconditions: three enqueued responses: `{"detail":"payment_required"}`,
  `{"detail":[{"msg":"receipt invalid","loc":["body","receipt"]}]}` (422 form),
  `{"detail":{"code":"ENTITLEMENT_CONFLICT"}}`. Steps: drive a mutating call for
  each. Expected: each yields `ApiResult.Error` with a non-null, parsed message;
  state rolls back / stays locked. Traces: AC6.

- **TC-AND-181-12 — 401 triggers exactly one refresh + one retry, no loop.**
  Type: contract/MockWebServer (JVM). Target: JVM (`core-data`).
  Preconditions: authenticated; enqueue `401` for the mutating call, `200` for
  `POST /ui/session/refresh`, then `200` for the retried mutating call.
  Steps: invoke the mutating call. Expected: sequence is original → one refresh
  (`POST /ui/session/refresh`) → one retry → success; assert exactly 3 recorded
  requests and no second refresh. (Negative variant: second `401` after retry
  surfaces an error / session-expired, no further refresh.) Traces: AC6.

- **TC-AND-181-13 — Like + unlock repository suite on physical arm64 / API 34.**
  Type: instrumented/e2e. Target: **PHYSICAL DEVICE (SM-A156U, arm64-v8a, API 34)
  — MUST run here**, to catch arm64-vs-x86 and API-34-vs-35 differences vs the
  `test35` emulator. Preconditions: `MockWebServer` on device loopback; same
  fixtures as TC-01/07. Steps: run the like-toggle + unlock repository instrumented
  variants on-device. Expected: identical pass behavior to JVM/emulator; no
  ABI/Moshi/codegen divergence. Traces: AC1, AC8.

- **TC-AND-181-14 — Like toggle Compose UI semantics + rollback.**
  Type: Compose-UI / instrumented. Target: emulator `test35` (CI).
  Preconditions: Hilt-injected fake `LikeRepository` scripting success then a
  failure `ApiResult`. Steps: render `FeedItem` locked-like state; click node with
  content description "Like"; for failure variant let the fake return Error.
  Expected: success → node flips to "Unlike", `assertIsOn()`; failure → reverts to
  "Like", `assertIsOff()` + error surfaced. Traces: AC4.

- **TC-AND-181-15 — Paywall unlock Compose UI: locked render, reveal, stay-locked.**
  Type: Compose-UI / instrumented. Target: emulator `test35` (CI).
  Preconditions: fake `EntitlementRepository`. Steps: render locked item (assert
  paywall affordance + price visible, `feedItemGatedContent` hidden); trigger
  unlock with scripted success → gated content shown without reload; repeat with
  scripted failure → stays locked, error surfaced. Expected: as described.
  Traces: AC4.

- **TC-AND-181-16 — Accessibility semantics for like + unlock controls.**
  Type: Compose-UI / instrumented (accessibility). Target: emulator `test35` (CI).
  Preconditions: rendered feed item. Steps: assert like control exposes a
  toggleable role with content description "Like"/"Unlike" (resolved via
  `getString(R.string.feed_like_cd)`, not literals) and `assertIsOn/Off`; assert
  unlock CTA exposes `Role.Button` with a label containing the localized price.
  Expected: all semantics present. Traces: AC4.

- **TC-AND-181-17 — No real-host egress (hermetic guard).**
  Type: manual / CI inspection. Target: build host.
  Preconditions: full test run. Steps: inspect test config + recorded request
  hosts. Expected: every request host is loopback `MockWebServer`; no reference to
  `18.222.237.167:8000`; no `INTERNET`-host config in test setup. Traces: AC7, AC8.

### Coverage matrix

| §14 Acceptance Criterion | Covered by |
|---|---|
| AC1 (sources compile, both modules) | TC-13 (on-device build/run), plus all JVM/UI cases compiling |
| AC2 (`core-data` like tests pass) | TC-01, TC-02, TC-03, TC-04, TC-05, TC-06 |
| AC3 (`EntitlementRepositoryTest` passes) | TC-07, TC-08, TC-09, TC-10 |
| AC4 (`feature-feed` UI tests pass) | TC-01 (path), TC-14, TC-15, TC-16 |
| AC5 (`X-CSRF-Token` on mutating requests) | TC-06 (like); extend TC-07 (unlock) for header assert |
| AC6 (three `detail` shapes → `ApiResult.Error`) | TC-02, TC-09, TC-11, TC-12 |
| AC7 (no dev-host contact; loopback only) | TC-03, TC-17 |
| AC8 (deterministic, zero flakes) | TC-13, TC-17 (all cases are sleep-free/`advanceUntilIdle`) |
