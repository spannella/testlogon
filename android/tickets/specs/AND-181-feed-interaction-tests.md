---
id: AND-181
title: Feed interaction tests
milestone: M4
epic: E24
priority: P1
size: M
status: draft
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
  `frontend/src/api/endpoints/feed.ts` / `interactions.ts`.
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
paths/shapes (mirrored from `frontend/src/api/endpoints/*`):

**Like toggle** — `POST /ui/feed/{item_id}/like` (and `DELETE` for unlike), with
the `X-CSRF-Token` header echoed from the `ui_csrf` cookie:
```json
// 200 response
{ "feed_item_id": "f1", "liked": true, "like_count": 43 }
```

**Unlock** — `POST /ui/feed/{item_id}/unlock`:
```json
// request
{ "receipt": { "provider": "stub", "token": "stub-ok-001", "product_id": "unlock_f9" } }
// 200 response
{ "feed_item_id": "f9", "entitled": true, "unlocked_at": "2026-06-05T12:00:00Z" }
```

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
