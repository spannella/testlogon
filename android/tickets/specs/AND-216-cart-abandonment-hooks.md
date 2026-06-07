---
id: AND-216
title: Cart abandonment hooks
milestone: M5
epic: E29
priority: P2
size: M
depends_on: [AND-210]
blocks: []
status: reviewed
reviewed_on: 2026-06-06
---

# AND-216 — Cart abandonment hooks

## 1. Overview & Goal

This ticket adds **cart abandonment detection and event emission** to the native Android port of TestLogon. When a user adds one or more items to their cart, begins (or could begin) checkout, and then leaves without completing the purchase, the app must emit a single, well-formed `cart_abandoned` analytics event describing the abandoned cart. The web reference's `frontend/src/api/endpoints/cartAbandonment.ts` does **not** implement client-side abandonment detection or an event emitter; it is a thin API client that *reads* the backend's server-derived abandonment state (`getCartAbandonmentStatus`, `getCartAbandonmentStats`, `runCartAbandonmentSweep`). Abandonment on the web is therefore a **server-side** concept (a sweep over `last_activity_at`/`abandoned_at` keyed by `threshold_hours`), not a client signal. This Android ticket deliberately introduces a *new, client-side* abandonment signal (a `feature-cart` use case plus a lifecycle/timing tracker that emits an in-app event); it is **not** a 1:1 port of the web file. See §16 for the corrected provenance.

The **goal** is narrowly scoped: detect abandonment deterministically and emit exactly one abandonment event per abandonment episode. It is explicitly *not* in scope to build the analytics transport pipeline (batching, upload, retry to a backend collector), to render any UI (recovery banners, "come back" prompts), or to implement push/email recovery campaigns — those are downstream concerns. This ticket produces the *signal*; consumers subscribe to it.

The single authoritative acceptance bar from the backlog is: **"Abandonment event emitted."** Everything below makes that testable: when, exactly once, with what payload, under which lifecycle and timing conditions.

## 2. Context & References

- **Source ticket:** AND-216 — Cart abandonment hooks. Type: Feature · Priority: P2 · Deps: AND-210. Scope: `cartAbandonment.ts` events. Acceptance: Abandonment event emitted.
- **Upstream dependency:** **AND-210 — Cart API + DTOs** (`cart.ts` endpoints/DTOs). AND-210 owns the cart model (`Cart`, `CartItem`, totals), the `CartRepository`, and the `Cart` <-> DTO mapping. AND-216 consumes the cart state AND-210 exposes; it must not redefine cart models.
- **Web reference (CORRECTED):** `frontend/src/api/endpoints/cartAbandonment.ts` is a backend-API client only (status read + admin stats + admin sweep), **not** an event-shape/trigger source. `frontend/src/api/endpoints/cart.ts` (cart fetch/mutation/purchase). `frontend/src/api/types.ts` holds the cart DTOs (`CartSummary`, `CartItem`, `CartTotal`, `CartPurchase`) and the abandonment DTOs (`CartAbandonmentStatus`, `CartAbandonmentStats`, `CartAbandonmentSweepResult`). There is **no** `cart_abandoned` event type in the web codebase. See §16.
- **Module layering:** `app -> feature-cart -> core-*`. The abandonment tracker and use case live in `feature-cart` (or `feature-cart`'s domain layer); the event sink contract and event model live in `core-model` / `core-data` so non-cart consumers can subscribe without depending on `feature-cart`.
- **Stack:** Kotlin 2.0.21, Coroutines/Flow, Hilt (KSP), DataStore for the abandonment marker, AndroidX Lifecycle (`ProcessLifecycleOwner`, `androidx.lifecycle:lifecycle-process`). minSdk 24, JDK 17.
- **Canonical package:** `com.testlogon.android` (applicationId base and namespace root).
- **Backend note:** This ticket does **not** call the FastAPI backend. The cart payload that seeds an event is already in memory (from AND-210). No new network endpoint is introduced. See §5.

## 3. Functional Requirements

**FR-1 — Define "abandonment episode".** An abandonment episode begins the moment the cart transitions from empty (no line items) to non-empty. The episode is *active* while the cart remains non-empty and the purchase is not completed.

**FR-2 — Abandonment triggers.** An active episode is considered abandoned when **any** of these occurs:
1. **App backgrounded for longer than the inactivity threshold.** The app moves to the background (`ON_STOP` via `ProcessLifecycleOwner`) while the cart is non-empty, and either the process is killed or returns to foreground after the threshold has elapsed.
2. **Inactivity timeout in foreground.** No cart-mutating interaction occurs for `INACTIVITY_THRESHOLD` while the cart is non-empty and the user is not on the order-confirmation screen.
3. **Explicit navigation away** from the checkout/cart flow back to a non-purchase surface while the cart is non-empty (a "soft" abandonment, emitted after a short debounce to avoid false positives on incidental navigation).

**FR-3 — Exactly-once semantics.** For a given episode (identified by a stable `episodeId`), at most one `cart_abandoned` event is emitted. Re-entering the cart, re-backgrounding, or process restart must not produce duplicate events for the same unchanged cart contents.

**FR-4 — Episode reset.** The episode (and the right to emit a new event) resets when the cart becomes empty, when checkout is completed successfully, or when the cart contents materially change after an event was already emitted (a new episode begins on the next empty -> non-empty transition; an already-abandoned cart whose items change starts a *new* episode keyed by a new contents hash).

**FR-5 — Event content.** The emitted event MUST carry: episode id, cart id, item count, distinct SKU/line count, monetary subtotal and currency, the abandonment reason (`BACKGROUND_TIMEOUT` | `FOREGROUND_INACTIVITY` | `NAV_AWAY` | `PROCESS_KILLED`), the timestamp the episode started, and the timestamp of abandonment. (See §5 for the JSON shape.)

**FR-6 — Suppression on success.** If checkout finalizes (order placed) during an active episode, no abandonment event is emitted and the episode is closed.

**FR-7 — No UI.** This ticket emits to an in-app event sink (a `SharedFlow`) and persists the de-dupe marker. It renders nothing.

## 4. Technical Design

### 4.1 Components

```kotlin
package com.testlogon.android.core.model.analytics

enum class AbandonmentReason {
    BACKGROUND_TIMEOUT, FOREGROUND_INACTIVITY, NAV_AWAY, PROCESS_KILLED
}

data class CartAbandonedEvent(
    val episodeId: String,        // UUID v4, stable per episode
    val cartId: String,
    val itemCount: Int,           // sum of quantities
    val lineCount: Int,           // distinct line items
    val subtotalMinor: Long,      // smallest currency unit (cents)
    val currency: String,         // ISO-4217, e.g. "USD"
    val reason: AbandonmentReason,
    val contentsHash: String,     // stable hash of (sku,qty) set; de-dupe key
    val episodeStartedAtEpochMs: Long,
    val abandonedAtEpochMs: Long,
)
```

The event sink lives in `core-data` so any module can subscribe:

```kotlin
package com.testlogon.android.core.data.analytics

interface CartEventSink {
    val events: SharedFlow<CartAbandonedEvent>
    suspend fun emit(event: CartAbandonedEvent)
}

@Singleton
class DefaultCartEventSink @Inject constructor() : CartEventSink {
    private val _events = MutableSharedFlow<CartAbandonedEvent>(
        replay = 0, extraBufferCapacity = 16, onBufferOverflow = BufferOverflow.DROP_OLDEST
    )
    override val events: SharedFlow<CartAbandonedEvent> = _events.asSharedFlow()
    override suspend fun emit(event: CartAbandonedEvent) { _events.emit(event) }
}
```

### 4.2 The use case

```kotlin
package com.testlogon.android.feature.cart.domain

class EmitCartAbandonmentUseCase @Inject constructor(
    private val sink: CartEventSink,
    private val store: AbandonmentMarkerStore,   // DataStore-backed de-dupe (§6)
    private val clock: Clock,                     // injectable for tests
) {
    /** Returns true if an event was emitted; false if suppressed (duplicate/empty). */
    suspend operator fun invoke(cart: Cart, reason: AbandonmentReason): Boolean {
        if (cart.items.isEmpty()) return false
        val hash = cart.contentsHash()
        if (store.lastEmittedHash() == hash) return false   // exactly-once per contents
        val event = cart.toAbandonedEvent(reason, clock.nowEpochMs())
        sink.emit(event)
        store.recordEmitted(hash, event.episodeId)
        return true
    }
}
```

`Cart`, `CartItem`, subtotal, and currency come from AND-210's `core-model`. `contentsHash()` is a deterministic SHA-256 over the sorted `(sku, quantity)` pairs, hex-encoded — stable across process restarts so duplicate suppression survives kills.

### 4.3 The tracker (lifecycle + timing)

```kotlin
package com.testlogon.android.feature.cart.domain

@Singleton
class CartAbandonmentTracker @Inject constructor(
    private val cartRepository: CartRepository,        // AND-210
    private val emit: EmitCartAbandonmentUseCase,
    private val store: AbandonmentMarkerStore,
    @ApplicationScope private val scope: CoroutineScope,
    private val clock: Clock,
) : DefaultLifecycleObserver {

    companion object {
        val INACTIVITY_THRESHOLD = 5.minutes
        val NAV_DEBOUNCE = 3.seconds
    }

    fun start() {
        ProcessLifecycleOwner.get().lifecycle.addObserver(this)
        observeInactivity()
    }

    override fun onStop(owner: LifecycleOwner) {              // app backgrounded
        scope.launch {
            val cart = cartRepository.currentCart() ?: return@launch
            if (cart.items.isNotEmpty()) store.markBackgrounded(clock.nowEpochMs(), cart.contentsHash())
        }
    }

    override fun onStart(owner: LifecycleOwner) {             // app foregrounded
        scope.launch {
            val mark = store.backgroundMark() ?: return@launch
            val cart = cartRepository.currentCart() ?: return@launch
            if (cart.items.isNotEmpty() &&
                cart.contentsHash() == mark.hash &&
                clock.nowEpochMs() - mark.atEpochMs >= INACTIVITY_THRESHOLD.inWholeMilliseconds) {
                emit(cart, AbandonmentReason.BACKGROUND_TIMEOUT)
            }
            store.clearBackgroundMark()
        }
    }

    fun onCheckoutCompleted() { scope.launch { store.reset() } }   // FR-6
    fun onNavAwayFromCart() { /* debounced NAV_AWAY emit (§FR-2.3) */ }
    private fun observeInactivity() { /* timer reset on cart mutations; emits FOREGROUND_INACTIVITY */ }
}
```

`PROCESS_KILLED` is recovered lazily: on next launch, if a background mark exists whose age already exceeds the threshold and the cart hash still matches, the use case emits with `reason = PROCESS_KILLED` (resolved inside `onStart` by comparing against `mark.killedSuspected`). The tracker is started from the single `Activity`/`Application` via Hilt at process init.

### 4.4 Wiring

A Hilt module binds `CartEventSink` -> `DefaultCartEventSink`. `CartAbandonmentTracker.start()` is invoked from `Application.onCreate()` (the tracker registers with `ProcessLifecycleOwner`). Cart mutation calls in AND-210's `CartRepository` notify the tracker of activity (resetting the inactivity timer) via a shared `Flow` the tracker already collects — no new coupling beyond observing `cartRepository.cartFlow`.

## 5. API Contract

**No backend HTTP endpoint is introduced by this ticket.** Cart abandonment, as emitted here, is a client-derived signal computed entirely from local cart state. The cart fetch/persistence contract is owned by **AND-210** and lives under the `/ui/shoppingcart/carts*` family (CORRECTED — the path prefix is `/ui/shoppingcart/...`, **not** `/ui/cart`). The downstream analytics upload contract (sending events to a collector) is **out of scope** and is not yet ticketed; until then `CartEventSink` is the contract.

**Backend abandonment endpoints already exist (server-side) and are distinct from this client signal** (verified, §16): `GET /ui/shoppingcart/carts/{cart_id}/abandonment-status` -> `CartAbandonmentStatus`; `GET /ui/shoppingcart/admin/cart-abandonment/stats` -> `CartAbandonmentStats`; `POST /ui/shoppingcart/admin/cart-abandonment/scan` (body `CartAbandonmentSweepIn`) -> `CartAbandonmentSweepOut`. The backend computes abandonment via an admin/sweep over `last_activity_at`/`abandoned_at` with `threshold_hours`. This ticket does **not** call these; it produces an independent in-app real-time signal. A future ticket may reconcile the two.

The **internal event contract** (the JSON-equivalent payload, used in tests and logs) is:

```json
{
  "event": "cart_abandoned",
  "episode_id": "8f1d3c2a-...-9b",
  "cart_id": "cart_01HXYZ",
  "item_count": 4,
  "line_count": 2,
  "subtotal_minor": 5298,
  "currency": "USD",
  "reason": "BACKGROUND_TIMEOUT",
  "contents_hash": "a3f9...e2",
  "episode_started_at_epoch_ms": 1749100000000,
  "abandoned_at_epoch_ms": 1749100600000
}
```

`reason` is one of `BACKGROUND_TIMEOUT | FOREGROUND_INACTIVITY | NAV_AWAY | PROCESS_KILLED`. **CORRECTED:** these field names do **not** mirror `cartAbandonment.ts` — that file contains no `cart_abandoned` event and no `episode_id`/`subtotal_minor` fields. This event shape is a new, Android-specific contract owned by this ticket. The monetary field should be sourced from AND-210's cart DTOs, which name money fields `*_cents` (`unit_price_cents`, `line_total_cents`, `total_cents`) and currency `currency`; `subtotal_minor` here is the Android-internal name for the cents subtotal (consider renaming to `subtotal_cents` for parity with the web DTOs — see §16 Open assumptions). There is **no** existing `POST /ui/events` endpoint (verified absent in the OpenAPI index). If/when an upload endpoint lands it would, by analogy to the rest of the API, use cookie auth + `X-CSRF-Token` (from the `ui_csrf` cookie) and likely live under `/ui/shoppingcart/...` or a new analytics path; the exact path is an **unverified assumption** and is the downstream ticket's responsibility, not this one.

## 6. Data & State Management

**Persistent de-dupe marker (DataStore Preferences).** A `AbandonmentMarkerStore` backed by `DataStore<Preferences>` persists the minimal state needed for exactly-once and process-kill recovery:

```kotlin
class AbandonmentMarkerStore @Inject constructor(
    private val dataStore: DataStore<Preferences>,
) {
    private val KEY_LAST_HASH = stringPreferencesKey("cart_abandon_last_hash")
    private val KEY_BG_HASH   = stringPreferencesKey("cart_abandon_bg_hash")
    private val KEY_BG_AT     = longPreferencesKey("cart_abandon_bg_at")
    private val KEY_EPISODE   = stringPreferencesKey("cart_abandon_episode_id")

    suspend fun lastEmittedHash(): String?
    suspend fun recordEmitted(hash: String, episodeId: String)
    suspend fun markBackgrounded(atEpochMs: Long, hash: String)
    suspend fun backgroundMark(): BackgroundMark?
    suspend fun clearBackgroundMark()
    suspend fun reset()   // clears all keys on checkout success / cart emptied
}
```

**Why DataStore, not Room:** the state is a handful of scalar keys with no relational queries; DataStore is the prescribed prefs store and survives process death. The cart itself is *not* duplicated here — it is read on demand from AND-210's `CartRepository`.

**In-memory state:** `CartAbandonmentTracker` holds the live inactivity timer (a cancellable coroutine `Job`) and the current `episodeId`. The episode id is generated when the cart transitions empty -> non-empty and stored alongside the contents hash so it can be attached to the event and survive a kill.

**Event delivery:** `SharedFlow` with `replay = 0` (abandonment is a fire-and-forget moment-in-time signal; late subscribers should not replay stale abandonment events) and a bounded buffer with `DROP_OLDEST` to guarantee `emit` never suspends the lifecycle callback.

## 7. Error Handling & Resilience

- **Missing/empty cart:** `invoke` short-circuits and returns `false`; no event, no crash.
- **DataStore read/write failure:** wrapped in `runCatching`; a read failure degrades to "no prior marker" (worst case: one possible duplicate event, which is preferable to dropping a real abandonment). Write failures are logged (§10) and do not propagate.
- **Clock skew / negative durations:** durations clamped at 0; a non-positive elapsed time never triggers `BACKGROUND_TIMEOUT`.
- **Process death during background:** handled by the lazy `PROCESS_KILLED` recovery in `onStart`/next-launch (§4.3). The background mark is the durable source of truth.
- **Buffer overflow:** `DROP_OLDEST` ensures the lifecycle thread never blocks; given abandonment events are rare (per-episode), overflow is effectively impossible but bounded defensively.
- **Coroutine scope:** the tracker uses an `@ApplicationScope` `SupervisorJob` scope so a failure in one emission cannot cancel the tracker.
- **No network:** because no upload occurs here, backend unreliability (the ~20s-timeout dev host) is irrelevant to this ticket; the signal is emitted regardless of connectivity, and the future uploader owns retry/offline handling.

## 8. Security & Privacy

- The event contains **no PII**: no username, email, address, or payment data — only cart id, aggregate counts, subtotal, currency, reason, and timestamps. SKUs are excluded from the contents *hash* output (the hash is opaque) and individual SKUs are **not** placed in the event payload.
- `subtotalMinor` is a monetary aggregate, not sensitive; included for funnel analysis.
- The DataStore marker stores only a hash, timestamps, and ids; it contains no credentials and is in app-private storage. It is not backed up to cloud (exclude via `dataExtractionRules`/`fullBackupContent` if backup is enabled).
- No new permissions. No cookies, no CSRF, no auth surface touched — this ticket does not perform network I/O.
- The `contentsHash` is a one-way SHA-256; it cannot be reversed to reveal purchase intent contents off-device.

## 9. Accessibility & i18n

Not applicable to UI — this ticket renders no user-facing surface, so there are no Compose semantics, focus, TalkBack, or contrast requirements. **i18n note:** the event carries `currency` (ISO-4217) and `subtotalMinor` in minor units so any downstream UI (a future recovery banner ticket) can format per-locale correctly; this ticket emits locale-neutral data and performs no string formatting. Any user-facing recovery messaging is owned by a downstream M5 UI ticket, not AND-216.

## 10. Telemetry & Logging

The event *is* the telemetry product of this ticket. For diagnostics:

- A tagged logger (`Timber`/`Log` with tag `CartAbandon`) logs at `DEBUG`: episode start, trigger reason, suppression decisions (duplicate hash, empty cart, checkout-success suppression), and successful emit. No payload fields beyond ids and reason are logged; never log raw SKUs or totals at `INFO`+.
- A counter-style log line on emit (`emitted reason=BACKGROUND_TIMEOUT episode=...`) supports manual verification of the "exactly-once" property during QA.
- The `CartEventSink.events` flow is the integration point for any future analytics collector; subscribing to it is how downstream tickets forward events upstream. This ticket adds a no-op debug subscriber (behind `BuildConfig.DEBUG`) that logs received events to confirm wiring end-to-end.

## 11. Testing Strategy

**Unit (core-testing, JUnit + Turbine + injected `Clock`):**
- `EmitCartAbandonmentUseCase` emits exactly one event for a non-empty cart and returns `true`. (Directly satisfies the acceptance bar.)
- Calling `invoke` twice with the same `contentsHash` emits only once (second returns `false`).
- Empty cart -> no emit, returns `false`.
- Event field mapping: `itemCount`, `lineCount`, `subtotalMinor`, `currency`, `reason`, timestamps populated from a fixture `Cart` (AND-210 model).
- `contentsHash()` is order-independent and stable across instances (same `(sku,qty)` set -> same hash; changed qty -> different hash).
- Checkout-success path: `onCheckoutCompleted()` resets the store so a subsequent identical cart can start a new episode.

**Tracker tests (with fake `Clock`, fake `CartRepository`, fake `AbandonmentMarkerStore`):**
- `onStop` then `onStart` after `>= INACTIVITY_THRESHOLD` with unchanged non-empty cart -> emits `BACKGROUND_TIMEOUT`.
- `onStop`/`onStart` *under* threshold -> no emit.
- Cart changed while backgrounded -> no `BACKGROUND_TIMEOUT` (hash mismatch).
- Foreground inactivity timer fires after threshold -> `FOREGROUND_INACTIVITY`; a cart mutation resets the timer.
- Simulated process kill (background mark present at next launch, aged past threshold) -> `PROCESS_KILLED`, emitted once.

**Instrumentation (optional, minimal):** verify `AbandonmentMarkerStore` round-trips through a real `DataStore` and survives a recreated store instance (process-kill analogue).

All async assertions use Turbine on `CartEventSink.events`; tests are deterministic via the injected `Clock` (no real delays).

## 12. Dependencies & Sequencing

- **Hard dependency: AND-210 — Cart API + DTOs.** Provides `Cart`, `CartItem`, `CartRepository`, subtotal/currency, and the cart `Flow` the tracker observes. AND-216 cannot land until AND-210's cart model and repository are merged. This matches the backlog `Deps: AND-210`.
- **Transitive:** AND-210 depends on AND-027 (its own dep); no direct action needed here.
- **Provides for downstream:** the `CartEventSink` contract and `CartAbandonedEvent` model become the input to (a) a future analytics-upload ticket and (b) any M5 cart-recovery UI ticket. AND-216 `blocks` nothing currently listed but is a prerequisite for those.
- **Sequencing within this ticket:** (1) add `CartAbandonedEvent` + `AbandonmentReason` to `core-model`; (2) add `CartEventSink` + `DefaultCartEventSink` + Hilt binding to `core-data`; (3) add `AbandonmentMarkerStore` (DataStore); (4) add `EmitCartAbandonmentUseCase`; (5) add `CartAbandonmentTracker` + lifecycle wiring in `Application`; (6) tests.

## 13. Risks & Open Questions

- **Threshold values (5 min inactivity, 3 s nav debounce) are unconfirmed and have no web counterpart.** CORRECTED: `cartAbandonment.ts` exposes **no** client-side threshold constants — the only threshold in the web/backend world is the server sweep's `threshold_hours` (hours, admin-tunable, default server-side; range 0–8760 per `CartAbandonmentSweepIn`), which governs server batch detection, not a real-time client signal. There is therefore nothing to "align to web" for the client thresholds; they are Android product decisions. *Open question: confirm desired client inactivity/debounce values with product; do not assume parity with `threshold_hours` (different unit and semantics).*
- **False positives from `NAV_AWAY`.** Incidental navigation (e.g., to product detail and back) could fire abandonment. Mitigation: debounce + only count navigation that exits the cart/checkout subgraph; consider gating `NAV_AWAY` behind a feature flag for the first release if web does not implement it.
- **Definition of "checkout flow"** for FR-2.2/FR-2.3 depends on the Navigation-Compose graph, which may not be finalized at M5; the tracker should treat the cart/checkout route ids as a configurable set.
- **Duplicate vs. lost events trade-off:** on DataStore failure we prefer a possible duplicate over a lost signal; confirm this matches analytics expectations once a collector exists.
- **Process-kill timestamp accuracy:** elapsed time across a kill relies on wall-clock (`System.currentTimeMillis()`), which can be affected by user clock changes; acceptable for this signal's precision needs.

## 14. Acceptance Criteria

1. **Abandonment event emitted** (backlog bar): given a non-empty cart and any qualifying trigger (background-past-threshold, foreground inactivity, process-kill recovery, or debounced nav-away), exactly one `CartAbandonedEvent` is published on `CartEventSink.events`.
2. The event contains correctly mapped `cartId`, `itemCount`, `lineCount`, `subtotalMinor`, `currency`, `reason`, `contentsHash`, and both timestamps, sourced from AND-210's `Cart`.
3. **Exactly-once:** repeated triggers for the same unchanged cart contents emit at most one event (verified by a duplicate-suppression unit test).
4. **Suppression on success:** completing checkout during an active episode emits no event and resets the episode.
5. **Reset:** emptying the cart or changing contents after an emit allows a new episode (and a new event) to be emitted later.
6. The de-dupe marker persists across process death (DataStore), so a kill does not produce a duplicate on relaunch, and a kill *while non-empty past threshold* produces one `PROCESS_KILLED` event.
7. No UI, no network call, no new permission is introduced.
8. All unit/tracker tests in §11 pass; emission tests are deterministic via injected `Clock`.

## 15. Definition of Done

- `CartAbandonedEvent`, `AbandonmentReason`, `CartEventSink`/`DefaultCartEventSink`, `AbandonmentMarkerStore`, `EmitCartAbandonmentUseCase`, and `CartAbandonmentTracker` implemented in the correct modules under `com.testlogon.android.*`, wired via Hilt, with the tracker started from `Application.onCreate()`.
- Event field names and semantics are documented in §5 as a new Android-specific contract (CORRECTED: there is no `cart_abandoned` event in `cartAbandonment.ts` to match); money fields are sourced from AND-210's `*_cents` cart DTOs.
- All §11 tests written and green in CI; coverage includes the exactly-once, suppression-on-success, and process-kill recovery paths.
- `./gradlew :feature-cart:test :core-data:test :core-model:test detekt lint` passes; no new lint/detekt regressions.
- No PII in event or persisted marker; backup exclusion applied to the marker keys.
- Code reviewed and merged to `android-port`; downstream consumers can subscribe to `CartEventSink.events` without depending on `feature-cart`.
- Spec dependencies remain consistent: AND-216 depends on AND-210 only.

## 16. Citations & Assumption Audit

Each key technical claim, its verdict, and the exact source pointer.

1. **Claim:** The web reference `cartAbandonment.ts` implements client-side abandonment "event shape and trigger logic."
   **VERDICT: Corrected.** The file is a thin backend API client only — three calls: `getCartAbandonmentStatus`, `getCartAbandonmentStats`, `runCartAbandonmentSweep`. No emitter, no triggers, no `cart_abandoned` event.
   **SOURCE:** `src/api/endpoints/cartAbandonment.ts` (whole file).

2. **Claim:** Field names of the emitted event "mirror `cartAbandonment.ts`" (`cart_abandoned`, `episode_id`, `subtotal_minor`, etc.).
   **VERDICT: Corrected.** None of `cart_abandoned`, `episode_id`, `contents_hash`, `subtotal_minor`, or the four reason enum values exist in the web codebase. The event is a new Android-specific contract.
   **SOURCE:** `src/api/endpoints/cartAbandonment.ts`; `src/api/types.ts: CartAbandonmentStatus / CartAbandonmentStats / CartAbandonmentSweepResult` (the only abandonment DTOs; fields are `cart_id`, `status`, `last_activity_at`, `abandoned_at`, `reminder_count`, `is_abandoned`, `total_open`, `total_abandoned`, `total_purchased`, `total_carts`, `abandonment_rate`, `scanned`, `reminded`, `expired`, `threshold_hours`).

3. **Claim:** A future upload endpoint is expected to be `POST /ui/events`.
   **VERDICT: Corrected / Unverified-assumption.** No `/ui/events` path exists in the OpenAPI index. The real abandonment endpoints are namespaced under `/ui/shoppingcart/...`. The future-upload path is unknowable from current sources.
   **SOURCE:** absence verified by grep over `reference/openapi.index.txt` (no `/ui/events` line); present endpoints below (#4).

4. **Claim (added):** Backend abandonment endpoints exist server-side.
   **VERDICT: Verified.**
   **SOURCE (OpenAPI):** `GET /ui/shoppingcart/carts/{cart_id}/abandonment-status` (resp 200; op `ui_cart_abandonment_status_...`); `GET /ui/shoppingcart/admin/cart-abandonment/stats`; `POST /ui/shoppingcart/admin/cart-abandonment/scan` → `CartAbandonmentSweepOut` (req `CartAbandonmentSweepIn`), all in `reference/openapi.index.txt` lines 1857–1863.

5. **Claim:** The cart fetch contract is the `/ui/cart` family.
   **VERDICT: Corrected.** The prefix is `/ui/shoppingcart/carts*`.
   **SOURCE (OpenAPI):** `POST /ui/shoppingcart/carts` (op `ui_start_cart_...` → `ShoppingCartSummary`); `GET /ui/shoppingcart/carts/{cart_id}/items` (→ `ShoppingCartItemsOut`); `GET /ui/shoppingcart/carts/{cart_id}/total` (→ `ShoppingCartTotalOut`); `reference/openapi.index.txt` lines 1859–1870. Frontend: `src/api/endpoints/cart.ts: createCart/getCarts/getCartItems/getCartTotal`.

6. **Claim:** Money/currency fields come from AND-210's cart model.
   **VERDICT: Verified, with naming correction.** Web DTOs use `*_cents` and `currency`, not `subtotal_minor`. `CartItem` has `unit_price_cents`, `line_total_cents`, `quantity`, `sku`; `CartTotal` has `total_cents`, `currency`; `CartSummary` has `currency`.
   **SOURCE:** `src/api/types.ts: CartItem` (lines ~2003–2013), `CartTotal` (~2020–2024), `CartSummary` (~1955–1966). OpenAPI `ShoppingCartTotalOut`, `ShoppingCartSummary`.

7. **Claim:** Checkout completion is the "order placed" signal that suppresses abandonment (FR-6).
   **VERDICT: Verified (web has a purchase endpoint).** Purchase is `POST /ui/shoppingcart/carts/{cart_id}/purchase` (req `CartPurchaseIn`, resp `ShoppingCartPurchaseOut` → web `CartPurchase` with `order_id`, `purchased_at`, `purchased_total_cents`). The tracker's `onCheckoutCompleted()` is the local hook fired after a successful purchase call.
   **SOURCE:** `src/api/endpoints/cart.ts: purchaseCart`; `src/api/types.ts: CartPurchase`; OpenAPI `reference/openapi.index.txt` line 1869 (note: purchase also takes `X-Idempotency-Key`).

8. **Claim:** A future upload would use cookie + `X-CSRF-Token`.
   **VERDICT: Verified (transport pattern).** The web client sends `credentials: "include"` and sets header `X-CSRF-Token` from the `ui_csrf` cookie on mutating requests. (Note: the OpenAPI also documents an `X-SESSION-ID`/`X-API-Key` header auth variant for these endpoints; the *web* client relies on cookie + CSRF.)
   **SOURCE:** `src/api/client.ts` lines 16–17 (`getCookie`), 124/183/220 (`credentials: "include"`), 167–170 (`X-CSRF-Token` from `ui_csrf`).

9. **Claim:** This ticket performs no network I/O and adds no new permission, cookie, CSRF, or auth surface.
   **VERDICT: Verified (by design / scope).** No endpoint is called; this is an internal design decision, not contradicted by any source.
   **SOURCE:** spec §4–§8 (design intent); no API dependency in `src/api/endpoints/cartAbandonment.ts`.

10. **Claim:** Stack choices — `ProcessLifecycleOwner`/`lifecycle-process`, DataStore Preferences for the marker, `SharedFlow` for the sink, Hilt, injectable `Clock`.
    **VERDICT: Unverified-assumption (framework refs).** These are Android framework choices, reasonable and idiomatic, but not derivable from backend/frontend sources.
    **SOURCE (framework ref):** AndroidX Lifecycle ProcessLifecycleOwner — https://developer.android.com/topic/libraries/architecture/lifecycle ; DataStore — https://developer.android.com/topic/libraries/architecture/datastore ; Kotlin `SharedFlow` — https://kotlinlang.org/api/kotlinx.coroutines/kotlinx-coroutines-core/kotlinx.coroutines.flow/-shared-flow/ ; Hilt — https://developer.android.com/training/dependency-injection/hilt-android .

11. **Claim:** Client inactivity threshold = 5 min, nav debounce = 3 s, and these should match web `cartAbandonment.ts` constants.
    **VERDICT: Corrected / Unverified-assumption.** No client constants exist in the web file. The only related server value is `threshold_hours` (hours, range 0–8760, admin sweep) — a different unit and semantics. The chosen client values are product decisions, currently unconfirmed.
    **SOURCE:** `src/api/endpoints/cartAbandonment.ts` (no constants); OpenAPI `CartAbandonmentSweepIn.threshold_hours` (`reference/openapi.pretty.json` ~line 14602, max 8760).

### Corrections made

- §1, §2, §5, §13, §15: removed/qualified the false claim that `cartAbandonment.ts` defines a client-side `cart_abandoned` event and trigger logic; restated it as a backend status/stats/sweep API client. The Android event is a new contract.
- §5: corrected the cart path family from `/ui/cart` to `/ui/shoppingcart/carts*`; added the real backend abandonment endpoints.
- §5: removed the nonexistent `POST /ui/events` as a stated expectation; marked the future-upload path as an unverified assumption; documented the verified cookie + `X-CSRF-Token` (`ui_csrf`) transport pattern.
- §5/§15: noted money fields are `*_cents` in AND-210 DTOs (not `subtotal_minor`) and flagged a possible `subtotal_cents` rename for parity.
- §13: corrected the "align thresholds to web" risk — there are no web client thresholds; only the server `threshold_hours` sweep value (hours) exists.

### Open assumptions

- **Event field naming (`subtotal_minor` vs `subtotal_cents`, snake_case JSON keys).** Unverifiable: no web event exists to match. Recommend `*_cents` for parity with AND-210/backend DTOs; product/analytics owner to confirm before a collector ticket fixes the wire format.
- **Future upload endpoint path, method, and idempotency key.** Unverifiable: no such endpoint exists in the OpenAPI today. The purchase endpoint precedent uses `X-Idempotency-Key`, which a future POST might reuse.
- **Client thresholds (5 min inactivity, 3 s nav debounce, episode definition).** Unverifiable from sources; product decision. Server `threshold_hours` is not a substitute (different unit/semantics).
- **Android framework choices (ProcessLifecycleOwner, DataStore, SharedFlow, Hilt, injected Clock).** Not verifiable against backend/frontend; standard Android patterns (framework refs above).
- **`PROCESS_KILLED` elapsed-time accuracy across kills using wall-clock.** Inherent platform limitation acknowledged in §13; not source-verifiable.

## 17. Test Plan

Test target legend: JVM = JVM unit/Robolectric (local, no device); EMU = headless emulator AVD `test35` (x86_64, API 35); DEV = physical Samsung Galaxy A15 5G (SM-A156U, API 34, arm64-v8a). Cases here are pure-Kotlin/lifecycle/DataStore logic with no UI, camera, biometric, push, or media — so JVM/Robolectric and the emulator cover everything; the physical device is only needed for the real process-death + DataStore-durability and ABI/API-34 confirmation cases.

- **TC-AND-216-01 — Happy path: emit on non-empty cart.**
  Type: unit (JVM). Target: `EmitCartAbandonmentUseCase`. Preconditions: fake `CartEventSink` (Turbine), fresh `AbandonmentMarkerStore` (no prior hash), injected fixed `Clock`, fixture `Cart` with 2 lines / 4 items, `total_cents=5298`, `currency="USD"`. Steps: call `invoke(cart, BACKGROUND_TIMEOUT)`. Expected: returns `true`; exactly one `CartAbandonedEvent` on `events` with `itemCount=4`, `lineCount=2`, `subtotalMinor=5298`, `currency="USD"`, `reason=BACKGROUND_TIMEOUT`, non-null `episodeId`/`contentsHash`/timestamps. Traces: AC-1, AC-2.

- **TC-AND-216-02 — Exactly-once: duplicate suppression by contents hash.**
  Type: unit (JVM). Target: `EmitCartAbandonmentUseCase` + `AbandonmentMarkerStore`. Preconditions: same fixture cart. Steps: `invoke` twice with identical cart contents. Expected: first returns `true` and emits once; second returns `false` and emits nothing (`store.lastEmittedHash()==hash`). Traces: AC-3.

- **TC-AND-216-03 — Empty cart short-circuits.**
  Type: unit (JVM). Target: `EmitCartAbandonmentUseCase`. Preconditions: cart with no items. Steps: `invoke(emptyCart, NAV_AWAY)`. Expected: returns `false`, no emit, no crash, no marker write. Traces: AC-1 (negative), AC-7.

- **TC-AND-216-04 — Field mapping from AND-210 cart DTO.**
  Type: unit (JVM). Target: `Cart.toAbandonedEvent()` mapper. Preconditions: fixture cart built from AND-210 model fields (`sku`, `quantity`, `unit_price_cents`, `line_total_cents`, `total_cents`, `currency`, `cart_id`). Steps: map to event. Expected: `cartId` from `cart_id`; `subtotalMinor`==sum of `line_total_cents` (== `total_cents`); `itemCount`==Σ`quantity`; `lineCount`==distinct sku count; `currency` carried verbatim. Traces: AC-2.

- **TC-AND-216-05 — contentsHash is order-independent and quantity-sensitive.**
  Type: unit (JVM). Target: `Cart.contentsHash()`. Preconditions: two carts with the same `(sku,qty)` set in different order; a third with one qty changed. Steps: compute hashes. Expected: hashes 1==2; hash 3 differs; SHA-256 hex, deterministic across instances. Traces: AC-2, AC-3, AC-5.

- **TC-AND-216-06 — Background-past-threshold emits BACKGROUND_TIMEOUT.**
  Type: unit (JVM, fake Clock/repo/store). Target: `CartAbandonmentTracker`. Preconditions: non-empty cart, fake `Clock`. Steps: `onStop` at t0 (marks background); advance clock by `INACTIVITY_THRESHOLD + 1ms`; `onStart` with unchanged cart hash. Expected: exactly one `BACKGROUND_TIMEOUT` event; background mark cleared. Traces: AC-1.

- **TC-AND-216-07 — Background under threshold does not emit.**
  Type: unit (JVM). Target: `CartAbandonmentTracker`. Steps: `onStop` then `onStart` with elapsed < threshold (and also test negative/zero elapsed for clock-skew clamp). Expected: no event; mark cleared. Traces: AC-1 (negative), maps to §7 resilience.

- **TC-AND-216-08 — Cart changed while backgrounded suppresses BACKGROUND_TIMEOUT.**
  Type: unit (JVM). Target: `CartAbandonmentTracker`. Steps: `onStop` with hash A; change cart to hash B; advance past threshold; `onStart`. Expected: no `BACKGROUND_TIMEOUT` (hash mismatch); a new episode is eligible. Traces: AC-3, AC-5.

- **TC-AND-216-09 — Foreground inactivity timer fires; cart mutation resets it.**
  Type: unit (JVM, virtual time via `TestDispatcher`). Target: `CartAbandonmentTracker.observeInactivity`. Steps: non-empty cart idle past `INACTIVITY_THRESHOLD` → expect one `FOREGROUND_INACTIVITY`; in a second run, emit a cart mutation just before threshold and verify the timer resets (no emit until a fresh full interval). Expected: emit-once after a full quiet interval; mutation resets. Traces: AC-1.

- **TC-AND-216-10 — Suppression on checkout success.**
  Type: unit (JVM). Target: `CartAbandonmentTracker.onCheckoutCompleted` + store. Preconditions: active episode, non-empty cart. Steps: call `onCheckoutCompleted()`; then trigger a would-be abandonment (e.g. background past threshold). Expected: no event emitted; store reset; a subsequent identical cart can start a NEW episode and emit later. Traces: AC-4, AC-5.

- **TC-AND-216-11 — DataStore read/write failure degrades safely.**
  Type: unit (JVM, store throwing IOException). Target: `EmitCartAbandonmentUseCase` + `AbandonmentMarkerStore` `runCatching`. Steps: force `lastEmittedHash()` read to throw, then `invoke`. Expected: treated as "no prior marker" → emits (prefer duplicate over lost signal); write failure is swallowed/logged, no crash. Traces: AC-1, AC-8; §7.

- **TC-AND-216-12 — Marker round-trips through a real DataStore (process-restart analogue).**
  Type: integration/instrumented (EMU `test35`). Target: `AbandonmentMarkerStore` over real `DataStore<Preferences>`. Steps: `recordEmitted(hash, episodeId)`; dispose and recreate the store instance pointing at the same file; read back. Expected: `lastEmittedHash()` and episode id survive; `reset()` clears all keys. Traces: AC-6.

- **TC-AND-216-13 — Real process death + relaunch: one PROCESS_KILLED, no duplicate.**
  Type: instrumented/e2e — **MUST run on the physical device (DEV, SM-A156U, API 34)**; real `am kill`/force-stop behavior and on-disk DataStore persistence across an actual process death are not faithfully reproduced on the headless emulator. Target: `CartAbandonmentTracker` + `AbandonmentMarkerStore` end-to-end. Preconditions: non-empty cart; background mark written with age that will exceed threshold. Steps: background the app, `adb shell am force-stop com.testlogon.android`, wait past threshold, relaunch. Expected: exactly one `PROCESS_KILLED` event on `CartEventSink.events`; relaunching again produces no further event for the same unchanged cart (de-dupe persisted). Also confirm correct arm64-v8a/API-34 behavior here vs the x86_64/API-35 emulator. Traces: AC-1, AC-3, AC-6.

- **TC-AND-216-14 — Security/privacy: no PII in event or marker; no network/permission.**
  Type: unit + static check (JVM) with a manual review step. Target: `CartAbandonedEvent`, `AbandonmentMarkerStore`, manifest. Steps: assert event fields are limited to ids/counts/subtotal/currency/reason/hash/timestamps (no SKU strings, name, email, address, payment); assert marker keys store only hash/timestamps/ids; assert the build adds no new `<uses-permission>` and the module makes no HTTP call (no Retrofit/OkHttp usage in `feature-cart` abandonment classes); confirm backup exclusion for marker keys via `dataExtractionRules`/`fullBackupContent`. Expected: all assertions hold. Traces: AC-7; §8.

- **TC-AND-216-15 — Wiring smoke: debug sink subscriber receives emitted event.**
  Type: integration (EMU `test35`, `BuildConfig.DEBUG`). Target: Hilt graph (`CartEventSink`→`DefaultCartEventSink`) + tracker started from `Application.onCreate()`. Steps: launch app, drive a non-empty cart, trigger foreground-inactivity (shortened threshold for test build), observe the debug subscriber log / collected flow. Expected: exactly one event flows end-to-end; binding resolves; tracker registered with `ProcessLifecycleOwner`. Traces: AC-1, AC-8; §10.

**Accessibility note:** This ticket renders no UI (FR-7, §9), so there are no Compose-UI/TalkBack/contrast cases. Accessibility coverage is N/A by design and is owned by the downstream recovery-UI ticket.

### Coverage matrix

| AC (§14) | Covered by |
|---|---|
| AC-1 (event emitted on qualifying trigger) | TC-01, TC-03(neg), TC-06, TC-07(neg), TC-09, TC-11, TC-13, TC-15 |
| AC-2 (correct field mapping) | TC-01, TC-04, TC-05 |
| AC-3 (exactly-once per unchanged contents) | TC-02, TC-05, TC-08, TC-13 |
| AC-4 (suppression on checkout success) | TC-10 |
| AC-5 (reset enables new episode) | TC-05, TC-08, TC-10 |
| AC-6 (de-dupe survives process death; one PROCESS_KILLED) | TC-12, TC-13 |
| AC-7 (no UI / no network / no new permission) | TC-03, TC-14 |
| AC-8 (deterministic tests via injected Clock; §11 green) | TC-01, TC-06, TC-09, TC-11, TC-15 |
