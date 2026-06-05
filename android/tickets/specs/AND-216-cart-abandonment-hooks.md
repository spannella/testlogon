---
id: AND-216
title: Cart abandonment hooks
milestone: M5
epic: E29
priority: P2
size: M
status: draft
depends_on: [AND-210]
blocks: []
---

# AND-216 — Cart abandonment hooks

## 1. Overview & Goal

This ticket adds **cart abandonment detection and event emission** to the native Android port of TestLogon. When a user adds one or more items to their cart, begins (or could begin) checkout, and then leaves without completing the purchase, the app must emit a single, well-formed `cart_abandoned` analytics event describing the abandoned cart. The web reference implements this in `frontend/src/api/endpoints/cartAbandonment.ts`; this ticket ports the equivalent behaviour into the Kotlin codebase as a `feature-cart` use case plus a lightweight tracker that observes cart state and lifecycle.

The **goal** is narrowly scoped: detect abandonment deterministically and emit exactly one abandonment event per abandonment episode. It is explicitly *not* in scope to build the analytics transport pipeline (batching, upload, retry to a backend collector), to render any UI (recovery banners, "come back" prompts), or to implement push/email recovery campaigns — those are downstream concerns. This ticket produces the *signal*; consumers subscribe to it.

The single authoritative acceptance bar from the backlog is: **"Abandonment event emitted."** Everything below makes that testable: when, exactly once, with what payload, under which lifecycle and timing conditions.

## 2. Context & References

- **Source ticket:** AND-216 — Cart abandonment hooks. Type: Feature · Priority: P2 · Deps: AND-210. Scope: `cartAbandonment.ts` events. Acceptance: Abandonment event emitted.
- **Upstream dependency:** **AND-210 — Cart API + DTOs** (`cart.ts` endpoints/DTOs). AND-210 owns the cart model (`Cart`, `CartItem`, totals), the `CartRepository`, and the `Cart` <-> DTO mapping. AND-216 consumes the cart state AND-210 exposes; it must not redefine cart models.
- **Web reference:** `frontend/src/api/endpoints/cartAbandonment.ts` (event shape and trigger logic), `frontend/src/api/endpoints/cart.ts` (cart fetch), `frontend/src/api/types.ts` (shared cart/event types).
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

**No backend HTTP endpoint is introduced by this ticket.** Cart abandonment is a client-derived signal computed entirely from local cart state. The cart fetch/persistence contract is owned by **AND-210** (`/ui/cart` family). The downstream analytics upload contract (sending events to a collector) is **out of scope** and is not yet ticketed; until then `CartEventSink` is the contract.

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

`reason` is one of `BACKGROUND_TIMEOUT | FOREGROUND_INACTIVITY | NAV_AWAY | PROCESS_KILLED`. Field names mirror `frontend/src/api/endpoints/cartAbandonment.ts` so a future collector accepts both clients identically. If/when an upload endpoint lands, it is expected to be `POST /ui/events` (cookie + `X-CSRF-Token`, idempotent on `episode_id`); that POST is the downstream ticket's responsibility, not this one.

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

- **Threshold values (5 min inactivity, 3 s nav debounce) are unconfirmed.** They should match the web reference `cartAbandonment.ts` constants; if the web uses different values, align to web. *Open question: confirm web thresholds.*
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
- Field names and event semantics match `frontend/src/api/endpoints/cartAbandonment.ts`.
- All §11 tests written and green in CI; coverage includes the exactly-once, suppression-on-success, and process-kill recovery paths.
- `./gradlew :feature-cart:test :core-data:test :core-model:test detekt lint` passes; no new lint/detekt regressions.
- No PII in event or persisted marker; backup exclusion applied to the marker keys.
- Code reviewed and merged to `android-port`; downstream consumers can subscribe to `CartEventSink.events` without depending on `feature-cart`.
- Spec dependencies remain consistent: AND-216 depends on AND-210 only.
