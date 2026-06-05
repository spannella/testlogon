---
id: AND-017
title: Connectivity & backend health probe
milestone: M1
epic: E02
priority: P1
size: M
status: draft
depends_on: [AND-010]
blocks: []
---

# AND-017 — Connectivity & backend health probe

## 1. Overview & Goal

The dev backend (`http://18.222.237.167:8000`) is a plaintext, single-host,
unreliable FastAPI deployment that frequently becomes slow or unreachable. The
Android client must never present a frozen or silently-broken UI when the host
is down. This ticket delivers a **reachability monitor** that combines two
signals — OS-level network transport availability and a lightweight, periodic
backend liveness ping — into a single observable `Flow<BackendStatus>` published
from `core-network`.

Goal: any feature module or the app shell can collect a hot, conflated
`StateFlow<BackendStatus>` to drive offline banners, retry affordances, and
"stale data" indicators, without each feature re-implementing connectivity
logic. The probe must flip to `Unreachable` within a bounded interval when the
host goes down and recover to `Reachable` automatically when it returns, with
all behavior verifiable using `MockWebServer` and a fake network callback.

Out of scope: the offline UI banner composable (owned by AND-024), per-request
retry/refresh interceptors (AND-014/AND-016), and the global error-to-UiState
mapper (AND-013). This ticket owns only the *signal*, not its presentation.

## 2. Context & References

- **Module:** `core-network` (Gradle path `:core-network`), namespace
  `com.testlogon.android.core.network`. The status model lives in `core-model`
  (`com.testlogon.android.core.model`) so feature modules depend only on the
  model, not the network module, to read the type.
- **Depends on:** AND-010 (Retrofit + Moshi setup) — provides the shared
  `OkHttpClient`, `Moshi`, and `BuildConfig.API_BASE_URL` that the probe reuses
  for its ping client so timeouts and the cookie jar are consistent.
- **Stack:** Kotlin 2.0.21, Coroutines/Flow, OkHttp 4.12, Retrofit 2.11, Hilt
  (KSP), `androidx.core` `ConnectivityManager` APIs, minSdk 24 / targetSdk 35.
- **Backend:** FastAPI. OpenAPI at `/openapi.json`. A dedicated health endpoint
  (`GET /healthz`, see §5) is the preferred probe target; if absent on the dev
  host, the probe falls back to a `HEAD /openapi.json`. Web reference does not
  implement an equivalent monitor; this is Android-specific.
- **Consumers (downstream):** AND-024 (offline/stale banner), app shell
  splash/retry, and any `feature-*` ViewModel that wants to gate network calls.

## 3. Functional Requirements

FR-1. Expose a singleton `BackendHealthMonitor` providing
`val status: StateFlow<BackendStatus>` — hot, conflated, shared via
`SharingStarted.WhileSubscribed(5_000)`, seeded with `BackendStatus.Unknown`.

FR-2. The monitor combines two inputs:
  (a) **Transport availability** from `ConnectivityManager` (any validated
  internet-capable transport: WIFI, CELLULAR, ETHERNET).
  (b) **Backend liveness** from a lightweight HTTP ping to the health endpoint.

FR-3. When no transport is available, status is `Offline` immediately and **no
ping is issued** (do not waste battery/requests). The transport callback is the
source of truth for the device-network dimension.

FR-4. When a transport is available, the monitor pings the backend on an
interval: every **15 s while `Reachable`**, and every **5 s while `Unreachable`**
(faster recovery detection), with ±20% jitter to avoid thundering herd. A ping
is also triggered immediately on transport-gained and on first subscription.

FR-5. A ping succeeds when the health request returns any 2xx within the probe
timeout. Any timeout, IOException, or non-2xx response counts as a failure.

FR-6. **Debounce flapping** with hysteresis: require **1** consecutive success
to enter `Reachable` (fast recovery) but **2** consecutive failures to enter
`Unreachable` (avoid a single blip flipping the banner).

FR-7. The probe must not run forever in the background: collection is driven by
subscribers via `WhileSubscribed`, so when no UI observes the flow the polling
loop stops within the 5 s grace window.

FR-8. Expose a `suspend fun probeNow(): BackendStatus` for manual "Retry"
buttons that forces an immediate ping and returns the resulting status.

## 4. Technical Design

### 4.1 Status model (`core-model`)

```kotlin
package com.testlogon.android.core.model

sealed interface BackendStatus {
    /** Initial state before the first signal is observed. */
    data object Unknown : BackendStatus
    /** Device has no validated network transport. */
    data object Offline : BackendStatus
    /** Transport up, backend answering health checks. */
    data class Reachable(val latencyMs: Long) : BackendStatus
    /** Transport up, backend not answering. */
    data class Unreachable(val reason: ProbeFailure) : BackendStatus
}

enum class ProbeFailure { TIMEOUT, IO_ERROR, HTTP_ERROR }
```

### 4.2 Network observer (`core-network`)

```kotlin
package com.testlogon.android.core.network.health

interface NetworkConnectivityObserver {
    /** Emits true when a validated internet-capable transport is available. */
    val transportAvailable: Flow<Boolean>
}

class NetworkConnectivityObserverImpl @Inject constructor(
    @ApplicationContext context: Context,
) : NetworkConnectivityObserver {
    override val transportAvailable: Flow<Boolean> = callbackFlow {
        val cm = context.getSystemService(ConnectivityManager::class.java)
        val callback = object : ConnectivityManager.NetworkCallback() {
            override fun onAvailable(network: Network) { trySend(true) }
            override fun onLost(network: Network) { trySend(false) }
            override fun onCapabilitiesChanged(
                network: Network, caps: NetworkCapabilities,
            ) {
                trySend(caps.hasCapability(NET_CAPABILITY_VALIDATED))
            }
        }
        val request = NetworkRequest.Builder()
            .addCapability(NET_CAPABILITY_INTERNET)
            .build()
        cm.registerNetworkCallback(request, callback)
        trySend(cm.activeNetwork != null)
        awaitClose { cm.unregisterNetworkCallback(callback) }
    }.distinctUntilChanged().conflate()
}
```

### 4.3 Ping client

A small, dedicated Retrofit/OkHttp surface reusing the shared client (AND-010)
but with a **shorter, probe-specific timeout** (4 s connect+read) so a hung host
does not stall the 15 s loop. The shared 20 s timeout is for real data calls.

```kotlin
interface HealthApi {
    @GET("healthz")
    suspend fun healthz(): Response<Unit>

    @HEAD("openapi.json") // fallback target
    suspend fun openApiHead(): Response<Unit>
}

@Qualifier annotation class HealthClient
```

The probe client is built by cloning the AND-010 `OkHttpClient` via
`newBuilder()` and overriding timeouts; it shares the persistent cookie jar so
probes do not create rogue sessions.

### 4.4 Monitor implementation

```kotlin
@Singleton
class BackendHealthMonitor @Inject constructor(
    observer: NetworkConnectivityObserver,
    private val healthApi: HealthApi,
    @ApplicationScope private val scope: CoroutineScope,
    private val clock: Clock = Clock.System,
) {
    val status: StateFlow<BackendStatus> =
        observer.transportAvailable
            .flatMapLatest { up ->
                if (!up) flowOf(BackendStatus.Offline)
                else pingLoop()
            }
            .scan(BackendStatus.Unknown as BackendStatus, ::applyHysteresis)
            .distinctUntilChanged()
            .stateIn(scope, SharingStarted.WhileSubscribed(5_000),
                     BackendStatus.Unknown)

    private fun pingLoop(): Flow<RawProbe> = flow {
        while (true) {
            emit(singleProbe())
            val period = if (lastWasFailure) 5_000L else 15_000L
            delay(jitter(period))
        }
    }

    suspend fun probeNow(): BackendStatus { /* force singleProbe(), fold */ }
    private suspend fun singleProbe(): RawProbe { /* time + call healthApi */ }
}
```

`applyHysteresis` holds a small counter of consecutive raw results and only
transitions `Reachable`→`Unreachable` after 2 failures, `Unreachable`→`Reachable`
after 1 success (FR-6). `flatMapLatest` guarantees that losing transport
cancels the in-flight ping loop instantly and emits `Offline`.

### 4.5 Hilt wiring

A `@Module @InstallIn(SingletonComponent::class)` binds
`NetworkConnectivityObserver`, provides the `@HealthClient` Retrofit and
`HealthApi`, and provides the `@ApplicationScope CoroutineScope`
(`CoroutineScope(SupervisorJob() + Dispatchers.Default)`). `BackendHealthMonitor`
is `@Singleton` and constructor-injected.

## 5. API Contract

The probe is read-only and idempotent (GET/HEAD only — consistent with the
"retries for idempotent GETs only" project rule).

**Primary:** `GET /healthz`

```
HTTP/1.1 200 OK
Content-Type: application/json
{"status":"ok"}
```

Only the status code matters; the body is ignored (`Response<Unit>`). Any 2xx =
healthy.

**Fallback:** `HEAD /openapi.json` (used when `/healthz` returns 404, recorded
once via a capability flag so we stop probing the missing endpoint).

```
HTTP/1.1 200 OK
Content-Type: application/json
```

Failure mapping: socket/connect timeout → `ProbeFailure.TIMEOUT`; IOException /
DNS / connection-refused → `IO_ERROR`; any non-2xx → `HTTP_ERROR`. No request
body, no auth required, no CSRF header needed (health is unauthenticated). If a
probe unexpectedly returns 401 it is treated as `HTTP_ERROR` and does **not**
trigger the AND-016 session-refresh path.

## 6. Data & State Management

- Single source of truth: `BackendHealthMonitor.status: StateFlow<BackendStatus>`.
- Conflated and `WhileSubscribed(5_000)` — late subscribers immediately receive
  the latest value; no replay buffer beyond the StateFlow's single slot.
- No persistence: status is ephemeral runtime state, **not** written to DataStore
  or Room. (Stale-cache decisions belong to `core-data` consumers, not here.)
- Internal hysteresis counters are confined to the `scan` accumulator and the
  monitor instance; they are never exposed.
- Threading: all probing runs on `Dispatchers.Default`/OkHttp dispatcher;
  collectors observe via the StateFlow on whatever dispatcher they choose. The
  `ConnectivityManager` callback is registered on the application scope and
  unregistered via `awaitClose` to prevent leaks.

## 7. Error Handling & Resilience

- A failed ping is a normal, expected outcome (not an exception that propagates):
  `singleProbe()` wraps the call in `runCatching` and converts throwables to a
  `RawProbe.Failure(ProbeFailure)`. The loop never crashes.
- **Bounded behavior:** probe timeout is fixed at 4 s; the loop never issues
  overlapping pings (sequential `emit` then `delay`). No unbounded retry — the
  interval *is* the retry cadence.
- Backoff: faster cadence (5 s) while `Unreachable` for quick recovery, slower
  (15 s) while healthy to conserve resources; jitter prevents synchronized
  bursts across app instances.
- Hysteresis (FR-6) prevents UI flapping on a single dropped packet.
- Transport loss short-circuits to `Offline` without waiting for a ping timeout,
  so the UI reflects airplane mode instantly.
- The application-scope `SupervisorJob` ensures a failure in the monitor never
  cancels sibling app coroutines.

## 8. Security & Privacy

- Health probes hit an **unauthenticated** endpoint; no credentials, tokens, or
  CSRF header are attached, and probe responses are discarded.
- The dev backend is plaintext HTTP; the network security config (owned by
  AND-009) must already permit cleartext to `18.222.237.167`. This ticket adds
  no new cleartext exceptions.
- No PII is collected or logged. Latency and status are non-sensitive.
- Requires `ACCESS_NETWORK_STATE` permission (normal, install-time) for
  `ConnectivityManager`; declared in `core-network`'s manifest. No
  `ACCESS_FINE_LOCATION` and no `CHANGE_NETWORK_STATE` are needed.
- The probe shares the cookie jar but issues only idempotent GET/HEAD requests,
  so it cannot mutate session state.

## 9. Accessibility & i18n

No UI is shipped by this ticket, so direct a11y/i18n surface is N/A here. To
keep downstream work consistent, the model exposes **machine-readable** values
only (sealed types/enums) and contains **no user-facing strings**. AND-024 owns
the offline banner, its `contentDescription`/announce-on-change semantics
(`liveRegion`), and all localized copy (e.g. "No connection", "Server
unavailable"), mapping `BackendStatus` → string resources there.

## 10. Telemetry & Logging

- Structured debug logging via the project logger (Timber-style) under tag
  `BackendHealth`: log each *transition* (e.g. `Reachable→Unreachable(TIMEOUT)`)
  at INFO, individual ping results at VERBOSE only. Never log on every poll at
  INFO to avoid log spam at the 15 s/5 s cadence.
- Emit a structured event per transition for future analytics:
  `health_status_changed { from, to, reason, latencyMs }`. Wire-up to a real
  analytics sink is deferred to the telemetry ticket; here we expose a no-op /
  injected `HealthEventSink` interface so it is testable.
- Logging is gated by `BuildConfig.DEBUG` for VERBOSE; transitions log in all
  builds (low volume).

## 11. Testing Strategy

All tests run on JVM (`core-testing` + `MockWebServer` + Turbine), no
instrumentation required.

- **MockWebServer up/down/recover (AC-critical):** enqueue 200s → assert
  `Reachable`; enqueue failures (`SocketPolicy.NO_RESPONSE` / 503) → assert
  `Unreachable` after 2 failures; re-enqueue 200 → assert `Reachable` again.
  Use `Turbine`'s `test {}` on the `status` flow and a virtual-time
  `TestScope`/`StandardTestDispatcher` to fast-forward the poll `delay`.
- **Transport gating:** feed a fake `NetworkConnectivityObserver` emitting
  `false` → assert `Offline` and assert `MockWebServer.requestCount == 0`
  (FR-3). Flip to `true` → assert an immediate probe fires.
- **Hysteresis:** one failure between successes must NOT flip to `Unreachable`;
  two consecutive must. One success must flip back from `Unreachable`.
- **Cadence:** with virtual time, advance 15 s while healthy and assert exactly
  one additional probe; advance 5 s while unreachable and assert one probe.
- **Failure mapping:** timeout → `TIMEOUT`, 500 → `HTTP_ERROR`, connection
  refused → `IO_ERROR`.
- **Fallback:** `/healthz` 404 then `HEAD /openapi.json` 200 → `Reachable`.
- **probeNow():** returns synchronously-resolved status and forces a request.
- **Leak check:** assert `awaitClose` unregisters the network callback when the
  flow's last collector cancels.

Target: ≥ 90% line coverage on `BackendHealthMonitor` and `applyHysteresis`.

## 12. Dependencies & Sequencing

- **Hard dependency:** AND-010 (Retrofit + Moshi, shared `OkHttpClient`,
  `BuildConfig.API_BASE_URL`). Must merge first.
- **Soft prerequisite:** AND-009 (network security config for cleartext) — the
  probe will fail with `IO_ERROR` against the dev host without it; not a build
  blocker but required for green integration tests against the real host.
- **Provides to:** AND-024 (offline/stale banner consumes `status`), app shell
  splash/retry gating. This ticket should land before AND-024 starts.
- Sequencing: implement `core-model` `BackendStatus` → `NetworkConnectivity
  Observer` → `HealthApi` + `@HealthClient` module → `BackendHealthMonitor` →
  tests.

## 13. Risks & Open Questions

- **R1:** `/healthz` may not exist on the dev host. Mitigation: `HEAD
  /openapi.json` fallback (§5). *Open:* confirm canonical health path with
  backend owner; update if a different path (`/health`, `/ping`) is canonical.
- **R2:** `NET_CAPABILITY_VALIDATED` can lag on captive portals — device shows
  transport but no real internet. The backend ping is the backstop (we will
  report `Unreachable`, which is correct for the user).
- **R3:** Battery/data from polling. Mitigated by `WhileSubscribed` (stops with
  no UI) and conservative 15 s healthy cadence. *Open:* confirm whether the
  monitor should also pause when the app is backgrounded — current design relies
  on UI collectors stopping, which naturally pauses it.
- **R4:** Clock/virtual-time flakiness in tests; mitigated by injecting
  `Clock` and using `StandardTestDispatcher`.

## 14. Acceptance Criteria

- AC-1 (source): With `MockWebServer`, status flips to `Unreachable` after the
  host stops responding (per hysteresis, ≤ 2 failed probes) and recovers to
  `Reachable` when the host returns — proven by an automated test.
- AC-2: `BackendHealthMonitor.status` is a `StateFlow<BackendStatus>` over the
  `Unknown/Offline/Reachable/Unreachable` model, conflated and
  `WhileSubscribed`.
- AC-3: No transport → `Offline` and zero probe requests issued (verified via
  `requestCount`).
- AC-4: Transport regained triggers an immediate probe; healthy cadence is 15 s,
  unhealthy 5 s, both with jitter (verified under virtual time).
- AC-5: `probeNow()` forces an immediate ping and returns the resolved status.
- AC-6: Probe requests are GET/HEAD only, carry no auth/CSRF, and a probe 401
  does not invoke session refresh.
- AC-7: Network callback is unregistered when the last collector cancels (no
  leak).
- AC-8: All new tests pass on JVM with no instrumentation; coverage ≥ 90% on the
  monitor.

## 15. Definition of Done

- `BackendStatus`/`ProbeFailure` in `core-model`; `NetworkConnectivityObserver`,
  `HealthApi`, `@HealthClient` module, and `BackendHealthMonitor` in
  `core-network`, all Hilt-wired and constructor-injected.
- `ACCESS_NETWORK_STATE` declared in `core-network` manifest.
- Unit/integration tests (§11) green in CI; ktlint/detekt clean; no new lint
  baseline entries.
- KDoc on the public `BackendHealthMonitor`, `status`, and `probeNow()`.
- Probe verified against the live dev host (`http://18.222.237.167:8000`) at
  least once manually, with the up→down→up transition observed in logs.
- Code review approved on branch `android-port`; no user-facing strings
  introduced (banner copy deferred to AND-024).
