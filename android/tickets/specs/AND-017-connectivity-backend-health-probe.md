---
id: AND-017
title: Connectivity & backend health probe
milestone: M1
epic: E02
priority: P1
size: M
status: reviewed
reviewed_on: 2026-06-06
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
- **Backend:** FastAPI. A dedicated health endpoint (`GET /health`, see §5) is
  the preferred probe target; `GET /api/ping` is an equivalent verified
  alternative. (CORRECTION: the OpenAPI spec has **no `/healthz`** root endpoint
  — only a domain-scoped `GET /messaging/healthz`; the canonical health paths are
  `GET /health` and `GET /api/ping`.) Web reference does not implement an
  equivalent backend-probe monitor — the web `OfflineBanner` only watches the
  browser `navigator.onLine` / `online`/`offline` events
  (`src/components/shared/OfflineBanner.tsx`); this active backend probe is
  Android-specific.
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
    @GET("health")            // verified: GET /health, 200, no params/auth
    suspend fun health(): Response<Unit>

    @GET("api/ping")          // verified fallback: GET /api/ping, 200, no params/auth
    suspend fun ping(): Response<Unit>
}

@Qualifier annotation class HealthClient
```

> NOTE (corrected): the original draft targeted `@GET("healthz")` and a
> `@HEAD("openapi.json")` fallback. Neither is a documented backend endpoint.
> The verified targets are `GET /health` and `GET /api/ping`. A `HEAD` fallback
> is not used because the spec defines only one `head` operation across the whole
> API and `/openapi.json` is not a documented path.

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

**Primary:** `GET /health` (verified: `op=health_health_get`, response `200`,
`application/json`, no params, no auth).

```
HTTP/1.1 200 OK
Content-Type: application/json
```

CORRECTION: the OpenAPI 200 response schema for `/health` is an **empty schema
(`{}`)** — the body shape is undefined. Do **not** assume a `{"status":"ok"}`
body; only the status code matters and the body is ignored (`Response<Unit>`).
Any 2xx = healthy.

**Fallback:** `GET /api/ping` (verified: `op=ping_api_ping_get`, response `200`,
`application/json`, no params, no auth) — used when `/health` returns 404,
recorded once via a capability flag so we stop probing the missing endpoint.

```
HTTP/1.1 200 OK
Content-Type: application/json
```

(The original `HEAD /openapi.json` fallback was removed: `/openapi.json` is not a
documented path and the API defines only a single `head` operation, so a HEAD
probe is unsupported and unverifiable.)

Failure mapping: socket/connect timeout → `ProbeFailure.TIMEOUT`; IOException /
DNS / connection-refused → `IO_ERROR`; any non-2xx → `HTTP_ERROR`. No request
body, no auth required, no CSRF header needed (health is unauthenticated; the
web client's `X-CSRF-Token` header — set from the `ui_csrf` cookie in
`src/api/client.ts` — applies to mutations, not these idempotent GETs). If a
probe unexpectedly returns 401 it is treated as `HTTP_ERROR` and does **not**
trigger the AND-016 session-refresh path. (The web client *does* auto-refresh on
401 for authenticated users in `src/api/client.ts`; the probe deliberately opts
out of that path.)

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
- **Fallback:** `/health` 404 then `GET /api/ping` 200 → `Reachable`.
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

- **R1:** A given health path may not be deployed on the dev host. Mitigation:
  `GET /api/ping` fallback when `GET /health` 404s (§5); both are documented in
  the backend OpenAPI spec. *Open:* confirm with the backend owner which of
  `/health` vs `/api/ping` is the intended liveness probe (both currently return
  200 with an undefined body); update the primary target if guidance differs.
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

## 16. Citations & Assumption Audit

Each key technical claim, its verification verdict, and the exact source pointer.

1. **Claim:** Primary probe target is `GET /healthz`.
   **VERDICT: Corrected.** No `/healthz` root endpoint exists; the only
   `healthz` path is domain-scoped (`GET /messaging/healthz`). Corrected to
   `GET /health`.
   **SOURCE:** OpenAPI `GET /health` (`op=health_health_get`); negative check on
   `GET /healthz` in `reference/openapi.index.txt`.

2. **Claim:** Fallback probe is `HEAD /openapi.json`.
   **VERDICT: Corrected.** `/openapi.json` is not a documented path in the spec,
   and the API defines only one `head` operation total, so a HEAD probe is
   unsupported/unverifiable. Corrected to `GET /api/ping`.
   **SOURCE:** OpenAPI `GET /api/ping` (`op=ping_api_ping_get`); absence of
   `/openapi.json` path and single `"head"` occurrence in
   `reference/openapi.pretty.json`.

3. **Claim:** `GET /health` returns `200 OK` with body `{"status":"ok"}`.
   **VERDICT: Corrected.** The 200 response is `application/json` but its schema
   is empty (`{}`) — the body shape is undefined. Spec now states the body is
   ignored and only the status code matters.
   **SOURCE:** OpenAPI `GET /health` responses.200.content.application/json.schema
   `= {}` (`reference/openapi.pretty.json` line ~109005).

4. **Claim:** `GET /api/ping` returns `200` and is a usable health target.
   **VERDICT: Verified** (same empty-schema caveat as `/health`).
   **SOURCE:** OpenAPI `GET /api/ping` responses.200 (`reference/openapi.pretty.json`
   line ~92023).

5. **Claim:** The health endpoints require no auth and no params.
   **VERDICT: Verified.** Both `/health` and `/api/ping` index rows show
   `req=` (no request body) and empty `params=`, no security scheme.
   **SOURCE:** `reference/openapi.index.txt` rows for `GET /health` and `GET /api/ping`.

6. **Claim:** No CSRF header is needed for probes.
   **VERDICT: Verified.** The web client sets `X-CSRF-Token` from the `ui_csrf`
   cookie for requests generally, but these are unauthenticated idempotent GETs;
   CSRF protection is relevant to mutations, not GET/HEAD.
   **SOURCE:** `src/api/client.ts` (CSRF token block: `getCookie("ui_csrf")` →
   `headers.set("X-CSRF-Token", csrf)`).

7. **Claim:** A probe 401 must NOT trigger AND-016 session refresh.
   **VERDICT: Verified (as deliberate Android divergence).** The web client *does*
   auto-refresh once on 401 for authenticated users; the probe intentionally opts
   out and maps 401 → `HTTP_ERROR`.
   **SOURCE:** `src/api/client.ts` (the `if (res.status === 401) { ... refreshSession() ... }`
   block, ~lines 191-209).

8. **Claim:** The web reference app implements no equivalent backend-health
   monitor; this is Android-specific.
   **VERDICT: Verified.** The web `OfflineBanner` derives offline state purely
   from `navigator.onLine` and the browser `online`/`offline` events; no active
   backend ping/poll exists. No frontend code calls `/health` or `/api/ping`.
   **SOURCE:** `src/components/shared/OfflineBanner.tsx`; negative grep for
   `/health`/`/api/ping` connectivity use across `src/`.

9. **Claim:** The web client treats a thrown `fetch` (network error) as offline.
   **VERDICT: Verified** (supports the design rationale that transport/IO errors
   are the offline signal).
   **SOURCE:** `src/api/client.ts` (catch block: `// Network error (offline, DNS
   failure, etc.)` → `throw new ApiError(0, "Network error", err)`).

10. **Claim:** Standard error responses elsewhere use an `ErrorEnvelope` shape.
    **VERDICT: Verified** (relevant for the `HTTP_ERROR` mapping — note the
    health endpoints themselves declare no error schema, only 200).
    **SOURCE:** `components.schemas.ErrorEnvelope` (`{ error: ErrorDetail }`,
    `required: [error]`) in `reference/openapi.pretty.json` (~line 31777).

11. **Claim:** `ConnectivityManager` + `NetworkCallback` /
    `NET_CAPABILITY_VALIDATED` / `NET_CAPABILITY_INTERNET` is the correct API for
    transport observation; `ACCESS_NETWORK_STATE` is the required permission.
    **VERDICT: Unverified-assumption (framework ref).** Not checkable against the
    backend/frontend sources; standard Android framework behavior.
    **SOURCE:** framework ref —
    https://developer.android.com/reference/android/net/ConnectivityManager and
    https://developer.android.com/training/monitoring-device-state/connectivity-status-type

12. **Claim:** `SharingStarted.WhileSubscribed(5_000)` / `StateFlow` /
    `flatMapLatest` / `callbackFlow` semantics (conflation, cancellation, grace
    window) behave as described.
    **VERDICT: Unverified-assumption (framework ref).** Coroutines/Flow library
    behavior, not in scope of the project sources.
    **SOURCE:** framework ref —
    https://kotlinlang.org/api/kotlinx.coroutines/kotlinx-coroutines-core/kotlinx.coroutines.flow/-sharing-started/

13. **Claim:** AND-010 provides the shared `OkHttpClient`, `Moshi`, and
    `BuildConfig.API_BASE_URL`, and AND-009 owns the cleartext network-security
    config for `18.222.237.167`.
    **VERDICT: Unverified-assumption.** Cross-ticket dependency; cannot be
    confirmed from backend/frontend sources or framework docs.
    **SOURCE:** internal ticket dependency (AND-010 / AND-009) — confirm at
    integration time.

14. **Claim:** The dev backend is plaintext HTTP at `http://18.222.237.167:8000`.
    **VERDICT: Unverified-assumption.** The host/port is an environment fact not
    present in the OpenAPI or frontend sources provided.
    **SOURCE:** internal environment config — confirm with backend owner.

### Corrections made

- **C1 (§2, §4.3, §5, §11, §13):** Replaced the non-existent `GET /healthz`
  primary target with the verified `GET /health`.
- **C2 (§4.3, §5, §11):** Replaced the unsupported `HEAD /openapi.json` fallback
  with the verified `GET /api/ping`.
- **C3 (§5):** Removed the asserted `{"status":"ok"}` response body; the 200
  schema is empty/undefined, so only the status code is used.
- **C4 (§5):** Clarified CSRF — named the web header `X-CSRF-Token` (from
  `ui_csrf`) and the auto-refresh-on-401 path that the probe deliberately avoids.
- **C5 (§2):** Cited the web `OfflineBanner`'s `navigator.onLine` mechanism as
  evidence the active backend probe is genuinely Android-specific.

### Open assumptions

- **OA1 — Which health path is canonical.** Both `/health` and `/api/ping`
  return 200 with undefined bodies; backend owner has not designated one as the
  official liveness probe. (Why: no annotation/summary in the spec distinguishes
  them.)
- **OA2 — Android framework semantics** (ConnectivityManager, Flow/StateFlow
  sharing). (Why: outside the provided backend/frontend sources; rely on official
  Android/Kotlin docs.)
- **OA3 — Cross-ticket contracts** (AND-010 client/Moshi/BASE_URL, AND-009
  cleartext config). (Why: those tickets' artifacts are not in the source set.)
- **OA4 — Dev host/port** `http://18.222.237.167:8000`. (Why: an environment
  fact absent from OpenAPI/frontend sources.)

## 17. Test Plan

Case IDs `TC-AND-017-NN`. "Traces" links each case to §14 acceptance criteria.

- **TC-AND-017-01 — Happy path: up → Reachable.**
  Type: contract/MockWebServer. Preconditions: fake `NetworkConnectivityObserver`
  emits `true`; `MockWebServer` enqueues `200` for `GET /health`. Steps: collect
  `status` via Turbine under a `StandardTestDispatcher`/virtual time; let the
  first probe fire. Expected: status emits `Reachable(latencyMs >= 0)` after one
  success (FR-6 fast-recovery = 1). Traces: AC-1, AC-2.

- **TC-AND-017-02 — Down then recover (source AC).**
  Type: contract/MockWebServer. Preconditions: transport `true`. Steps: enqueue
  `200` (assert `Reachable`); enqueue two failures (`SocketPolicy.NO_RESPONSE`
  then `503`), advancing virtual time past each poll; then re-enqueue `200`.
  Expected: stays `Reachable` after the 1st failure, flips to
  `Unreachable` only after the **2nd** consecutive failure, then returns to
  `Reachable` after the next single success. Traces: AC-1.

- **TC-AND-017-03 — No transport → Offline, zero requests.**
  Type: unit/contract. Preconditions: fake observer emits `false`. Steps: collect
  `status`; let virtual time advance well beyond a poll interval. Expected:
  status is `Offline`; `MockWebServer.requestCount == 0` (FR-3). Traces: AC-3.

- **TC-AND-017-04 — Transport regained triggers immediate probe.**
  Type: contract/MockWebServer. Preconditions: observer starts `false`
  (`Offline`), then flips to `true`; enqueue `200`. Steps: flip transport;
  observe. Expected: a probe fires immediately (not after waiting a full 15 s)
  and status becomes `Reachable`. Traces: AC-4.

- **TC-AND-017-05 — Cadence under virtual time.**
  Type: unit (virtual time). Preconditions: transport `true`. Steps: while
  `Reachable`, advance 15 s and assert exactly one additional request; force
  `Unreachable`, advance 5 s and assert exactly one request; assert each computed
  delay falls within ±20% jitter of the base period. Expected: 15 s healthy /
  5 s unhealthy cadence honored. Traces: AC-4.

- **TC-AND-017-06 — Hysteresis edge cases.**
  Type: unit (`applyHysteresis`). Steps: feed success, failure, success → assert
  no flip to `Unreachable`; feed failure, failure → assert flip; feed one
  success → assert flip back to `Reachable`. Expected: matches FR-6 (2 fails to
  drop, 1 success to recover). Traces: AC-1.

- **TC-AND-017-07 — Failure mapping to ProbeFailure.**
  Type: contract/MockWebServer. Steps: enqueue a `NO_RESPONSE`/read-timeout →
  expect `Unreachable(TIMEOUT)`; enqueue `500` → expect
  `Unreachable(HTTP_ERROR)`; simulate connection refused (server shutdown / bad
  port) → expect `Unreachable(IO_ERROR)`. Expected: correct `ProbeFailure`
  variants per §5/§7. Traces: AC-1.

- **TC-AND-017-08 — Health 404 falls back to /api/ping.**
  Type: contract/MockWebServer. Preconditions: transport `true`. Steps: enqueue
  `404` for `GET /health`, then `200` for `GET /api/ping`. Expected: status
  becomes `Reachable`; the capability flag records the fallback so subsequent
  polls hit `/api/ping` (the dead `/health` is not re-probed). Traces: AC-1, AC-6.

- **TC-AND-017-09 — probeNow() forces an immediate ping.**
  Type: unit/contract. Steps: with transport `true` and a `200` enqueued, call
  `probeNow()`. Expected: a request is issued synchronously w.r.t. the call and
  the resolved `BackendStatus` (e.g. `Reachable`) is returned to the caller.
  Traces: AC-5.

- **TC-AND-017-10 — Probe requests are GET-only, unauthenticated, no CSRF; 401
  does not refresh.** Type: contract/MockWebServer. Steps: run several probes and
  inspect `RecordedRequest`s. Expected: every request method is `GET`, path is
  `/health` or `/api/ping`, no `Authorization`/`X-CSRF-Token`/`Cookie`-derived
  auth header is required for success; a `401` response maps to
  `Unreachable(HTTP_ERROR)` and **no** session-refresh request is emitted.
  Traces: AC-6.

- **TC-AND-017-11 — Probe timeout does not stall the loop.**
  Type: contract/MockWebServer. Steps: configure the `@HealthClient` 4 s timeout;
  enqueue a delayed/`NO_RESPONSE` body so the probe times out; advance time.
  Expected: probe resolves as `TIMEOUT` near the 4 s bound (not the shared 20 s),
  the loop proceeds to the next scheduled poll, and no overlapping pings occur.
  Traces: AC-1, AC-4.

- **TC-AND-017-12 — Callback unregistered on last collector cancel (leak check).**
  Type: unit. Steps: collect `status`, then cancel the last collector; allow the
  `WhileSubscribed(5_000)` grace window to elapse in virtual time. Expected:
  `awaitClose` runs and `cm.unregisterNetworkCallback` is invoked (verified via a
  fake/spy `ConnectivityManager`); polling stops. Traces: AC-7.

- **TC-AND-017-13 — Flaky/offline dev-host path against live host (manual).**
  Type: manual / instrumented. Preconditions: AND-009 cleartext config present;
  device pointed at `http://18.222.237.167:8000`. Steps: observe `Reachable`;
  stop/sever the host (or enable airplane mode); restore. Expected: logs show
  `Reachable→Unreachable(...)` then `Unreachable→Reachable`; airplane mode yields
  `Offline` instantly with no ping attempt. Traces: AC-1, AC-3, AC-4.

- **TC-AND-017-14 — JVM-only, coverage gate.**
  Type: unit/CI. Steps: run the §11 suite with no instrumentation; measure
  coverage. Expected: all tests pass on JVM; ≥ 90% line coverage on
  `BackendHealthMonitor` and `applyHysteresis`. Traces: AC-8.

> Accessibility note: this ticket ships no UI, so no Compose-UI/a11y cases apply
> here. The a11y verification for the offline banner (contentDescription,
> `liveRegion`/announce-on-change, localized copy) is owned by AND-024 and is
> explicitly out of scope (§9).

### Coverage matrix

| §14 Acceptance Criterion | Covered by |
| --- | --- |
| AC-1 (up→down→recover; failure mapping; fallback) | TC-01, TC-02, TC-06, TC-07, TC-08, TC-11, TC-13 |
| AC-2 (StateFlow over the model, conflated, WhileSubscribed) | TC-01 |
| AC-3 (no transport → Offline, zero requests) | TC-03, TC-13 |
| AC-4 (immediate probe on regain; 15 s/5 s cadence + jitter) | TC-04, TC-05, TC-11, TC-13 |
| AC-5 (probeNow forces a ping, returns status) | TC-09 |
| AC-6 (GET/HEAD only, no auth/CSRF, 401 ≠ refresh) | TC-08, TC-10 |
| AC-7 (callback unregistered on last cancel) | TC-12 |
| AC-8 (JVM tests pass, ≥90% coverage) | TC-14 |
