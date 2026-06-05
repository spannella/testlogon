---
id: AND-291
title: TURN/STUN credentials
milestone: M7
epic: E39
priority: P0
size: M
status: draft
depends_on: [AND-289, AND-288]
blocks: [AND-292]
---

# AND-291 — TURN/STUN credentials

## 1. Overview & Goal

WebRTC negotiation produced by the `core-webrtc` wrapper (AND-289) can only
traverse symmetric/port-restricted NATs and mobile carrier-grade NAT if the
`PeerConnection` is configured with a TURN relay in addition to STUN. AND-289
deliberately left `RtcConfig.iceServers` empty and flagged the ICE-server source
as an open question (AND-289 §13 OQ2). This ticket closes that gap: it fetches
short-lived, ephemeral TURN/STUN credentials from the FastAPI backend
(`turn-credentials`), maps them into the `List<RtcIceServer>` that AND-289's
`RtcConfig` already accepts, caches them with respect to their TTL, refreshes
them before expiry, and proves that a real relay (`relay`-type) ICE candidate is
selected when a direct/host path is unavailable.

The deliverable is an `IceServersRepository` plus its network DTOs, adapters,
and Hilt wiring in `core-data`/`core-network`, an `IceServersProvider` seam that
the broadcast/viewer call feature (AND-292+) calls before `createOffer()`, and a
connectivity proof that ICE selects the TURN relay candidate behind a NAT that
blocks host/srflx connectivity.

Out of scope: the signaling transport itself (SDP/ICE exchange over `/signal`,
owned by AND-290), the call UI/feature wiring (AND-292+), and ICE-restart on a
mid-call credential expiry (deferred; see §13 OQ2). This ticket only supplies
correctly-configured, fresh `iceServers` to a freshly-created `PeerConnection`.

## 2. Context & References

- **Repo / branch:** `spannella/testlogon`, Android app under `android/`, branch
  `android-port`. Canonical namespace `com.testlogon.android`.
- **Module layering:** `app -> feature-* -> core-*`. The fetch/cache logic lives
  in `core-data` (repository) + `core-network` (Retrofit API + DTOs), reusing the
  shared OkHttp/Retrofit/Moshi stack. The mapping into `RtcIceServer` produces the
  `core-webrtc` (AND-289) value type, so `core-data` depends on `core-webrtc` for
  the `RtcIceServer` model only (or `RtcIceServer` is hosted in `core-model`; see
  §6). No new module.
- **Upstream (AND-288):** `stream-webrtc-android` artifact, `PeerConnectionFactory`,
  `EglBase` singletons.
- **Upstream (AND-289):** `RtcConfig(iceServers: List<RtcIceServer> = emptyList(), ...)`,
  `RtcPeerConnectionFactory.create(config, signaling)`, and
  `data class RtcIceServer(val urls: List<String>, val username: String? = null, val credential: String? = null)`.
  This ticket *populates* that list; it does not change the wrapper API.
- **Backend:** FastAPI + DynamoDB, dev host `http://18.222.237.167:8000`
  (PLAINTEXT HTTP, UNRELIABLE). OpenAPI at `/openapi.json`. The credentials
  endpoint is authenticated via the cookie session + `X-CSRF-Token` echo
  established by `core-network` (AND-011 cookie jar, AND-012 CSRF interceptor,
  AND-013 401-refresh authenticator). Exact path/shape confirmed from
  `/openapi.json` at implementation (see §5; web reference under
  `frontend/src/api/endpoints/*.ts`).
- **Downstream (AND-292+):** the broadcast/viewer call feature obtains
  `List<RtcIceServer>` from `IceServersProvider` and passes it into `RtcConfig`
  before calling `RtcPeerConnection.createOffer()`/`createAnswer()`.
- **Stack baseline:** Kotlin 2.0.21, Coroutines/Flow, Hilt (KSP), Retrofit 2.11
  + OkHttp 4.12 + Moshi 1.15, DataStore (no Room needed — single ephemeral
  record), `ApiResult<T>` (AND-018), FastAPI `detail` error mapping (AND-015),
  bounded backoff for idempotent GETs (AND-016).

## 3. Functional Requirements

FR-1. **Fetch.** `IceServersApi.getTurnCredentials()` performs an authenticated
GET against the backend `turn-credentials` endpoint and returns the raw DTO.

FR-2. **Map.** `IceServersRepository` maps the DTO into
`IceServers(servers: List<RtcIceServer>, ttlSeconds: Long, fetchedAtEpochMs: Long)`.
STUN entries (no credential) and TURN entries (`username` + `credential`) are
both represented as `RtcIceServer`; multiple `urls` per server entry are
preserved (e.g. `turn:host:3478?transport=udp` and `...?transport=tcp`).

FR-3. **Cache + TTL.** Credentials are cached in-memory and persisted to
DataStore. A cached set is reused while it has at least
`REFRESH_SKEW_SECONDS` (default 60s) of TTL remaining; otherwise a refetch is
triggered. The cache survives process restart only if still within TTL.

FR-4. **Proactive refresh.** `IceServersProvider.current()` (suspend) returns a
non-expired set, transparently refetching if the cached one is within the skew
window. A best-effort background refresh may be scheduled when the call feature
goes active; mid-call rotation/ICE-restart is out of scope (§13 OQ2).

FR-5. **Configure ICE.** The provider's output is passed verbatim into
`RtcConfig.iceServers`. The wrapper (AND-289) constructs
`PeerConnection.IceServer` from each `RtcIceServer` (urls + username +
credential) with default `TlsCertPolicy` and `iceTransportPolicy = ALL`.

FR-6. **Relay verification hook.** Provide a debug/test capability to assert
that, given a TURN server and an `iceTransportPolicy = RELAY` config, the
selected candidate pair is of type `relay` (proves the credential authenticates
against the TURN server and the relay allocation succeeds).

FR-7. **Graceful degradation.** If the fetch fails (offline, 5xx, unreliable dev
host timeout), the provider returns the last-known-good cached set if still
valid; if none exists, it returns a STUN-only fallback list (configurable,
default a public-or-configured STUN URL) so direct-connectable peers still work,
and surfaces a typed warning state to the caller.

FR-8. **No leakage of credentials.** TURN `credential`/`username` are never
logged, never written to plaintext logs or analytics, and the persisted
DataStore copy is the only at-rest store (see §8).

## 4. Technical Design

### 4.1 DTOs & adapters (`core-network`)

```kotlin
package com.testlogon.android.core.network.webrtc

@JsonClass(generateAdapter = true)
data class TurnCredentialsDto(
    // shape confirmed from /openapi.json at impl; see §5 for fallbacks
    @Json(name = "ice_servers") val iceServers: List<IceServerDto>,
    @Json(name = "ttl") val ttlSeconds: Long? = null,            // seconds
    @Json(name = "username") val username: String? = null,        // some shapes hoist creds
    @Json(name = "credential") val credential: String? = null,
)

@JsonClass(generateAdapter = true)
data class IceServerDto(
    val urls: List<String>,                      // adapter coerces String -> List<String>
    val username: String? = null,
    val credential: String? = null,
)
```

A small Moshi adapter (`StringOrListAdapter`) coerces a scalar `"urls": "stun:..."`
into a single-element list, because TURN providers and the FastAPI shape vary.

### 4.2 API (`core-network`)

```kotlin
interface IceServersApi {
    // GET — idempotent, eligible for bounded-backoff retry (AND-016)
    @GET("turn-credentials")
    suspend fun getTurnCredentials(): TurnCredentialsDto
}
```

The base URL/host-selection interceptor (AND-014), cookie jar (AND-011), CSRF
header (AND-012), 401-refresh authenticator (AND-013), 20s timeouts (AND-009),
and idempotent-GET retry/backoff (AND-016) are all inherited from the shared
OkHttp/Retrofit client. No per-call config beyond annotating the call as a GET.

### 4.3 Domain model & mapping (`core-data`)

```kotlin
package com.testlogon.android.core.data.webrtc

data class IceServers(
    val servers: List<RtcIceServer>,     // RtcIceServer from core-webrtc/core-model
    val ttlSeconds: Long,
    val fetchedAtEpochMs: Long,
) {
    fun expiresAtEpochMs(): Long = fetchedAtEpochMs + ttlSeconds * 1_000
    fun isFreshAt(nowMs: Long, skewSec: Long): Boolean =
        nowMs < expiresAtEpochMs() - skewSec * 1_000
}

internal fun TurnCredentialsDto.toIceServers(nowMs: Long, defaultTtlSec: Long): IceServers =
    IceServers(
        servers = iceServers.map { dto ->
            RtcIceServer(
                urls = dto.urls,
                username = dto.username ?: this.username,
                credential = dto.credential ?: this.credential,
            )
        },
        ttlSeconds = ttlSeconds ?: defaultTtlSec,   // fallback if backend omits TTL
        fetchedAtEpochMs = nowMs,
    )
```

### 4.4 Repository & provider (`core-data`)

```kotlin
interface IceServersRepository {
    /** Returns fresh ICE servers, refetching if cache is stale/missing. */
    suspend fun getIceServers(forceRefresh: Boolean = false): ApiResult<IceServers>
    fun observe(): Flow<IceServersState>   // optional UI/telemetry surface
}

sealed interface IceServersState {
    data object Idle : IceServersState
    data object Loading : IceServersState
    data class Ready(val servers: IceServers, val stale: Boolean) : IceServersState
    data class FallbackStunOnly(val reason: ApiError) : IceServersState
    data class Error(val error: ApiError) : IceServersState
}

@Singleton
class DefaultIceServersRepository @Inject constructor(
    private val api: IceServersApi,
    private val store: IceServersStore,            // DataStore-backed
    private val clock: Clock,                       // injectable for tests
    @TurnConfig private val config: TurnFetchConfig,
) : IceServersRepository { /* ... */ }

data class TurnFetchConfig(
    val refreshSkewSeconds: Long = 60,
    val defaultTtlSeconds: Long = 600,             // used only if backend omits ttl
    val stunOnlyFallback: List<RtcIceServer> =
        listOf(RtcIceServer(urls = listOf("stun:stun.l.google.com:19302"))),
)
```

`IceServersProvider` is the thin seam the call feature depends on (it hides the
`ApiResult`/cache mechanics and always yields a usable list):

```kotlin
interface IceServersProvider {
    /** Never throws; returns fresh, cached-valid, or STUN-only fallback. */
    suspend fun current(): List<RtcIceServer>
}
```

`getIceServers` algorithm:
1. If `!forceRefresh` and the in-memory/DataStore cache `isFreshAt(now, skew)` →
   return `Ready(cache, stale=false)`.
2. Otherwise call `api.getTurnCredentials()` wrapped in `ApiResult`:
   - success → map via `toIceServers`, persist to `store`, return `Ready(...)`.
   - failure → if a cached set exists and is *not* fully expired, return it as
     `Ready(stale=true)`; else `FallbackStunOnly(error)`.

### 4.5 Wiring into AND-289

The call feature (AND-292+) builds the config:

```kotlin
val iceServers = iceServersProvider.current()
val pc = rtcFactory.create(
    RtcConfig(iceServers = iceServers, role = RtcRole.Offerer),
    signaling,
)
```

No change to `RtcPeerConnectionFactory`/`RtcPeerConnection`. AND-289's wrapper is
responsible for translating `RtcIceServer` → `org.webrtc.PeerConnection.IceServer`
inside `RTCConfiguration`. This ticket only guarantees the list is correct and
fresh.

### 4.6 Hilt

```kotlin
@Module @InstallIn(SingletonComponent::class)
abstract class IceServersModule {
    @Binds abstract fun bindRepo(impl: DefaultIceServersRepository): IceServersRepository
    @Binds abstract fun bindProvider(impl: DefaultIceServersProvider): IceServersProvider
    companion object {
        @Provides fun api(retrofit: Retrofit): IceServersApi = retrofit.create()
        @Provides @TurnConfig fun config(): TurnFetchConfig = TurnFetchConfig()
    }
}
```

## 5. API Contract

**Endpoint:** `GET turn-credentials` (authenticated; cookie session +
`X-CSRF-Token`). Exact path segment and JSON shape MUST be confirmed against
`/openapi.json` and the web reference (`frontend/src/api/endpoints/*.ts`,
`frontend/src/api/types.ts`) at implementation time — the backlog scope names the
resource as `turn-credentials`. Two common shapes are supported by the adapter:

Canonical (Twilio/coturn-style) response:

```json
{
  "ice_servers": [
    { "urls": ["stun:stun.testlogon.example:3478"] },
    {
      "urls": [
        "turn:turn.testlogon.example:3478?transport=udp",
        "turn:turn.testlogon.example:3478?transport=tcp",
        "turns:turn.testlogon.example:5349?transport=tcp"
      ],
      "username": "1717603200:tl-ephemeral",
      "credential": "b64-hmac-derived-secret=="
    }
  ],
  "ttl": 600
}
```

Hoisted-credential variant (single shared username/credential):

```json
{
  "ice_servers": [{ "urls": "turn:turn.testlogon.example:3478" }],
  "username": "1717603200:tl-ephemeral",
  "credential": "b64-hmac-derived-secret==",
  "ttl": 600
}
```

**Request:** no body. Standard session cookies + `X-CSRF-Token` header applied by
interceptors.

**Errors (FastAPI `detail` mapping, AND-015):** `401` → triggers one
`POST /ui/session/refresh` + retry (AND-013) then surfaces auth error; `403`
(missing/invalid CSRF) → `ApiError.Forbidden`; `5xx`/timeout from the unreliable
dev host → `ApiError.Network`/`ApiError.Server`, routed to the
cached-or-fallback path (§4.4). `detail` may be `string | [{msg}] | {code,...}`
and is normalized by the shared error mapper.

## 6. Data & State Management

- **Model home:** `RtcIceServer` is defined in `core-webrtc` (AND-289). To keep
  `core-data` from depending on `core-webrtc` purely for one value type, the
  preferred option is to relocate `RtcIceServer` to `core-model` (a pure model
  module both `core-webrtc` and `core-data` already depend on). If relocation is
  rejected in review, `core-data` takes a narrow dependency on `core-webrtc` for
  the type only. This is the single notable layering decision (see §13 OQ1).
- **Persistence:** one ephemeral record in **DataStore** (Proto or typed
  Preferences), key `ice_servers`. Stored fields: serialized servers (urls +
  username + credential), `ttlSeconds`, `fetchedAtEpochMs`. No Room — this is a
  single short-lived record, not a queryable cache. On read, if
  `now >= expiresAtEpochMs()` the record is treated as absent.
- **In-memory:** `DefaultIceServersRepository` holds a `@Volatile` last-known
  `IceServers` and a `Mutex` to coalesce concurrent fetches (one in-flight
  network call shared by concurrent `current()` callers).
- **State exposure:** `observe(): Flow<IceServersState>` for optional telemetry /
  a debug screen; the call feature uses the simpler `IceServersProvider.current()`.
- **No Paging.** Single record; not paged.

## 7. Error Handling & Resilience

- **Timeouts/unreliable host:** inherits the project 20s OkHttp timeout (AND-009)
  and bounded-backoff retry for idempotent GETs (AND-016) — this GET is
  idempotent and eligible. Beyond retries, failures fall through to cache → STUN
  fallback (§4.4), never throwing out of `IceServersProvider.current()`.
- **Stale-while-revalidate:** an expired-but-present cache is preferred over a
  hard failure when a refetch fails, marked `stale=true` so telemetry can record
  degraded operation. (A TURN credential past its TTL will likely fail the relay
  allocation; STUN entries from it still work, so the wrapper may still connect on
  direct/srflx paths.)
- **STUN-only fallback:** if no usable cache, return `config.stunOnlyFallback`.
  Connectivity behind symmetric NAT will fail in that case — surfaced as a
  recoverable degraded state, not a crash.
- **401:** single `POST /ui/session/refresh` + retry via the existing
  authenticator (AND-013); a second 401 propagates as an auth error and the call
  feature must re-auth.
- **Clock skew:** TTL is evaluated against device `Clock`; `REFRESH_SKEW_SECONDS`
  (60s) absorbs minor skew and request latency so credentials are refreshed
  before, not after, the TURN server rejects them.
- **No mid-call rotation here:** if credentials expire during an active call,
  recovery (ICE-restart with fresh creds) is deferred to a follow-up (§13 OQ2);
  this ticket guarantees freshness only at `createOffer`/`createAnswer` time.

## 8. Security & Privacy

- **Ephemeral credentials:** TURN `username`/`credential` are short-lived
  (TTL-bounded, typically HMAC time-windowed). They are secrets-in-transit only.
- **No logging of secrets:** `username`/`credential` (and full TURN URLs that
  embed them) are NEVER logged, even at DEBUG. Log only counts and URL *schemes*
  (e.g. `"ice servers: 1 stun, 1 turn (udp,tcp,tls), ttl=600s"`). This extends
  AND-289 §8/§10 redaction rules to the credential-fetch path.
- **At-rest:** the only persisted copy is the DataStore record. Use the standard
  app-private DataStore file; do not copy credentials to logs, analytics, or
  shared prefs. Because creds are short-lived and DataStore is in app-private
  storage, additional encryption is optional; document the choice (§13 OQ3).
- **Transport:** the dev backend is PLAINTEXT HTTP, so on dev the credentials
  traverse cleartext — acceptable for ephemeral dev creds against a dev TURN, but
  production MUST serve this endpoint over HTTPS (note carried to the prod
  hardening ticket). `turns:`/TLS TURN URLs are preserved and preferred when the
  server offers them.
- **Auth boundary:** the endpoint requires the authenticated cookie session; an
  unauthenticated caller gets 401 and no credentials. No new permissions or
  manifest entries.

## 9. Accessibility & i18n

No primary UI surface in this ticket — it is a data/config layer. A11y/TalkBack/
RTL concerns are owned by the call feature (AND-292+) that renders connection
state. The only user-facing artifact is the *degraded-connectivity* signal
(`IceServersState.FallbackStunOnly` / `stale`): this is exposed as a typed value,
not a string, and the consuming feature maps it to a localized message (e.g.
`call_connectivity_degraded`) in its own `strings.xml`. No hardcoded user copy is
introduced here. Any optional debug screen for inspecting fetched servers is
debug-only and exempt from localization.

## 10. Telemetry & Logging

- Tagged logger `IceServers`, gated on `BuildConfig.DEBUG` for verbose lines.
- **Events (via existing analytics seam, no new SDK):**
  - `turn_credentials_fetch_result` (`fresh_cache` | `network_ok` |
    `stale_cache` | `stun_fallback` | `error`),
  - `turn_credentials_fetch_duration_ms`,
  - `turn_ttl_seconds` (the granted TTL),
  - `ice_relay_selected` (bool, from the relay-verification path / call feature):
    whether the selected candidate pair was `relay`.
- **Redaction (mandatory):** never emit `username`/`credential` or full TURN URLs
  with embedded creds in any log/event — only counts, schemes, transports, TTL,
  and outcome enums.

## 11. Testing Strategy

**Unit (JVM, `core-testing` + MockWebServer harness AND-046):**
- `TurnCredentialsMappingTest`: both §5 JSON shapes (canonical list + hoisted
  creds; scalar vs. array `urls`) map to the expected `List<RtcIceServer>`,
  TTL defaulted when omitted.
- `IceServersRepositoryTest`:
  - fresh cache → no network call;
  - stale cache + network success → refetch + persist;
  - network failure + valid cache → returns cached `stale=true`;
  - network failure + no cache → `FallbackStunOnly`;
  - TTL/skew boundary cases via injected `Clock`;
  - concurrent `current()` callers coalesce into one network call (`Mutex`).
- `IceServersStoreTest`: DataStore round-trip; expired record read as absent.
- `RedactionTest`: assert log/event formatter never contains credential/username
  substrings.

**Instrumentation (androidTest, `core-webrtc`) — relay proof (source acceptance):**
- `RelayCandidateTest`: build a `RtcConfig` with the fetched (or test-fixture)
  TURN server and `iceTransportPolicy = RELAY`; run the AND-289 loopback/peer
  harness; assert the selected/connected candidate pair type is `relay` (read via
  `PeerConnection.getStats()` `selectedCandidatePairId` → `candidate-pair`
  `local/remote candidateType == "relay"`), and the session reaches
  `RtcSessionState.Connected`. This requires a reachable TURN server (test TURN /
  coturn fixture or the dev TURN) and is gated `@RequiresDevice` / network-tagged
  in CI (see R-flaky note §13).
- Optionally a NAT-simulation/`RELAY`-only run demonstrates connectivity when
  host/srflx are excluded, satisfying "relay path works behind NAT".

**Acceptance mapping:** "ICE uses provided TURN" ⇒ `IceServersRepositoryTest` +
mapping tests + config wiring; "relay path works behind NAT" ⇒
`RelayCandidateTest` (relay candidate pair selected).

## 12. Dependencies & Sequencing

- **Depends on AND-289** — provides `RtcConfig.iceServers`, `RtcIceServer`, and
  the peer/loopback harness used by `RelayCandidateTest`. Cannot configure ICE
  servers without the wrapper API.
- **Depends on AND-288** (transitively) — `PeerConnectionFactory`/`EglBase`/the
  artifact, needed for the instrumented relay test.
- **Relies on `core-network` baseline** — cookie jar (AND-011), CSRF (AND-012),
  401 refresh (AND-013), host selection (AND-014), error mapping (AND-015),
  GET retry/backoff (AND-016), `ApiResult` (AND-018), and the MockWebServer
  harness (AND-046) for unit tests. These predate M7 and are assumed present.
- **Blocks AND-292** (and the rest of the broadcast/call feature) — they call
  `IceServersProvider.current()` before establishing a `PeerConnection`. Without
  this ticket the wrapper has empty `iceServers` and fails behind NAT.
- **Coordinates with AND-290** (signaling): independent network surfaces; both
  consume the authenticated session. No code dependency in either direction.
- Milestone **M7**, epic **E39** (real-time/WebRTC).

## 13. Risks & Open Questions

- **R1 — Backend shape uncertainty:** the exact `turn-credentials` path and JSON
  are not in this ticket; the adapter handles the two common shapes but MUST be
  reconciled with `/openapi.json` and `frontend/src/api/types.ts` at impl. If the
  shape differs materially, only the DTO + mapper change.
- **R2 — TURN server availability for CI:** `RelayCandidateTest` needs a live
  TURN allocation; the dev host is unreliable and a public TURN may be unreachable
  from CI. Mitigation: stand up a coturn test fixture or tag the relay test
  `@RequiresDevice`/network-only and keep mapping/repository unit tests as the CI
  gate.
- **R3 — Credential expiry mid-call:** out of scope here; surfaced as OQ2.
- **R4 — Plaintext dev transport:** ephemeral creds in cleartext on the dev host
  (HTTP); acceptable for dev, production requires HTTPS.
- **OQ1 — Model home:** relocate `RtcIceServer` to `core-model` vs. let
  `core-data` depend on `core-webrtc`? Proposed: relocate to `core-model`.
- **OQ2 — ICE-restart on expiry:** add a `restartIce()` + refetch path for
  long-lived calls now or defer? Proposed: defer to a follow-up; this ticket only
  guarantees freshness at session creation.
- **OQ3 — At-rest encryption:** encrypt the DataStore credential record
  (EncryptedFile/Tink) or rely on app-private storage given short TTL? Proposed:
  app-private DataStore is sufficient; revisit if TTLs lengthen.
- **OQ4 — TTL source of truth:** does the backend always return `ttl`? If not,
  `defaultTtlSeconds` (600s) governs; confirm against OpenAPI.

## 14. Acceptance Criteria

AC-1. `IceServersApi.getTurnCredentials()` performs an authenticated GET to the
backend `turn-credentials` endpoint through the shared OkHttp/Retrofit client
(cookie + CSRF + 401-refresh + GET retry all applied).

AC-2. `TurnCredentialsDto` maps to `IceServers`/`List<RtcIceServer>` for both §5
JSON shapes (canonical per-server creds and hoisted creds; scalar and array
`urls`), with TTL defaulted when the backend omits it. (Passing
`TurnCredentialsMappingTest`.)

AC-3. The fetched `List<RtcIceServer>` is consumable directly as
`RtcConfig.iceServers` and the AND-289 wrapper builds a `PeerConnection`
configured with those STUN/TURN servers. (Backlog: "ICE uses provided TURN".)

AC-4. Caching honors TTL: a fresh cache is reused without a network call; a cache
within `REFRESH_SKEW_SECONDS` of expiry triggers a refetch; an expired record is
treated as absent. (Passing `IceServersRepositoryTest`/`IceServersStoreTest`.)

AC-5. On fetch failure, the provider returns a valid cached set (`stale=true`) if
available, else a STUN-only fallback, and never throws from
`IceServersProvider.current()`. (Passing failure-path tests.)

AC-6. **(Source acceptance)** With a reachable TURN server and a `RELAY` config,
the connected candidate pair is of type `relay` and the session reaches
`RtcSessionState.Connected`. (Passing `RelayCandidateTest` —
"relay path works behind NAT".)

AC-7. TURN `username`/`credential` and credentialed URLs never appear in logs or
analytics events (verified by `RedactionTest` + log-site review).

## 15. Definition of Done

- All §14 acceptance criteria met; backlog acceptance ("ICE uses provided TURN;
  relay path works behind NAT") demonstrably satisfied — relay candidate pair
  proven in `RelayCandidateTest`, and ICE-server configuration verified end-to-end
  with the AND-289 wrapper.
- `IceServersApi`, `TurnCredentialsDto`/`IceServerDto` + Moshi adapters,
  `IceServersRepository`/`DefaultIceServersRepository`, `IceServersProvider`,
  `IceServersStore` (DataStore), and `IceServersModule` implemented under
  `com.testlogon.android.core.network.webrtc` / `...core.data.webrtc`.
- `RtcIceServer` model home decided (OQ1) and applied; layering review passed (no
  illegal `core` ↔ `core` dependency introduced).
- Unit tests (mapping, repository TTL/cache/coalescing, store round-trip,
  redaction) green in CI; instrumented `RelayCandidateTest` green on a
  device/network-capable runner (or documented gating).
- Telemetry events emitted via the existing seam; credential redaction enforced;
  no secrets in logs.
- KDoc on the public `IceServersRepository`/`IceServersProvider` surface so
  AND-292+ can wire it without reading the implementation.
- ktlint/detekt clean, no new lint baseline regressions; code reviewed and merged
  to `android-port`; AND-292 unblocked.
