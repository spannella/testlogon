---
id: AND-291
title: TURN/STUN credentials
milestone: M7
epic: E39
priority: P0
size: M
status: reviewed
reviewed_on: 2026-06-06
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
(`POST /messaging/messages/calls/{call_id}/turn-credentials`; CORRECTED — the
backlog's bare `turn-credentials` slug resolves to this authenticated, **per-call
POST** endpoint, verified against `/openapi.json` op
`issue_turn_credentials_endpoint`), maps them into the `List<RtcIceServer>` that AND-289's
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
  endpoint is `POST /messaging/messages/calls/{call_id}/turn-credentials`
  (VERIFIED, op `issue_turn_credentials_endpoint`). It is **scoped to a specific
  `call_id`** — credentials are issued per call session, so this ticket's
  provider/repository API takes a `callId` (see §4 correction). Auth: per the web
  client (`src/api/client.ts`) every request carries a Bearer `Authorization`
  header (from the auth store) **and** cookies (`credentials: include`) **and** an
  `X-CSRF-Token` header echoed from the `ui_csrf` cookie; the OpenAPI spec lists
  `authorization` and `X-SESSION-ID` as the documented (optional) headers for this
  op. On Android this maps to AND-011 cookie jar, AND-012 CSRF interceptor,
  AND-013 401-refresh authenticator, plus the Bearer-token header the existing
  client already attaches. (CORRECTED: the prior draft implied a bare unauthed-
  context `turn-credentials` GET with only cookie+CSRF; the real op is a per-call
  POST and also relies on the Bearer header.)
- **Downstream (AND-292+):** the broadcast/viewer call feature obtains
  `List<RtcIceServer>` from `IceServersProvider` and passes it into `RtcConfig`
  before calling `RtcPeerConnection.createOffer()`/`createAnswer()`.
- **Stack baseline:** Kotlin 2.0.21, Coroutines/Flow, Hilt (KSP), Retrofit 2.11
  + OkHttp 4.12 + Moshi 1.15, DataStore (no Room needed — single ephemeral
  record), `ApiResult<T>` (AND-018), FastAPI `detail` error mapping (AND-015),
  bounded backoff for idempotent GETs (AND-016).

## 3. Functional Requirements

FR-1. **Fetch.** `IceServersApi.getTurnCredentials(callId)` performs an
authenticated **POST** (empty body) against
`/messaging/messages/calls/{call_id}/turn-credentials` and returns the raw DTO.
(CORRECTED: POST not GET; takes a `call_id` path param. Because it is a non-GET
mutation per HTTP semantics, the AND-016 idempotent-GET retry/backoff does **not**
apply automatically — see §7 correction. The web client treats it as effectively
idempotent and simply retries on demand.)

FR-2. **Map.** `IceServersRepository` maps the DTO into
`IceServers(servers: List<RtcIceServer>, ttlSeconds: Long, expiresAtEpochMs: Long, fetchedAtEpochMs: Long)`.
Each `TurnIceServerOut` entry carries a required `urls: List<String>`, required
`username`, and required `credential` (VERIFIED against schema `TurnIceServerOut`;
all three are in `required`). Multiple `urls` per entry are preserved (e.g.
`turn:host:3478?transport=udp` and `...?transport=tcp`). NOTE/CORRECTION: in the
real backend shape every returned entry has credentials and `urls` is always an
array — there is no credential-less STUN entry and no scalar-`urls` variant in
the documented response (those were assumptions in the prior draft). STUN-only
entries appear only in this ticket's *local fallback* list (§4.4), not from the
endpoint.

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

// Shape VERIFIED against /openapi.json schema TurnCredentialsOut / TurnIceServerOut.
@JsonClass(generateAdapter = true)
data class TurnCredentialsDto(
    @Json(name = "ice_servers") val iceServers: List<IceServerDto>,  // required
    @Json(name = "ttl_seconds") val ttlSeconds: Long,                // required (CORRECTED: was "ttl")
    @Json(name = "expires_at") val expiresAtEpochSeconds: Long,      // required (NEW: was missing)
)

@JsonClass(generateAdapter = true)
data class IceServerDto(
    val urls: List<String>,            // always an array in the backend shape
    val username: String,              // required per TurnIceServerOut
    val credential: String,            // required per TurnIceServerOut
)
```

CORRECTIONS vs. the prior draft:
- TTL field is `ttl_seconds` (not `ttl`); it is **required**, so the
  `defaultTtlSeconds` fallback is defensive only (the backend always returns it).
- The response also includes a required `expires_at` (epoch **seconds**) — prefer
  it as the authoritative expiry over locally computed `fetchedAt + ttl`.
- There is **no** top-level hoisted `username`/`credential` and **no** scalar-vs-
  array `urls` variance in the documented schema; `username`/`credential` are
  required on each `TurnIceServerOut`. The `StringOrListAdapter` and hoisted-cred
  mapping are therefore **removed** as unnecessary. (If a future TURN provider
  changes the shape, re-introduce a tolerant adapter then — not now.)

### 4.2 API (`core-network`)

```kotlin
interface IceServersApi {
    // POST per-call (CORRECTED: was GET "turn-credentials"). Empty body.
    @POST("messaging/messages/calls/{callId}/turn-credentials")
    suspend fun getTurnCredentials(@Path("callId") callId: String): TurnCredentialsDto
}
```

The base URL/host-selection interceptor (AND-014), cookie jar (AND-011), CSRF
header (AND-012), Bearer `Authorization` header, 401-refresh authenticator
(AND-013), and 20s timeouts (AND-009) are inherited from the shared
OkHttp/Retrofit client. CORRECTION: AND-016 bounded backoff is scoped to
*idempotent GETs*; since this is a POST it is not auto-retried by that policy. The
op is read-only/idempotent in practice, so if retry is desired it must be opted in
explicitly (e.g. a small in-repo retry around the suspend call) rather than
relying on AND-016.

### 4.3 Domain model & mapping (`core-data`)

```kotlin
package com.testlogon.android.core.data.webrtc

data class IceServers(
    val servers: List<RtcIceServer>,     // RtcIceServer from core-webrtc/core-model
    val ttlSeconds: Long,
    val expiresAtEpochMs: Long,          // from backend expires_at (epoch seconds * 1000)
    val fetchedAtEpochMs: Long,
) {
    // Prefer the server-provided expires_at; fall back to fetchedAt + ttl only if absent.
    fun isFreshAt(nowMs: Long, skewSec: Long): Boolean =
        nowMs < expiresAtEpochMs - skewSec * 1_000
}

internal fun TurnCredentialsDto.toIceServers(nowMs: Long, defaultTtlSec: Long): IceServers =
    IceServers(
        servers = iceServers.map { dto ->
            RtcIceServer(
                urls = dto.urls,
                username = dto.username,        // required on every entry
                credential = dto.credential,   // required on every entry
            )
        },
        ttlSeconds = ttlSeconds,                          // required field (defaultTtlSec is defensive)
        expiresAtEpochMs = expiresAtEpochSeconds * 1_000,
        fetchedAtEpochMs = nowMs,
    )
```

### 4.4 Repository & provider (`core-data`)

```kotlin
interface IceServersRepository {
    /**
     * Returns fresh ICE servers for [callId], refetching if cache is stale/missing.
     * (CORRECTED: credentials are per-call, so the cache key includes callId.)
     */
    suspend fun getIceServers(callId: String, forceRefresh: Boolean = false): ApiResult<IceServers>
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
    /** Never throws; returns fresh, cached-valid, or STUN-only fallback for [callId]. */
    suspend fun current(callId: String): List<RtcIceServer>
}
```

`getIceServers` algorithm:
1. If `!forceRefresh` and the in-memory/DataStore cache for `callId`
   `isFreshAt(now, skew)` → return `Ready(cache, stale=false)`.
2. Otherwise call `api.getTurnCredentials(callId)` wrapped in `ApiResult`:
   - success → map via `toIceServers`, persist to `store`, return `Ready(...)`.
   - failure → if a cached set exists and is *not* fully expired, return it as
     `Ready(stale=true)`; else `FallbackStunOnly(error)`.

### 4.5 Wiring into AND-289

The call feature (AND-292+) builds the config:

```kotlin
val iceServers = iceServersProvider.current(callId)   // per-call (CORRECTED)
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

**Endpoint (VERIFIED):** `POST /messaging/messages/calls/{call_id}/turn-credentials`
(op `issue_turn_credentials_endpoint`). Authenticated; per-call. The web client
(`src/api/endpoints/messaging.ts: fetchTurnCredentials`) calls it as
`api.post(\`/messaging/messages/calls/${callId}/turn-credentials\`, {})` — POST
with an empty JSON body. Documented header params: `authorization` (Bearer) and
`X-SESSION-ID`. The shared web client (`src/api/client.ts`) additionally sends the
`X-CSRF-Token` header and cookies on every request.

**Response 200 — schema `TurnCredentialsOut` (VERIFIED):** all three fields are
required; each `ice_servers[]` entry (`TurnIceServerOut`) has required `urls`
(array), `username`, and `credential`:

```json
{
  "ttl_seconds": 600,
  "expires_at": 1717603800,
  "ice_servers": [
    {
      "urls": [
        "turn:turn.testlogon.example:3478?transport=udp",
        "turn:turn.testlogon.example:3478?transport=tcp",
        "turns:turn.testlogon.example:5349?transport=tcp"
      ],
      "username": "1717603200:tl-ephemeral",
      "credential": "b64-hmac-derived-secret=="
    }
  ]
}
```

CORRECTIONS: TTL key is `ttl_seconds` (not `ttl`); `expires_at` (epoch seconds) is
a required field that the prior draft omitted; there is no top-level hoisted
`username`/`credential` and no scalar `urls` variant; STUN-only credential-less
entries do not appear in this response (they only exist in the local fallback).

**Request:** POST with empty JSON body `{}`. `call_id` in the path. Bearer/session
cookies + `X-CSRF-Token` applied by interceptors.

**Errors (VERIFIED — structured `TurnCredentialErrorOut` with
`detail: { code: string, message: string }`):**
- `400` "Invalid TURN credential request"
- `403` "Forbidden or feature disabled"
- `404` "Call session not found"
- `409` "Call state or participant mismatch"
- `503` "TURN service/configuration unavailable"
- `422` `HTTPValidationError` (FastAPI validation, `detail: [{loc,msg,type}]`)

CORRECTION: 401 is **not** a documented response for this op; the generic
401-refresh authenticator (AND-013) still applies at the transport layer (web does
`POST /ui/session/refresh` then retries — `src/api/client.ts`), but auth failures
here surface chiefly as `403`. The endpoint's own error body is the structured
`{code, message}` shape, **not** the generic FastAPI `detail: string | [{msg}]`
union; the shared mapper (AND-015) should read `detail.code`/`detail.message`.
`5xx`/`503`/timeout from the unreliable dev host route to the cached-or-fallback
path (§4.4).

## 6. Data & State Management

- **Model home:** `RtcIceServer` is defined in `core-webrtc` (AND-289). To keep
  `core-data` from depending on `core-webrtc` purely for one value type, the
  preferred option is to relocate `RtcIceServer` to `core-model` (a pure model
  module both `core-webrtc` and `core-data` already depend on). If relocation is
  rejected in review, `core-data` takes a narrow dependency on `core-webrtc` for
  the type only. This is the single notable layering decision (see §13 OQ1).
- **Persistence:** one ephemeral record in **DataStore** (Proto or typed
  Preferences), keyed by `callId` (CORRECTED: credentials are per-call). Stored
  fields: serialized servers (urls + username + credential), `ttlSeconds`,
  `expiresAtEpochMs` (from `expires_at`), `fetchedAtEpochMs`. No Room — a single
  short-lived most-recent record (or a tiny bounded map keyed by callId), not a
  queryable cache. On read, if `now >= expiresAtEpochMs` the record is treated as
  absent.
- **In-memory:** `DefaultIceServersRepository` holds a `@Volatile` last-known
  `IceServers` and a `Mutex` to coalesce concurrent fetches (one in-flight
  network call shared by concurrent `current()` callers).
- **State exposure:** `observe(): Flow<IceServersState>` for optional telemetry /
  a debug screen; the call feature uses the simpler `IceServersProvider.current(callId)`.
- **No Paging.** Single record; not paged.

## 7. Error Handling & Resilience

- **Timeouts/unreliable host:** inherits the project 20s OkHttp timeout (AND-009).
  CORRECTION: AND-016 bounded backoff only covers *idempotent GETs*; this op is a
  POST, so it is not auto-retried by AND-016. The op is effectively read-only, so
  if retry-on-5xx/timeout is wanted it must be added explicitly in the repository.
  Beyond retries, failures fall through to cache → STUN fallback (§4.4), never
  throwing out of `IceServersProvider.current(callId)`.
- **Stale-while-revalidate:** an expired-but-present cache is preferred over a
  hard failure when a refetch fails, marked `stale=true` so telemetry can record
  degraded operation. (A TURN credential past its TTL will likely fail the relay
  allocation; STUN entries from it still work, so the wrapper may still connect on
  direct/srflx paths.)
- **STUN-only fallback:** if no usable cache, return `config.stunOnlyFallback`.
  Connectivity behind symmetric NAT will fail in that case — surfaced as a
  recoverable degraded state, not a crash.
- **401 / 403:** a transport-level `401` triggers a single `POST /ui/session/refresh`
  + retry via the existing authenticator (AND-013) — VERIFIED against the web
  client (`src/api/client.ts`); a second 401 propagates as an auth error and the
  call feature must re-auth. NOTE: this op does not document a 401; its own
  auth/permission failures surface as `403` "Forbidden or feature disabled" with a
  `{code, message}` body, which maps to a non-retryable auth/feature-disabled
  state (treated like the fallback path, not a refresh-retry).
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
- `TurnCredentialsMappingTest`: the verified §5 `TurnCredentialsOut` shape maps to
  the expected `List<RtcIceServer>` (each entry's array `urls` + required
  `username`/`credential`), `ttl_seconds` and `expires_at` are carried through, and
  a multi-`urls` entry (udp/tcp/turns) preserves all transports. (CORRECTED: the
  hoisted-cred and scalar-`urls` cases were removed; the backend shape is fixed.)
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

- **R1 — Backend shape (RESOLVED in this review):** path/method/shape are now
  VERIFIED against `/openapi.json` (op `issue_turn_credentials_endpoint`, schema
  `TurnCredentialsOut`/`TurnIceServerOut`) and the web client
  (`src/api/endpoints/messaging.ts: fetchTurnCredentials`,
  `src/hooks/useRtcPeerConnection.ts`). The endpoint is the per-call POST; the DTO
  matches the fixed shape (no hoisted creds, no scalar `urls`). Residual risk is
  only if the backend later changes the schema, in which case only the DTO + mapper
  change.
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

AC-1. `IceServersApi.getTurnCredentials(callId)` performs an authenticated
**POST** to `/messaging/messages/calls/{call_id}/turn-credentials` through the
shared OkHttp/Retrofit client (Bearer + cookie + CSRF + 401-refresh applied).
(CORRECTED: POST per-call, not a bare GET; AND-016 GET-retry does not apply.)

AC-2. `TurnCredentialsDto` maps to `IceServers`/`List<RtcIceServer>` for the
verified `TurnCredentialsOut` shape (array `urls`, required per-entry
`username`/`credential`), carrying `ttl_seconds` and `expires_at`. (Passing
`TurnCredentialsMappingTest`.)

AC-3. The fetched `List<RtcIceServer>` is consumable directly as
`RtcConfig.iceServers` and the AND-289 wrapper builds a `PeerConnection`
configured with those STUN/TURN servers. (Backlog: "ICE uses provided TURN".)

AC-4. Caching honors TTL: a fresh cache is reused without a network call; a cache
within `REFRESH_SKEW_SECONDS` of expiry triggers a refetch; an expired record is
treated as absent. (Passing `IceServersRepositoryTest`/`IceServersStoreTest`.)

AC-5. On fetch failure, the provider returns a valid cached set (`stale=true`) if
available, else a STUN-only fallback, and never throws from
`IceServersProvider.current(callId)`. (Passing failure-path tests.)

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

## 16. Citations & Assumption Audit

Each key technical claim with VERDICT and exact SOURCE pointer.

1. **Endpoint is `POST /messaging/messages/calls/{call_id}/turn-credentials`** (per-call,
   POST, empty body) — **Corrected** (draft said bare `GET turn-credentials`).
   Source: OpenAPI `POST /messaging/messages/calls/{call_id}/turn-credentials`
   (op `issue_turn_credentials_endpoint`, openapi.index.txt line 407); frontend
   `src/api/endpoints/messaging.ts: fetchTurnCredentials` → `api.post(.../turn-credentials, {})`.
2. **Response schema fields: `ttl_seconds` (int, required), `expires_at` (int epoch,
   required), `ice_servers` (array, required)** — **Corrected** (draft used `ttl` and
   omitted `expires_at`). Source: OpenAPI schema `TurnCredentialsOut`
   (openapi.pretty.json); frontend `src/api/endpoints/messaging.ts: TurnCredentialsResp`.
3. **Each `ice_servers[]` entry (`TurnIceServerOut`) has `urls: string[]`, `username`,
   `credential`, ALL required** — **Corrected** (draft assumed optional creds, scalar-or-
   array `urls`, and a hoisted top-level cred variant; none exist). Source: OpenAPI
   schema `TurnIceServerOut` (`required: [urls, username, credential]`);
   frontend `src/api/endpoints/messaging.ts: TurnIceServer`.
4. **No credential-less STUN entries and no scalar-`urls` coercion needed** —
   **Corrected** (removed `StringOrListAdapter` and hoisted-cred mapping). Source: same
   as #3 (urls is `array<string>`; creds required).
5. **Error responses are structured `TurnCredentialErrorOut` with
   `detail: {code, message}` for 400/403/404/409/503; 422 is `HTTPValidationError`** —
   **Corrected** (draft assumed the generic FastAPI `detail: string | [{msg}]` union
   and a 401 path on this op). Source: OpenAPI responses block for the op
   (openapi.pretty.json lines ~122064–122123); schemas `TurnCredentialErrorOut`,
   `TurnCredentialErrorDetailOut` (`required: [code, message]`).
6. **401 → single `POST /ui/session/refresh` + retry, then re-auth** — **Verified** (as a
   transport-layer behavior, not specific to this op). Source: frontend
   `src/api/client.ts` (401 handler calls `refreshSession()` → `fetch("/ui/session/refresh")`,
   then retries) and `src/api/endpoints/auth.ts: refreshSession` → `api.post("/ui/session/refresh")`.
7. **Auth carries Bearer `Authorization` + cookies + `X-CSRF-Token` (from `ui_csrf` cookie)**
   — **Verified** (Bearer/cookie/CSRF) with a refinement. Source: frontend
   `src/api/client.ts` (sets `Authorization: Bearer`, `X-CSRF-Token` from `getCookie("ui_csrf")`,
   `credentials: "include"`). OpenAPI lists `authorization` and `X-SESSION-ID` as the
   documented header params for this op.
8. **Web behavior: fetch TURN per call, map `ice_servers` 1:1 to `RTCIceServer`, and on
   failure continue with empty ICE servers** — **Verified**. Source: frontend
   `src/hooks/useRtcPeerConnection.ts` (`fetchTurnCredentials(callId)`, `.map(...)`, and a
   `catch {}` that proceeds with empty `iceServers`). NOTE: the web does NOT inject a STUN-
   only fallback; the STUN fallback in this spec (§4.4/FR-7) is an Android-side design
   addition, marked below as an assumption.
9. **AND-016 bounded-backoff applies only to idempotent GETs; this POST is not auto-retried**
   — **Corrected** (draft claimed the call is an eligible idempotent GET). Source: HTTP
   method per #1 + the AND-016 policy scope as cited in the spec's own §2/§7. (Project-
   internal ticket; not independently re-verifiable from the provided sources — see Open
   assumptions.)
10. **Relay verification via `PeerConnection.getStats()` selected candidate-pair type
    `relay`** — **Unverified-assumption** (Android/WebRTC framework usage; no source in the
    provided references). Framework ref: WebRTC `RTCPeerConnection.getStats()` /
    `RTCIceCandidatePairStats` (https://www.w3.org/TR/webrtc/#dom-rtcicecandidatepairstats)
    and stream-webrtc-android `PeerConnection.getStats`. Standard and low-risk.
11. **`expires_at` is epoch seconds** — **Unverified-assumption** (schema types it as
    `integer` with no unit). Treated as seconds (×1000 to ms) consistent with `ttl_seconds`;
    confirm at impl. Source: OpenAPI `TurnCredentialsOut.expires_at` (type integer only).

### Corrections made

- Endpoint method/path: `GET turn-credentials` → `POST /messaging/messages/calls/{call_id}/turn-credentials`
  (per-call). Propagated through §1, §2, FR-1, §4.1/§4.2/§4.3/§4.4/§4.5, §5, §6, §7, AC-1.
- DTO fields: `ttl` → `ttl_seconds` (required); added required `expires_at`; removed the
  nullable hoisted `username`/`credential` and the `StringOrListAdapter` (urls is always an
  array; per-entry creds are required). Updated §3 FR-2, §4.1, §4.3, §11, AC-2.
- Repository/provider APIs now take `callId` (`getIceServers(callId, …)`,
  `current(callId)`); cache keyed by `callId`. Updated §4.4, §6, §4.5, AC-5.
- Error model: structured `{code, message}` for 400/403/404/409/503, `HTTPValidationError`
  for 422; 401 is a transport-level concern, this op's auth/feature failure is 403. Updated
  §5, §7.
- Retry semantics: removed the "idempotent GET → AND-016 retry" claim (POST is out of
  AND-016 scope). Updated FR-1, §4.2, §7.
- R1 in §13 reclassified from open risk to RESOLVED (shape verified).

### Open assumptions

- **STUN-only local fallback list (FR-7 / §4.4 `stunOnlyFallback`)** — not present in the
  backend response or web behavior (web simply continues with empty ICE servers). This is an
  Android design choice; keep it, but it is unverified against the reference contract.
- **`expires_at` unit = seconds** — schema gives only `integer`; assumed seconds to match
  `ttl_seconds`. Confirm at impl against a live response.
- **AND-016 / AND-011/012/013/018 baseline behavior** — internal Android-port tickets, not in
  the provided sources; assumed present and behaving as the web client's transport
  (cookie/CSRF/Bearer/refresh) demonstrates.
- **Relay candidate-pair assertion mechanics** — framework-standard `getStats()` usage;
  no project source, treated as a framework ref (claim #10).
- **`X-SESSION-ID` header** — documented optional param for the op; whether the Android
  client must send it (vs. cookie session) is unconfirmed. Assume cookie/Bearer suffices,
  send `X-SESSION-ID` if the session id is available.

## 17. Test Plan

Test-target legend: **JVM** = JVM unit/Robolectric (no device); **emu35** = headless
emulator AVD `test35` (x86_64, API 35); **A15** = physical Samsung Galaxy A15 5G
(SM-A156U, serial R5CX821TA9R, API 34, arm64-v8a). Hardware/relay/real-network cases
prefer **A15**.

- **TC-AND-291-01** — Type: unit (JVM). Target: `TurnCredentialsMappingTest`.
  Preconditions: a fixture matching the verified `TurnCredentialsOut` JSON (one entry with
  udp/tcp/turns `urls`, `username`, `credential`, `ttl_seconds=600`, `expires_at`).
  Steps: deserialize via Moshi → `TurnCredentialsDto` → `toIceServers(now, default)`.
  Expected: one `RtcIceServer` with all three `urls` preserved, `username`/`credential`
  populated, `ttlSeconds=600`, `expiresAtEpochMs = expires_at*1000`. Traces: AC-2.
- **TC-AND-291-02** — Type: contract/MockWebServer (JVM). Target: `IceServersApi.getTurnCredentials`.
  Preconditions: MockWebServer enqueues a 200 `TurnCredentialsOut` body; Retrofit client wired.
  Steps: call `getTurnCredentials("call-123")`; capture the recorded request.
  Expected: method **POST**, path `/messaging/messages/calls/call-123/turn-credentials`,
  empty/`{}` body, parsed DTO equals fixture. Traces: AC-1.
- **TC-AND-291-03** — Type: contract/MockWebServer (JVM). Target: shared client auth headers.
  Preconditions: cookie jar holds session + `ui_csrf`; Bearer token set.
  Steps: invoke the API; inspect recorded headers.
  Expected: request carries `Authorization: Bearer …`, cookie header, and `X-CSRF-Token`.
  Traces: AC-1, AC-7 (no creds in request log).
- **TC-AND-291-04** — Type: unit (JVM). Target: `IceServersRepositoryTest` (fresh cache).
  Preconditions: store holds a record for `call-123` fresh at injected `Clock`.
  Steps: `getIceServers("call-123")`. Expected: returns `Ready(stale=false)` with **no**
  MockWebServer request dispatched. Traces: AC-4.
- **TC-AND-291-05** — Type: unit (JVM). Target: `IceServersRepositoryTest` (skew/expiry boundary).
  Preconditions: cached record within `REFRESH_SKEW_SECONDS` of `expires_at`; network returns
  fresh 200. Steps: `getIceServers("call-123")`. Expected: a refetch occurs, new record
  persisted; an already-expired record is treated as absent → refetch. Traces: AC-4.
- **TC-AND-291-06** — Type: unit (JVM). Target: `IceServersRepositoryTest` (stale-while-revalidate).
  Preconditions: a valid (non-expired) cache exists; network fails (5xx/timeout).
  Steps: force refresh path. Expected: returns cached set with `stale=true`; never throws.
  Traces: AC-5.
- **TC-AND-291-07** — Type: unit (JVM). Target: `IceServersProvider` (STUN-only fallback / offline).
  Preconditions: no cache; network unreachable (simulated offline / flaky dev host timeout).
  Steps: `current("call-123")`. Expected: returns `config.stunOnlyFallback`
  (`stun:stun.l.google.com:19302`), emits `FallbackStunOnly`, never throws. Traces: AC-5.
- **TC-AND-291-08** — Type: contract/MockWebServer (JVM). Target: error mapping.
  Preconditions: enqueue 403 body `{"detail":{"code":"feature_disabled","message":"…"}}`,
  and separately 404/409/503 variants and a 422 `HTTPValidationError`.
  Steps: call the repo; inspect mapped `ApiError`. Expected: 403 → forbidden/feature-disabled
  state routed to fallback (not refresh-retry); `detail.code`/`detail.message` surfaced;
  422 mapped via the validation shape. Traces: AC-5.
- **TC-AND-291-09** — Type: contract/MockWebServer (JVM). Target: 401 refresh-once behavior.
  Preconditions: first response 401, then `/ui/session/refresh` succeeds, retry returns 200.
  Steps: call the repo while authenticated. Expected: exactly one `POST /ui/session/refresh`
  then a single retry that succeeds; a second 401 surfaces an auth error. Traces: AC-1.
- **TC-AND-291-10** — Type: unit (JVM, coroutines test). Target: concurrent-fetch coalescing.
  Preconditions: stale/missing cache; 3 concurrent `current("call-123")` callers; MockWebServer
  with a single slow 200. Steps: launch concurrently. Expected: exactly **one** network request
  (Mutex coalesces), all callers receive the same result. Traces: AC-4, AC-5.
- **TC-AND-291-11** — Type: unit/Robolectric (JVM). Target: `IceServersStoreTest` (DataStore round-trip).
  Preconditions: in-memory/temp DataStore. Steps: write a record keyed by `callId`, read back;
  advance `Clock` past `expiresAtEpochMs`, read again. Expected: round-trip equal; expired read
  returns absent. Traces: AC-4.
- **TC-AND-291-12** — Type: unit (JVM). Target: `RedactionTest`.
  Preconditions: an `IceServers` with real-looking `username`/`credential` and credentialed
  TURN URLs. Steps: run the log/event formatter and analytics payload builder.
  Expected: output contains counts/schemes/transports/TTL/outcome only; never the
  `username`/`credential` substrings or credentialed URLs. Traces: AC-7.
- **TC-AND-291-13** — Type: instrumented/e2e (A15 — MUST run on physical device).
  Target: `RelayCandidateTest`. Preconditions: a reachable TURN server (coturn fixture or dev
  TURN) and valid (or fixture) credentials; `RtcConfig` with `iceTransportPolicy = RELAY`;
  AND-289 peer/loopback harness. Steps: create the PeerConnection with the fetched ICE servers,
  negotiate, read `getStats()`. Expected: selected candidate-pair `local`/`remote`
  `candidateType == "relay"` and session reaches `RtcSessionState.Connected`. Rationale for
  device: real WebRTC media/ICE + TURN allocation + arm64/API-34 behavior; emulator NAT/media
  stack is unreliable. Traces: AC-3, AC-6.
- **TC-AND-291-14** — Type: instrumented (emu35 acceptable; A15 confirmatory). Target:
  end-to-end config wiring with AND-289. Preconditions: MockWebServer returns a 200
  `TurnCredentialsOut`; provider + wrapper wired. Steps: `current(callId)` →
  `rtcFactory.create(RtcConfig(iceServers=…))`; assert the wrapper built
  `PeerConnection.IceServer` entries matching the DTO (urls/username/credential).
  Expected: ICE servers present and correctly translated; no empty `iceServers`. Traces: AC-3.
- **TC-AND-291-15** — Type: manual/security review. Target: at-rest + logcat inspection.
  Preconditions: run a real fetch on A15. Steps: capture full `adb logcat` during fetch+use;
  inspect the app-private DataStore file. Expected: no `username`/`credential` in logcat or
  analytics; the only at-rest copy is the app-private DataStore record; dev plaintext-HTTP
  caveat noted. Traces: AC-7.

### Coverage matrix

| AC | Covered by |
| --- | --- |
| AC-1 (authenticated POST via shared client) | TC-02, TC-03, TC-09 |
| AC-2 (DTO → IceServers mapping, verified shape) | TC-01 |
| AC-3 (list consumable as `RtcConfig.iceServers`; wrapper configured) | TC-13, TC-14 |
| AC-4 (TTL caching: fresh reuse / skew refetch / expired absent) | TC-04, TC-05, TC-10, TC-11 |
| AC-5 (failure → stale cache / STUN fallback; never throws) | TC-06, TC-07, TC-08, TC-10 |
| AC-6 (relay candidate-pair behind NAT) | TC-13 |
| AC-7 (no credential leakage in logs/analytics) | TC-03, TC-12, TC-15 |
