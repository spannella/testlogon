---
id: AND-192
title: VOD rental flow
milestone: M4
epic: E26
priority: P2
size: M
status: draft
depends_on: [AND-191, AND-031]
blocks: [AND-193, AND-194, AND-195]
---

# AND-192 — VOD rental flow

## 1. Overview & Goal

This ticket implements the **time-boxed VOD rental flow** in the native Android app: a
signed-in user can rent a video from the VOD detail screen, the backend grants a
rental entitlement with an access window (and optional view budget), and the app
unlocks playback only while that window is active. The web reference for this flow is
`frontend/src/api/endpoints/vodRental.ts`; this spec ports that surface to the Android
`feature-vod` module.

The single acceptance bar from the backlog is: **"Rental grants time-boxed access."**
Concretely, after a successful rent the app must (a) reflect an *active* rental with a
correct expiry, (b) gate the play action on that active state, and (c) re-lock the
content once the window elapses or the view budget is exhausted, without requiring an
app restart.

Scope is the rental **domain + data + ViewModel + access-gating UI affordance** on top of
the VOD detail screen delivered by AND-191. Actual ExoPlayer playback wiring, ad-supported
playback (AND-194), tiered purchase (AND-193), and watermarked download (AND-195) are out
of scope; this ticket produces the entitlement state and a `playback_url` those tickets
consume.

## 2. Context & References

- **Backlog:** AND-192, Feature, P2. Deps: **AND-191** (VOD catalog: list/detail render,
  provides `videoId` and the detail screen host) and **AND-031** (LoginViewModel: provides
  the authenticated cookie session this flow rides on).
- **Web reference:** `frontend/src/api/endpoints/vodRental.ts`, shared types in
  `frontend/src/api/types.ts`.
- **Live API:** `http://18.222.237.167:8000/openapi.json`. Verified rental endpoints:
  `GET /ui/vod/rental/list`, `POST /ui/vod/rental/{video_id}/start`,
  `GET /ui/vod/rental/{video_id}/status`, `GET /ui/vod/rental/{video_id}/access`,
  `POST /ui/vod/rental/{video_id}/playback`,
  `POST /ui/vod/rental/{video_id}/playback-complete`.
- **Platform deps consumed:** Retrofit/Moshi (AND-010), OkHttp client + 20s timeouts
  (AND-009), persistent cookie jar (AND-011), CSRF interceptor (AND-012), 401 refresh
  authenticator (AND-013), `ApiResult<T>` (AND-018), error `detail` mapping (AND-015),
  idempotent-GET retry/backoff (AND-016), state composables (AND-021).
- **Namespace:** all code under `com.testlogon.android`. Module: `feature-vod`
  (`com.testlogon.android.feature.vod.rental`), DTOs in `core-model`, API in `core-network`.

## 3. Functional Requirements

1. **Rent action.** On the VOD detail screen (AND-191), when the content is not currently
   accessible, show a **Rent** affordance labelled with the price (e.g. "Rent · $3.99").
   Tapping it issues `POST /ui/vod/rental/{video_id}/start` with the chosen `tier`.
2. **Access window grant.** On success the app records `rental_id`, `tier`, `expires_at`
   (epoch seconds, nullable), and `views_remaining`. The rental is *active* when the
   server says `active=true`; the app must not invent its own activation rule beyond the
   client-side expiry tick described in §6.
3. **Gating.** The **Play** affordance is enabled only when access is active
   (`active && (expires_at == null || now < expires_at) && views_remaining != 0`).
   Otherwise the Rent affordance is shown.
4. **Live countdown.** While active, the detail screen shows remaining time derived from
   `remaining_seconds` / `expires_at`, updated at least every second; on reaching zero the
   UI transitions to the re-locked (Rent) state.
5. **Resume on revisit.** Returning to a previously-rented video must reflect the current
   server state via `GET /ui/vod/rental/{video_id}/status` (or `/access`) without requiring
   a re-rent if the window is still open (`already_active` path on start is also handled).
6. **Playback handshake.** When the user starts watching, the app calls
   `POST /ui/vod/rental/{video_id}/playback` to obtain a short-lived `playback_url`
   (+ `token_expires_at`). When playback ends, it calls
   `POST /ui/vod/rental/{video_id}/playback-complete` so the server can decrement the view
   budget. (Player attachment itself is AND-194/downstream; this ticket exposes the URL and
   the complete call.)
7. **Idempotent re-rent.** If `start` returns `already_active=true`, treat it as success and
   refresh state rather than charging again or surfacing an error.

## 4. Technical Design

Module placement: `feature-vod`, package `com.testlogon.android.feature.vod.rental`.
Layering: ViewModel → `VodRentalRepository` → `VodRentalApi` (Retrofit). DTOs live in
`core-model`; mapping to domain happens in the repository.

```kotlin
// core-model
data class RentalAccess(
    val active: Boolean,
    val tier: String?,
    val reason: String?,          // e.g. "expired", "exhausted", "none"
    val expiresAt: Long?,         // epoch seconds, nullable
    val remainingSeconds: Long,
    val viewsRemaining: Int,
    val rentalId: String?,
    val started: Boolean,
)

data class RentalReceipt(
    val videoId: String,
    val rentalId: String,
    val tier: String,
    val alreadyActive: Boolean,
    val expiresAt: Long?,
    val viewsRemaining: Int,
    val amountCents: Int,
    val durationHours: Int?,
)

data class RentalPlayback(
    val videoId: String,
    val playbackUrl: String,
    val manifestKey: String?,
    val mode: String?,
    val thumbnailUrl: String?,
    val tokenExpiresAt: Long,
    val access: RentalAccess,
)
```

```kotlin
// feature-vod: ViewModel
@HiltViewModel
class VodRentalViewModel @Inject constructor(
    private val repo: VodRentalRepository,
    private val clock: Clock,                 // injectable; UTC epoch seconds
    savedState: SavedStateHandle,
) : ViewModel() {

    private val videoId: String = checkNotNull(savedState["videoId"])
    private val _state = MutableStateFlow(VodRentalUiState.Loading)
    val state: StateFlow<VodRentalUiState> = _state.asStateFlow()

    fun load()                                 // GET status -> reduce
    fun rent(tier: String)                     // POST start -> reduce; guards isRenting
    fun beginPlayback()                        // POST playback -> emits PlaybackReady effect
    fun finishPlayback()                       // POST playback-complete -> refresh access
    fun retry()
}

sealed interface VodRentalUiState {
    data object Loading : VodRentalUiState
    data class Locked(                         // not yet rented or expired
        val tiers: List<RentalTierOption>,     // from detail (AND-191); fallback single tier
        val lastReason: String?,
        val isRenting: Boolean = false,
    ) : VodRentalUiState
    data class Active(
        val access: RentalAccess,
        val countdownLabel: String,            // "02:14:09" / "expires in 1d 3h"
        val isStartingPlayback: Boolean = false,
    ) : VodRentalUiState
    data class Error(val message: String, val offline: Boolean) : VodRentalUiState
}
```

A one-shot `Channel<VodRentalEffect>` carries `PlaybackReady(url, tokenExpiresAt)` and
`ShowMessage` to the screen, so navigation/snackbars are not replayed on recomposition.

The Rent button is disabled while `isRenting`; the Play button is disabled while
`isStartingPlayback`. The countdown is driven by a `viewModelScope` ticker
(`while (isActive) { reduceTick(); delay(1.seconds) }`) started only in the `Active` state
and cancelled on `Locked`/`Error`, so it costs nothing when the video is locked.

## 5. API Contract

All paths are relative to the flavored base URL (AND-006/AND-014). Session rides on the
persistent cookie jar; mutating POSTs carry `X-CSRF-Token` (AND-012). The optional
`now`, `user_sub`, `X-SESSION-ID`, `X-IMPERSONATION-TOKEN` parameters are **not** sent by
the production client (server derives identity from the cookie session); they are noted only
for fixture fidelity.

**Start (rent).** `POST /ui/vod/rental/{video_id}/start`
```json
// request — VodRentalStartIn (tier required)
{ "tier": "sd", "payment_method_id": null, "rental_duration_hours": 48 }
```
```json
// 200 — VodRentalStartOut
{ "video_id": "v_123", "rental_id": "r_abc", "tier": "sd",
  "already_active": false, "started": true, "expires_at": 1749200000,
  "views_remaining": 3, "amount_cents": 399, "duration_hours": 48 }
```

**Status.** `GET /ui/vod/rental/{video_id}/status` → `VodRentalStatusOut`
```json
{ "video_id": "v_123", "rental_id": "r_abc", "tier": "sd", "amount_cents": 399,
  "created_at": 1749100000, "started_at": 1749100050, "duration_hours": 48,
  "active": true, "reason": "active", "expires_at": 1749200000,
  "remaining_seconds": 86400, "views_remaining": 3, "started": true }
```

**Access.** `GET /ui/vod/rental/{video_id}/access` → `VodRentalAccessOut`
(`active` required; same access fields as above; used as the lightweight gate check).

**Playback.** `POST /ui/vod/rental/{video_id}/playback` → `VodRentalPlaybackOut`
```json
{ "video_id": "v_123", "playback_url": "https://.../master.m3u8?tok=...",
  "manifest_key": "vod/v_123/master.m3u8", "mode": "hls",
  "thumbnail_url": null, "token_expires_at": 1749103600,
  "access": { "active": true, "remaining_seconds": 86040, "views_remaining": 2, "...": "..." } }
```

**Playback complete.** `POST /ui/vod/rental/{video_id}/playback-complete` →
`VodRentalConsumeOut`: `{ "ok": true, "tier": "sd", "views_remaining": 2, "consumed": true }`.

**List (entitlements).** `GET /ui/vod/rental/list?limit=N` → `VodRentalListOut`
(`items: VodRentalStatusOut[]`); used to hydrate the "My rentals" surface and warm cache.

Retrofit interface:

```kotlin
interface VodRentalApi {
    @GET("ui/vod/rental/{video_id}/status")
    suspend fun status(@Path("video_id") id: String): VodRentalStatusOut

    @GET("ui/vod/rental/{video_id}/access")
    suspend fun access(@Path("video_id") id: String): VodRentalAccessOut

    @POST("ui/vod/rental/{video_id}/start")
    suspend fun start(@Path("video_id") id: String, @Body body: VodRentalStartIn): VodRentalStartOut

    @POST("ui/vod/rental/{video_id}/playback")
    suspend fun playback(@Path("video_id") id: String): VodRentalPlaybackOut

    @POST("ui/vod/rental/{video_id}/playback-complete")
    suspend fun playbackComplete(@Path("video_id") id: String): VodRentalConsumeOut

    @GET("ui/vod/rental/list")
    suspend fun list(@Query("limit") limit: Int = 50): VodRentalListOut
}
```

The repository wraps every call in `apiCall { … }` returning `ApiResult<T>` (AND-018) and
maps FastAPI `detail` to domain errors via AND-015.

## 6. Data & State Management

- **Source of truth:** the server. `expires_at` and `views_remaining` are authoritative;
  the client only *interpolates* the countdown between fetches and never extends access on
  its own.
- **Time base:** all timestamps are epoch **seconds, UTC**. The client compares against an
  injected `Clock` (UTC). Local device clock skew is tolerated by trusting the server-
  provided `remaining_seconds` at fetch time and decrementing locally; on the next
  `status`/`access` round-trip the value is re-anchored.
- **Active predicate (client tick):** `active = serverActive && (expiresAt == null ||
  clock.nowSeconds() < expiresAt) && viewsRemaining != 0`. When the tick crosses zero the
  ViewModel emits `Locked(lastReason = "expired")`.
- **Caching (Room, AND-191 cache infra):** persist the latest `VodRentalStatusOut` per
  `videoId` in a `rental_status` table keyed by `video_id`, with a `fetched_at_ms` column.
  On screen open, emit the cached state first (Stale) then refresh. This satisfies the
  offline/stale baseline; cache rows are pruned when `expires_at` is in the past and the
  server confirms re-lock.
- **No DataStore prefs** are introduced by this ticket.
- **Refresh triggers:** screen `onResume`, after `start`, after `playback-complete`, and on
  countdown-zero (one confirming `access` fetch).

## 7. Error Handling & Resilience

- **GETs** (`status`, `access`, `list`) are idempotent: use the bounded backoff retry
  (AND-016) under the 20s OkHttp timeout (AND-009). On exhaustion show the offline/stale
  state (AND-021) backed by the Room cache.
- **POSTs** (`start`, `playback`, `playback-complete`) are **never auto-retried** on
  network failure to avoid double-charging; surface a retryable inline error and let the
  user re-tap. `start` is naturally idempotent server-side via `already_active`, which the
  client treats as success.
- **401:** handled transparently by the refresh authenticator (AND-013) — single
  `POST /ui/session/refresh` then retry; if refresh fails the user is routed to login
  (AND-025).
- **402 / payment-required or 409 conflict** on `start`: map `detail` to a user message
  ("Payment failed", "Already rented") via AND-015; on 409+`already_active`, refresh state.
- **403 on `playback`** (access lapsed mid-session): re-lock UI, refresh `access`, show
  "Your rental has expired."
- **Token expiry:** if `token_expires_at` is in the past when playback is requested by a
  downstream consumer, re-call `playback`; do not reuse a stale `playback_url`.
- **`detail` shapes** handled: `string`, `[{msg}]`, `{code,...}` (AND-015).

## 8. Security & Privacy

- Session is **cookie-based**; no tokens are stored by this feature. The cookie jar
  (AND-011) and CSRF header (AND-012) are reused as-is.
- `playback_url` carries a short-lived signed token (`token_expires_at`): **never log it**,
  never persist it to Room/DataStore, and keep it only in in-memory state for the duration
  of the playback effect.
- Dev backend is plaintext HTTP (`18.222.237.167:8000`); the cleartext exception is already
  scoped to the dev flavor (AND-006). Release flavors must use HTTPS hosts only.
- `payment_method_id` (if ever populated by a downstream tier ticket) is PII-adjacent:
  pass-through only, never logged.
- Entitlement decisions are server-enforced; the client gate is a UX convenience and is not
  treated as a security boundary (a tampered client still cannot fetch a valid
  `playback_url` without a server-side active rental).

## 9. Accessibility & i18n

- All strings (`Rent · {price}`, `Play`, `Rental expired`, countdown labels, error copy)
  live in `feature-vod/src/main/res/values/strings.xml`; no hardcoded UI text.
- Price formatting from `amount_cents` uses `NumberFormat.getCurrencyInstance(locale)`;
  do not assume USD/`$`.
- Countdown exposes a `contentDescription` ("Rental expires in 2 hours 14 minutes"),
  distinct from the compact visual `HH:MM:SS`, so TalkBack reads natural language; the
  live region announces re-lock when the countdown hits zero.
- Rent/Play buttons meet the 48dp minimum touch target and expose enabled/disabled state
  semantics so assistive tech reflects gating.
- Timestamps render in the device timezone for any absolute "expires at" display.

## 10. Telemetry & Logging

This project has no analytics SDK; telemetry is structured Logcat via the shared logger
(tag `VodRental`), debug builds only.

- `rental_start_attempt` (videoId, tier), `rental_start_result` (success/already_active/
  error code, latencyMs), `rental_state` (active/locked/expired), `playback_request_result`,
  `playback_complete_result` (views_remaining).
- **Never** log `playback_url`, cookies, CSRF token, or `payment_method_id`.
- Network call logging is delegated to the OkHttp logging interceptor (AND-009), which is
  body-redacted in release.

## 11. Testing Strategy

- **Unit (ViewModel, `core-testing` + Turbine):** state machine transitions —
  Loading→Active (status returns `active=true`); Loading→Locked (`active=false`);
  Locked→(rent)→Active; `already_active=true` treated as success; countdown crossing zero
  flips Active→Locked with `reason="expired"`; `views_remaining==0` gates Play; `isRenting`
  disables the Rent button. Use a fake `Clock` to drive the ticker deterministically.
- **Repository contract (MockWebServer, AND-046 harness):** assert exact paths/methods,
  `X-CSRF-Token` present on POSTs, `tier` serialized in `start` body, and correct mapping of
  `VodRentalStatusOut`/`VodRentalAccessOut`/`VodRentalPlaybackOut`. Fixtures captured from
  the live OpenAPI examples in §5. Error fixtures: 402, 403, 409+`already_active`, and 401→
  refresh→retry.
- **Resilience:** GET retry on 503 then 200; POST does **not** retry; offline → cached
  stale status emitted.
- **Compose UI (AND-021 states):** Rent button shows price and is disabled while renting;
  after success Play is enabled and countdown visible; on simulated expiry UI re-locks.
  TalkBack/contentDescription assertions on the countdown.
- **Acceptance test** mapping the backlog bar: a scripted sequence (start → status active →
  clock advance past `expires_at` → access re-locked) proves "rental grants time-boxed
  access."

## 12. Dependencies & Sequencing

- **Hard deps:** AND-191 (detail screen host, `videoId` route arg, Room cache infra,
  tier/price source) and AND-031 (authenticated session). Also transitively requires the
  network stack AND-009–AND-018 and state composables AND-021.
- **Blocks / enables:** AND-193 (purchase tiers) reuses `VodRentalStartIn.tier`; AND-194
  (ad-supported) and AND-195 (watermark download) consume the `playback_url`/access state
  this ticket establishes.
- **Sequencing:** land DTOs (`core-model`) + `VodRentalApi`/repository first with contract
  tests, then `VodRentalViewModel`, then wire the Rent/Play affordance into the AND-191
  detail screen behind the same nav route.

## 13. Risks & Open Questions

1. **Tier catalog source.** `start` requires `tier`, but the rental endpoints do not return
   the list of purchasable tiers/prices. Assumption: AND-191 detail (or AND-193) supplies
   `RentalTierOption(tier, amountCents)`. *Open:* if AND-191 lacks it, this ticket needs a
   single default tier from config until AND-193 lands. **Owner: AND-193.**
2. **`reason` enum.** `reason` is a free-form string in the schema; the client must map
   unknown values to a generic "unavailable" message rather than switch exhaustively.
3. **Clock skew.** Heavy reliance on `expires_at` (absolute) vs `remaining_seconds`
   (relative). We anchor on `remaining_seconds` at fetch time to neutralize device-clock
   skew; verify the server returns a consistent `remaining_seconds`.
4. **Payment integration.** `payment_method_id` is nullable and unused here; whether rental
   requires a stored payment method is deferred to the purchase epic. **Owner: AND-193.**
5. **`now`/`user_sub` params.** Confirmed not needed when cookie session is present; flagged
   only if server identity derivation changes.

## 14. Acceptance Criteria

1. Tapping **Rent** with a valid session and tier issues
   `POST /ui/vod/rental/{video_id}/start` (with `tier` in the body and CSRF header) and, on
   200, transitions the UI to **Active** reflecting the returned `expires_at` and
   `views_remaining`.
2. **Play is gated:** enabled only while access is active per the §6 predicate; otherwise the
   Rent affordance is shown.
3. A live countdown is shown while active and decrements at least once per second; on
   reaching `expires_at` the UI re-locks to the Rent state **without an app restart**.
4. `views_remaining == 0` re-locks the content even if `expires_at` is in the future.
5. Revisiting a still-active rental restores the Active state from
   `GET /ui/vod/rental/{video_id}/status` without re-charging; `already_active=true` from
   `start` is treated as success.
6. POST calls are never auto-retried; idempotent GETs use bounded backoff and fall back to
   cached/stale state offline.
7. `playback_url` is never logged or persisted.
8. Unit tests cover every documented state transition; repository contract tests assert the
   exact paths, methods, CSRF header, and body for all six endpoints; the time-boxed
   re-lock scenario passes.

## 15. Definition of Done

- `feature-vod` rental DTOs, `VodRentalApi`, `VodRentalRepository`, and `VodRentalViewModel`
  implemented under `com.testlogon.android.feature.vod.rental`, with Hilt bindings (KSP).
- Rent/Play affordance + countdown integrated into the AND-191 detail screen behind the
  existing nav route; all states (Loading/Locked/Active/Error/Offline) render via AND-021
  composables.
- All §14 acceptance criteria verified by automated tests (Turbine unit + MockWebServer
  contract + Compose UI); CI unit-test job (AND-050) green.
- No hardcoded strings; price/timestamp formatting locale-aware; TalkBack descriptions on
  countdown and gated buttons.
- Lint/detekt/ktlint (AND-005) clean; no secrets or `playback_url` in logs.
- Code reviewed and merged to `android-port`; spec deps (AND-191, AND-031) confirmed
  satisfied at merge time.
