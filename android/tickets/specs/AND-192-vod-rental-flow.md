---
id: AND-192
title: VOD rental flow
milestone: M4
epic: E26
priority: P2
size: M
status: reviewed
reviewed_on: 2026-06-06
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
   **Corrected:** `tier` is constrained by the schema to `^(rental|view_once)$` (verified
   `VodRentalStartIn.tier` pattern), **not** quality labels like `"sd"`/`"hd"`. The two
   product modes are a time-boxed `rental` and a `view_once` grant. `rental_duration_hours`
   is sent only for `tier="rental"` and omitted for `view_once` (matches the web reference
   `VodRentalAccessPanel.tsx`).
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
    val reason: String?,          // observed server values: "not_rented" (default),
                                  // "pending", "expired", "consumed" (corrected from
                                  // the original "none"/"exhausted" guess; treat as
                                  // free-form and map unknowns to a generic message)
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
persistent cookie jar; mutating POSTs carry `X-CSRF-Token` (AND-012). **Note (verified
against `src/api/client.ts`):** the web client reads the CSRF value from the `ui_csrf`
cookie and attaches `X-CSRF-Token` to **every** request (GET and POST), and *also* sends an
`Authorization: Bearer <accessToken>` header when an access token is present (hybrid
bearer+cookie auth). The Android port is **cookie-only by design** (AND-011 cookie jar,
AND-013 401-refresh authenticator) and applies CSRF on mutating POSTs; sending CSRF on GETs
as well is harmless and matches the web client if we choose to. This divergence from the web
client's bearer header is an intentional platform decision, not a bug — recorded in §16.
The optional `now`, `user_sub`, `X-SESSION-ID`, `X-IMPERSONATION-TOKEN` parameters are
confirmed present in the OpenAPI on every rental op but are **not** sent by the production
client (server derives identity from the session); they are noted only for fixture fidelity.

**Start (rent).** `POST /ui/vod/rental/{video_id}/start`
```json
// request — VodRentalStartIn (tier required; pattern ^(rental|view_once)$)
{ "tier": "rental", "payment_method_id": null, "rental_duration_hours": 48 }
// for view_once, omit rental_duration_hours: { "tier": "view_once" }
```
```json
// 200 — VodRentalStartOut (required: video_id, rental_id, tier)
{ "video_id": "v_123", "rental_id": "r_abc", "tier": "rental",
  "already_active": false, "started": true, "expires_at": 1749200000,
  "views_remaining": -1, "amount_cents": 399, "duration_hours": 48 }
// NOTE: views_remaining default is -1 (unlimited within the window for a "rental");
// a finite count (e.g. 1) applies to "view_once". The gate uses views_remaining != 0.
```

**Status.** `GET /ui/vod/rental/{video_id}/status` → `VodRentalStatusOut`
(only `video_id` is schema-required; all other fields have server defaults).
```json
{ "video_id": "v_123", "rental_id": "r_abc", "tier": "rental", "amount_cents": 399,
  "created_at": 1749100000, "started_at": 1749100050, "duration_hours": 48,
  "active": true, "reason": "pending", "expires_at": 1749200000,
  "remaining_seconds": 86400, "views_remaining": -1, "started": true }
// reason is free-form; default "not_rented". Observed values in the web reference:
// "not_rented", "pending", "expired", "consumed". Do not switch exhaustively on it.
```

**Access.** `GET /ui/vod/rental/{video_id}/access` → `VodRentalAccessOut`
(`active` required; same access fields as above; used as the lightweight gate check).

**Playback.** `POST /ui/vod/rental/{video_id}/playback` → `VodRentalPlaybackOut`
```json
{ "video_id": "v_123", "playback_url": "https://.../master.m3u8?tok=...",
  "manifest_key": "vod/v_123/master.m3u8", "mode": "dev",
  "thumbnail_url": null, "token_expires_at": 1749103600,
  "access": { "active": true, "remaining_seconds": 86040, "views_remaining": -1, "...": "..." } }
// Corrected: VodRentalPlaybackOut.mode default is "dev" (not "hls"); manifest_key/mode/
// token_expires_at are optional with defaults. Required: video_id, playback_url, access.
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
- **402 / payment-required or 409 conflict** on `start`: *Unverified assumption.* The
  OpenAPI declares only **200** and **422** for `POST .../start` (no 402/409). These codes
  are defensive: IF the server returns them, map `detail` to a user message ("Payment
  failed", "Already rented") via AND-015; on 409+`already_active`, refresh state. Do not
  write contract tests asserting these as guaranteed responses — drive them via injected
  fixtures only. (The first-class idempotency signal is the documented `already_active`
  field on the 200 `VodRentalStartOut`.)
- **403 on `playback`** (access lapsed mid-session): *Unverified assumption.* The OpenAPI
  declares only **200** and **422** for `POST .../playback`. IF a 403 is returned, re-lock
  UI, refresh `access`, show "Your rental has expired." The reliable signal that access
  lapsed is `access.active == false` inside a 200 response (verified `VodRentalPlaybackOut`
  embeds the `VodRentalAccessOut`).
- **Token expiry:** if `token_expires_at` is in the past when playback is requested by a
  downstream consumer, re-call `playback`; do not reuse a stale `playback_url`.
- **`detail` shapes** handled: `string`, `[{msg}]`, `{code,...}` (AND-015).

## 8. Security & Privacy

- Session is **cookie-based** for the Android port; no tokens are stored by this feature.
  The cookie jar (AND-011) and CSRF header (AND-012) are reused as-is. *Verified divergence:*
  the web client (`src/api/client.ts`) is hybrid — it sends `Authorization: Bearer` in
  addition to the cookie session and CSRF cookie (`ui_csrf`). The Android port deliberately
  relies on the cookie session + 401-refresh authenticator (AND-013) instead of a stored
  bearer token; this feature introduces no new credential storage.
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
  `VodRentalStatusOut`/`VodRentalAccessOut`/`VodRentalPlaybackOut`. `tier` must serialize as
  `rental` or `view_once` (schema pattern). Fixtures captured from the live OpenAPI examples
  in §5 (corrected tiers/`mode`/`reason`). Error fixtures: 422 HTTPValidationError
  (`detail: [{loc,msg,type}]` — the only documented error for these ops), plus *synthetic*
  402/403/409 fixtures to exercise the defensive mappers (those codes are not in the OpenAPI
  for these ops), and 401 -> refresh -> retry against `POST /ui/session/refresh`.
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

## 16. Citations & Assumption Audit

Each key technical claim, with VERDICT and an exact SOURCE pointer. OpenAPI sources cite the
endpoint index (`METHOD /path`) and/or `components.schemas.<Name>` in `openapi.pretty.json`;
frontend sources cite a path under `reference/src/`.

1. **Endpoint paths/methods** — `POST /ui/vod/rental/{video_id}/start`,
   `GET /ui/vod/rental/{video_id}/status`, `GET /ui/vod/rental/{video_id}/access`,
   `POST /ui/vod/rental/{video_id}/playback`,
   `POST /ui/vod/rental/{video_id}/playback-complete`, `GET /ui/vod/rental/list`.
   **Verified.** Source: OpenAPI index lines for each path; and
   `src/api/endpoints/vodRental.ts` (`startRental`, `getRentalStatus`, `getRentalAccess`,
   `issueRentalPlayback`, `completeRentalPlayback`, `listRentals`).
2. **`start` request body = `VodRentalStartIn`** with `tier` (required), `payment_method_id?`,
   `rental_duration_hours?`. **Verified.** Source: `components.schemas.VodRentalStartIn`;
   `src/api/types.ts: VodRentalStartRequest`.
3. **`tier` allowed values.** Spec originally said `"sd"`/`"hd"`. **Corrected** to
   `^(rental|view_once)$`. Source: `VodRentalStartIn.tier.pattern` in OpenAPI;
   `src/api/types.ts: VodRentalStartRequest` (`"rental" | "view_once"`); usage in
   `src/pages/vod/VodRentalAccessPanel.tsx` (`startMut.mutate("rental"|"view_once")`).
4. **`rental_duration_hours` sent only for `tier="rental"`** (bounds 1..720). **Verified.**
   Source: `VodRentalStartIn.rental_duration_hours` (min 1, max 720);
   `src/pages/vod/VodRentalAccessPanel.tsx` (`rental_duration_hours: tier === "rental" ? … : undefined`).
5. **`VodRentalStartOut` fields** (`video_id`, `rental_id`, `tier` required; `already_active`,
   `started`, `expires_at?`, `views_remaining`, `amount_cents`, `duration_hours?`).
   **Verified.** Source: `components.schemas.VodRentalStartOut`; `src/api/types.ts: VodRentalStartResponse`.
6. **`expires_at` is nullable epoch-seconds integer.** **Verified.** Source:
   `VodRentalStartOut.expires_at` / `VodRentalStatusOut.expires_at` / `VodRentalAccessOut.expires_at`
   (anyOf integer|null).
7. **`views_remaining` default = -1** (sentinel for unlimited), gate uses `!= 0`. **Verified.**
   Source: `VodRentalAccessOut.views_remaining.default = -1` (and same in StatusOut/StartOut/ConsumeOut).
   The §3/§6 gate `views_remaining != 0` therefore correctly does NOT lock on the -1 default.
8. **`reason` values.** Spec §4 comment originally said `"expired"/"exhausted"/"none"`.
   **Corrected** to default `"not_rented"`, free-form; observed values `not_rented`, `pending`,
   `expired`, `consumed`. Source: `VodRentalAccessOut.reason.default = "not_rented"`;
   `src/pages/vod/VodRentalAccessPanel.tsx` (handles `pending`, `expired`, `consumed`,
   `not_rented`).
9. **`VodRentalPlaybackOut`** requires `video_id`, `playback_url`, `access`; `mode` default
   value. Spec example said `"mode": "hls"`. **Corrected** to default `"dev"`. Source:
   `components.schemas.VodRentalPlaybackOut.mode.default = "dev"`; required list `[video_id,
   playback_url, access]`; `src/api/types.ts: VodRentalPlayback`.
10. **`playback` embeds `access` (VodRentalAccessOut)** so access lapse is detectable inside a
    200. **Verified.** Source: `VodRentalPlaybackOut.access $ref VodRentalAccessOut`.
11. **`playback-complete` response** = `{ ok, tier, views_remaining, consumed }` (`VodRentalConsumeOut`,
    only `ok` required). **Verified.** Source: `components.schemas.VodRentalConsumeOut`;
    `src/api/endpoints/vodRental.ts: completeRentalPlayback` (inline type matches).
12. **`list` returns `{ items: VodRentalStatusOut[] }`, takes `limit`.** **Verified.** Source:
    `components.schemas.VodRentalListOut`; OpenAPI index `GET /ui/vod/rental/list … params=limit,…`;
    `src/api/endpoints/vodRental.ts: listRentals(limit?)`.
13. **CSRF: `X-CSRF-Token` from `ui_csrf` cookie.** **Verified (with nuance).** The web client
    sends it on **every** request, not just POSTs (spec implied POST-only). Source:
    `src/api/client.ts` (`getCookie("ui_csrf")` → `headers.set("X-CSRF-Token", csrf)` for all
    methods). Android applying it to mutating POSTs is a compatible subset (recorded as a
    design choice).
14. **Auth model.** Spec claims pure cookie session, no tokens. **Verified-divergence:** the web
    client is hybrid — also sets `Authorization: Bearer <accessToken>` and
    `X-IMPERSONATION-TOKEN`. Source: `src/api/client.ts` (auth/impersonation header blocks).
    The Android port is cookie-only **by design** (AND-011/AND-013); not a defect.
15. **401 → single `POST /ui/session/refresh` then retry, else logout.** **Verified.** Source:
    `src/api/client.ts: refreshSession()` + 401 branch; OpenAPI index
    `POST /ui/session/refresh`.
16. **Error `detail` shapes** = `string` | `[{loc,msg,type}]` | `{code,…}`. **Verified.** Source:
    `components.schemas.HTTPValidationError` (`detail: ValidationError[]`),
    `components.schemas.ValidationError` (`loc,msg,type` required); `src/api/client.ts:
    normalizeErrorDetail` + `mapAuthorizationError` (handles string/array-of-{msg}/object-{code}).
17. **402 / 409 on `start`, 403 on `playback`.** **Unverified-assumption.** The OpenAPI declares
    only `200` and `422` for both ops. Source: `/ui/vod/rental/{video_id}/start` and
    `/ui/vod/rental/{video_id}/playback` `responses` blocks (200, 422 only). Defensive mapping
    retained but flagged; idempotency is keyed off `already_active`, lapse off `access.active`.
18. **Optional `now`/`user_sub`/`X-SESSION-ID`/`X-IMPERSONATION-TOKEN` params not sent by the
    production client.** **Verified.** Source: present on every rental op in OpenAPI index;
    `src/api/client.ts` sets `X-IMPERSONATION-TOKEN` only when impersonating, and never sends
    `now`/`user_sub`/`X-SESSION-ID`. Android production client omits all four.
19. **Web reference gates on `access` (not `status`) in the per-video panel.** **Verified.**
    Source: `src/pages/vod/VodRentalAccessPanel.tsx` (`getRentalAccess`); `status`/`list` are used
    by `src/pages/vod/VodRentalsPage.tsx`. The spec's choice of `status` for resume is a valid
    design choice (both endpoints return equivalent access fields).
20. **Android framework choices** (Retrofit/Moshi, OkHttp, Hilt+KSP, Compose, StateFlow,
    `SavedStateHandle`, `viewModelScope` ticker). **Unverified-assumption (framework ref):** not
    derivable from backend/frontend; standard Android. Framework refs:
    https://developer.android.com/jetpack/compose/state ,
    https://developer.android.com/topic/libraries/architecture/viewmodel ,
    https://square.github.io/retrofit/ , https://dagger.dev/hilt/ .

### Corrections made
- §3.1 / §5 / §14: `tier` corrected from `"sd"`/`"hd"` to `^(rental|view_once)$`; added the
  `rental_duration_hours` rental-only rule (claims 3, 4).
- §4: `reason` example values corrected from `"expired"/"exhausted"/"none"` to the real default
  `"not_rented"` and observed `pending/expired/consumed` (claim 8).
- §5 `start`/`status` examples: `views_remaining` shown as the real default `-1`; `reason` example
  changed to a real value (claims 7, 8).
- §5 `playback` example: `mode` corrected from `"hls"` to the schema default `"dev"` (claim 9).
- §5 / §8: CSRF clarified (sent on all requests, from `ui_csrf` cookie) and auth-model divergence
  (web is hybrid bearer+cookie; Android cookie-only by design) documented (claims 13, 14).
- §7 / §11: 402/409/403 demoted to *unverified, defensive* mappings (OpenAPI declares only
  200/422); error-fixture list updated to lead with the documented 422 shape (claim 17).

### Open assumptions
- **Tier catalog / prices** (`amount_cents`, view-once vs rental price): the rental endpoints do
  not return a purchasable-tier list; sourced from AND-191 detail or AND-193. Unverifiable here.
- **402/409/403 status codes** (claim 17): not in the OpenAPI for these ops; cannot confirm
  whether the server ever emits them. Treated as defensive only.
- **`reason` complete enum**: free-form `string` in the schema; only four values observed in the
  web reference. Unknown values must map to a generic message.
- **Server `remaining_seconds` consistency** for skew-anchoring (§6, Risk 3): behavioral, not
  expressible in the schema; must be confirmed against a live server.
- **Android framework/library choices** (claim 20): design decisions, no backend/frontend source.

## 17. Test Plan

Test IDs `TC-AND-192-NN`. Targets: JVM = local JVM/Robolectric unit; MWS = MockWebServer
contract; EMU = headless emulator AVD `test35` (API 35, x86_64); DEVICE = physical Samsung
Galaxy A15 5G (SM-A156U, API 34, arm64-v8a). `Traces` link to §14 Acceptance Criteria (AC-#).

- **TC-AND-192-01 — Rent happy path (start → Active).**
  Type: unit (ViewModel) + MWS. Target: JVM/MWS.
  Preconditions: authenticated cookie session; video locked (`access.active=false`).
  Steps: enqueue 200 `VodRentalStartOut` `{tier:"rental", already_active:false, started:true,
  expires_at:now+86400, views_remaining:-1, amount_cents:399}`; call `rent("rental")`.
  Expected: request is `POST /ui/vod/rental/{id}/start` with `X-CSRF-Token` header and body
  `{tier:"rental", rental_duration_hours:48}`; UI transitions Loading/Locked → Active with the
  returned `expires_at` and `views_remaining`. Traces: AC-1.

- **TC-AND-192-02 — Tier serialization & view_once variant.**
  Type: MWS contract. Target: MWS.
  Preconditions: locked video.
  Steps: call `rent("view_once")`; inspect recorded request body.
  Expected: body `{tier:"view_once"}` with **no** `rental_duration_hours`; `tier` always matches
  `^(rental|view_once)$`; a `"sd"`/`"hd"` value is never sent. Traces: AC-1.

- **TC-AND-192-03 — Play gating predicate.**
  Type: unit (ViewModel). Target: JVM.
  Preconditions: fake `Clock`.
  Steps: feed access states: (a) `active=true, expires_at=now+10, views_remaining=-1`;
  (b) `active=false`; (c) `active=true, views_remaining=0`; (d) `active=true, expires_at=now-1`.
  Expected: Play enabled only for (a); (b),(c),(d) show Locked/Rent. Confirms
  `active && (expires_at==null || now<expires_at) && views_remaining!=0`. Traces: AC-2, AC-4.

- **TC-AND-192-04 — Live countdown re-lock without restart.**
  Type: unit (ViewModel, fake Clock + Turbine). Target: JVM.
  Preconditions: Active with `remaining_seconds=3`.
  Steps: advance the injected clock/ticker past zero.
  Expected: countdown decrements at least once/second; on crossing zero emits
  `Locked(lastReason="expired")` in-process (no restart). Traces: AC-3.

- **TC-AND-192-05 — views_remaining==0 locks despite future expiry.**
  Type: unit (ViewModel). Target: JVM.
  Preconditions: access `active=true, expires_at=now+86400, views_remaining=0`.
  Steps: reduce state.
  Expected: UI is Locked (view budget exhausted) even though the window is open. Traces: AC-4.

- **TC-AND-192-06 — Resume + idempotent re-rent (`already_active`).**
  Type: MWS contract + unit. Target: MWS/JVM.
  Preconditions: previously rented, window open.
  Steps: (a) on revisit, `GET .../status` returns `active=true` → restore Active without a new
  charge; (b) call `rent` and have `start` return 200 `already_active=true`.
  Expected: (a) no `start` call issued on resume; (b) `already_active=true` treated as success,
  state refreshed, no error, no duplicate charge. Traces: AC-5.

- **TC-AND-192-07 — Playback handshake + complete decrements budget.**
  Type: MWS contract. Target: MWS.
  Preconditions: Active rental.
  Steps: call `beginPlayback()` → 200 `VodRentalPlaybackOut {playback_url, mode:"dev",
  token_expires_at, access{active:true}}`; then `finishPlayback()` → 200 `VodRentalConsumeOut
  {ok:true, consumed:true, views_remaining:0}`.
  Expected: `POST .../playback` then `POST .../playback-complete`, both with `X-CSRF-Token`;
  PlaybackReady effect carries url+`token_expires_at`; after complete, access is refreshed and
  reflects the decremented budget. Traces: AC-1, AC-5.

- **TC-AND-192-08 — `playback_url` never logged or persisted.**
  Type: unit + instrumented. Target: JVM (+ EMU for Room check).
  Preconditions: Logcat capture; Room `rental_status` table.
  Steps: run the §07 handshake; scan emitted log lines and the persisted Room row.
  Expected: `playback_url`, cookies, CSRF token, `payment_method_id` appear in **no** log line
  and in **no** Room/DataStore column; url lives only in transient in-memory effect state.
  Traces: AC-7.

- **TC-AND-192-09 — 422 validation error mapping (documented error).**
  Type: MWS contract. Target: MWS.
  Preconditions: locked video.
  Steps: enqueue 422 `HTTPValidationError {detail:[{loc:["body","tier"],msg:"string does not
  match regex",type:"value_error"}]}` on `start`.
  Expected: AND-015 maps the `[{msg}]` array to a readable inline error; POST is **not**
  auto-retried; the Rent button returns to a re-tappable state. Traces: AC-6, AC-8.

- **TC-AND-192-10 — Defensive 402/409/403 mapping (synthetic).**
  Type: MWS contract. Target: MWS.
  Preconditions: synthetic fixtures (these codes are NOT in the OpenAPI — fixture-driven only).
  Steps: enqueue 402 `{detail:"Payment failed"}` and 409 `{detail:{code:"already_rented"}}` on
  `start`; 403 `{detail:"expired"}` on `playback`.
  Expected: 402/409 → user message via AND-015, no auto-retry, state refresh on 409; 403 →
  re-lock + `access` refresh. Test must NOT assert these as guaranteed server behavior.
  Traces: AC-6.

- **TC-AND-192-11 — 401 → refresh → retry.**
  Type: MWS contract. Target: MWS.
  Preconditions: expired session.
  Steps: first `status` returns 401; authenticator issues `POST /ui/session/refresh` (200);
  original request retried (200).
  Expected: exactly one refresh call, then a single successful retry; no infinite loop; on
  refresh failure user routed to login (AND-025). Traces: AC-6.

- **TC-AND-192-12 — Offline / flaky-dev-host resilience.**
  Type: MWS + instrumented. Target: MWS (logic) and DEVICE (real airplane-mode toggle).
  Preconditions: Room cache holds a prior `VodRentalStatusOut`.
  Steps: GET path: 503 then 200 (bounded backoff retries, AND-016) → succeeds. Offline path:
  disable network (airplane mode on the physical device) → GETs exhaust retries; verify POST
  (`start`) does **not** auto-retry. Expected: GET recovers via retry; when fully offline the
  cached/stale status is emitted (AND-021) and POSTs surface a retryable inline error without
  double-firing. Runs on DEVICE because it needs a real radio/airplane-mode toggle, not an
  emulated network. Traces: AC-6.

- **TC-AND-192-13 — Compose UI states + price/locale formatting.**
  Type: Compose-UI / instrumented. Target: EMU (`test35`).
  Preconditions: provide fake states (Loading/Locked/Active/Error/Offline).
  Steps: render each state; assert Rent shows `amount_cents` via
  `NumberFormat.getCurrencyInstance(locale)` (not hardcoded `$`), Rent disabled while
  `isRenting`, Play enabled+countdown visible in Active, Play disabled while
  `isStartingPlayback`, re-lock on simulated expiry.
  Expected: all five states render correctly; no hardcoded strings (all from `strings.xml`).
  Traces: AC-1, AC-2, AC-3.

- **TC-AND-192-14 — Accessibility (TalkBack / touch targets).**
  Type: Compose-UI / instrumented (accessibility). Target: DEVICE (real TalkBack) with EMU
  smoke fallback.
  Preconditions: Active state with a running countdown.
  Steps: enable TalkBack; inspect countdown `contentDescription` and live-region; measure
  Rent/Play touch targets and enabled/disabled semantics.
  Expected: countdown exposes natural-language description ("Rental expires in 2 hours 14
  minutes") distinct from `HH:MM:SS`; live region announces re-lock at zero; buttons ≥ 48dp and
  expose enabled/disabled state to assistive tech. Run on DEVICE to validate real TalkBack
  output (emulator a11y is a smoke check only). Traces: AC-2, AC-3.

### Coverage matrix

| §14 Acceptance Criterion | Covered by |
| --- | --- |
| AC-1 (Rent → start with tier+CSRF → Active) | TC-01, TC-02, TC-07, TC-13 |
| AC-2 (Play gated by §6 predicate) | TC-03, TC-13, TC-14 |
| AC-3 (live countdown, re-lock w/o restart) | TC-04, TC-13, TC-14 |
| AC-4 (views_remaining==0 locks despite future expiry) | TC-03, TC-05 |
| AC-5 (resume w/o re-charge; `already_active` = success) | TC-06, TC-07 |
| AC-6 (POSTs no auto-retry; GET backoff; offline cache) | TC-09, TC-10, TC-11, TC-12 |
| AC-7 (`playback_url` never logged/persisted) | TC-08 |
| AC-8 (unit transitions + contract tests for all 6 endpoints + time-box re-lock) | TC-01..07, TC-09, TC-11 |
