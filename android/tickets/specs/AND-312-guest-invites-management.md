---
id: AND-312
title: Guest invites & management
milestone: M7
epic: E41
priority: P2
size: M
status: draft
depends_on: [AND-308]
blocks: []
---

# AND-312 — Guest invites & management

## 1. Overview & Goal

This ticket delivers the host-side and guest-side flows for inviting people to co-broadcast on a live stream and managing them once they join. A "guest" is a remote participant the host pulls into the broadcast as a second ingest source (built on the WebRTC ingest pipeline from AND-308). The host can create an invite, send it, and once a guest accepts, the host manages that guest's lifecycle: **promote** (grant the guest publish/on-air rights), **mute** (force-mute the guest's audio without removing them), and **remove** (eject the guest from the broadcast). The guest side can **accept** an invite and the host (or guest) can **revoke**/leave.

Goal: ship a `feature-guest` module that exposes a host management panel and a guest accept screen, backed by a `GuestRepository` over the `/ui/broadcasts/{broadcastId}/guests` endpoints, with optimistic-but-reconciled UI state, full error handling against the unreliable dev backend, and cookie/CSRF-authenticated calls. The actual media transport (negotiating the guest's WebRTC `inputs` + `webrtc-offer`) is owned by AND-308; this ticket owns invite/membership/permission state and the management UI that drives it.

## 2. Context & References

- Repo: `spannella/testlogon`, Android app under `android/`, branch `android-port`.
- Namespace / applicationId base: `com.testlogon.android`. This feature: `com.testlogon.android.feature.guest`.
- Module layering: `app -> feature-guest -> core-network, core-model, core-ui, core-data, core-testing`.
- Stack: Kotlin 2.0.21, Compose + Material 3, Navigation-Compose, Hilt (KSP), Coroutines/Flow, Retrofit 2.11 / OkHttp 4.12 / Moshi 1.15, Room 2.6, DataStore, Paging 3. minSdk 24, compileSdk/targetSdk 35, JDK 17, AGP 8.7.3, Gradle 8.9.
- Auth: cookie-based session + `ui_csrf` cookie echoed as `X-CSRF-Token`; persistent cookie jar; on `401`, `POST /ui/session/refresh` once then retry. Provided by `core-network` (the shared `OkHttpClient`, `CookieJar`, `CsrfInterceptor`, and `AuthAuthenticator`). This ticket consumes those, it does not re-implement them.
- Backend: FastAPI + DynamoDB; dev host `http://18.222.237.167:8000` (plaintext HTTP, unreliable). OpenAPI at `/openapi.json`. FastAPI error `detail` shapes: `string | [{msg}] | {code,...}`.
- Web reference: `frontend/src/api/endpoints/*.ts` (guest endpoints) and shared types in `frontend/src/api/types.ts`. Reconcile the Moshi DTOs in §5 against `types.ts` during implementation; if a field name differs, the web type is authoritative and the DTO `@Json(name=...)` must be updated.
- **Depends on AND-308 (WebRTC ingest):** the broadcast must support multiple ingest inputs before a guest's media can be carried. AND-312 produces the membership/permission state that AND-308's session consumes to add/remove a guest's media track.

## 3. Functional Requirements

Host (broadcast owner) flows:

- **FR-1 Create invite.** Host taps "Invite guest" in the live broadcast controls and creates an invite. The app returns a shareable invite URL / code and shows it (copy + system share sheet). An invite has a status (`pending`, `accepted`, `revoked`, `expired`).
- **FR-2 Revoke invite.** Host can revoke a still-`pending` invite; the slot is freed.
- **FR-3 Guest list.** Host sees a live list of guests for the broadcast with each guest's `status` (`invited`, `joined`, `onair`, `muted`) and role.
- **FR-4 Promote.** Host promotes a `joined` guest to `onair` (publish rights). This is what makes the guest's WebRTC track go live via AND-308.
- **FR-5 Mute.** Host mutes/unmutes an on-air guest. Mute is a server-enforced state, not just a local UI toggle.
- **FR-6 Remove.** Host removes a guest; the guest is ejected and the slot freed. Removal is destructive and requires a confirm dialog.

Guest flows:

- **FR-7 Accept invite.** A guest opening an invite deep link (`testlogon://guest/accept?token=...`) lands on an accept screen showing the broadcast title/host; accepting transitions the guest to `joined` and hands off to the AND-308 join flow.
- **FR-8 Leave.** A joined guest can leave (self-revoke), which the host sees reflected in the list.

Cross-cutting:

- **FR-9** All mutations (accept/revoke/promote/mute/remove) are state-changing `POST`/`DELETE` calls and carry `X-CSRF-Token`. They are **not** retried automatically (non-idempotent).
- **FR-10** The guest list reflects server truth: a host action is optimistically applied, then reconciled against the server response; on failure the optimistic change is rolled back and an error is surfaced.

## 4. Technical Design

Module `feature-guest`. Single-Activity Navigation-Compose; this feature registers a nav graph `guestGraph`.

```kotlin
// Navigation
object GuestRoutes {
    const val MANAGE = "broadcast/{broadcastId}/guests"      // host panel
    const val ACCEPT = "guest/accept?token={token}"          // guest accept (deep link)
    fun manage(broadcastId: String) = "broadcast/$broadcastId/guests"
    fun accept(token: String) = "guest/accept?token=$token"
}

fun NavGraphBuilder.guestGraph(navController: NavController)
```

Domain models (in `core-model`):

```kotlin
enum class GuestStatus { INVITED, JOINED, ONAIR, MUTED, LEFT, REMOVED }
enum class GuestRole   { GUEST, COHOST }
enum class InviteStatus { PENDING, ACCEPTED, REVOKED, EXPIRED }

data class Guest(
    val id: String,
    val broadcastId: String,
    val displayName: String,
    val avatarUrl: String?,
    val status: GuestStatus,
    val role: GuestRole,
    val mutedAudio: Boolean,
    val joinedAt: Instant?,
)

data class GuestInvite(
    val id: String,
    val broadcastId: String,
    val token: String,
    val url: String,
    val status: InviteStatus,
    val expiresAt: Instant?,
)
```

Repository (in `feature-guest`, interface in `core-data` if shared):

```kotlin
interface GuestRepository {
    fun observeGuests(broadcastId: String): Flow<List<Guest>>   // Room-backed, refreshed on poll/action
    suspend fun refreshGuests(broadcastId: String): ApiResult<List<Guest>>
    suspend fun createInvite(broadcastId: String): ApiResult<GuestInvite>
    suspend fun revokeInvite(broadcastId: String, inviteId: String): ApiResult<Unit>
    suspend fun acceptInvite(token: String): ApiResult<Guest>
    suspend fun promote(broadcastId: String, guestId: String): ApiResult<Guest>
    suspend fun setMuted(broadcastId: String, guestId: String, muted: Boolean): ApiResult<Guest>
    suspend fun remove(broadcastId: String, guestId: String): ApiResult<Unit>
    suspend fun leave(broadcastId: String): ApiResult<Unit>
}
```

`ApiResult<T>` is the shared sealed type from `core-network` (`Success(value)`, `Error(detail, httpCode)`, `NetworkError`, `Offline`). The repository maps Retrofit/IO exceptions and FastAPI `detail` into it (see §7).

ViewModels expose `StateFlow<UiState>`:

```kotlin
@HiltViewModel
class GuestManageViewModel @Inject constructor(
    private val repo: GuestRepository,
    savedState: SavedStateHandle,
) : ViewModel() {
    private val broadcastId: String = checkNotNull(savedState["broadcastId"])
    val uiState: StateFlow<GuestManageUiState>
    fun onCreateInvite()
    fun onRevokeInvite(inviteId: String)
    fun onPromote(guestId: String)
    fun onToggleMute(guestId: String, muted: Boolean)
    fun onRemove(guestId: String)         // called after confirm
    fun onRetryRefresh()
}

data class GuestManageUiState(
    val guests: List<Guest> = emptyList(),
    val invite: GuestInvite? = null,
    val isLoading: Boolean = false,
    val isStale: Boolean = false,         // last refresh failed; showing cached
    val inFlight: Set<String> = emptySet(), // guestIds with a pending mutation (disable row)
    val error: UiText? = null,
)

@HiltViewModel
class GuestAcceptViewModel @Inject constructor(
    private val repo: GuestRepository,
    savedState: SavedStateHandle,
) : ViewModel() {
    val uiState: StateFlow<GuestAcceptUiState>
    fun onAccept()
}
```

Compose surface: `GuestManageScreen` (host) renders an invite card (create / copy / share / revoke) plus a `LazyColumn` of `GuestRow`s. Each row shows avatar (Coil), name, status chip, and an overflow menu with Promote / Mute-Unmute / Remove. `GuestAcceptScreen` shows broadcast summary + Accept/Decline. Confirm removal via `AlertDialog` from `core-ui`.

Live updates: there is no WebSocket layer specified for this milestone, so the host list uses **bounded polling** — `refreshGuests` every 5s while `GuestManageScreen` is in the `RESUMED` lifecycle state (collected via `repeatOnLifecycle`), plus an immediate refresh after every successful mutation. Polling stops when the screen is backgrounded. Room is the single source of truth so the UI does not flicker between polls.

Deep link: register an intent filter on the single Activity for `testlogon://guest/accept` and route it to `GuestRoutes.ACCEPT` with the `token` query param.

## 5. API Contract

Base path `/ui/broadcasts/{broadcastId}/guests`. All calls go through the shared authenticated Retrofit instance (cookie jar + `X-CSRF-Token`). Reconcile exact field names with `frontend/src/api/types.ts`.

```kotlin
interface GuestApi {
    @GET("ui/broadcasts/{broadcastId}/guests")
    suspend fun listGuests(@Path("broadcastId") id: String): Response<GuestListDto>

    @POST("ui/broadcasts/{broadcastId}/guests/invites")
    suspend fun createInvite(@Path("broadcastId") id: String): Response<GuestInviteDto>

    @DELETE("ui/broadcasts/{broadcastId}/guests/invites/{inviteId}")
    suspend fun revokeInvite(@Path("broadcastId") id: String, @Path("inviteId") inviteId: String): Response<Unit>

    @POST("ui/guests/accept")
    suspend fun acceptInvite(@Body body: AcceptInviteRequest): Response<GuestDto>

    @POST("ui/broadcasts/{broadcastId}/guests/{guestId}/promote")
    suspend fun promote(@Path("broadcastId") id: String, @Path("guestId") guestId: String): Response<GuestDto>

    @POST("ui/broadcasts/{broadcastId}/guests/{guestId}/mute")
    suspend fun setMuted(@Path("broadcastId") id: String, @Path("guestId") guestId: String,
                         @Body body: MuteRequest): Response<GuestDto>

    @DELETE("ui/broadcasts/{broadcastId}/guests/{guestId}")
    suspend fun remove(@Path("broadcastId") id: String, @Path("guestId") guestId: String): Response<Unit>

    @POST("ui/broadcasts/{broadcastId}/guests/leave")
    suspend fun leave(@Path("broadcastId") id: String): Response<Unit>
}
```

DTOs (Moshi):

```kotlin
@JsonClass(generateAdapter = true)
data class GuestListDto(@Json(name = "guests") val guests: List<GuestDto>,
                        @Json(name = "invite") val invite: GuestInviteDto?)

@JsonClass(generateAdapter = true)
data class GuestDto(
    @Json(name = "id") val id: String,
    @Json(name = "display_name") val displayName: String,
    @Json(name = "avatar_url") val avatarUrl: String?,
    @Json(name = "status") val status: String,          // invited|joined|onair|muted|left|removed
    @Json(name = "role") val role: String,              // guest|cohost
    @Json(name = "muted_audio") val mutedAudio: Boolean = false,
    @Json(name = "joined_at") val joinedAt: String?,    // ISO-8601
)

@JsonClass(generateAdapter = true)
data class GuestInviteDto(
    @Json(name = "id") val id: String,
    @Json(name = "token") val token: String,
    @Json(name = "url") val url: String,
    @Json(name = "status") val status: String,          // pending|accepted|revoked|expired
    @Json(name = "expires_at") val expiresAt: String?,
)

@JsonClass(generateAdapter = true)
data class AcceptInviteRequest(@Json(name = "token") val token: String)

@JsonClass(generateAdapter = true)
data class MuteRequest(@Json(name = "muted") val muted: Boolean)
```

Example `POST /ui/broadcasts/{id}/guests/invites` response:

```json
{ "id": "inv_a1b2", "token": "g_8f3...", "url": "https://testlogon.app/g/8f3", "status": "pending", "expires_at": "2026-06-05T22:00:00Z" }
```

Example `GET .../guests` response:

```json
{ "guests": [ { "id": "gst_77", "display_name": "Avery", "avatar_url": null,
  "status": "onair", "role": "guest", "muted_audio": true,
  "joined_at": "2026-06-05T21:10:03Z" } ],
  "invite": { "id": "inv_a1b2", "token": "g_8f3", "url": "https://testlogon.app/g/8f3",
              "status": "pending", "expires_at": "2026-06-05T22:00:00Z" } }
```

Unknown enum strings map to a defensive default (`GuestStatus.JOINED` / `InviteStatus.PENDING`) and are logged, never thrown. Exact endpoint paths/verbs must be verified against `/openapi.json`; the mapping layer is the only place that changes if they differ.

## 6. Data & State Management

- **Room (cache).** `guests` table keyed by `(broadcastId, guestId)`; `guest_invites` keyed by `broadcastId` (one active invite per broadcast for this milestone). `GuestDao` exposes `Flow<List<GuestEntity>>` filtered by `broadcastId`. Repository writes server results into Room inside a transaction; UI observes Room only.
- **Mapping.** `GuestDto -> GuestEntity -> Guest`. ISO timestamps parse to `Instant`; null/invalid -> `null`.
- **Optimistic mutations.** On `onToggleMute`/`onPromote`/`onRemove`, the ViewModel adds the `guestId` to `inFlight`, applies the predicted change to the emitted state, then calls the repo. On `ApiResult.Success` it persists the authoritative `GuestDto` to Room (reconcile) and clears `inFlight`. On any error it clears `inFlight`, re-emits from Room (rollback), and sets `error`.
- **DataStore (prefs).** No durable prefs needed; an in-memory pending-invite token from a deep link is held in `SavedStateHandle`, not persisted.
- **Lifecycle.** Polling job is tied to `viewModelScope` + screen lifecycle; cancelled on stop to respect the unreliable backend and battery.
- **No Paging.** Guest lists are small (single-digit to low-tens); `Paging 3` is not used here.

## 7. Error Handling & Resilience

- **Timeouts/backoff.** OkHttp call timeout ~20s (from `core-network`). The only retryable call here is the idempotent `GET listGuests`, which uses bounded exponential backoff (2 retries, ~1s/2s, jittered) for transient `IOException`/`5xx`. All mutations (§FR-9) are non-idempotent and are **never** auto-retried; the user retries explicitly.
- **401 handling.** Handled centrally by `core-network`'s `AuthAuthenticator` (`POST /ui/session/refresh` once, then retry). If refresh fails, the call surfaces as `ApiResult.Error(httpCode=401)` and the feature navigates to re-auth (owned by the auth feature).
- **FastAPI `detail` mapping.** A shared `parseDetail(body): String` handles the three shapes: plain `string`; validation array `[{msg}]` (join `msg`s); structured `{code, message}` (prefer `message`). Surface to UI as `UiText`.
- **Offline / stale.** When `refreshGuests` fails but Room has data, set `isStale=true` and keep showing the cached list with a "Reconnecting…" banner; do not clear the list. Mutations attempted while offline return `ApiResult.Offline` and show a transient snackbar without mutating Room.
- **Conflict cases.** `409`/`410` on accept (`expired`/`revoked` invite) -> dedicated copy on the accept screen ("This invite is no longer valid"). `404` on a guest mutation (guest already left) -> silently refresh the list. Removing/muting a guest who is already gone is treated as success-equivalent (refresh).

## 8. Security & Privacy

- All endpoints require an authenticated session; calls ride the persistent cookie jar and echo `ui_csrf` as `X-CSRF-Token` (enforced by the shared `CsrfInterceptor`). Mutation calls without the header will be rejected by the backend — verified by test.
- Invite tokens are bearer-capable secrets: never log the raw `token`/`url` (redact to last 4 chars in logs); do not write them to crash reports; deep-link token is dropped from `SavedStateHandle` once accepted.
- Host-only actions (create invite, promote, mute, remove) are authorized server-side by broadcast ownership; the client also hides these controls unless the current user (`GET /ui/me`) owns the broadcast, but the server is the authority.
- Removal and revocation are destructive; remove requires explicit confirm (FR-6).
- Plaintext HTTP dev host: tokens transit unencrypted in dev only. `usesCleartextTraffic` stays restricted to the dev `network_security_config` host; production uses HTTPS. Document this constraint; do not ship cleartext in release builds.

## 9. Accessibility & i18n

- All strings in `feature-guest/src/main/res/values/strings.xml`; no hardcoded user-facing text. Status chips and role labels are localized; statuses are not conveyed by color alone (icon + text on each chip).
- Overflow menu items (Promote/Mute/Remove), invite copy/share buttons, and the accept/decline buttons have `contentDescription`s; touch targets >= 48dp.
- The invite token field is `Modifier.semantics { contentDescription = "Guest invite link" }` and supports a single "Copy" action rather than per-character TalkBack reading.
- Dynamic type: layouts use Material 3 typography and avoid fixed text sizes; verify at 200% font scale. RTL-safe (no hardcoded start/end paddings).
- Mute toggle announces its new state ("Guest muted" / "Guest unmuted") via an accessibility live region after a successful server response.

## 10. Telemetry & Logging

- Events via the shared analytics interface (`core-data`): `guest_invite_created`, `guest_invite_revoked`, `guest_invite_accepted`, `guest_promoted`, `guest_muted` (with `muted: Boolean`), `guest_removed`, `guest_left`. Each carries `broadcastId` and a hashed `guestId`; never the invite token.
- Failure events: `guest_action_failed` with `action`, `http_code`, and mapped `error_code` (not the message body).
- Logging via Timber: `INFO` for state transitions, `WARN` for reconciled conflicts (404/409/410), `ERROR` for unexpected mapping failures. Tokens/URLs redacted (§8). No PII (display names) in logs.

## 11. Testing Strategy

- **Unit (core-testing + JUnit/Turbine).**
  - `GuestRepositoryTest`: each method maps `Response` -> `ApiResult`; `detail` shapes (string/array/object) parse correctly; unknown enum -> default + logged; idempotent GET retries on 5xx, mutations do not retry.
  - `GuestManageViewModelTest`: optimistic mute applies then reconciles on success; rolls back on error and emits `error`; `inFlight` set/cleared; polling refresh updates state; `isStale` set when refresh fails with cached data present.
  - `GuestAcceptViewModelTest`: success -> `Joined`; expired (`410`) -> invalid-invite state.
- **Persistence.** `GuestDaoTest` (Room in-memory): upsert/observe by `broadcastId`, delete-on-remove, transactional reconcile.
- **API contract.** MockWebServer tests asserting paths/verbs, presence of `X-CSRF-Token` on every mutation, and JSON (de)serialization against captured sample bodies.
- **UI (Compose).** `GuestManageScreen`: overflow actions invoke ViewModel callbacks; remove shows confirm dialog; stale banner shows when `isStale`; in-flight rows disabled. `GuestAcceptScreen`: accept/decline and invalid-invite copy. Accessibility assertions for content descriptions and 48dp targets.
- **Coverage gate:** repository + ViewModel >= 80% line coverage.

## 12. Dependencies & Sequencing

- **Depends on AND-308 (WebRTC ingest).** AND-308 provides the multi-input broadcast/ingest session that consumes this ticket's membership/permission state (promote -> publish, remove -> drop track). Build the membership/state layer (§4-§6) independently and mockable; wire promote/remove into AND-308's session via a thin `GuestMediaBridge` interface so the two can integrate without a hard compile-time coupling:

```kotlin
interface GuestMediaBridge {            // implemented in AND-308's module
    suspend fun onGuestPromoted(broadcastId: String, guestId: String)
    suspend fun onGuestRemoved(broadcastId: String, guestId: String)
    suspend fun onGuestMuteChanged(broadcastId: String, guestId: String, muted: Boolean)
}
```

- Consumes from `core-network` (auth/cookie/CSRF stack), `core-model`, `core-ui` (dialog, chips, snackbar), `core-data` (analytics).
- Blocks: none recorded.
- Suggested order: (1) DTOs + `GuestApi` + repository + Room; (2) ViewModels + state; (3) Compose screens + deep link; (4) integrate `GuestMediaBridge` with AND-308.

## 13. Risks & Open Questions

- **OQ-1** Exact endpoint paths/verbs and `mute` semantics (toggle vs explicit `muted` field) must be confirmed against `/openapi.json` and `frontend/src/api/endpoints/*.ts`. Spec assumes explicit `{muted}` body.
- **OQ-2** Real-time updates: no WebSocket layer is specified for M7, so the host list uses polling. If a push channel lands, replace polling with it (Room source-of-truth keeps the swap localized).
- **OQ-3** Invite cardinality: spec assumes one active invite per broadcast. If multiple concurrent guests/invites are required, `guest_invites` becomes a list keyed by `inviteId` and the invite card becomes a list.
- **OQ-4** Promote -> "cohost" role vs publish-rights: confirm whether promote changes `role` or only `status` to `onair`. Spec maps promote to `status=onair`.
- **Risk** Unreliable dev backend makes polling-heavy UI flaky in manual QA; mitigated by stale state + bounded backoff and by testing against MockWebServer.
- **Risk** Plaintext token transit in dev (§8) — acceptable for dev only, must not regress into release.

## 14. Acceptance Criteria

- **AC-1 (FR-1/2)** Host can create an invite, see/copy/share the link, and revoke a pending invite; the invite card reflects `pending -> revoked`.
- **AC-2 (FR-7)** Opening a valid invite deep link shows the accept screen; accepting transitions the guest to `joined` and the host's list shows the new guest within one poll cycle (<= 5s). (Maps to ticket acceptance: "Guest join … work.")
- **AC-3 (FR-4)** Host promote moves a guest to `onair` and triggers `GuestMediaBridge.onGuestPromoted`.
- **AC-4 (FR-5)** Host mute sets server-enforced mute; UI chip + accessibility announcement reflect it; unmute reverses it.
- **AC-5 (FR-6)** Host remove, after confirm, ejects the guest (`removed`), frees the slot, and triggers `onGuestRemoved`. (Maps to ticket acceptance: "… manage work.")
- **AC-6 (FR-8)** A joined guest can leave; host list reflects the departure.
- **AC-7 (FR-9/§8)** Every mutation request carries `X-CSRF-Token`; verified by MockWebServer test.
- **AC-8 (§7)** With the backend unreachable, the host list shows cached guests with a stale/reconnecting banner; an attempted mutation shows an error without corrupting cached state; expired-invite accept shows the invalid-invite message.
- **AC-9 (§11)** All listed unit/DAO/contract/UI tests pass; repository + ViewModel coverage >= 80%.

## 15. Definition of Done

- Code merged to `android-port` under `feature-guest` (`com.testlogon.android.feature.guest`); module wired into `app` nav graph and deep-link intent filter registered.
- All acceptance criteria (§14) met and demoed against the dev backend (or MockWebServer where the backend is unreliable).
- DTO field names reconciled against `frontend/src/api/types.ts` and paths against `/openapi.json`; any deltas applied in the mapping layer only.
- No hardcoded user-facing strings; accessibility checks (§9) pass; no tokens/PII in logs (§8/§10).
- Tests (§11) green in CI; coverage gate met. Lint/detekt clean; no new cleartext traffic in release config.
- `GuestMediaBridge` integration with AND-308 verified, or stubbed behind the interface with a tracked follow-up if AND-308 is not yet merged.
