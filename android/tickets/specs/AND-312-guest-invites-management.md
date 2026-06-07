---
id: AND-312
title: Guest invites & management
milestone: M7
epic: E41
priority: P2
size: M
status: reviewed
reviewed_on: 2026-06-06
depends_on: [AND-308]
blocks: []
---

# AND-312 — Guest invites & management

## 1. Overview & Goal

This ticket delivers the host-side and guest-side flows for inviting people to co-broadcast on a live stream and managing them once they join. A "guest" is a remote participant the host pulls into the broadcast as a second ingest source (built on the WebRTC ingest pipeline from AND-308). The host can create an invite, send it, and once a guest accepts, the host manages that guest's lifecycle: **promote** (grant the guest publish/on-air rights), **mute** (force-mute the guest's audio without removing them), and **remove** (eject the guest from the broadcast). The guest side can **accept** an invite and the host (or guest) can **revoke**/leave.

Goal: ship a `feature-guest` module that exposes a host management panel and a guest accept screen, backed by a `GuestRepository` over the `/broadcast/sessions/{session_id}/guest-invites` and `/broadcast/sessions/{session_id}/guests/{input_id}/*` endpoints, with optimistic-but-reconciled UI state, full error handling against the unreliable dev backend, and cookie/CSRF-authenticated calls. The actual media transport (negotiating the guest's WebRTC `inputs` + `webrtc-offer`) is owned by AND-308; this ticket owns invite/membership/permission state and the management UI that drives it.

> **[REVIEW CORRECTION]** The original spec assumed a dedicated `/ui/broadcasts/{broadcastId}/guests` resource tree. The backend has **no such resource**. Guests are modeled as broadcast **inputs** (`input_type == "guest"`) under `/broadcast/sessions/{session_id}`. The identifier throughout is `session_id` (not `broadcastId`) and the per-guest handle is `input_id` (not a separate `guestId`). The "guest list" is the union of `GET .../guest-invites` (pending/accepted invites) and `GET .../inputs` filtered to `input_type == "guest"`. See §5 and §16 for the verified contract.

## 2. Context & References

- Repo: `spannella/testlogon`, Android app under `android/`, branch `android-port`.
- Namespace / applicationId base: `com.testlogon.android`. This feature: `com.testlogon.android.feature.guest`.
- Module layering: `app -> feature-guest -> core-network, core-model, core-ui, core-data, core-testing`.
- Stack: Kotlin 2.0.21, Compose + Material 3, Navigation-Compose, Hilt (KSP), Coroutines/Flow, Retrofit 2.11 / OkHttp 4.12 / Moshi 1.15, Room 2.6, DataStore, Paging 3. minSdk 24, compileSdk/targetSdk 35, JDK 17, AGP 8.7.3, Gradle 8.9.
- Auth: cookie-based session + `ui_csrf` cookie echoed as `X-CSRF-Token`; persistent cookie jar; on `401`, `POST /ui/session/refresh` once then retry. Provided by `core-network` (the shared `OkHttpClient`, `CookieJar`, `CsrfInterceptor`, and `AuthAuthenticator`). This ticket consumes those, it does not re-implement them.
- Backend: FastAPI + DynamoDB; dev host `http://18.222.237.167:8000` (plaintext HTTP, unreliable). OpenAPI at `/openapi.json`. FastAPI error `detail` shapes: `string | [{msg}] | {code,...}`.
- Web reference: guest endpoints live in `src/api/endpoints/broadcast-inputs.ts` (NOT a `guests.ts`; the original spec's `frontend/src/api/endpoints/*.ts` pointer was vague) and shared types in `src/api/types.ts` (`BroadcastGuestInvite`, `BroadcastGuestInviteList`, `BroadcastGuestAcceptResult`, `BroadcastInput`). Reconcile the Moshi DTOs in §5 against `types.ts` during implementation; if a field name differs, the web type is authoritative and the DTO `@Json(name=...)` must be updated. **The DTOs in §5 were corrected during this review against `types.ts` and the OpenAPI schemas.**
- **Depends on AND-308 (WebRTC ingest):** the broadcast must support multiple ingest inputs before a guest's media can be carried. AND-312 produces the membership/permission state that AND-308's session consumes to add/remove a guest's media track.

## 3. Functional Requirements

Host (broadcast owner) flows:

- **FR-1 Create invite.** Host taps "Invite guest" in the live broadcast controls and creates an invite. The app returns a shareable invite URL / code and shows it (copy + system share sheet). An invite has a status (`pending`, `accepted`, `revoked`, `expired`).
- **FR-2 Revoke invite.** Host can revoke a still-`pending` invite; the slot is freed.
- **FR-3 Guest list.** Host sees a live list of guests for the broadcast. **[REVIEW CORRECTION]** There is no single "guests" endpoint returning a typed status/role per guest. The list is derived client-side by merging: (a) `GET .../guest-invites` (`BroadcastGuestInviteOut[]` with `status` in `pending|accepted|expired|revoked`) and (b) `GET .../inputs` filtered to `input_type == "guest"` (`BroadcastInput[]` with `is_live`, `connected_at`, `disconnected_at`). The display `status` and any mute/on-air state must be **derived** from these fields (e.g. `is_live==true` → on-air); the wire has no `role` or `muted_audio` field. See §5/§6 for the derivation.
- **FR-4 Promote.** Host promotes a `joined` guest to `onair` (publish rights). This is what makes the guest's WebRTC track go live via AND-308.
- **FR-5 Mute.** Host mutes/unmutes an on-air guest. Mute is a server-enforced state, not just a local UI toggle.
- **FR-6 Remove.** Host removes a guest; the guest is ejected and the slot freed. Removal is destructive and requires a confirm dialog.

Guest flows:

- **FR-7 Accept invite.** A guest opening an invite deep link lands on an accept screen showing the broadcast title/host; accepting transitions the guest to a live input and hands off to the AND-308 join flow. **[REVIEW CORRECTION]** Accept is `POST /broadcast/sessions/{session_id}/guest-invites/{invite_id}/accept` and requires a **`{ "display_name": "..." }`** body (1–100 chars, required) — it does **not** take a `token`. The accept response (`BroadcastGuestAcceptOut`) returns `invite_id`, `input_id`, `join_mode`, `session_id`, and `ingest_url` — the `input_id`/`ingest_url` are what AND-308 needs to start media. The deep link must therefore carry **both `session_id` and `invite_id`** (the original `?token=...` design does not map to any endpoint param). The accept screen must collect a display name.
- **FR-8 Leave.** A joined guest can leave. **[REVIEW CORRECTION — UNSUPPORTED]** The backend exposes **no guest "leave"/self-revoke endpoint** (`/broadcast/sessions/{session_id}/viewers/leave` exists but is for *viewers*, not co-broadcast guests). The only departure paths are host-initiated `revoke` (pending invite) and host-initiated `remove` (`.../guests/{input_id}/remove`). Until a backend leave endpoint exists, FR-8 cannot be implemented as specified; treat it as out of scope / blocked, or model "leave" as the guest dropping their WebRTC input (AND-308) which the host then `remove`s. See §16 Open assumptions.

Cross-cutting:

- **FR-9** All mutations (accept/revoke/promote/mute/remove) are state-changing calls that carry `X-CSRF-Token`. They are **not** retried automatically (non-idempotent). **[REVIEW CORRECTION]** All five are **`POST`** (the backend uses `POST .../revoke` and `POST .../guests/{input_id}/remove`, not `DELETE`). The only guest-related `DELETE` is `DELETE .../inputs/{input_id}` (owned by AND-308's input lifecycle), which is not used by this feature's mutation set.
- **FR-10** The guest list reflects server truth: a host action is optimistically applied, then reconciled against the server response; on failure the optimistic change is rolled back and an error is surfaced.

## 4. Technical Design

Module `feature-guest`. Single-Activity Navigation-Compose; this feature registers a nav graph `guestGraph`.

```kotlin
// Navigation
// [REVIEW CORRECTION] Routes key on sessionId (the backend session_id), and the
// accept deep link carries BOTH sessionId and inviteId (there is no opaque `token`
// param on the accept endpoint). The guest also supplies a display_name on accept.
object GuestRoutes {
    const val MANAGE = "broadcast/{sessionId}/guests"                       // host panel
    const val ACCEPT = "guest/accept?sessionId={sessionId}&inviteId={inviteId}" // guest accept (deep link)
    fun manage(sessionId: String) = "broadcast/$sessionId/guests"
    fun accept(sessionId: String, inviteId: String) =
        "guest/accept?sessionId=$sessionId&inviteId=$inviteId"
}

fun NavGraphBuilder.guestGraph(navController: NavController)
```

Domain models (in `core-model`):

```kotlin
// [REVIEW CORRECTION] These are CLIENT-SIDE domain models. Several fields are
// DERIVED, not wire fields: GuestStatus/mutedAudio/role have no direct backend
// representation (see §3 FR-3 and §5). The wire identifies a guest by `input_id`.
enum class GuestStatus { INVITED, JOINED, ONAIR, MUTED, LEFT, REMOVED } // derived from invite.status + input.is_live/connected_at
enum class GuestRole   { GUEST, COHOST }                                // DERIVED ONLY — no wire `role`; default GUEST
enum class InviteStatus { PENDING, ACCEPTED, REVOKED, EXPIRED }          // wire `status` strings (note: "pending", not "invited")

data class Guest(
    val inputId: String,            // wire: input_id (was `id`); guest's input handle
    val inviteId: String?,          // wire: invite_id from the invite, if known
    val sessionId: String,          // wire: session_id (was `broadcastId`)
    val displayName: String,        // wire: guest_display_name (nullable on wire; fall back to label/join_mode)
    val avatarUrl: String?,         // [UNVERIFIED] no avatar field on the wire; keep null until a source confirms one
    val status: GuestStatus,        // DERIVED (see above)
    val role: GuestRole,            // DERIVED — always GUEST for now
    val mutedAudio: Boolean,        // client-tracked from the last mute POST; no wire field echoes it back
    val connectedAt: Instant?,      // wire: connected_at (epoch seconds, nullable) — was mislabeled `joinedAt`
)

data class GuestInvite(
    val inviteId: String,           // wire: invite_id (was `id`)
    val sessionId: String,          // wire: session_id
    val inputId: String,            // wire: input_id (pre-allocated per invite)
    val url: String?,               // wire: invite_url (nullable)
    val ingestUrl: String?,         // wire: ingest_url (nullable)
    val streamKey: String?,         // wire: stream_key (nullable; SECRET — redact, see §8)
    val joinMode: String,           // wire: join_mode ("rtmp" | "browser")
    val status: InviteStatus,       // wire status: pending|accepted|expired|revoked
    val expiresAt: Instant?,        // wire: expires_at (epoch seconds integer, NOT ISO string)
    val createdAt: String,          // wire: created_at (ISO-8601 string)
)
// NOTE: there is no opaque `token` field on the wire. The "invite token" the
// original spec referenced does not exist; identity is (session_id, invite_id).
```

Repository (in `feature-guest`, interface in `core-data` if shared):

```kotlin
// [REVIEW CORRECTION] sessionId replaces broadcastId; per-guest ops key on inputId.
// refreshGuests must fan out to BOTH guest-invites and inputs and merge (§3 FR-3).
// promote/mute/remove return Unit (the wire returns { "ok": true } / 200 empty),
// NOT a GuestDto — the original ApiResult<Guest> returns were wrong.
interface GuestRepository {
    fun observeGuests(sessionId: String): Flow<List<Guest>>      // Room-backed, refreshed on poll/action
    suspend fun refreshGuests(sessionId: String): ApiResult<List<Guest>> // merges GET guest-invites + GET inputs
    suspend fun createInvite(
        sessionId: String,
        joinMode: String = "browser",       // "rtmp" | "browser"
        label: String = "Guest",
        expiryMinutes: Int = 60,            // 5..1440
    ): ApiResult<GuestInvite>
    suspend fun revokeInvite(sessionId: String, inviteId: String): ApiResult<Unit>
    suspend fun acceptInvite(
        sessionId: String, inviteId: String, displayName: String,  // display_name required, 1..100
    ): ApiResult<GuestAcceptResult>          // returns input_id/ingest_url for AND-308 handoff
    suspend fun promote(sessionId: String, inputId: String): ApiResult<Unit>
    suspend fun setMuted(sessionId: String, inputId: String, muted: Boolean): ApiResult<Unit>
    suspend fun remove(sessionId: String, inputId: String): ApiResult<Unit>
    // NOTE: no `leave(...)` — backend exposes no guest leave endpoint (§3 FR-8).
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

Deep link: register an intent filter on the single Activity for `testlogon://guest/accept` and route it to `GuestRoutes.ACCEPT`. **[REVIEW CORRECTION]** Parse `sessionId` and `inviteId` from the link (NOT a `token`), since accept is addressed by `(session_id, invite_id)`. The web `invite_url` is a site-relative path (the web client prefixes `window.location.origin`); the Android deep link contract must be agreed with backend/web (mobile `invite_url` shape is an open assumption, §16).

## 5. API Contract

**[REVIEW CORRECTION — this section was substantially wrong and has been rewritten against the OpenAPI index/spec and `src/api/endpoints/broadcast-inputs.ts`.]** Base path `/broadcast/sessions/{session_id}`. All calls go through the shared authenticated Retrofit instance (cookie jar + `X-CSRF-Token`). Verified path/verb/status for each operation:

| Op | Verb + path | Req body | Success | Resp schema |
|---|---|---|---|---|
| list invites | `GET /broadcast/sessions/{session_id}/guest-invites` | — | 200 | `BroadcastGuestInviteListOut` |
| list inputs (guests) | `GET /broadcast/sessions/{session_id}/inputs` | — | 200 | `BroadcastInputListOut` (filter `input_type=="guest"`) |
| create invite | `POST /broadcast/sessions/{session_id}/guest-invites` | `BroadcastGuestInviteCreateIn` | **201** | `BroadcastGuestInviteOut` |
| accept invite | `POST /broadcast/sessions/{session_id}/guest-invites/{invite_id}/accept` | `BroadcastGuestAcceptIn` (`display_name` required) | 200 | `BroadcastGuestAcceptOut` |
| revoke invite | `POST /broadcast/sessions/{session_id}/guest-invites/{invite_id}/revoke` | — | 200 | `{ ok }` / empty |
| promote guest | `POST /broadcast/sessions/{session_id}/guests/{input_id}/promote` | — | 200 | `{ ok }` / empty |
| mute guest | `POST /broadcast/sessions/{session_id}/guests/{input_id}/mute` | `BroadcastGuestMuteIn` (`muted`, default true) | 200 | `{ ok }` / empty |
| remove guest | `POST /broadcast/sessions/{session_id}/guests/{input_id}/remove` | — | 200 | `{ ok }` / empty |

Note: revoke/promote/mute/remove are all **POST** (not DELETE), and only define `200` + `422 HTTPValidationError` in the OpenAPI; the 404/409/410 handling in §7 is a defensive client assumption (FastAPI may surface those as `4xx` with a `detail` body but they are not in the documented response set — flagged in §16).

```kotlin
interface GuestApi {
    @GET("broadcast/sessions/{sessionId}/guest-invites")
    suspend fun listInvites(@Path("sessionId") sessionId: String): Response<GuestInviteListDto>

    @GET("broadcast/sessions/{sessionId}/inputs")
    suspend fun listInputs(@Path("sessionId") sessionId: String): Response<BroadcastInputListDto>

    @POST("broadcast/sessions/{sessionId}/guest-invites")
    suspend fun createInvite(@Path("sessionId") sessionId: String,
                             @Body body: CreateInviteRequest): Response<GuestInviteDto>   // 201

    @POST("broadcast/sessions/{sessionId}/guest-invites/{inviteId}/accept")
    suspend fun acceptInvite(@Path("sessionId") sessionId: String,
                             @Path("inviteId") inviteId: String,
                             @Body body: AcceptInviteRequest): Response<GuestAcceptDto>

    @POST("broadcast/sessions/{sessionId}/guest-invites/{inviteId}/revoke")
    suspend fun revokeInvite(@Path("sessionId") sessionId: String,
                             @Path("inviteId") inviteId: String): Response<Unit>

    @POST("broadcast/sessions/{sessionId}/guests/{inputId}/promote")
    suspend fun promote(@Path("sessionId") sessionId: String,
                        @Path("inputId") inputId: String): Response<Unit>

    @POST("broadcast/sessions/{sessionId}/guests/{inputId}/mute")
    suspend fun setMuted(@Path("sessionId") sessionId: String,
                         @Path("inputId") inputId: String,
                         @Body body: MuteRequest): Response<Unit>

    @POST("broadcast/sessions/{sessionId}/guests/{inputId}/remove")
    suspend fun remove(@Path("sessionId") sessionId: String,
                       @Path("inputId") inputId: String): Response<Unit>

    // NOTE: no leave() endpoint exists (§3 FR-8 / §16).
}
```

DTOs (Moshi). **[REVIEW CORRECTION]** Rewritten to match `BroadcastGuestInviteOut`, `BroadcastGuestInviteListOut`, `BroadcastGuestAcceptOut`, `BroadcastGuestAcceptIn`, `BroadcastGuestInviteCreateIn`, `BroadcastGuestMuteIn`, and `BroadcastInput` exactly. Key fixes: `id`→`invite_id`/`input_id`; there is **no `token`** field; `url`→`invite_url`; `expires_at` is an **integer epoch**, not an ISO string; `created_at` is a string; there is **no `guests` list response** (use invites + inputs); guests have **no `role`/`muted_audio`/`avatar_url`** fields.

```kotlin
@JsonClass(generateAdapter = true)
data class GuestInviteListDto(
    @Json(name = "session_id") val sessionId: String,
    @Json(name = "invites") val invites: List<GuestInviteDto> = emptyList(),
    @Json(name = "count") val count: Int = 0,
)

@JsonClass(generateAdapter = true)
data class GuestInviteDto(
    @Json(name = "invite_id") val inviteId: String,
    @Json(name = "session_id") val sessionId: String,
    @Json(name = "input_id") val inputId: String,
    @Json(name = "join_mode") val joinMode: String,             // rtmp | browser
    @Json(name = "status") val status: String,                  // pending|accepted|expired|revoked
    @Json(name = "expires_at") val expiresAt: Long,             // epoch seconds (INTEGER, required)
    @Json(name = "created_at") val createdAt: String,           // ISO-8601 string (required)
    @Json(name = "accepted_at") val acceptedAt: Long? = null,   // epoch seconds, nullable
    @Json(name = "invite_url") val inviteUrl: String? = null,
    @Json(name = "ingest_url") val ingestUrl: String? = null,
    @Json(name = "stream_key") val streamKey: String? = null,   // SECRET — redact (§8)
    @Json(name = "guest_user_id") val guestUserId: String? = null,
    @Json(name = "guest_display_name") val guestDisplayName: String? = null,
)

// Guests are inputs with input_type == "guest".
@JsonClass(generateAdapter = true)
data class BroadcastInputListDto(
    @Json(name = "session_id") val sessionId: String,
    @Json(name = "inputs") val inputs: List<BroadcastInputDto> = emptyList(),
    @Json(name = "count") val count: Int = 0,
    @Json(name = "max_inputs") val maxInputs: Int = 0,
)

@JsonClass(generateAdapter = true)
data class BroadcastInputDto(
    @Json(name = "input_id") val inputId: String,
    @Json(name = "session_id") val sessionId: String,
    @Json(name = "input_type") val inputType: String,           // primary | guest | screen
    @Json(name = "label") val label: String,
    @Json(name = "is_live") val isLive: Boolean = false,
    @Json(name = "connected_at") val connectedAt: Long? = null, // epoch seconds
    @Json(name = "disconnected_at") val disconnectedAt: Long? = null,
    @Json(name = "position") val position: Int = 0,
    @Json(name = "ingest_url") val ingestUrl: String? = null,
    @Json(name = "created_at") val createdAt: String? = null,
)

@JsonClass(generateAdapter = true)
data class GuestAcceptDto(                                       // BroadcastGuestAcceptOut
    @Json(name = "invite_id") val inviteId: String,
    @Json(name = "input_id") val inputId: String,
    @Json(name = "join_mode") val joinMode: String,
    @Json(name = "session_id") val sessionId: String,
    @Json(name = "ingest_url") val ingestUrl: String? = null,
)

@JsonClass(generateAdapter = true)
data class CreateInviteRequest(                                  // BroadcastGuestInviteCreateIn
    @Json(name = "join_mode") val joinMode: String = "browser", // ^(rtmp|browser)$
    @Json(name = "label") val label: String = "Guest",          // maxLen 100
    @Json(name = "expiry_minutes") val expiryMinutes: Int = 60, // 5..1440
)

@JsonClass(generateAdapter = true)
data class AcceptInviteRequest(                                  // BroadcastGuestAcceptIn
    @Json(name = "display_name") val displayName: String,       // required, 1..100
)

@JsonClass(generateAdapter = true)
data class MuteRequest(@Json(name = "muted") val muted: Boolean) // BroadcastGuestMuteIn (default true)
```

Example `POST /broadcast/sessions/{session_id}/guest-invites` response (**201**, `BroadcastGuestInviteOut`):

```json
{ "invite_id": "inv_a1b2", "session_id": "sess_xyz", "input_id": "in_77",
  "join_mode": "browser", "status": "pending",
  "invite_url": "/g/8f3", "ingest_url": null, "stream_key": null,
  "guest_user_id": null, "guest_display_name": null,
  "expires_at": 1749160800, "accepted_at": null, "created_at": "2026-06-05T21:00:00Z" }
```

Example `GET .../guest-invites` response (`BroadcastGuestInviteListOut`):

```json
{ "session_id": "sess_xyz", "count": 1,
  "invites": [ { "invite_id": "inv_a1b2", "session_id": "sess_xyz", "input_id": "in_77",
    "join_mode": "browser", "status": "accepted", "guest_display_name": "Avery",
    "expires_at": 1749160800, "accepted_at": 1749160203, "created_at": "2026-06-05T21:00:00Z" } ] }
```

Example accept response (`BroadcastGuestAcceptOut`):

```json
{ "invite_id": "inv_a1b2", "input_id": "in_77", "join_mode": "browser",
  "session_id": "sess_xyz", "ingest_url": "rtmp://.../in_77" }
```

Unknown enum strings map to a defensive default (`GuestStatus.JOINED` / `InviteStatus.PENDING`) and are logged, never thrown. Note the invite `status` set is `pending|accepted|expired|revoked` (the model's `INVITED` is not a wire value; map `pending` → invited-equivalent in the UI). Exact endpoint paths/verbs were verified against the OpenAPI index during this review (§16); the mapping layer is the only place that changes if they drift.

## 6. Data & State Management

- **Room (cache).** **[REVIEW CORRECTION]** `guests` table keyed by `(sessionId, inputId)`; `guest_invites` keyed by `(sessionId, inviteId)` — the backend supports **multiple** invites per session (`BroadcastGuestInviteListOut.invites[]` / `count`), so the original "one active invite per broadcast" assumption is dropped (see also OQ-3). `GuestDao` exposes `Flow<List<GuestEntity>>` filtered by `sessionId`. Repository writes server results into Room inside a transaction; UI observes Room only.
- **Mapping.** `GuestInviteDto + BroadcastInputDto -> GuestEntity/GuestInviteEntity -> Guest/GuestInvite`. **Timestamps:** `expires_at`/`accepted_at`/`connected_at`/`disconnected_at` are **epoch seconds (Long)** → `Instant.ofEpochSecond(..)`; `created_at` is an ISO-8601 string → parse to `Instant`; null/invalid → `null`. (The original "ISO timestamps" claim was wrong for the epoch fields.)
- **Merge/derivation.** `refreshGuests` fans out to `GET .../guest-invites` and `GET .../inputs`, filters inputs to `input_type == "guest"`, and joins on `input_id`. Display `status` is derived: invite `revoked/expired` → that; input `is_live == true` → ON-AIR; `connected_at != null && disconnected_at == null` → JOINED; invite `accepted` w/o live input → JOINED; otherwise INVITED. `mutedAudio` is client-tracked from the last successful mute POST (no wire echo).
- **Optimistic mutations.** On `onToggleMute`/`onPromote`/`onRemove`, the ViewModel adds the `inputId` to `inFlight`, applies the predicted change to the emitted state, then calls the repo. On `ApiResult.Success` (the wire returns `{ ok }` / empty, **not** an updated guest object) it triggers an immediate `refreshGuests` to reconcile against server truth, then clears `inFlight`. On any error it clears `inFlight`, re-emits from Room (rollback), and sets `error`.
- **DataStore (prefs).** No durable prefs needed; an in-memory pending-invite token from a deep link is held in `SavedStateHandle`, not persisted.
- **Lifecycle.** Polling job is tied to `viewModelScope` + screen lifecycle; cancelled on stop to respect the unreliable backend and battery.
- **No Paging.** Guest lists are small (single-digit to low-tens); `Paging 3` is not used here.

## 7. Error Handling & Resilience

- **Timeouts/backoff.** OkHttp call timeout ~20s (from `core-network`). The only retryable calls here are the idempotent `GET .../guest-invites` and `GET .../inputs` (the two reads `refreshGuests` fans out to), which use bounded exponential backoff (2 retries, ~1s/2s, jittered) for transient `IOException`/`5xx`. All mutations (§FR-9) are non-idempotent and are **never** auto-retried; the user retries explicitly.
- **401 handling.** Handled centrally by `core-network`'s `AuthAuthenticator` (`POST /ui/session/refresh` once, then retry). **VERIFIED** against `src/api/client.ts` (`refreshSession()` → `POST /ui/session/refresh`, single-flight, retry-once, logout on failure). If refresh fails, the call surfaces as `ApiResult.Error(httpCode=401)` and the feature navigates to re-auth (owned by the auth feature).
- **FastAPI `detail` mapping.** A shared `parseDetail(body): String` handles the three shapes: plain `string`; validation array `[{msg}]` (join `msg`s); structured `{code, message}` (prefer `message`). **VERIFIED** against `src/api/client.ts: normalizeErrorDetail` (handles string, array-of-`{msg}`, and object-with-`code`/`msg`). The documented `422` responses use `HTTPValidationError` (the array-of-`{msg}` shape). Surface to UI as `UiText`.
- **Offline / stale.** When `refreshGuests` fails but Room has data, set `isStale=true` and keep showing the cached list with a "Reconnecting…" banner; do not clear the list. Mutations attempted while offline return `ApiResult.Offline` and show a transient snackbar without mutating Room.
- **Conflict cases.** **[REVIEW NOTE]** The OpenAPI only documents `200`/`201` and `422` for these endpoints; `404/409/410` are **not** in the documented response set. Treat them as defensive client handling, not a verified contract (§16 open assumption). Behavior if they occur: `409`/`410`/`422`-with-expired on accept (`expired`/`revoked` invite) -> dedicated copy on the accept screen ("This invite is no longer valid"); also detect an `accepted`/`revoked`/`expired` invite `status` proactively before accepting. `404` on a guest mutation (guest already gone) -> silently refresh the list. Removing/muting a guest who is already gone is treated as success-equivalent (refresh).

## 8. Security & Privacy

- All endpoints require an authenticated session; calls ride the persistent cookie jar and echo `ui_csrf` as `X-CSRF-Token` (enforced by the shared `CsrfInterceptor`). **VERIFIED** against `src/api/client.ts` (reads `ui_csrf` cookie, sets `X-CSRF-Token`, `credentials: include`). Mutation calls without the header are expected to be rejected by the backend — assert by test. (Note: the web client additionally sends `Authorization: Bearer` and may send `X-IMPERSONATION-TOKEN`; the Android stack relies on the cookie session — confirm with `core-network` from AND-308's auth work, §16.)
- **[REVIEW CORRECTION]** Invite secrets are the **`stream_key`** and **`invite_url`/`ingest_url`** (there is no opaque `token` field). Never log these (redact to last 4 chars); do not write them to crash reports; the deep-link `inviteId`/`sessionId` are dropped from `SavedStateHandle` once accepted. `stream_key` in particular is RTMP-publish-capable and must never be logged or surfaced beyond the create/copy UI.
- Host-only actions (create invite, promote, mute, remove) are authorized server-side by session ownership; the client also hides these controls unless the current user (`GET /ui/me`, verified to exist) owns the broadcast session, but the server is the authority.
- Removal and revocation are destructive; remove requires explicit confirm (FR-6).
- Plaintext HTTP dev host: tokens transit unencrypted in dev only. `usesCleartextTraffic` stays restricted to the dev `network_security_config` host; production uses HTTPS. Document this constraint; do not ship cleartext in release builds.

## 9. Accessibility & i18n

- All strings in `feature-guest/src/main/res/values/strings.xml`; no hardcoded user-facing text. Status chips and role labels are localized; statuses are not conveyed by color alone (icon + text on each chip).
- Overflow menu items (Promote/Mute/Remove), invite copy/share buttons, and the accept/decline buttons have `contentDescription`s; touch targets >= 48dp.
- The invite token field is `Modifier.semantics { contentDescription = "Guest invite link" }` and supports a single "Copy" action rather than per-character TalkBack reading.
- Dynamic type: layouts use Material 3 typography and avoid fixed text sizes; verify at 200% font scale. RTL-safe (no hardcoded start/end paddings).
- Mute toggle announces its new state ("Guest muted" / "Guest unmuted") via an accessibility live region after a successful server response.

## 10. Telemetry & Logging

- Events via the shared analytics interface (`core-data`): `guest_invite_created`, `guest_invite_revoked`, `guest_invite_accepted`, `guest_promoted`, `guest_muted` (with `muted: Boolean`), `guest_removed`. (`guest_left` is dropped — no leave endpoint, §3 FR-8.) Each carries `session_id` and a hashed `input_id`/`invite_id`; never the `stream_key`, `invite_url`, or `ingest_url`.
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

- **OQ-1 [RESOLVED in review]** Paths/verbs verified against the OpenAPI index and `src/api/endpoints/broadcast-inputs.ts` (§5/§16). `mute` semantics confirmed: explicit `{ "muted": boolean }` body (`BroadcastGuestMuteIn`, default `true`) — the spec's assumption was correct.
- **OQ-2** Real-time updates: no WebSocket layer is specified for M7, so the host list uses polling. The web reference also polls (`refetchInterval: 5000` in `GuestInviteDialog.tsx`), corroborating the 5s cadence. If a push channel lands, replace polling with it (Room source-of-truth keeps the swap localized).
- **OQ-3 [RESOLVED in review — multiple]** The backend returns a **list** of invites (`BroadcastGuestInviteListOut.invites[]` + `count`); multiple concurrent invites/guests are supported. `guest_invites` is keyed by `(sessionId, inviteId)` and the invite UI is a list (§6).
- **OQ-4 [RESOLVED in review]** There is **no wire `role` field** and promote returns `{ ok }` (no body). Promote changes server-side publish state only; the client derives ON-AIR from the input's `is_live`. The `GuestRole.COHOST` value is client-cosmetic, not backend-driven.
- **Risk** Unreliable dev backend makes polling-heavy UI flaky in manual QA; mitigated by stale state + bounded backoff and by testing against MockWebServer.
- **Risk** Plaintext token transit in dev (§8) — acceptable for dev only, must not regress into release.

## 14. Acceptance Criteria

- **AC-1 (FR-1/2)** Host can create an invite, see/copy/share the link, and revoke a pending invite; the invite card reflects `pending -> revoked`.
- **AC-2 (FR-7)** Opening a valid invite deep link shows the accept screen; accepting transitions the guest to `joined` and the host's list shows the new guest within one poll cycle (<= 5s). (Maps to ticket acceptance: "Guest join … work.")
- **AC-3 (FR-4)** Host promote moves a guest to `onair` and triggers `GuestMediaBridge.onGuestPromoted`.
- **AC-4 (FR-5)** Host mute sets server-enforced mute; UI chip + accessibility announcement reflect it; unmute reverses it.
- **AC-5 (FR-6)** Host remove, after confirm, ejects the guest (`removed`), frees the slot, and triggers `onGuestRemoved`. (Maps to ticket acceptance: "… manage work.")
- **AC-6 (FR-8)** A joined guest can leave; host list reflects the departure. **[REVIEW NOTE]** No backend guest-leave endpoint exists (§3 FR-8 / §16); this AC is **blocked/out-of-scope** until backend support lands. The host-side equivalent (host `remove` removes a guest and the list reflects it) is covered by AC-5. Re-scope AC-6 to "host sees a guest depart when the guest's input disconnects" (derived from `disconnected_at`/`is_live`) if a true self-leave is not delivered this milestone.
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

## 16. Citations & Assumption Audit

Each key technical claim with VERDICT and exact SOURCE pointer. OpenAPI pointers are `METHOD /path` from `reference/openapi.index.txt` and schema names from `reference/openapi.pretty.json` (`components.schemas.<Name>`). Frontend pointers are paths under `reference/src/`.

1. **Create invite** is `POST /broadcast/sessions/{session_id}/guest-invites`, returns **201** `BroadcastGuestInviteOut`, body `BroadcastGuestInviteCreateIn` (`join_mode` `^(rtmp|browser)$` default `browser`, `label` ≤100 default `Guest`, `expiry_minutes` 5–1440 default 60). VERDICT: **Corrected** (spec had `POST .../guests/invites`, no body, implied 200). SOURCE: OpenAPI `POST /broadcast/sessions/{session_id}/guest-invites`; schema `BroadcastGuestInviteCreateIn` / `BroadcastGuestInviteOut`; `src/api/endpoints/broadcast-inputs.ts: createGuestInvite`.
2. **List invites** is `GET /broadcast/sessions/{session_id}/guest-invites` → `BroadcastGuestInviteListOut` (`session_id`, `invites[]`, `count`). VERDICT: **Corrected** (spec had `GET .../guests` returning a `{guests, invite}` object). SOURCE: OpenAPI `GET /broadcast/sessions/{session_id}/guest-invites`; schema `BroadcastGuestInviteListOut`; `src/api/endpoints/broadcast-inputs.ts: listGuestInvites`; `src/api/types.ts: BroadcastGuestInviteList`.
3. **Guests are inputs** (`input_type == "guest"`), listed via `GET /broadcast/sessions/{session_id}/inputs` → `BroadcastInputListOut`; no dedicated typed "guest" object with status/role/muted exists. VERDICT: **Corrected** (spec invented a guest list with `status/role/muted_audio/joined_at`). SOURCE: OpenAPI `GET /broadcast/sessions/{session_id}/inputs`; `src/api/types.ts: BroadcastInput` (`input_type: "primary"|"guest"|"screen"`, `is_live`, `connected_at`, `disconnected_at`).
4. **Accept invite** is `POST /broadcast/sessions/{session_id}/guest-invites/{invite_id}/accept`, body `BroadcastGuestAcceptIn` = `{ display_name }` (required, 1–100), response `BroadcastGuestAcceptOut` (`invite_id`, `input_id`, `join_mode`, `session_id`, `ingest_url?`). VERDICT: **Corrected** (spec had `POST /ui/guests/accept` with `{token}` → `GuestDto`). SOURCE: OpenAPI `POST .../guest-invites/{invite_id}/accept`; schemas `BroadcastGuestAcceptIn` / `BroadcastGuestAcceptOut`; `src/api/endpoints/broadcast-inputs.ts: acceptGuestInvite`; `src/api/types.ts: BroadcastGuestAcceptResult`.
5. **Revoke invite** is `POST /broadcast/sessions/{session_id}/guest-invites/{invite_id}/revoke` (no body, 200). VERDICT: **Corrected** (spec had `DELETE .../guests/invites/{inviteId}`). SOURCE: OpenAPI `POST .../guest-invites/{invite_id}/revoke`; `src/api/endpoints/broadcast-inputs.ts: revokeGuestInvite`.
6. **Promote** is `POST /broadcast/sessions/{session_id}/guests/{input_id}/promote` (no body, 200, returns `{ ok }`). VERDICT: **Corrected** (spec keyed on `{guestId}` and returned `GuestDto`). SOURCE: OpenAPI `POST .../guests/{input_id}/promote`; `src/api/endpoints/broadcast-inputs.ts: promoteGuest`.
7. **Mute** is `POST /broadcast/sessions/{session_id}/guests/{input_id}/mute`, body `BroadcastGuestMuteIn` = `{ muted }` (default `true`), 200. VERDICT: **Verified** for body shape (explicit `{muted}`), **Corrected** for path param (`input_id` not `guestId`) and return type (`{ ok }` not `GuestDto`). SOURCE: OpenAPI `POST .../guests/{input_id}/mute`; schema `BroadcastGuestMuteIn`; `src/api/endpoints/broadcast-inputs.ts: muteGuest`.
8. **Remove** is `POST /broadcast/sessions/{session_id}/guests/{input_id}/remove` (no body, 200, returns `{ ok }`). VERDICT: **Corrected** (spec had `DELETE .../guests/{guestId}`). SOURCE: OpenAPI `POST .../guests/{input_id}/remove`; `src/api/endpoints/broadcast-inputs.ts: removeGuest`.
9. **No guest leave endpoint.** VERDICT: **Corrected** (spec's FR-8/`leave()` `POST .../guests/leave` does not exist; only `POST /broadcast/sessions/{session_id}/viewers/leave` for *viewers*). SOURCE: OpenAPI index grep for `/leave` — no guest leave route; `viewer_leave_route` is viewer-scoped.
10. **Invite identifier is `invite_id`/`input_id`; session is `session_id`; there is no `token`.** VERDICT: **Corrected**. SOURCE: schema `BroadcastGuestInviteOut` (`invite_id`, `session_id`, `input_id`, no `token`); `src/api/types.ts: BroadcastGuestInvite`.
11. **Invite fields:** `invite_url` (nullable), `ingest_url` (nullable), `stream_key` (nullable, secret), `join_mode`, `status` (`pending|accepted|expired|revoked`), `expires_at` (**integer epoch**), `created_at` (**ISO string**), `accepted_at` (nullable epoch), `guest_display_name`/`guest_user_id` (nullable). VERDICT: **Corrected** (spec had `url`, `token`, ISO `expires_at`, and `status` value `revoked` set without `accepted`/`expired`). SOURCE: schema `BroadcastGuestInviteOut`; `src/api/types.ts: BroadcastGuestInvite`.
12. **Auth/transport: cookie session + `ui_csrf` cookie echoed as `X-CSRF-Token`, `credentials: include`.** VERDICT: **Verified**. SOURCE: `src/api/client.ts` (`getCookie("ui_csrf")` → `headers.set("X-CSRF-Token", csrf)`; `credentials: "include"`).
13. **401 handling: single-flight `POST /ui/session/refresh`, retry once, logout on failure.** VERDICT: **Verified**. SOURCE: `src/api/client.ts: refreshSession` / `api` 401 branch; OpenAPI `POST /ui/me`-adjacent session routes — `/ui/session/refresh` is the documented refresh path used by the client.
14. **FastAPI `detail` shapes: string | array-of-`{msg}` | object-with-`code`/`msg`.** VERDICT: **Verified**. SOURCE: `src/api/client.ts: normalizeErrorDetail`; `422` responses use `HTTPValidationError` (array-of-`{msg}`) across all guest endpoints in OpenAPI.
15. **Ownership check `GET /ui/me`.** VERDICT: **Verified** (endpoint exists). SOURCE: OpenAPI `GET /ui/me`.
16. **Multiple invites per session supported.** VERDICT: **Verified/Corrected** (spec assumed one active invite). SOURCE: schema `BroadcastGuestInviteListOut` (`invites: array`, `count`); web `GuestInviteDialog.tsx` renders `invites.map(...)`.
17. **Polling cadence ~5s for the host list.** VERDICT: **Verified** (matches web). SOURCE: `src/pages/broadcast/GuestInviteDialog.tsx` (`refetchInterval: 5000`).
18. **Documented response set is only `2xx` + `422 HTTPValidationError`.** VERDICT: **Verified** (so the §7 `404/409/410` handling is defensive, not contractual). SOURCE: OpenAPI `resp=` columns for all guest routes (`201/200` + `422:HTTPValidationError`).
19. **Mute state is not echoed by any read endpoint.** VERDICT: **Corrected/Unverified-assumption** (no `muted` field on `BroadcastInput` or `BroadcastGuestInviteOut`); the client must track mute locally from the last successful mute POST. SOURCE: schemas `BroadcastInput`, `BroadcastGuestInviteOut` (no `muted`/`muted_audio` field).
20. **Android stack relies on cookie session (not `Authorization: Bearer`).** VERDICT: **Unverified-assumption** (web sends both `Authorization: Bearer` and `X-CSRF-Token`; the Android `core-network` from AND-308 is the authority and was not inspected here). SOURCE: `src/api/client.ts` (web sends Bearer); Android `core-network` not in provided sources.

### Corrections made

- §1/§2/§5: base resource `/ui/broadcasts/{broadcastId}/guests` → `/broadcast/sessions/{session_id}` family; `broadcastId` → `session_id`; per-guest `guestId` → `input_id`.
- §5: full `GuestApi` + DTO rewrite — correct paths/verbs (all mutations are POST; revoke/remove are POST not DELETE); create returns 201; accept body is `{display_name}` not `{token}`; removed nonexistent `leave`; added `listInputs`; corrected field names (`invite_id`/`input_id`/`invite_url`/`ingest_url`/`stream_key`), epoch-vs-ISO timestamps, and removed invented `role`/`muted_audio`/`avatar_url`/`token`.
- §3 FR-3: guest list is derived from invites + inputs, not a single endpoint. FR-7: accept needs display_name + (session_id, invite_id), not a token. FR-8: guest leave unsupported by backend. FR-9: mutations are POST (not POST/DELETE).
- §4: routes/domain models/repository signatures re-keyed to `session_id`/`input_id`; mutations return `Unit`; accept returns `GuestAcceptResult`; deep link carries `sessionId`+`inviteId`.
- §6: Room keys `(sessionId, inputId)` / `(sessionId, inviteId)`; multiple invites; epoch timestamp parsing; merge/derivation of status; reconcile-via-refresh (no guest object returned by mutations).
- §7/§8/§10/§13/§14: status/secret/telemetry/OQ/AC text aligned with the corrected contract; OQ-1/3/4 resolved; AC-6 flagged blocked; secrets are `stream_key`/`invite_url`/`ingest_url` (no `token`).

### Open assumptions

- **Mobile deep-link / `invite_url` shape (unverified).** Web `invite_url` is a site-relative path joined with `window.location.origin` (`GuestInviteDialog.tsx: copyUrl`). The Android `testlogon://guest/accept?sessionId=..&inviteId=..` mapping is a proposal; the actual mobile link format must be agreed with backend/web. Why unverifiable: no mobile deep-link contract in the provided sources.
- **Guest self-leave (unsupported).** No backend endpoint; FR-8/AC-6 blocked until one exists. Why: confirmed absent in OpenAPI.
- **`404/409/410` conflict semantics (unverified).** Only `2xx`/`422` are documented; the §7 conflict handling is defensive. Why: not in OpenAPI response sets.
- **Mute read-back (unverified).** No read endpoint returns mute state; client tracks it locally. Why: no `muted` field in any guest/input schema.
- **Android auth header policy (unverified).** Whether the Android client sends `Authorization: Bearer`/`X-IMPERSONATION-TOKEN` in addition to the cookie is owned by AND-308's `core-network`, not provided here.
- **`avatar_url` (unverified).** No avatar field on the wire; UI avatar is best-effort/null.
- **`GuestStatus` `INVITED`/`role` mapping (client-derived).** No backend `role`; statuses are derived from invite `status` + input `is_live`/`connected_at`.

## 17. Test Plan

Test target keys: **JVM** = JVM unit/Robolectric (local, no device); **emu35** = headless AVD `test35` (x86_64, API 35); **A15** = physical Samsung Galaxy A15 5G (SM-A156U, API 34, arm64-v8a). Hardware-dependent cases prefer **A15**.

- **TC-AND-312-01** — Type: contract/MockWebServer. Target: JVM. Preconditions: `GuestApi` + repository wired to MockWebServer; CSRF cookie present. Steps: call `createInvite(session, browser, "Guest", 60)`; MockWebServer returns 201 with the §5 `BroadcastGuestInviteOut` sample. Expected: request is `POST /broadcast/sessions/{session}/guest-invites` with JSON body `{join_mode,label,expiry_minutes}` and header `X-CSRF-Token`; response maps to `GuestInvite` with `inviteId="inv_a1b2"`, `expiresAt` parsed from epoch `1749160800`, `status=PENDING`. Traces: AC-1, AC-7.
- **TC-AND-312-02** — Type: contract/MockWebServer. Target: JVM. Preconditions: repository wired. Steps: enqueue `GET .../guest-invites` (one accepted invite) and `GET .../inputs` (one `input_type=="guest"`, `is_live=true`); call `refreshGuests`. Expected: two GETs issued to the correct paths; results merged/joined on `input_id`; derived guest `status=ONAIR` (from `is_live`), `displayName="Avery"`. Traces: AC-2.
- **TC-AND-312-03** — Type: contract/MockWebServer. Target: JVM. Preconditions: repository wired. Steps: call `acceptInvite(session, "inv_a1b2", "Avery")`; server returns `BroadcastGuestAcceptOut`. Expected: request is `POST .../guest-invites/inv_a1b2/accept` with body `{"display_name":"Avery"}` (NOT `token`) and `X-CSRF-Token`; response maps to `GuestAcceptResult(inputId="in_77", ingestUrl=..)` for AND-308 handoff. Traces: AC-2.
- **TC-AND-312-04** — Type: contract/MockWebServer. Target: JVM. Preconditions: repository wired. Steps: invoke `promote`, `setMuted(true)`, `remove`, `revokeInvite` in turn. Expected: each is a **POST** to `.../guests/{input_id}/promote|mute|remove` and `.../guest-invites/{invite_id}/revoke`; mute carries body `{"muted":true}`; every request carries `X-CSRF-Token`; all map to `ApiResult.Success(Unit)`. Traces: AC-3, AC-4, AC-5, AC-7.
- **TC-AND-312-05** — Type: unit. Target: JVM. Preconditions: `parseDetail` + DTO adapters available. Steps: feed the three FastAPI `detail` shapes (plain string; `422` `[{msg}]` array; `{code,message}` object) and an unknown enum string for invite `status`. Expected: each shape maps to the right `UiText`; unknown enum → defensive default (`InviteStatus.PENDING` / `GuestStatus.JOINED`) + logged, never thrown. Traces: AC-8, AC-9.
- **TC-AND-312-06** — Type: unit. Target: JVM. Preconditions: repository with mockable `GuestApi`. Steps: make `GET .../inputs` fail with `503` twice then succeed; separately make `mute` fail with `503`. Expected: the idempotent GETs retry with bounded backoff (2 retries) and eventually succeed; the non-idempotent `mute` is **not** retried and surfaces `ApiResult.Error`. Traces: AC-9.
- **TC-AND-312-07** — Type: unit (ViewModel + Turbine). Target: JVM. Preconditions: `GuestManageViewModel` with fake repo. Steps: call `onToggleMute(inputId, true)`; repo returns Success; then a second case where repo returns Error. Expected: optimistic state shows muted + `inFlight` contains `inputId`; on Success → immediate `refreshGuests` reconciles, `inFlight` cleared; on Error → rollback to Room state, `inFlight` cleared, `error` set. Traces: AC-4, AC-8.
- **TC-AND-312-08** — Type: unit (ViewModel). Target: JVM. Preconditions: `GuestAcceptViewModel` with fake repo. Steps: (a) accept returns Success; (b) accept of an expired/revoked invite returns Error (e.g. `422`/`410`). Expected: (a) emits joined/handoff state with `input_id`; (b) emits invalid-invite state ("This invite is no longer valid"). Traces: AC-2, AC-8.
- **TC-AND-312-09** — Type: integration (Room). Target: emu35. Preconditions: in-memory Room DB. Steps: upsert guests/invites keyed by `(sessionId, inputId)`/`(sessionId, inviteId)`; observe `Flow` filtered by `sessionId`; remove a guest; reconcile within a transaction. Expected: observed list reflects upserts/removal; multiple invites coexist for one session; transactional reconcile is atomic. Traces: AC-1, AC-5, AC-9.
- **TC-AND-312-10** — Type: Compose-UI. Target: emu35. Preconditions: `GuestManageScreen` with a fake ViewModel; one joined guest, one pending invite. Steps: open the row overflow menu; tap Remove → confirm dialog → confirm; toggle stale banner via `isStale=true`; set a row `inFlight`. Expected: overflow actions invoke the right callbacks; Remove shows an `AlertDialog` and only fires `onRemove` after confirm; stale/"Reconnecting…" banner visible when `isStale`; in-flight row disabled. Traces: AC-5, AC-8.
- **TC-AND-312-11** — Type: Compose-UI (accessibility). Target: emu35. Preconditions: `GuestManageScreen` + `GuestAcceptScreen`. Steps: assert `contentDescription`s on overflow items (Promote/Mute/Remove), copy/share buttons, accept/decline; assert touch targets ≥48dp; verify mute toggle live-region announcement after success; render at 200% font scale. Expected: all assertions pass; no clipped/overlapping layout at 200%; status chips convey state by icon+text (not color alone). Traces: AC-4, AC-9.
- **TC-AND-312-12** — Type: contract/MockWebServer (security). Target: JVM. Preconditions: `CsrfInterceptor` from `core-network` in the OkHttp stack with a `ui_csrf` cookie set. Steps: issue each mutation (create/accept/revoke/promote/mute/remove). Expected: every request carries `X-CSRF-Token` equal to the `ui_csrf` cookie; a request with the cookie absent does not send the header (and the backend would 4xx — asserted via a 403 stub mapping to `ApiResult.Error`). Also assert `stream_key`/`invite_url` are never emitted to the Timber test tree. Traces: AC-7, and §8 secret-redaction.
- **TC-AND-312-13** — Type: instrumented (offline/flaky-host). Target: A15 (physical; real radio for airplane-mode toggling). Preconditions: app pointed at dev host with cached guests in Room; toggle device offline. Steps: with network down, pull-to-refresh (or wait a poll cycle) then attempt a mute. Expected: list keeps showing cached guests with the stale/"Reconnecting…" banner (no clear); the mute returns `ApiResult.Offline` and shows a transient snackbar without mutating Room; on reconnect, the next poll reconciles. Note: MUST run on A15 to exercise real connectivity loss/airplane-mode (emulator network toggling is unreliable for this). Traces: AC-8.
- **TC-AND-312-14** — Type: instrumented/e2e (deep link). Target: A15 (physical; real deep-link tap + clipboard/share + handoff to AND-308 WebRTC ingest which needs mic/camera). Preconditions: a valid invite created on dev; `testlogon://guest/accept?sessionId=..&inviteId=..` link. Steps: tap the deep link → accept screen shows broadcast summary + display-name field → enter name → Accept → handoff. Expected: link routes to `GuestRoutes.ACCEPT` parsing `sessionId`+`inviteId`; accept POSTs `{display_name}`; on success the host's `GuestManageScreen` shows the new guest within ≤5s (one poll); the AND-308 ingest path receives `input_id`/`ingest_url`. Note: MUST run on A15 because the post-accept WebRTC guest ingest requires real mic/camera and arm64 media stack. Traces: AC-2, AC-3.

### Coverage matrix

| AC | Covered by |
|---|---|
| AC-1 (create/revoke invite) | TC-01, TC-09 |
| AC-2 (accept + host sees within poll) | TC-02, TC-03, TC-08, TC-14 |
| AC-3 (promote → onair + bridge) | TC-04, TC-14 |
| AC-4 (server-enforced mute + a11y) | TC-04, TC-07, TC-11 |
| AC-5 (remove + confirm + bridge) | TC-04, TC-09, TC-10 |
| AC-6 (guest leave) | **Blocked — no backend endpoint (§16);** host-remove equivalent covered by TC-04/TC-10 |
| AC-7 (X-CSRF-Token on mutations) | TC-01, TC-04, TC-12 |
| AC-8 (offline/stale + error + invalid invite) | TC-05, TC-07, TC-08, TC-10, TC-13 |
| AC-9 (tests pass + coverage ≥80%) | TC-05, TC-06, TC-09, TC-11 |
