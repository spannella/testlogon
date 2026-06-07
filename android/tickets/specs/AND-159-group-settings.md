---
id: AND-159
title: Group settings
milestone: M3
epic: E22
priority: P2
size: M
status: reviewed
reviewed_on: 2026-06-06
depends_on: [AND-157, AND-158]
blocks: []
---

# AND-159 — Group settings

## 1. Overview & Goal

This ticket delivers the **Group settings** surface for the TestLogon native Android
client: the screen and actions that let a member manage their relationship with an
existing group conversation. Three user-facing capabilities are in scope per the
backlog ticket:

- **Mute / unmute** — toggle notification muting for the group, optionally for a
  bounded duration.
- **Leave** — remove the current user from the group membership.
- **Accept invite** — for groups the user has been invited to (pending membership),
  accept the invitation so the conversation becomes active.

Group **creation** is owned by AND-157 and **participant add/remove/role** management
is owned by AND-158; this ticket consumes the conversation/group model those tickets
established and adds the per-member settings panel layered on top. The goal is a
`GroupSettingsScreen` reachable from the group conversation overflow menu, backed by a
`GroupSettingsViewModel` exposing `StateFlow<GroupSettingsUiState>`, with each of the
three actions wired to its FastAPI endpoint, optimistic-where-safe, and fully tested.

Definition of success: each setting (mute, leave, accept-invite) works against the dev
backend and is covered by an automated test, and the membership/mute change is
reflected back in the conversation list and the group header.

## 2. Context & References

- **Repo / module:** `spannella/testlogon`, Android app under `android/`, branch
  `android-port`. New code lives in `feature-groups` (created by AND-157) under
  package `com.testlogon.android.feature.groups.settings`.
- **Layering:** `app -> feature-groups -> core-*` (`core-network`, `core-model`,
  `core-data`, `core-ui`, `core-testing`). No new module is introduced.
- **Upstream tickets:** AND-157 (group create — establishes `Conversation`/`GroupRef`
  models, `GroupRepository`, navigation graph entry). AND-158 (participants management —
  establishes role enum, membership write patterns and cache invalidation). This ticket
  reuses both.
- **Backend:** FastAPI + DynamoDB. Dev host `http://18.222.237.167:8000` (plaintext
  HTTP, unreliable). OpenAPI at `/openapi.json`. **CORRECTED:** the conversation/group
  endpoints this ticket uses live under `/messaging/conversations/*` (not `/conversations/*`).
  Authoritative request/response shapes are verified against `/openapi.json` and the web
  reference layer in `src/api/endpoints/messaging.ts`, `src/api/endpoints/groups.ts`, and
  `src/api/types.ts`. (Note: there is a separate social-groups domain `/ui/groups/*` with
  its own leave/invite endpoints and a web `GroupSettingsPage.tsx`, but it has **no mute**;
  see §13 and §16 for the domain-selection rationale.)
- **Auth:** cookie-based session with `ui_csrf` echoed as `X-CSRF-Token` on all
  mutating requests (VERIFIED against `src/api/client.ts`: `getCookie("ui_csrf")` →
  `X-CSRF-Token` header, `credentials: "include"`); persistent cookie jar; single
  `POST /ui/session/refresh` retry on 401 then logout on continued 401 (VERIFIED). The
  web client also attaches an `Authorization: Bearer <token>` header from its auth store
  when present; the Android client uses the cookie session as primary. All mutations in
  this ticket are authenticated and CSRF-protected; the read (`GET .../{id}`) is a GET.
- **Stack baseline:** Kotlin 2.0.21, Compose + Material 3, Navigation-Compose, Hilt
  (KSP), Coroutines/Flow, Retrofit 2.11 + OkHttp 4.12 + Moshi 1.15, Room 2.6,
  DataStore, minSdk 24 / target 35, JDK 17.

> Note: exact group settings endpoint names below are derived from the conversation
> resource conventions. Endpoint paths MUST be reconciled against `/openapi.json`
> during implementation; see Open Questions (§13).

## 3. Functional Requirements

FR-1. **Entry point.** A "Group settings" item in the group conversation top-bar
overflow menu navigates to `groupSettings/{conversationId}`.

FR-2. **Mute toggle.** The screen shows the current mute state. The user can mute or
unmute. Mute offers duration presets (8 hours, 1 week, Until I turn it back on). The
chosen state is persisted server-side and reflected in the conversation list (muted
groups show a muted indicator and are excluded from notification surfacing — the
notification side itself is owned by the messaging notifications ticket).

FR-3. **Leave group.** The user can leave the group. A confirmation dialog is shown
("Leave <group name>? You won't receive new messages."). On success the user is
removed from membership, navigated back to the conversation list, and the group is
removed from (or marked left in) the local list. Leaving is **not** optimistic — it
only updates UI after server confirmation.

FR-4. **Accept invite.** When the conversation's membership status for the current user
is `invited`/`pending`, the screen shows an "Accept invitation" affordance (and a
"Decline" affordance that performs leave). On accept, membership transitions to
`active`, the full group settings (mute/leave) become available, and the conversation
becomes a normal active conversation.

FR-5. **State gating.** Mute and Leave are only enabled when membership status is
`active` (or `muted`). Accept invite is only shown when status is `invited`. The screen
must handle a conversation the user has already left (read-only / "You left this group"
terminal state).

FR-6. **Reflection.** All three actions invalidate the relevant Room cache so the
conversation list and group header reflect the change without a manual refresh.

FR-7. **Resilience states.** The screen renders `Loading`, `Content`, `Empty/NotFound`
(conversation gone or 404), and `Error` (with retry for the idempotent load). In-flight
actions disable their controls and show progress.

## 4. Technical Design

### Navigation

```kotlin
// feature-groups navigation
const val GROUP_SETTINGS_ROUTE = "groupSettings"
const val ARG_CONVERSATION_ID = "conversationId"

fun NavGraphBuilder.groupSettingsScreen(onLeftGroup: () -> Unit, onBack: () -> Unit) {
    composable(
        route = "$GROUP_SETTINGS_ROUTE/{$ARG_CONVERSATION_ID}",
        arguments = listOf(navArgument(ARG_CONVERSATION_ID) { type = NavType.StringType })
    ) {
        GroupSettingsRoute(onLeftGroup = onLeftGroup, onBack = onBack)
    }
}

fun NavController.navigateToGroupSettings(conversationId: String) =
    navigate("$GROUP_SETTINGS_ROUTE/$conversationId")
```

### State & ViewModel

```kotlin
enum class MuteDuration { EIGHT_HOURS, ONE_WEEK, FOREVER }

data class GroupSettingsUiState(
    val phase: Phase = Phase.Loading,
    val conversationId: String = "",
    val groupName: String = "",
    val avatarUrl: String? = null,
    val membership: MembershipStatus = MembershipStatus.UNKNOWN, // active|muted|invited|left
    val muted: Boolean = false,
    val mutedUntilEpochMs: Long? = null,
    val actionInFlight: ActionKind? = null, // MUTE|LEAVE|ACCEPT|null
    val errorMessage: String? = null
) {
    enum class Phase { Loading, Content, NotFound, Error }
}

enum class ActionKind { MUTE, LEAVE, ACCEPT }

sealed interface GroupSettingsEvent {
    data object LeftGroup : GroupSettingsEvent
    data class ShowSnackbar(val text: String) : GroupSettingsEvent
}

@HiltViewModel
class GroupSettingsViewModel @Inject constructor(
    savedStateHandle: SavedStateHandle,
    private val repo: GroupRepository
) : ViewModel() {

    private val conversationId: String =
        checkNotNull(savedStateHandle[ARG_CONVERSATION_ID])

    private val _uiState = MutableStateFlow(GroupSettingsUiState(conversationId = conversationId))
    val uiState: StateFlow<GroupSettingsUiState> = _uiState.asStateFlow()

    private val _events = Channel<GroupSettingsEvent>(Channel.BUFFERED)
    val events: Flow<GroupSettingsEvent> = _events.receiveAsFlow()

    init { load() }

    fun load() { /* fetch settings, map ApiResult -> Phase */ }
    fun setMuted(muted: Boolean, duration: MuteDuration = MuteDuration.FOREVER) { /* ... */ }
    fun leave() { /* ... */ }
    fun acceptInvite() { /* ... */ }
    fun dismissError() { _uiState.update { it.copy(errorMessage = null) } }
}
```

### Repository

`GroupRepository` is introduced by AND-157; this ticket extends it (or adds a
`GroupSettingsRepository` if AND-157's interface is closed). Methods:

```kotlin
interface GroupRepository {
    // ... create (AND-157), participants (AND-158) ...
    suspend fun getGroupSettings(conversationId: String): ApiResult<GroupSettings>
    suspend fun setMute(conversationId: String, muted: Boolean, untilEpochMs: Long?): ApiResult<GroupSettings>
    suspend fun leaveGroup(conversationId: String): ApiResult<Unit>
    suspend fun acceptInvite(conversationId: String): ApiResult<GroupSettings>
}
```

The repo writes through to the `conversations` Room table (mute flag, membership
status) and emits via the shared conversation `Flow` so the list and header recompute.
`getGroupSettings` is the only idempotent GET and is the only call eligible for bounded
backoff retry.

### Compose UI

`GroupSettingsScreen(state, onSetMuted, onLeave, onAccept, onRetry, onBack)` is a
stateless composable driven by `GroupSettingsUiState`. Sections:

- Header: avatar (Coil) + group name (read-only here; rename owned by AND-158).
- For `invited`: prominent "Accept invitation" `Button` + "Decline" `TextButton`.
- For `active`/`muted`: a "Mute notifications" `Switch` row; tapping opens a
  `MuteDurationSheet` (ModalBottomSheet) when enabling; "Leave group" destructive row.
- For `left`: a terminal info row "You left this group" with only a back action.

Confirmation for Leave/Decline uses a Material 3 `AlertDialog`. While
`actionInFlight != null`, the corresponding control shows a `CircularProgressIndicator`
and is disabled.

## 5. API Contract

All requests carry session cookies and `X-CSRF-Token` (mutations). Base path
`/messaging/conversations/{conversationId}`. **Shapes below are VERIFIED against
`/openapi.json` and the web reference layer** (corrections from the original draft are
flagged inline and audited in §16).

**Read conversation (idempotent GET):** *CORRECTED — there is no `/settings`
sub-resource; the conversation itself is the source of truth.*
```
GET /messaging/conversations/{conversationId}
200 OK -> ConversationOut   (VERIFIED: components.schemas.ConversationOut)
{
  "conversation_id": "c_01H...",
  "type": "group",                         // conversation type (string)
  "status": "active",                      // CONVERSATION lifecycle status (string), NOT membership
  "title": "Eng Standup",                  // CORRECTED: field is "title", not "name"
  "icon": "https://.../g.png",             // CORRECTED: field is "icon", not "avatar_url"
  "muted_until": 0,                        // CORRECTED: INTEGER epoch (default 0 = not muted), not ISO string / not nullable
  "participant_count": 4,
  "participants": [                         // membership status is per-participant, NOT a top-level field
    { "user_id": "u_self", "status": "active", "role": "member",
      "joined_at": 0, "left_at": 0, "muted_until": 0 }
  ]
  // ... created_at, created_by, last_message, unread_count, etc. (see schema)
}
```
> **Membership status** for the current user is derived from the matching entry in
> `participants[]` (`app__routers__messaging__ParticipantOut.status`). In the social-groups
> domain the enum is `active | invited | pending_approval` (VERIFIED: `types.ts: GroupMember.status`).
> CORRECTED: there is **no** top-level `membership_status` field, and **no** `muted`/`left`
> membership-status value. "Muted" is expressed by `muted_until` (epoch ms, 0 = unmuted);
> "left" is expressed by the participant's `left_at` (or absence from `participants[]`).

**Mute / unmute:** *CORRECTED — method is POST (not PUT) and the path is prefixed
`/messaging`.*
```
POST /messaging/conversations/{conversationId}/mute
Body: MuteIn { "muted": true, "muted_until": 1717635600000 }
  // VERIFIED schema MuteIn = { muted?: boolean|null, muted_until?: integer|null }
  // muted_until is an INTEGER epoch (web client sends epoch number), NOT an ISO-8601 string.
  // "Forever" => send muted: true with muted_until omitted/null. Unmute => muted: false (or muted_until: 0).
200 OK   // CORRECTED: response body is empty (no ConversationOut echo); re-read GET .../{id} to refresh
```
> Web reference (`messaging.ts: muteConversation`) sends only `{ muted_until }`. The
> Android client SHOULD send `muted` explicitly so unmute is unambiguous; `muted_until`
> remains an integer epoch.

**Leave:** *CORRECTED — `POST .../leave`, not `DELETE .../members/me`.*
```
POST /messaging/conversations/{conversationId}/leave
Body: (none)
200 OK   // empty body. (VERIFIED: openapi op leave_conversation; web groups.ts also uses POST .../leave)
```

**Accept invite:** *CORRECTED — `POST .../accept`, not `POST .../invite/accept`.*
```
POST /messaging/conversations/{conversationId}/accept
Body: (none)            // CORRECTED: no request body
200 OK   // empty body (VERIFIED: openapi op accept_conversation). Re-read GET .../{id} to confirm active.
```
(Decline: the messaging domain has no dedicated decline; declining an invited
conversation is implemented via `POST .../leave`. In the social-groups domain the
equivalent is `POST /ui/groups/{groupId}/invites/{userId}/respond` body `{ "accept": false }`
— VERIFIED `groups.ts: respondToInvite`. See §13 for which domain applies.)

### Retrofit / Moshi

```kotlin
// CORRECTED to verified /messaging/conversations/* contract.
interface GroupSettingsApi {
    @GET("messaging/conversations/{id}")
    suspend fun getConversation(@Path("id") id: String): ConversationDto

    @POST("messaging/conversations/{id}/mute")          // CORRECTED: POST, not PUT
    suspend fun setMute(@Path("id") id: String, @Body body: MuteRequest)  // empty 200 body

    @POST("messaging/conversations/{id}/leave")         // CORRECTED: POST .../leave
    suspend fun leave(@Path("id") id: String)           // empty 200 body

    @POST("messaging/conversations/{id}/accept")        // CORRECTED: POST .../accept (no body)
    suspend fun acceptInvite(@Path("id") id: String)    // empty 200 body
}

// MuteIn — muted_until is an INTEGER epoch (Long), not a String. muted is nullable.
@JsonClass(generateAdapter = true)
data class MuteRequest(@Json(name = "muted") val muted: Boolean?,
                       @Json(name = "muted_until") val mutedUntil: Long?)

// Subset of ConversationOut consumed by this screen (full schema has more fields).
@JsonClass(generateAdapter = true)
data class ConversationDto(
    @Json(name = "conversation_id") val conversationId: String,
    @Json(name = "type") val type: String,
    @Json(name = "status") val status: String,             // conversation lifecycle, NOT membership
    @Json(name = "title") val title: String?,              // CORRECTED: "title", not "name"
    @Json(name = "icon") val icon: String?,                // CORRECTED: "icon", not "avatar_url"
    @Json(name = "muted_until") val mutedUntil: Long = 0,  // CORRECTED: Long epoch, 0 = not muted
    @Json(name = "participant_count") val participantCount: Int = 0,
    @Json(name = "participants") val participants: List<ParticipantDto> = emptyList()
)

@JsonClass(generateAdapter = true)
data class ParticipantDto(
    @Json(name = "user_id") val userId: String,
    @Json(name = "status") val status: String,             // active | invited | pending_approval
    @Json(name = "role") val role: String,
    @Json(name = "left_at") val leftAt: Long = 0,          // > 0 => has left
    @Json(name = "muted_until") val mutedUntil: Long = 0
)
```
> Mapping note: the ViewModel derives `membership` from the **current user's** entry in
> `participants[]` (match on `user_id`): `left_at > 0` => left; else use that entry's
> `status`. `muted` is `mutedUntil > now` (conversation-level or the self participant).

Calls are wrapped by the shared `apiCall { }` helper (from `core-network`) returning
`ApiResult<T>`; FastAPI `detail` (string | `[{msg}]` | `{code,...}`) is mapped to a
user-facing message by the shared error mapper.

## 6. Data & State Management

- **Room (`core-data`):** reuse the `conversations` entity from AND-157. This ticket
  reads/writes `muted: Boolean`, `mutedUntil: Long?`, and `membershipStatus: String`
  columns. If those columns do not yet exist, add a Room migration
  (`MIGRATION_x_y`) adding `muted INTEGER NOT NULL DEFAULT 0`,
  `muted_until INTEGER`, and `membership_status TEXT NOT NULL DEFAULT 'active'`.
- **Source of truth:** the conversation list and group header observe the `conversations`
  table via `Flow`. After any successful action the repo upserts the returned
  `GroupSettings` so reflection (FR-6) is automatic.
- **Optimism policy:** Mute is applied optimistically (toggle the row immediately,
  roll back on failure). Leave and Accept are **not** optimistic — UI updates only on a
  successful response, because both are membership-altering and irreversible-ish.
- **DataStore:** not used for group state; no per-group prefs are stored client-side.
- **Time:** CORRECTED — `muted_until` is sent/received as an **integer epoch**, not
  ISO-8601 (VERIFIED: `MuteIn.muted_until: integer` and `messaging.ts: muteConversation`
  sends an epoch number). No string parsing is required. `MuteDuration.FOREVER` =>
  `muted: true` with `muted_until = null` (and the server may persist a sentinel). A
  read-back `muted_until` of `0` means not muted.
- **Process death:** `conversationId` survives via `SavedStateHandle`; UI state is
  re-derived by `load()` in `init`, so no extra `@Parcelize` state bag is required.

## 7. Error Handling & Resilience

- **Timeouts/backoff:** OkHttp call timeout ~20s (global config). Only the
  `getGroupSettings` GET is retried with bounded exponential backoff (max 2 retries,
  jitter); mutations are never auto-retried.
- **401:** handled centrally — one `POST /ui/session/refresh` then a single retry; on
  continued 401 the user is routed to re-auth by the global auth interceptor.
- **404 / gone:** `getSettings` 404 -> `Phase.NotFound` ("This group no longer
  exists."). A 404/409 on Leave/Accept (already left / invite expired) is treated as a
  benign terminal state: surface a snackbar and refresh.
- **409 conflict on Accept** (e.g., already a member): treat as success, refresh state.
- **Offline:** show last cached settings from Room with a stale banner; mutation
  attempts while offline show "You're offline — try again."
- **Mute rollback:** on optimistic mute failure, revert the row and show the mapped
  error via `errorMessage`.
- **Concurrency:** `actionInFlight` guards against double-submit; a second tap while an
  action is in flight is ignored.

## 8. Security & Privacy

- All endpoints require the authenticated cookie session; mutations
  (PUT/DELETE/POST) include the `X-CSRF-Token` header sourced from the `ui_csrf` cookie
  via the shared OkHttp interceptor. No tokens are logged.
- Authorization is server-enforced (only members may read settings; only the acting
  user may mute/leave their own membership). The client must not assume capability — it
  renders affordances by `membership_status` but relies on server 403 as the
  authoritative gate (403 -> mapped error, no client crash).
- The dev backend is plaintext HTTP; `usesCleartextTraffic` is restricted to the dev
  network-security-config (owned by the networking ticket). No group content or
  membership data is written to logs at INFO+.
- Leaving a group must not leave orphaned cached message content readable; rely on the
  conversation cache eviction already used by AND-158 when membership ends.

## 9. Accessibility & i18n

- All controls have `contentDescription` / semantics: the mute `Switch` announces
  state ("Mute notifications, off"); destructive "Leave group" row uses
  `Role.Button`.
- Destructive actions (Leave/Decline) use a confirmation dialog so they are not
  triggered by a single mis-tap; dialog buttons are min 48dp touch targets.
- Mute duration presets and the muted-until time are localized; all strings live in
  `feature-groups` `strings.xml` (no hardcoded UI text). `muted_until` is formatted with
  the device locale/time zone.
- Color is not the sole signal for muted/destructive state (icon + label accompany
  color). Verified at large font scale (200%) and in dark theme. RTL layouts mirror
  correctly (use `start`/`end` constraints).

## 10. Telemetry & Logging

- Emit analytics events (via the shared analytics facade, owned by the core analytics
  ticket): `group_settings_open`, `group_mute_toggled` (props: `muted`, `duration`),
  `group_left`, `group_invite_accepted`, `group_invite_declined`, each with a hashed
  `conversation_id` — never the raw name.
- Failures emit `group_settings_action_failed` with `action` and a coarse
  `error_kind` (network/http_4xx/http_5xx), no PII.
- Logging: use Timber; DEBUG-level only for request lifecycle, redacting cookies/CSRF.
  No body logging at release level (OkHttp `HttpLoggingInterceptor` set to `NONE` in
  release per global config).

## 11. Testing Strategy

- **ViewModel unit tests (`core-testing` + Turbine + MockK):**
  - `load()` maps 200 -> `Phase.Content` with correct membership/mute mapping.
  - `load()` maps 404 -> `Phase.NotFound`; 5xx -> `Phase.Error`.
  - `setMuted(true)` applies optimistic state then confirms on success; reverts on
    failure and surfaces `errorMessage`.
  - `leave()` is non-optimistic, emits `GroupSettingsEvent.LeftGroup` only on success.
  - `acceptInvite()` transitions `invited -> active` and unlocks mute/leave.
  - `actionInFlight` blocks concurrent submits.
- **Repository tests:** Retrofit against MockWebServer — assert the corrected paths
  (`POST /messaging/conversations/{id}/mute|leave|accept`, `GET /messaging/conversations/{id}`),
  HTTP methods, `X-CSRF-Token` presence on mutations, request body JSON for mute
  (`muted_until` is an **integer**, forever => `muted_until: null`), and Room
  write-through for each action. Assert 409 on accept is coalesced to success.
- **Compose UI tests (`createAndroidComposeRule`):** invited state shows Accept/Decline;
  active state shows mute switch + leave; left state is terminal; Leave shows
  confirmation dialog and only calls `onLeave` after confirm; in-flight disables
  controls.
- **Acceptance gate:** the backlog acceptance ("Each setting works (tested)") is met
  when mute, leave, and accept each have a passing end-to-end MockWebServer-backed test
  plus one manual verification against the dev host.

## 12. Dependencies & Sequencing

- **Depends on AND-157** (group create): provides `feature-groups` module, navigation
  graph, `Conversation`/`GroupRepository`, and the `conversations` Room entity.
- **Depends on AND-158** (participants management): establishes membership/role model,
  CSRF mutation pattern, and conversation cache invalidation reused here; the `left`
  state interacts with membership semantics defined there. (Backlog lists Deps: AND-157;
  AND-158 is added as a hard dependency because this ticket reuses its membership write
  + cache-invalidation patterns.)
- **Soft dependencies:** networking/auth interceptor (cookie jar, CSRF, refresh-on-401),
  analytics facade, and notification suppression of muted groups are owned by their
  respective infra/messaging tickets; this ticket only sets the mute flag.
- **Blocks:** none currently.
- **Sequencing:** implement repo + API + Room migration first, then ViewModel, then
  Compose screen and navigation wiring, then tests.

## 13. Risks & Open Questions

- **Domain selection (high — RESOLVED in review).** Two backends offer overlapping
  "group" features: **messaging conversations** (`/messaging/conversations/*`, which has
  `mute`, `leave`, `accept`) and **social groups** (`/ui/groups/*`, which has `leave` and
  invite `respond` but **no mute**). Because AND-159 requires all three actions including
  mute, and depends on participant management (AND-158 → `/messaging/conversations/{id}/participants`),
  this ticket targets the **messaging-conversations** domain. The corrected §5 reflects
  that. If product intends the social-groups surface instead, mute is unavailable there
  and the scope must change — confirm with the backend/product owner. (Endpoint paths
  themselves are now VERIFIED, not inferred.)
- **Invite model (RESOLVED).** "Invited" is a per-participant `status` value
  (`ParticipantOut.status` / `GroupMember.status` ∈ `active|invited|pending_approval`),
  not a separate `/invites` resource and not a top-level conversation field. Accept =
  `POST .../accept`; Decline = `POST .../leave` (messaging) or `respondToInvite({accept:false})`
  (social groups). VERIFIED.
- **Mute duration support (RESOLVED).** `MuteIn.muted_until` (integer epoch) IS
  supported by the backend, so the duration sheet is viable. Open sub-question: the
  server's interpretation of "forever" (null vs sentinel) — confirm during integration.
- **Reflection scope (low).** Conversation list filtering/indicator for muted/left
  groups may be partly owned by the conversation list ticket; coordinate to avoid
  duplicate UI logic.
- **403 handling.** Confirm server returns 403 (not 404) when a non-member reads
  settings, so `NotFound` vs error mapping is correct.

## 14. Acceptance Criteria

AC-1. From a group conversation, "Group settings" opens `GroupSettingsScreen` for that
`conversationId`, showing current name, avatar, membership status, and mute state.

AC-2. **Mute works:** toggling mute calls `POST /messaging/conversations/{id}/mute` with
the correct `MuteIn` body (`muted` boolean + integer `muted_until`; `muted_until: null`
for "forever"), updates the switch optimistically, persists on success, reverts + shows
an error on failure, and the muted indicator appears in the conversation list. (Covered
by ViewModel, repo, and UI tests.)

AC-3. **Leave works:** "Leave group" requires confirmation, calls
`POST /messaging/conversations/{id}/leave` (no body), only updates UI on success, emits
`LeftGroup`, navigates back, and removes/marks-left the group in the list.

AC-4. **Accept invite works:** for an `invited` conversation, "Accept invitation" calls
`POST /messaging/conversations/{id}/accept` (no body), transitions membership to
`active`, and unlocks mute/leave; "Decline" performs leave on the pending membership.

AC-5. State gating per FR-5 is enforced (invited shows accept/decline; active shows
mute/leave; left is terminal).

AC-6. Loading/Content/NotFound/Error phases render correctly; the settings GET retries
with bounded backoff while mutations do not; 401 triggers a single refresh+retry.

AC-7. All three actions send `X-CSRF-Token` and ride the persistent cookie session.

AC-8. Automated tests for mute, leave, and accept-invite all pass (backlog acceptance:
"Each setting works (tested)").

## 15. Definition of Done

- `feature-groups.settings` package contains `GroupSettingsRoute/Screen`,
  `GroupSettingsViewModel`, `GroupSettingsUiState`, and `GroupSettingsApi`, wired into
  the navigation graph with `navigateToGroupSettings`.
- `GroupRepository` extended with `getGroupSettings`, `setMute`, `leaveGroup`,
  `acceptInvite`, all returning `ApiResult<T>` and writing through to Room; Room
  migration added if new columns were required.
- All endpoint paths reconciled against `/openapi.json` (Open Questions resolved or
  ticketed).
- Unit, repository (MockWebServer), and Compose UI tests for all three actions pass in
  CI; `./gradlew :feature-groups:testDebugUnitTest` and the module's connected/Robolectric
  UI tests are green.
- ktlint/detekt clean; no hardcoded strings; a11y semantics verified at 200% font and
  in dark + RTL.
- No secrets/PII/cookies logged at release level; analytics events emit with hashed
  `conversation_id`.
- Code reviewed and merged to `android-port`; manual smoke against the dev host
  confirms mute, leave, and accept-invite end to end.

## 16. Citations & Assumption Audit

Each key technical claim, its VERDICT (Verified / Corrected / Unverified-assumption), and
the exact source pointer (OpenAPI `METHOD /path` + schema, or frontend file:symbol).

1. **Read settings via `GET /conversations/{id}/settings` returning a `GroupSettings`
   shape.** VERDICT: **Corrected.** No `/settings` sub-resource exists (grep of
   openapi + frontend = no matches). Source of truth is the conversation object.
   SOURCE: OpenAPI `GET /messaging/conversations/{conversation_id}` (op
   `get_conversation...`) → `200: ConversationOut`; schema `components.schemas.ConversationOut`.

2. **Mute is `PUT /conversations/{id}/mute`.** VERDICT: **Corrected** (wrong method +
   path). SOURCE: OpenAPI `POST /messaging/conversations/{conversation_id}/mute` (op
   `mute_conversation...`, `req=MuteIn`); frontend `src/api/endpoints/messaging.ts: muteConversation`
   (`api.post('/messaging/conversations/${id}/mute', { muted_until })`).

3. **Mute body field `muted_until` is an ISO-8601 string, nullable.** VERDICT:
   **Corrected.** It is an **integer epoch**. SOURCE: `components.schemas.MuteIn` =
   `{ muted?: boolean|null, muted_until?: integer|null }`; frontend `messaging.ts:
   muteConversation(conversationId, mutedUntil: number)`.

4. **Mute response echoes the GroupSettings/`muted` shape.** VERDICT: **Corrected.**
   Response has no documented body (`resp=200:` empty). Client must re-`GET` the
   conversation to refresh. SOURCE: OpenAPI index line for `mute_conversation...` (`resp=200:;422`).

5. **Leave is `DELETE /conversations/{id}/members/me` → `{ left: true }`.** VERDICT:
   **Corrected.** SOURCE: OpenAPI `POST /messaging/conversations/{conversation_id}/leave`
   (op `leave_conversation...`, empty `req`, `resp=200:` empty). Social-groups analogue
   `frontend/src/api/endpoints/groups.ts: leaveGroup` = `api.post('/ui/groups/${groupId}/leave')`.

6. **Accept invite is `POST /conversations/{id}/invite/accept` with body `{}`.** VERDICT:
   **Corrected.** SOURCE: OpenAPI `POST /messaging/conversations/{conversation_id}/accept`
   (op `accept_conversation...`, no `req` body, `resp=200:` empty).

7. **`membership_status` is a top-level field with values `active|muted|invited|left`.**
   VERDICT: **Corrected.** No such top-level field. Membership status is per-participant
   (`participants[].status`) with enum `active|invited|pending_approval`; there is no
   `muted` or `left` status value. SOURCE: `components.schemas.app__routers__messaging__ParticipantOut`
   (`status`, `role`, `left_at`, `muted_until`); `src/api/types.ts: GroupMember.status`
   (`"active" | "invited" | "pending_approval"`).

8. **Group display fields `name` and `avatar_url`.** VERDICT: **Corrected.** The
   `ConversationOut` fields are `title` and `icon`. SOURCE: `components.schemas.ConversationOut`
   (`title`, `icon`; no `name`/`avatar_url`). (Social-groups `UserGroup` does use `name`/
   `cover_image_url` — `types.ts: UserGroup` — but that is the other domain.)

9. **`muted` is a boolean field; `muted_until` nullable string.** VERDICT: **Corrected.**
   `ConversationOut.muted_until` is `integer` (default 0, not nullable); there is no
   `muted` boolean on the conversation. Muted ⇔ `muted_until > now`. SOURCE:
   `components.schemas.ConversationOut.muted_until` (integer, default 0).

10. **Auth: cookie session with `ui_csrf` echoed as `X-CSRF-Token` on mutations.**
    VERDICT: **Verified.** SOURCE: `src/api/client.ts` lines 168–170
    (`getCookie("ui_csrf")` → `headers.set("X-CSRF-Token", csrf)`), `credentials: "include"`
    (lines 183/220).

11. **Single `POST /ui/session/refresh` retry on 401, then re-auth on continued 401.**
    VERDICT: **Verified.** SOURCE: `src/api/client.ts` lines 122 (`/ui/session/refresh`),
    194–236 (refresh once, retry, `logout("session_expired")` on second 401).

12. **FastAPI error `detail` is `string | [{msg}] | {code,...}` mapped to a user message.**
    VERDICT: **Verified.** SOURCE: `src/api/client.ts: normalizeErrorDetail` (handles
    string, array of `{msg}`, and `{code}` via `mapAuthorizationError`); 422 →
    `HTTPValidationError` across the messaging endpoints (OpenAPI index).

13. **Offline path shows a network-error affordance.** VERDICT: **Verified** (web
    behavior). SOURCE: `src/api/client.ts` lines 185–189 (fetch catch → "Network error"
    toast, `ApiError(0, ...)`). Android equivalent: surface offline banner / "You're offline".

14. **403 is the authoritative authorization gate (non-member, etc.).** VERDICT:
    **Verified** (handling exists). SOURCE: `src/api/client.ts` line 240+ (403 branch);
    messaging read endpoints declare `403` (OpenAPI index for `get_conversation...`).

15. **Decline = leave on the pending membership.** VERDICT: **Verified.** Messaging has
    no decline endpoint → reuse `POST .../leave`; social-groups uses
    `respondToInvite(groupId, userId, false)` → `POST /ui/groups/{groupId}/invites/{userId}/respond`
    body `{accept:false}`. SOURCE: `src/api/endpoints/groups.ts: respondToInvite`; OpenAPI
    `POST /ui/groups/{group_id}/invites/{user_id}/respond`.

16. **Domain choice (messaging conversations vs social groups).** VERDICT:
    **Corrected/Resolved.** The spec's three actions (esp. mute) only co-exist on
    `/messaging/conversations/*`; `/ui/groups/*` has no mute. SOURCE: absence of any
    `mute` op under `/ui/groups/*` in the OpenAPI index vs presence under
    `/messaging/conversations/{id}/mute`.

17. **Compose + Material 3 / Navigation-Compose / Hilt-KSP / Retrofit+OkHttp+Moshi /
    Room / DataStore stack.** VERDICT: **Unverified-assumption** (framework choices, not
    derivable from backend/frontend sources). SOURCE: framework ref —
    https://developer.android.com/jetpack/compose and
    https://developer.android.com/training/dependency-injection/hilt-android (versions are
    the team's chosen baseline, not contract-verifiable).

18. **`usesCleartextTraffic` for the plaintext dev host owned by the networking ticket.**
    VERDICT: **Unverified-assumption** (cross-ticket ownership; dev host is HTTP per §2).
    SOURCE: framework ref — https://developer.android.com/training/articles/security-config.

### Corrections made

- Base path `/conversations/*` → **`/messaging/conversations/*`** (claims 1–9, AC-2/3/4,
  §2, §5, §6, §11, §13).
- Read: removed nonexistent `GET .../settings`; use **`GET /messaging/conversations/{id}`
  → `ConversationOut`** (claim 1).
- Mute: **`PUT` → `POST`**; body `MuteIn` with **integer** `muted_until` (not ISO string);
  **empty response** (re-GET to refresh) (claims 2–4).
- Leave: **`DELETE .../members/me` → `POST .../leave`**, empty body (claim 5).
- Accept: **`POST .../invite/accept` → `POST .../accept`**, no request body (claim 6).
- Membership model: removed top-level `membership_status`; derive from
  **`participants[].status`** (`active|invited|pending_approval`) + `left_at`; dropped the
  unreal `muted`/`left` status values (claim 7).
- DTO field names: **`name`→`title`, `avatar_url`→`icon`**; `muted_until` typed as **Long**
  epoch; removed `muted` boolean field (claims 8–9).
- Updated `GroupSettingsApi`/`MuteRequest`/`ConversationDto`/`ParticipantDto` in §5, the
  Acceptance Criteria in §14, and the Risks/Open-Questions in §13 to mark them resolved.

### Open assumptions

- **Server's "forever" encoding.** Whether `muted_until: null` vs a far-future sentinel
  denotes permanent mute is not specified in `MuteIn`; confirm during integration
  (claim 3/9). Unverifiable from static sources.
- **Android stack versions** (Compose/Hilt/Retrofit/etc.) — team baseline, framework refs
  only, not contract-verifiable (claim 17).
- **Cleartext/network-security-config ownership** is a separate ticket; only the dev host
  being plaintext HTTP is established here (claim 18).
- **Reflection in the conversation list** (muted/left indicator) may be partly owned by
  the conversation-list ticket; the write-through contract is local, the rendering split is
  not verifiable from these sources (§13 "Reflection scope").
- **403-vs-404 for non-member reads.** Messaging read declares both `403` and (via
  `MessageControlsErrorOut`) `404` on sibling ops; the exact code for a non-member reading
  a group conversation is not pinned down — handle both (NotFound vs error) defensively.

## 17. Test Plan

Test target legend: **JVM** = JVM unit/Robolectric (local, no device); **MWS** =
contract test via MockWebServer; **EMU** = headless emulator AVD `test35` (x86_64,
API 35); **DEV** = physical Samsung Galaxy A15 5G (SM-A156U, API 34, arm64-v8a) over adb.
Compose-UI/instrumented cases run on EMU unless they require real hardware (then DEV).

- **TC-AND-159-01** — Type: contract/MWS (JVM). Target: MWS. Preconditions: MockWebServer
  enqueues `200` `ConversationOut` JSON (`title`, `icon`, `muted_until:0`, `participants`
  with self `status:"active"`). Steps: call `getConversation(id)`. Expected: `GET
  /messaging/conversations/{id}` issued; DTO maps `title`/`icon`/`mutedUntil:Long`/
  participants; `Phase.Content`, membership `active`, `muted=false`. **Traces: AC-1, AC-6.**

- **TC-AND-159-02** — Type: contract/MWS (JVM). Target: MWS. Preconditions: enqueue `200`
  empty body for mute. Steps: `setMute(id, muted=true, untilEpochMs=1717635600000)`.
  Expected: `POST /messaging/conversations/{id}/mute`; request JSON body is
  `{"muted":true,"muted_until":1717635600000}` (integer, **not** a string); `X-CSRF-Token`
  header present; no parse error on empty 200. **Traces: AC-2, AC-7.**

- **TC-AND-159-03** — Type: contract/MWS (JVM). Target: MWS. Preconditions: enqueue `200`.
  Steps: mute with `MuteDuration.FOREVER`. Expected: body has `muted_until:null` (and
  `muted:true`); asserts the "forever ⇒ null" encoding (flagged open assumption). **Traces: AC-2.**

- **TC-AND-159-04** — Type: unit (JVM). Target: ViewModel + fake repo. Preconditions:
  `Content`/`active`/unmuted. Steps: `setMuted(true)`; repo suspends then fails. Expected:
  switch flips optimistically immediately, then **reverts** on failure and `errorMessage`
  is set (mapped from `detail`). **Traces: AC-2.**

- **TC-AND-159-05** — Type: contract/MWS (JVM). Target: MWS. Preconditions: enqueue `200`
  empty body for leave. Steps: `leaveGroup(id)`. Expected: `POST
  /messaging/conversations/{id}/leave`, no request body, `X-CSRF-Token` present; repo
  returns `ApiResult.Success`; non-optimistic (no state change before response). **Traces: AC-3, AC-7.**

- **TC-AND-159-06** — Type: unit (JVM). Target: ViewModel. Preconditions: `active`. Steps:
  `leave()` → success. Expected: `GroupSettingsEvent.LeftGroup` emitted **only** after
  success; Room marked-left / removed; on failure no `LeftGroup` and error surfaced. **Traces: AC-3.**

- **TC-AND-159-07** — Type: contract/MWS (JVM). Target: MWS. Preconditions: enqueue `200`
  empty for accept, then `200` `ConversationOut` with self `status:"active"` for the
  refresh GET. Steps: `acceptInvite(id)` then reload. Expected: `POST
  /messaging/conversations/{id}/accept` (no body) + follow-up `GET .../{id}`; membership
  transitions `invited → active`; mute/leave unlocked. Also assert **409 on accept is
  coalesced to success** (enqueue `409`, expect refreshed state, no error). **Traces: AC-4, AC-5.**

- **TC-AND-159-08** — Type: unit (JVM). Target: ViewModel. Preconditions: action in
  flight (`actionInFlight != null`). Steps: invoke a second action (double-tap). Expected:
  second call ignored; no duplicate request. **Traces: AC-2, AC-3, AC-4.**

- **TC-AND-159-09** — Type: unit (JVM). Target: ViewModel. Preconditions: load returns
  `404`/conversation gone; and separately `5xx`. Steps: `load()`. Expected: `404 →
  Phase.NotFound`; `5xx → Phase.Error` with retry; the GET retries with bounded backoff
  (max 2) while mutations never auto-retry. **Traces: AC-6.**

- **TC-AND-159-10** — Type: Compose-UI (EMU). Target: `GroupSettingsScreen` via
  `createAndroidComposeRule`. Preconditions: states `invited`, `active`, `left`. Steps:
  render each. Expected: `invited` shows Accept + Decline; `active` shows mute Switch +
  Leave; `left` is terminal ("You left this group", back only); state gating per FR-5.
  **Traces: AC-1, AC-5.**

- **TC-AND-159-11** — Type: Compose-UI (EMU). Target: Screen. Preconditions: `active`.
  Steps: tap "Leave group". Expected: confirmation `AlertDialog` shown; `onLeave` invoked
  **only** after confirm; while `actionInFlight==LEAVE` the row shows progress and is
  disabled. **Traces: AC-3, AC-5.**

- **TC-AND-159-12** — Type: Compose-UI / accessibility (EMU). Target: Screen.
  Preconditions: `active`, dark theme + 200% font + RTL locale. Steps: inspect semantics.
  Expected: mute Switch announces state ("Mute notifications, off"), Leave row has
  `Role.Button`, touch targets ≥48dp, color not sole signal, layout mirrors in RTL, no
  truncation/overlap at 200%. **Traces: AC-1, AC-5.**

- **TC-AND-159-13** — Type: instrumented/integration (EMU). Target: OkHttp stack against
  MWS-on-device. Preconditions: enqueue `401` then a successful retry after refresh.
  Steps: trigger any mutation. Expected: one `POST /ui/session/refresh` then a single
  retry of the original request carrying `X-CSRF-Token`; continued `401` routes to re-auth.
  **Traces: AC-6, AC-7.**

- **TC-AND-159-14** — Type: manual/instrumented, flaky-host + offline (**DEV — physical
  device required**). Target: full app against dev host `http://18.222.237.167:8000`.
  Preconditions: real device on a network that can be toggled (airplane mode); plaintext
  HTTP allowed via dev network-security-config. Steps: (a) with network off, open settings
  → expect cached content + stale banner and "You're offline — try again" on mutation;
  (b) restore network, perform mute, leave, accept end-to-end; (c) exercise an
  intermittent/slow dev-host response. Expected: offline affordances correct; all three
  actions succeed against the real backend; cleartext HTTP works only on dev config; no
  cookies/CSRF/PII in logcat. Physical device chosen for real radio toggling, real-network
  flakiness, and API-34/arm64 verification (vs EMU's API-35/x86_64). **Traces: AC-2, AC-3,
  AC-4, AC-8.**

### Coverage matrix

| AC | Covered by |
|----|-----------|
| AC-1 (open screen, shows name/avatar/status/mute) | TC-01, TC-10, TC-12 |
| AC-2 (mute works: POST /mute, integer body, optimistic+revert, indicator) | TC-02, TC-03, TC-04, TC-08, TC-14 |
| AC-3 (leave: POST /leave, non-optimistic, LeftGroup, nav back) | TC-05, TC-06, TC-08, TC-11, TC-14 |
| AC-4 (accept: POST /accept, invited→active, 409 coalesced, decline=leave) | TC-07, TC-08, TC-14 |
| AC-5 (state gating invited/active/left) | TC-07, TC-10, TC-11, TC-12 |
| AC-6 (Loading/Content/NotFound/Error, GET retry, 401 refresh) | TC-01, TC-09, TC-13 |
| AC-7 (X-CSRF-Token + cookie session on all actions) | TC-02, TC-05, TC-13 |
| AC-8 (automated tests for all three actions pass; manual smoke) | TC-02, TC-05, TC-07, TC-14 |
