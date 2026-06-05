---
id: AND-159
title: Group settings
milestone: M3
epic: E22
priority: P2
size: M
status: draft
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
  HTTP, unreliable). OpenAPI at `/openapi.json`. Conversation/group endpoints under
  `/conversations/*`. Authoritative request/response shapes are confirmed against
  `/openapi.json` and the web reference layer in
  `frontend/src/api/endpoints/conversations.ts` and `frontend/src/api/types.ts`.
- **Auth:** cookie-based session with `ui_csrf` echoed as `X-CSRF-Token` on all
  mutating requests; persistent cookie jar; single `POST /ui/session/refresh` retry on
  401. All endpoints in this ticket are authenticated and CSRF-protected (they are
  non-GET mutations except the invite list read).
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
`/conversations/{conversationId}`. Shapes below to be confirmed against `/openapi.json`.

**Read settings (idempotent GET):**
```
GET /conversations/{conversationId}/settings
200 OK
{
  "conversation_id": "c_01H...",
  "name": "Eng Standup",
  "avatar_url": "https://.../g.png",
  "membership_status": "active",          // active | muted | invited | left
  "muted": false,
  "muted_until": null                      // ISO-8601 string or null
}
```

**Mute / unmute (idempotent-ish PUT):**
```
PUT /conversations/{conversationId}/mute
Body: { "muted": true, "muted_until": "2026-06-06T01:00:00Z" }   // muted_until null => forever
200 OK -> same GroupSettings shape (echoes muted, muted_until)
```

**Leave:**
```
DELETE /conversations/{conversationId}/members/me
200 OK -> { "left": true }   (or 204 No Content)
```

**Accept invite:**
```
POST /conversations/{conversationId}/invite/accept
Body: {}
200 OK -> GroupSettings shape with membership_status: "active"
```
(Decline is implemented via the Leave endpoint — `DELETE .../members/me` on an
`invited` conversation removes the pending membership.)

### Retrofit / Moshi

```kotlin
interface GroupSettingsApi {
    @GET("conversations/{id}/settings")
    suspend fun getSettings(@Path("id") id: String): GroupSettingsDto

    @PUT("conversations/{id}/mute")
    suspend fun setMute(@Path("id") id: String, @Body body: MuteRequest): GroupSettingsDto

    @DELETE("conversations/{id}/members/me")
    suspend fun leave(@Path("id") id: String)

    @POST("conversations/{id}/invite/accept")
    suspend fun acceptInvite(@Path("id") id: String): GroupSettingsDto
}

@JsonClass(generateAdapter = true)
data class MuteRequest(@Json(name = "muted") val muted: Boolean,
                       @Json(name = "muted_until") val mutedUntil: String?)

@JsonClass(generateAdapter = true)
data class GroupSettingsDto(
    @Json(name = "conversation_id") val conversationId: String,
    @Json(name = "name") val name: String,
    @Json(name = "avatar_url") val avatarUrl: String?,
    @Json(name = "membership_status") val membershipStatus: String,
    @Json(name = "muted") val muted: Boolean,
    @Json(name = "muted_until") val mutedUntil: String?
)
```

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
- **Time:** `muted_until` is sent/received as ISO-8601 UTC; converted to epoch ms for
  storage. `MuteDuration.FOREVER` => `muted_until = null`.
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
- **Repository tests:** Retrofit against MockWebServer — assert paths, method,
  `X-CSRF-Token` presence, request body JSON for mute (forever => `muted_until: null`),
  and Room write-through for each action. Assert 409 on accept is coalesced to success.
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

- **Endpoint shape uncertainty (high).** Exact paths for mute, leave, accept-invite are
  inferred. MUST be confirmed against `/openapi.json` and `frontend/src/api/endpoints/
  conversations.ts` before coding; adjust DTOs accordingly. If the backend models mute
  as a generic conversation-pref endpoint, swap the path but keep the repo interface.
- **Invite model (medium).** Whether "invited" is a `membership_status` on the
  conversation or a separate `/invites` resource is unconfirmed; affects how the invite
  list is discovered and the Decline semantics. Open question for backend owner.
- **Mute duration support (medium).** Backend may not support `muted_until`; if only a
  boolean is supported, the duration sheet degrades to a simple on/off toggle and
  `MuteDuration` is hidden behind a capability flag.
- **Reflection scope (low).** Conversation list filtering/indicator for muted/left
  groups may be partly owned by the conversation list ticket; coordinate to avoid
  duplicate UI logic.
- **403 handling.** Confirm server returns 403 (not 404) when a non-member reads
  settings, so `NotFound` vs error mapping is correct.

## 14. Acceptance Criteria

AC-1. From a group conversation, "Group settings" opens `GroupSettingsScreen` for that
`conversationId`, showing current name, avatar, membership status, and mute state.

AC-2. **Mute works:** toggling mute calls `PUT /conversations/{id}/mute` with the
correct body (including `muted_until: null` for "forever"), updates the switch
optimistically, persists on success, reverts + shows an error on failure, and the
muted indicator appears in the conversation list. (Covered by ViewModel, repo, and UI
tests.)

AC-3. **Leave works:** "Leave group" requires confirmation, calls
`DELETE /conversations/{id}/members/me`, only updates UI on success, emits
`LeftGroup`, navigates back, and removes/marks-left the group in the list.

AC-4. **Accept invite works:** for an `invited` conversation, "Accept invitation" calls
`POST /conversations/{id}/invite/accept`, transitions membership to `active`, and
unlocks mute/leave; "Decline" performs leave on the pending membership.

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
