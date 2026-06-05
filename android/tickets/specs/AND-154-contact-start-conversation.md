---
id: AND-154
title: Contact → start conversation
milestone: M3
epic: E21
priority: P1
size: M
status: draft
depends_on: [AND-153, AND-127]
blocks: []
---

# AND-154 — Contact → start conversation

## 1. Overview & Goal

This ticket wires the **contacts surface** (AND-153) to the **DM find-or-create**
flow (AND-127) so that a user can tap a contact and land directly inside the
direct-message conversation with that person. It is the connective "action"
ticket of epic **E21 (Contacts)**: AND-153 renders the list and search; AND-127
owns the `POST /conversations/dm/find-or-create` network call and the
conversation/thread screen; AND-154 is the navigation + intent glue that turns a
selected `Contact` into an open DM.

Two entry affordances are in scope:

1. **Tap a contact row → open DM** (primary, satisfies the acceptance bullet
   "Starting from a contact opens the DM").
2. **Open contact profile → "Message" button → open DM** (the "Open profile"
   half of the scope line).

The deliverable is a small, well-tested feature slice in `feature-contacts`
that resolves a `userId` to a `conversationId` via the find-or-create use case
and navigates to the thread route, with correct loading, dedupe, error, and
back-stack behaviour. No new networking endpoint is introduced here — AND-127
owns the contract; this ticket consumes it.

## 2. Context & References

- **Repo:** `spannella/testlogon`, Android app under `android/`, branch
  `android-port`. Namespace/applicationId base `com.testlogon.android`.
- **Module:** `feature-contacts` (introduced in AND-153), depending on
  `feature-messaging`'s public navigation contract (introduced in AND-127),
  `core-data`, `core-model`, `core-network`, `core-ui`.
- **Web reference:** `frontend/src/api/endpoints/conversations.ts`
  (`findOrCreateDm`) and `frontend/src/api/endpoints/contacts.ts`; shared types
  in `frontend/src/api/types.ts`. The web app navigates from a contact card to
  `/messaging/:conversationId` after the find-or-create resolves.
- **Backend:** FastAPI + DynamoDB, dev host `http://18.222.237.167:8000`
  (plaintext HTTP, unreliable). OpenAPI at `/openapi.json`. Auth is
  cookie-based with the `ui_csrf` cookie echoed as `X-CSRF-Token`.
- **Depends on:**
  - **AND-153 — Contacts list + search:** provides `ContactsScreen`,
    `ContactsViewModel`, `Contact` model, and `contacts` nav route.
  - **AND-127 — DM find-or-create:** provides `FindOrCreateDmUseCase`,
    `ConversationRepository`, the `conversation/{conversationId}` thread route,
    and the typed response model. This ticket calls that use case; it does not
    redefine it.

## 3. Functional Requirements

FR-1. Tapping a contact row in `ContactsScreen` triggers DM resolution for that
contact's `userId` and, on success, navigates to the thread screen for the
returned `conversationId`.

FR-2. A contact **profile** screen (`ContactProfileScreen`) is reachable from a
row's overflow/long-press or a row-trailing chevron; it shows the contact's
display name, handle, avatar, and a primary **"Message"** action that performs
the same DM resolution + navigation.

FR-3. While resolution is in flight, the originating affordance shows an inline
busy state (row trailing spinner, or disabled "Message" button with spinner).
The rest of the contacts list remains interactive.

FR-4. **Re-entrancy / double-tap guard:** a second tap on the same contact while
its resolution is pending is ignored (no duplicate `find-or-create` calls, no
duplicate navigation).

FR-5. On a successful resolution, navigation to the thread route uses
`launchSingleTop = true` so repeated entry to the same DM does not stack
duplicate thread destinations. The contacts screen remains on the back stack;
pressing Back from the thread returns to contacts.

FR-6. On failure, resolution does **not** navigate; an error is surfaced
(snackbar for transient/network errors with a Retry action; inline message for
terminal errors such as a blocked or non-existent target).

FR-7. Self-DM guard: if the resolved target `userId` equals the current user's
id (from `GET /ui/me`), the affordance is disabled and labelled "You" — the
backend find-or-create is never invoked for self.

FR-8. The feature works in offline/stale states: if the device is offline at tap
time, no spinner churn — an immediate "You're offline" snackbar with Retry is
shown (find-or-create is a mutation and is **not** retried automatically).

## 4. Technical Design

### Module placement

All new code lives in `feature-contacts`. The thread route key and the DM
use case are imported from the messaging public surface owned by AND-127; this
ticket must not duplicate them.

```kotlin
// core navigation contract consumed here (owned by AND-127 / AND-153)
object MessagingRoutes {
    fun thread(conversationId: String) = "conversation/$conversationId"
    const val THREAD_PATTERN = "conversation/{conversationId}"
}
object ContactsRoutes {
    const val LIST = "contacts"
    const val PROFILE_PATTERN = "contacts/{userId}"
    fun profile(userId: String) = "contacts/$userId"
}
```

### Use case (from AND-127, consumed)

```kotlin
class FindOrCreateDmUseCase @Inject constructor(
    private val repo: ConversationRepository,
) {
    suspend operator fun invoke(targetUserId: String): ApiResult<Conversation>
}
```

### ViewModel

The contacts ViewModel gains a single-shot navigation channel and per-contact
pending state. `ContactsViewModel` is extended (not replaced) from AND-153.

```kotlin
data class ContactsUiState(
    val query: String = "",
    val contacts: List<Contact> = emptyList(),
    val isLoading: Boolean = false,
    val pendingDmUserId: String? = null,   // contact currently resolving
    val error: UiText? = null,
)

sealed interface ContactsEvent {
    data class OpenThread(val conversationId: String) : ContactsEvent
    data class ShowSnackbar(val text: UiText, val retryUserId: String?) : ContactsEvent
}

@HiltViewModel
class ContactsViewModel @Inject constructor(
    private val contactsRepo: ContactsRepository,       // AND-153
    private val findOrCreateDm: FindOrCreateDmUseCase,  // AND-127
    private val session: SessionStore,                  // current user id
) : ViewModel() {

    val uiState: StateFlow<ContactsUiState>
    private val _events = Channel<ContactsEvent>(Channel.BUFFERED)
    val events: Flow<ContactsEvent> = _events.receiveAsFlow()

    fun onContactClick(contact: Contact) = startDm(contact.userId)
    fun onMessageClick(userId: String) = startDm(userId)

    private fun startDm(targetUserId: String) {
        val state = uiState.value
        if (state.pendingDmUserId != null) return                 // FR-4 guard
        if (targetUserId == session.currentUserId) return         // FR-7 guard
        viewModelScope.launch {
            _state.update { it.copy(pendingDmUserId = targetUserId) }
            when (val r = findOrCreateDm(targetUserId)) {
                is ApiResult.Success ->
                    _events.send(ContactsEvent.OpenThread(r.data.id))
                is ApiResult.Error ->
                    _events.send(ContactsEvent.ShowSnackbar(r.message, targetUserId))
            }
            _state.update { it.copy(pendingDmUserId = null) }
        }
    }
}
```

### Compose wiring

```kotlin
@Composable
fun ContactsRoute(
    onOpenThread: (conversationId: String) -> Unit,
    onOpenProfile: (userId: String) -> Unit,
    viewModel: ContactsViewModel = hiltViewModel(),
) {
    val state by viewModel.uiState.collectAsStateWithLifecycle()
    val snackbarHost = remember { SnackbarHostState() }
    ObserveAsEvents(viewModel.events) { event ->
        when (event) {
            is ContactsEvent.OpenThread -> onOpenThread(event.conversationId)
            is ContactsEvent.ShowSnackbar -> { /* show + Retry -> startDm */ }
        }
    }
    ContactsScreen(state, snackbarHost, viewModel::onContactClick, onOpenProfile)
}
```

In the single-Activity `NavHost`:

```kotlin
composable(ContactsRoutes.LIST) {
    ContactsRoute(
        onOpenThread = { id ->
            navController.navigate(MessagingRoutes.thread(id)) {
                launchSingleTop = true            // FR-5
            }
        },
        onOpenProfile = { uid -> navController.navigate(ContactsRoutes.profile(uid)) },
    )
}
composable(ContactsRoutes.PROFILE_PATTERN) { /* ContactProfileRoute, same use case */ }
```

The "OpenThread → navigate" is delegated to the NavHost (not done inside the
ViewModel) so the ViewModel stays free of `NavController` and remains unit-
testable.

## 5. API Contract

This ticket introduces **no new endpoint**. It consumes the find-or-create
contract owned by **AND-127**. The shape consumed (for reference only; the
canonical definition lives in AND-127's spec) is:

`POST /conversations/dm/find-or-create`

Request:

```json
{ "target_user_id": "usr_8c1f2a" }
```

Headers: session cookies + `X-CSRF-Token: <ui_csrf cookie value>`.

Success `200`:

```json
{
  "id": "cnv_4b2d77",
  "kind": "dm",
  "created": false,
  "participants": [
    { "user_id": "usr_self",   "display_name": "Me" },
    { "user_id": "usr_8c1f2a", "display_name": "Ada L." }
  ]
}
```

`created` distinguishes a freshly created DM from an existing one; this ticket
treats both identically (navigate to `id`).

FastAPI error envelope (`detail` may be `string | [{msg}] | {code,...}`),
mapped by `core-network`'s shared parser:

```json
{ "detail": { "code": "user_blocked", "message": "You cannot message this user." } }
```

Relevant statuses this ticket handles: `401` (handled globally — single
`/ui/session/refresh` then retry, per platform rule), `403`/`409` blocked or
not-allowed (terminal, inline message), `404` target not found (terminal),
`5x`/timeout/IO (transient, snackbar + Retry). Because find-or-create is a
**mutation, it is never auto-retried**; only the global 401-refresh-once applies.

## 6. Data & State Management

- **No new persistence.** The `Contact` list and its Room/Paging cache are owned
  by AND-153; the `Conversation`/thread cache is owned by AND-127. AND-154 holds
  only transient in-memory state (`pendingDmUserId`) inside the ViewModel.
- **Current user id** is read from `SessionStore` (DataStore-backed, populated
  from `GET /ui/me`) for the self-DM guard (FR-7).
- **State exposure** follows the platform rule: `StateFlow<ContactsUiState>` for
  screen state; a `Channel`-backed `Flow<ContactsEvent>` for one-shot navigation
  / snackbar effects (so navigation does not re-fire on recomposition or config
  change).
- **Process death:** `pendingDmUserId` is intentionally not persisted; an in-
  flight find-or-create that is killed by process death simply does not navigate.
  On restore the user re-taps. (Documented as accepted behaviour, not a bug.)
- **Cache write-through:** when AND-127's repository returns a `Conversation`, it
  upserts into the conversations cache; this ticket relies on that so the thread
  screen can render immediately. AND-154 performs no direct cache writes.

## 7. Error Handling & Resilience

| Condition | Detection | UI behaviour |
|---|---|---|
| Offline at tap | `ConnectivityObserver` reports no network (or immediate IO error) | "You're offline" snackbar + Retry; no spinner persists (FR-8) |
| Timeout (~20s) / 5xx / IO | `ApiResult.Error` with transient classification | Snackbar "Couldn't start the conversation" + Retry → `startDm(retryUserId)` |
| 403/409 blocked / not allowed | mapped `detail.code` | Inline terminal message; no Retry |
| 404 target not found | status 404 | Inline "This contact is unavailable"; no Retry |
| 401 | global OkHttp authenticator | one `POST /ui/session/refresh` then retry; if still 401 → route to re-auth |
| Double tap same contact | `pendingDmUserId != null` | second tap ignored (FR-4) |

Timeouts use the platform OkHttp config (~20s). **No automatic backoff retry**
is applied because find-or-create is a non-idempotent mutation; the bounded
backoff rule applies only to idempotent GETs. Retry is user-initiated via the
snackbar action.

## 8. Security & Privacy

- All requests ride the persistent cookie jar; the mutation includes the
  `X-CSRF-Token` header sourced from the `ui_csrf` cookie (enforced by the shared
  OkHttp interceptor). No tokens or user ids are logged in plaintext.
- The self-DM guard prevents constructing a self-conversation and avoids leaking
  the current user's id into a target slot.
- Contact `userId`s are opaque server ids; they are passed only as route
  arguments and request bodies, never written to logs or analytics with PII. The
  profile route argument (`userId`) is an opaque id, not a username/email.
- Dev backend is plaintext HTTP; the app's network-security config must continue
  to permit the dev cleartext host only (inherited from `core-network`), and
  production builds must reject cleartext. No change to that policy here.

## 9. Accessibility & i18n

- Contact rows: full-row click target (min 48dp height), `contentDescription`
  "Message {name}" on the tap action; the trailing busy spinner exposes
  `stateDescription = "Starting conversation"`.
- "Message" button on the profile screen has a visible label and a
  `Modifier.semantics` role of Button; disabled "You" state announces
  "Messaging yourself is not available".
- Snackbar Retry action is reachable via TalkBack and has a discrete content
  description.
- All user-facing strings (`"Message"`, error/snackbar copy, "You're offline",
  "Starting conversation") are `strings.xml` resources wrapped via `UiText`; no
  hard-coded literals in Compose. No date/number/RTL formatting concerns unique
  to this ticket beyond inherited list rendering.

## 10. Telemetry & Logging

Emit structured analytics events via the shared `Analytics` facade (no PII;
ids hashed/opaque only where the platform already does so):

- `contact_dm_initiated { source: "row" | "profile" }`
- `contact_dm_opened { created: Boolean, latency_ms: Long }`
- `contact_dm_failed { reason: "offline" | "timeout" | "blocked" | "not_found" | "other" }`

Logging: use the `core` Timber tree at `DEBUG` for the find-or-create call
lifecycle (start, result class, latency); never log request/response bodies or
cookies. Latency is measured from tap to the `OpenThread` event for the
`latency_ms` field.

## 11. Testing Strategy

**Unit (ViewModel, `core-testing` + Turbine + MockK):**

- `onContactClick` success → emits `OpenThread(conversationId)` and clears
  `pendingDmUserId`.
- `onContactClick` error (transient) → emits `ShowSnackbar` with non-null
  `retryUserId`; no `OpenThread`.
- Double-tap while pending → use case invoked exactly once (`verify(exactly = 1)`).
- Self-DM (`targetUserId == currentUserId`) → use case never invoked, no events.
- Retry path → `startDm` re-invokes use case after a prior failure.
- `pendingDmUserId` toggles true during the call and false after (asserted via
  Turbine state sequence).

**UI (Compose `createAndroidComposeRule`, fake ViewModel/use case):**

- Tapping a row shows the row spinner and, on fake success, asserts the
  navigation callback received the returned `conversationId`.
- Profile "Message" button disabled + spinner while pending; re-enabled after.
- Offline fake → snackbar "You're offline" with Retry visible.
- `launchSingleTop` behaviour: navigating to the same thread twice yields a
  single thread destination (NavController test via `TestNavHostController`).

**Instrumentation / integration (against MockWebServer):**

- find-or-create `200 created=false` and `created=true` both navigate.
- `403 user_blocked` → terminal inline message, no navigation.
- 401 → refresh-once interceptor retries and then succeeds.

Acceptance test mirroring the backlog bullet: "from contacts, tapping a contact
opens the DM" is the headline instrumentation test (`startFromContact_opensDm`).

## 12. Dependencies & Sequencing

- **Hard depends_on:** AND-153 (contacts screen, `Contact`, ViewModel base,
  routes) and AND-127 (`FindOrCreateDmUseCase`, `ConversationRepository`, thread
  route, response model). Both must be merged before this ticket can compile.
- **Transitive:** AND-120 (shared API/session client) via both deps.
- **Sequencing:** implement after AND-153 and AND-127. If AND-127's thread route
  key is not yet stable, gate on its `MessagingRoutes` contract landing first to
  avoid a route-string mismatch.
- **Blocks:** nothing in the current backlog declares AND-154 as a dependency.

## 13. Risks & Open Questions

- **Route-key drift:** AND-154 hard-codes navigation to AND-127's
  `conversation/{conversationId}` pattern. Mitigation: consume the shared
  `MessagingRoutes` object rather than a literal string; add a compile-time
  reference test.
- **`created` flag semantics:** confirmed N/A to this ticket (both branches
  navigate), but a future "new conversation" toast may want it — left to a
  follow-up.
- **Open Q:** Does the contact row also need a long-press context menu (call /
  view profile / block) in M3, or only tap-to-DM + chevron-to-profile? Current
  spec assumes tap-to-DM + trailing chevron-to-profile; broader menu is out of
  scope.
- **Open Q:** Should an existing DM with unread messages deep-link to the unread
  anchor? Owned by AND-127's thread screen; not this ticket.
- **Risk:** find-or-create latency on the unreliable dev host may make the row
  spinner feel slow (~up to 20s). Accepted; mitigated by Retry and the offline
  short-circuit.

## 14. Acceptance Criteria

AC-1. From the contacts list, tapping a contact resolves and opens the DM thread
for that contact (the returned `conversationId`). **(Backlog bullet.)**

AC-2. From a contact profile, the "Message" action opens the same DM thread.

AC-3. A single find-or-create call is made per initiation; double-tapping the
same contact while pending does not produce a second call or second navigation.

AC-4. Returning Back from the thread lands on the contacts screen; re-opening the
same DM does not stack duplicate thread destinations (`launchSingleTop`).

AC-5. Transient/offline failures show a snackbar with a working Retry that
re-attempts; terminal failures (blocked/not-found) show an inline message and do
not navigate.

AC-6. The self-DM affordance is disabled/labelled "You" and never calls the
backend.

AC-7. While resolving, an inline busy indicator is shown on the originating
affordance and the rest of the list stays interactive.

## 15. Definition of Done

- `feature-contacts` builds on branch `android-port` against `compileSdk 35`,
  Kotlin 2.0.21, AGP 8.7.3, JDK 17; Hilt/KSP graph compiles.
- ViewModel unit tests, Compose UI tests, and the MockWebServer integration
  tests in section 11 pass in CI; the headline `startFromContact_opensDm` test
  passes.
- No hard-coded user-facing strings; all routed through `strings.xml` / `UiText`.
- No new endpoint added; AND-127's `FindOrCreateDmUseCase` and `MessagingRoutes`
  are consumed unchanged.
- ktlint/detekt clean; no new lint baseline entries; no plaintext logging of ids,
  cookies, or bodies.
- Telemetry events from section 10 emitted and verified in a debug build.
- PR links AND-153 and AND-127, includes a short demo of contact→DM (row and
  profile paths), and is reviewed/approved per repo policy.
