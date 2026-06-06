---
id: AND-154
title: Contact → start conversation
milestone: M3
epic: E21
priority: P1
size: M
status: reviewed
reviewed_on: 2026-06-06
depends_on: [AND-153, AND-127]
blocks: []
---

# AND-154 — Contact → start conversation

## 1. Overview & Goal

This ticket wires the **contacts surface** (AND-153) to the **DM find-or-create**
flow (AND-127) so that a user can tap a contact and land directly inside the
direct-message conversation with that person. It is the connective "action"
ticket of epic **E21 (Contacts)**: AND-153 renders the list and search; AND-127
owns the `POST /messaging/conversations/dm/find-or-create` network call and the
conversation/thread screen; AND-154 is the navigation + intent glue that turns a
selected `Contact` into an open DM.

> Review note (2026-06-06): the endpoint is namespaced under `/messaging`
> (`POST /messaging/conversations/dm/find-or-create`), not bare
> `/conversations/...`. See §16 for the full citation/correction audit.

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
- **Web reference:** `frontend/src/api/endpoints/messaging.ts`
  (`findOrCreateDm`, **corrected** from `conversations.ts` which does not exist)
  and `frontend/src/api/endpoints/contacts.ts`; shared types in
  `frontend/src/api/types.ts`. **Correction:** the web app does **not** navigate
  to `/messaging/:conversationId`. `ContactsPage.tsx: handleMessage` calls
  `navigate("/messages", { state: { openConversation: convo } })` — it routes to
  a single `/messages` surface and hands the resolved `Conversation` object via
  router state. The Android port's per-conversation route
  (`conversation/{conversationId}`) is an Android-side design choice owned by
  AND-127, not a mirror of the web URL. See §16.
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
display name and avatar (web `ContactEntry` exposes `display_name` and
`profile_photo_url`; there is **no `handle` field** — any "handle"/username line
is unverified and must either be dropped or sourced from a separate profile
lookup), and a primary **"Message"** action that performs the same DM resolution
+ navigation.

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
                    // server field is `conversation_id` (ConversationOut), mapped
                    // to Conversation.conversationId by core-network
                    _events.send(ContactsEvent.OpenThread(r.data.conversationId))
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

`POST /messaging/conversations/dm/find-or-create`
(op `find_or_create_dm_messaging_conversations_dm_find_or_create_post`;
req schema `FindOrCreateDmIn`; resp `200: ConversationOut`, `422: HTTPValidationError`).

> **Corrections (2026-06-06):** the path is `/messaging/conversations/dm/find-or-create`
> (was `/conversations/dm/find-or-create`); the request field is **`user_id`**
> (was `target_user_id`); the response is a full `ConversationOut`, whose id field
> is **`conversation_id`** (not `id`) and whose discriminator is **`type`** with
> values `"dm" | "group"` (not `kind`). There is **no `created` field** in the
> schema — the "freshly created vs existing" distinction below is removed.

Request (`FindOrCreateDmIn`, single required string field `user_id`):

```json
{ "user_id": "usr_8c1f2a" }
```

Headers: session cookies + `X-CSRF-Token: <ui_csrf cookie value>`. The web client
sets `X-CSRF-Token` from the `ui_csrf` cookie on **every** request when the cookie
is present (not only mutations); see `client.ts`.

Success `200` (`ConversationOut`, abridged to fields this ticket reads —
`conversation_id`, `type`, `status` are required; `participants` is an array of
`ParticipantOut`):

```json
{
  "conversation_id": "cnv_4b2d77",
  "type": "dm",
  "status": "active",
  "created_at": 1717600000,
  "created_by": "usr_self",
  "participant_count": 2,
  "participants": [
    { "user_id": "usr_self",   "display_name": "Me",     "status": "active", "role": "member" },
    { "user_id": "usr_8c1f2a", "display_name": "Ada L.", "status": "active", "role": "member" }
  ]
}
```

This ticket navigates using `conversation_id`. Because the schema exposes no
`created` flag, both the find and the create paths are indistinguishable to the
client and are treated identically (navigate to `conversation_id`). A future
"new conversation" toast would need a backend change to surface that flag.

FastAPI error envelope (`detail` may be `string | [{msg,...}] | {code,...}`),
mapped by `core-network`'s shared parser (mirrors web `normalizeErrorDetail` in
`client.ts`). The OpenAPI spec for this op declares only `200` and `422`
(`HTTPValidationError`); `403`/`404`/`409`/`5xx` are platform-wide error
behaviours not enumerated on this op, so their exact `detail.code` strings (e.g.
`user_blocked`) are **assumptions** pending backend confirmation:

```json
{ "detail": { "code": "user_blocked", "message": "You cannot message this user." } }
```

Statuses this ticket handles: `422` (validation — should not occur with a valid
`user_id`; surfaced as a terminal error), `401` (handled globally — single
`/ui/session/refresh` then one retry, and only if the user was already
authenticated; an unauthenticated 401 propagates — see `client.ts`),
`403`/`409` blocked or not-allowed (terminal, inline message), `404` target not
found (terminal), `5x`/timeout/IO (transient, snackbar + Retry). Because
find-or-create is a **mutation, it is never auto-retried**; only the global
401-refresh-once applies.

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

## 16. Citations & Assumption Audit

Each key technical claim, its verdict, and the exact source pointer. Sources:
OpenAPI index (`reference/openapi.index.txt`), OpenAPI spec
(`reference/openapi.pretty.json`, `components.schemas.<Name>`), and the frontend
reference (`reference/src/...`).

1. **DM find-or-create endpoint path** — Claim (original): `POST
   /conversations/dm/find-or-create`. **VERDICT: Corrected** to `POST
   /messaging/conversations/dm/find-or-create`. Source: OpenAPI `POST
   /messaging/conversations/dm/find-or-create`
   (op `find_or_create_dm_messaging_conversations_dm_find_or_create_post`);
   `src/api/endpoints/messaging.ts: findOrCreateDm`.

2. **HTTP method** — Claim: `POST`. **VERDICT: Verified.** Source: OpenAPI
   `POST /messaging/conversations/dm/find-or-create`;
   `src/api/endpoints/messaging.ts: findOrCreateDm` (`api.post`).

3. **Request body field** — Claim (original): `target_user_id`. **VERDICT:
   Corrected** to `user_id`. Source: schema `FindOrCreateDmIn`
   (single required string property `user_id`);
   `src/api/endpoints/messaging.ts: findOrCreateDm` posts `{ user_id: userId }`.

4. **Response id field** — Claim (original): `id` (e.g. `cnv_...`). **VERDICT:
   Corrected** to `conversation_id`. Source: schema `ConversationOut`
   (required `conversation_id`); `src/api/types.ts: Conversation.conversation_id`;
   `src/api/endpoints/messagingAdapter.ts: adaptConversation` maps
   `conversation_id`.

5. **Response discriminator field** — Claim (original): `kind: "dm"`. **VERDICT:
   Corrected** to `type` with values `"dm" | "group"`. Source: schema
   `ConversationOut.type` (required string); `src/api/types.ts: Conversation.type:
   "dm" | "group"`.

6. **`created` boolean in response** — Claim (original): response includes
   `created` distinguishing new vs existing DM. **VERDICT: Corrected (removed).**
   No `created` property exists on `ConversationOut`. Source: schema
   `ConversationOut` properties + `required` list; `src/api/types.ts:
   Conversation` (no `created`).

7. **Response schema** — Claim: response is the conversation/thread model.
   **VERDICT: Verified** (and named). Source: OpenAPI op resp `200:ConversationOut`;
   schema `ConversationOut`; participants are
   `app__routers__messaging__ParticipantOut` (fields incl. `user_id`,
   `display_name`, `status`, `role`).

8. **Auth = cookie-based with CSRF** — Claim: cookie session + `ui_csrf` cookie
   echoed as `X-CSRF-Token`. **VERDICT: Verified.** Source: `src/api/client.ts`
   (`getCookie("ui_csrf")` → `headers.set("X-CSRF-Token", csrf)`; `credentials:
   "include"`). Nuance: CSRF header is added to **every** request when the cookie
   is present, not only mutations.

9. **401 handling = refresh-once then retry** — Claim: single
   `/ui/session/refresh` then retry, global. **VERDICT: Verified (with nuance).**
   Source: OpenAPI `POST /ui/session/refresh`; `src/api/client.ts` refresh-once
   logic. Nuance: refresh+retry only fires if the user was already authenticated;
   an unauthenticated 401 propagates directly.

10. **Current-user source for self-DM guard** — Claim: current user id from `GET
    /ui/me`. **VERDICT: Verified.** Source: OpenAPI `GET /ui/me` (op
    `ui_me_ui_me_get`); `src/api/endpoints/auth.ts: getMe` (`api.get("/ui/me")`).

11. **FastAPI error envelope shape** — Claim: `detail` may be `string |
    [{msg}] | {code,...}`. **VERDICT: Verified.** Source: `src/api/client.ts:
    normalizeErrorDetail` (handles string, array, and `{code}` object forms).

12. **Web navigation target after find-or-create** — Claim (original): web
    navigates to `/messaging/:conversationId`. **VERDICT: Corrected.** Web
    navigates to `/messages` passing the conversation via router state. Source:
    `src/pages/contacts/ContactsPage.tsx: handleMessage` →
    `navigate("/messages", { state: { openConversation: convo } })`.

13. **Web reference file for the call** — Claim (original):
    `frontend/src/api/endpoints/conversations.ts`. **VERDICT: Corrected** to
    `messaging.ts` (no `conversations.ts` exists). Source: directory listing of
    `src/api/endpoints/` (`messaging.ts` present, `conversations.ts` absent);
    `src/api/endpoints/messaging.ts: findOrCreateDm`.

14. **Contact identifier field** — Claim (original): a contact's `userId`.
    **VERDICT: Corrected/clarified.** The web contact model keys on `contact_id`
    (the target user's id), passed straight into `findOrCreateDm`. Source:
    `src/api/types.ts: ContactEntry.contact_id`;
    `src/pages/contacts/ContactsPage.tsx: handleMessage` uses
    `contact.contact_id`. The Android `Contact.userId` must map to this id.

15. **Contact profile "handle" field** — Claim (original): profile shows display
    name, handle, avatar. **VERDICT: Corrected.** `ContactEntry` exposes only
    `display_name` and `profile_photo_url`; no `handle`. Source: `src/api/types.ts:
    ContactEntry`.

16. **Validation error code** — Claim: op returns validation errors. **VERDICT:
    Verified.** Source: OpenAPI op resp `422:HTTPValidationError`.

17. **Android navigation route `conversation/{conversationId}` and
    `launchSingleTop`** — **VERDICT: Unverified-assumption (Android-side design,
    owned by AND-127).** Not derivable from web (web uses `/messages` + state).
    Compose `NavController.launchSingleTop` semantics are a
    framework behaviour (framework ref:
    https://developer.android.com/guide/navigation/backstack ).

18. **`StateFlow` + `Channel`-backed one-shot events pattern** — **VERDICT:
    Unverified-assumption (Android platform convention).** Framework ref:
    https://developer.android.com/topic/architecture/ui-layer/events .

### Corrections made

- §1, §2, §5, §4 (ViewModel snippet): endpoint path corrected
  `/conversations/dm/find-or-create` → `/messaging/conversations/dm/find-or-create`.
- §5: request field `target_user_id` → `user_id` (`FindOrCreateDmIn`).
- §5, §4: response id `id` → `conversation_id`; discriminator `kind` → `type`
  (`"dm"|"group"`); removed the non-existent `created` field and its semantics.
- §2: web reference file `conversations.ts` → `messaging.ts`; corrected the web
  navigation claim (it routes to `/messages` with router state, not
  `/messaging/:conversationId`).
- §3 (FR-2): removed the unsupported "handle" field from the profile screen.
- §5: clarified 401 refresh-once nuance and that the op formally declares only
  `200`/`422`; flagged `403/404/409` codes as platform-level assumptions.

### Open assumptions

- **Error `detail.code` strings** (`user_blocked`, not-found code, etc.) and the
  exact non-2xx statuses (`403`/`404`/`409`) for find-or-create: the OpenAPI op
  declares only `200`/`422`, so these are inferred from platform conventions and
  unconfirmed against the backend. *Why:* not enumerated in `openapi.pretty.json`
  for this op.
- **Android per-conversation route + `launchSingleTop` back-stack behaviour:**
  Android-only design owned by AND-127; not mirrored by the web client (which uses
  a single `/messages` surface). *Why:* no web/OpenAPI source defines an Android
  route.
- **Self-DM guard rejection by backend:** whether the server rejects a self
  `user_id` (and with what status) is unconfirmed; the client-side guard is
  belt-and-suspenders. *Why:* not specified in the schema or web code.
- **`Contact.userId` ↔ `contact_id` mapping owned by AND-153:** assumed that
  AND-153's `Contact.userId` carries the same opaque id as web `contact_id`.
  *Why:* AND-153 source not in this review's reference set.

## 17. Test Plan

Test-target legend: **JVM** = JVM unit/Robolectric (no device); **emu35** =
headless emulator AVD `test35` (x86_64, API 35) in CI; **deviceA15** = physical
Samsung Galaxy A15 5G (SM-A156U, serial R5CX821TA9R, API 34, arm64-v8a). Cases
are sized to a navigation/glue ticket; the heavy hardware targets (camera,
biometrics, FCM, WebRTC) are out of scope for this ticket, so most run on JVM or
emu35.

- **TC-AND-154-01** — Type: unit (JVM, Turbine + MockK). Target: `ContactsViewModel`.
  Preconditions: `findOrCreateDm` stubbed to return
  `ApiResult.Success(Conversation(conversationId="cnv_1", type="dm", ...))`;
  `session.currentUserId != target`. Steps: call `onContactClick(contact)`.
  Expected: emits `ContactsEvent.OpenThread("cnv_1")`; `pendingDmUserId`
  toggles non-null→null across the call; no snackbar event. Traces: AC-1, AC-7.

- **TC-AND-154-02** — Type: unit (JVM). Target: `ContactsViewModel`.
  Preconditions: `findOrCreateDm` stubbed `ApiResult.Success`. Steps: call
  `onMessageClick(userId)` (profile path). Expected: emits
  `OpenThread(conversationId)`; single use-case invocation. Traces: AC-2.

- **TC-AND-154-03** — Type: unit (JVM). Target: `ContactsViewModel` re-entrancy.
  Preconditions: `findOrCreateDm` suspended (never completes within test).
  Steps: call `onContactClick(c)` twice for the same contact while pending.
  Expected: `verify(exactly = 1) { findOrCreateDm(...) }`; only one
  `pendingDmUserId` transition; no second `OpenThread`. Traces: AC-3.

- **TC-AND-154-04** — Type: unit (JVM). Target: self-DM guard.
  Preconditions: `session.currentUserId == target`. Steps: call
  `onContactClick(selfContact)`. Expected: `findOrCreateDm` never invoked
  (`verify(exactly = 0)`); no events emitted. Traces: AC-6.

- **TC-AND-154-05** — Type: unit (JVM). Target: transient-error + retry path.
  Preconditions: `findOrCreateDm` returns `ApiResult.Error` (transient) on first
  call, `Success` on second. Steps: `onContactClick(c)`; on `ShowSnackbar` invoke
  `startDm(retryUserId)`. Expected: first emits `ShowSnackbar` with non-null
  `retryUserId` and **no** `OpenThread`; retry emits `OpenThread`; use case
  invoked twice. Traces: AC-5.

- **TC-AND-154-06** — Type: contract/MockWebServer (emu35 or JVM-Robolectric).
  Target: `ConversationRepository`/`FindOrCreateDmUseCase` transport (consuming
  AND-127). Preconditions: MockWebServer enqueues `200` with a real
  `ConversationOut` body (`conversation_id`, `type:"dm"`, `status:"active"`,
  `participants[]`). Steps: invoke use case with `user_id`. Expected: request is
  `POST /messaging/conversations/dm/find-or-create` with JSON body
  `{"user_id": "..."}` and header `X-CSRF-Token` equal to the `ui_csrf` cookie;
  parsed `Conversation.conversationId == "cnv_..."`. Traces: AC-1.

- **TC-AND-154-07** — Type: contract/MockWebServer. Target: error mapping.
  Preconditions: MockWebServer enqueues `403` with body
  `{"detail":{"code":"user_blocked","message":"..."}}`. Steps: invoke use case.
  Expected: `ApiResult.Error` classified terminal (no Retry); message derived
  from `detail` via the shared parser. (Note: `403`/`user_blocked` is an
  assumed shape per §16 — keep the assertion on classification + parser, not the
  literal code, until backend-confirmed.) Traces: AC-5.

- **TC-AND-154-08** — Type: contract/MockWebServer. Target: 401 refresh-once.
  Preconditions: authenticated session; MockWebServer enqueues `401`, then
  `200` for `POST /ui/session/refresh`, then `200 ConversationOut` for the
  retried find-or-create. Steps: invoke use case. Expected: exactly one
  `/ui/session/refresh` call, then one retry of find-or-create, then success;
  resulting `OpenThread`. Traces: AC-1, AC-5.

- **TC-AND-154-09** — Type: integration/instrumented (emu35; or **deviceA15** to
  exercise real Wi-Fi/airplane toggling — PREFER deviceA15 for the genuine
  offline transition). Target: offline short-circuit (FR-8). Preconditions:
  network disabled (airplane mode on deviceA15, or `ConnectivityObserver` faked
  offline on emu35). Steps: tap a contact row. Expected: immediate "You're
  offline" snackbar with Retry; no persistent row spinner; **no** find-or-create
  request observed. Toggling network on + Retry then succeeds. Traces: AC-5, AC-7.

- **TC-AND-154-10** — Type: Compose-UI (emu35, `createAndroidComposeRule`, fake
  ViewModel). Target: `ContactsScreen` row busy state. Preconditions: fake state
  with `pendingDmUserId = contact.userId`. Steps: render. Expected: tapped row
  shows trailing spinner; on fake success the `onOpenThread` callback receives the
  returned `conversationId`; rest of list remains clickable. Traces: AC-1, AC-7.

- **TC-AND-154-11** — Type: Compose-UI (emu35). Target: `ContactProfileScreen`
  Message button. Preconditions: profile rendered for a non-self contact. Steps:
  tap "Message"; observe pending then success. Expected: button disabled + spinner
  while pending, re-enabled after; self contact renders disabled "You" variant
  and does not call the use case. Traces: AC-2, AC-6, AC-7.

- **TC-AND-154-12** — Type: instrumented/e2e nav (emu35, `TestNavHostController`).
  Target: NavHost back-stack + `launchSingleTop`. Preconditions: NavHost wired
  with `ContactsRoutes.LIST` and `MessagingRoutes.THREAD_PATTERN`. Steps: open
  the same DM thread twice via `OpenThread`; press Back. Expected: a single
  `conversation/{id}` destination on the back stack (no duplicate); Back returns
  to `contacts`. Traces: AC-4.

- **TC-AND-154-13** — Type: Compose-UI accessibility (emu35, TalkBack semantics
  assertions). Target: row + profile a11y. Preconditions: contacts list rendered.
  Steps: assert semantics. Expected: row tap action has `contentDescription
  "Message {name}"` and ≥48dp target; busy spinner exposes `stateDescription
  "Starting conversation"`; disabled self state announces "Messaging yourself is
  not available"; snackbar Retry is focusable with a content description. Traces:
  AC-6, AC-7.

- **TC-AND-154-14** — Type: manual (deviceA15, real dev host
  `http://18.222.237.167:8000`). Target: end-to-end on the flaky plaintext dev
  backend. Preconditions: signed-in build pointed at the dev host; cleartext
  permitted for that host only. Steps: from contacts, tap a contact and wait
  through dev-host latency; repeat to an already-existing DM. Expected: thread
  opens for both find and create paths; slow responses show only the inline
  spinner (bounded ~20s) with Retry on timeout; production build still rejects
  cleartext (verify the network-security config). Traces: AC-1, AC-4, AC-5.

### Coverage matrix

| AC | Description | Covered by |
|----|-------------|-----------|
| AC-1 | Tap contact opens DM thread (`conversation_id`) | TC-01, TC-06, TC-08, TC-10, TC-14 |
| AC-2 | Profile "Message" opens same DM | TC-02, TC-11 |
| AC-3 | Single call per initiation; double-tap guarded | TC-03 |
| AC-4 | Back returns to contacts; `launchSingleTop` no dupes | TC-12, TC-14 |
| AC-5 | Transient/offline → snackbar+Retry; terminal → inline, no nav | TC-05, TC-07, TC-08, TC-09, TC-14 |
| AC-6 | Self-DM disabled/"You", never calls backend | TC-04, TC-11, TC-13 |
| AC-7 | Inline busy on originating affordance; list stays interactive | TC-01, TC-09, TC-10, TC-11, TC-13 |
