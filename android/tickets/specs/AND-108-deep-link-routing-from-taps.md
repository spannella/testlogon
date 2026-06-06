---
id: AND-108
title: Deep-link routing from taps
milestone: M2
epic: E15
priority: P0
size: M
status: reviewed
reviewed_on: 2026-06-06
depends_on: [AND-107, AND-022]
blocks: []
---

# AND-108 — Deep-link routing from taps

## 1. Overview & Goal

When a user taps a system notification posted by the TestLogon Android app, the app
must open and route directly to the in-app screen that the notification is about —
a specific message thread, a broadcast detail, or an alert detail — rather than
dumping the user on a generic home/start destination. This ticket owns the
**payload → in-app destination** mapping and the navigation plumbing that performs
the routing reliably across cold start, warm start, and already-running states.

AND-107 (FCM message handling / notification posting) is upstream: it receives the
push payload, decides whether to post a notification, and constructs the
`PendingIntent`. AND-108 defines the **contract for what data that `PendingIntent`
carries**, parses it back out on tap, maps it to a type-safe `NavRoute`, and drives
`TestLogonNavHost` (AND-022) to that destination. The deliverable is a tested,
deterministic deep-link router: tapping a notification opens the correct screen with
the correct arguments, with correct back-stack behavior, and with safe fallbacks
when the payload is malformed, the referenced entity is gone, or the user is logged
out.

Out of scope: receiving/handling the FCM message and posting the notification
(AND-107), notification channels/permission (AND-105/AND-106 in the notifications
epic), external web `https://` App Links / browsable URLs (a later marketing-link
ticket), and the actual message/broadcast/alert feature screens themselves (their
own feature tickets) — this ticket only routes *to* them via their already-defined
route types.

## 2. Context & References

- **Stack:** Kotlin 2.0.21, Jetpack Compose + Material 3, single-Activity
  Navigation-Compose 2.8.x type-safe routes, Hilt (KSP), Coroutines/Flow. minSdk 24,
  compileSdk/targetSdk 35, JDK 17, AGP 8.7.3, Gradle 8.9.
- **Package base (exact):** `com.testlogon.android`.
  - Deep-link parsing/mapping: `com.testlogon.android.navigation.deeplink`
  - App nav host + routes: `com.testlogon.android.navigation`
  - Shared nav primitives (`NavRoute`, `TopLevelRoute`): `com.testlogon.android.core.ui.navigation`
- **Module layering:** `app -> feature-* -> core-*`. The deep-link router and the
  `MainActivity` intent handling live in the `app` module (only `app` sees every
  feature route). The serializable `DeepLink` payload model and the
  `payload → route` interface live in `core-model` / `core-ui.navigation` so AND-107
  can construct the same payload type without depending on `app`.
- **Repo:** `spannella/testlogon`, Android app under `android/`, branch
  `android-port`.
- **Upstream — AND-107 (FCM handling):** posts the notification and builds the
  `PendingIntent`. AND-108 publishes the `NotificationDeepLink` contract (extras
  keys + factory) that AND-107 *must* use when building that intent. Both tickets
  reference the same constants object to avoid drift.
- **Upstream — AND-022 (Navigation host & routes):** provides `TestLogonNavHost`,
  the `NavRoute`/`TopLevelRoute` markers, `composable<T>` registration, and the
  callback/navigator conventions AND-108 builds on. AND-108 adds a deep-link entry
  path into that same single `NavHost`.
- **Feature route types consumed (defined by their feature tickets):**
  `MessageThread(threadId: String)`, `BroadcastDetail(broadcastId: String)`,
  `AlertDetail(alertId: String)`, and the authenticated `Home` top-level route. If a
  feature route is not yet merged when AND-108 lands, a temporary placeholder route
  of the same shape is used and swapped on merge (see §13).
- **Web reference (CORRECTED — verified against `reference/src/App.tsx`):** the web
  app's per-entity detail route for messages is `messages/:conversationId` (note: the
  route param is `conversationId`, and the underlying entity is a *conversation*, not a
  free "thread"; `MessagesPage` also opens a conversation via router `state`). There is
  **no** `/broadcasts/:id` route and **no** `/alerts/:id` route in the web app: the
  broadcast surface is `broadcast` / `broadcast/:sessionId/live-qa` (keyed by
  *session*), and `alerts` is a **list-only** page (no per-alert detail route). The
  earlier draft claim of `/messages/:id`, `/broadcasts/:id`, `/alerts/:id` was
  inaccurate; see §16. Android still mirrors the *information model* with type-safe
  in-process routes (not URL strings), but implementers must confirm the actual
  Android detail-route shapes with the feature-screen owners (the `broadcastId` /
  `alertId` route args used below are Android-side assumptions, since the web app has no
  matching per-id detail route — see §16 Open assumptions).
- **Auth context:** the app is cookie-session based (see project auth flow). A tap
  while logged out must land on Login and resume to the intended destination
  post-auth (§6, §7). No new backend endpoints are introduced by this ticket.

## 3. Functional Requirements

1. **Payload contract.** A single canonical extras contract carries the deep-link
   target on the notification `PendingIntent`: a `type` discriminator
   (`message` | `broadcast` | `alert`) plus the relevant entity id. AND-107 builds
   it via a factory exposed here; AND-108 parses it.
2. **Type → destination mapping.** `message → MessageThread(threadId)`,
   `broadcast → BroadcastDetail(broadcastId)`, `alert → AlertDetail(alertId)`. The
   mapping is total and centralized in one function.
3. **Cold start.** Tapping a notification when the app process is dead launches
   `MainActivity`, and after the `NavHost` is composed, navigates to the mapped
   destination — not the default start destination.
4. **Warm start / already running.** Tapping when `MainActivity` already exists
   delivers the intent via `onNewIntent` and routes to the mapped destination
   without recreating the Activity or losing unrelated state.
5. **Synthetic back stack.** After deep-linking to a detail screen, pressing Back
   returns the user to a sensible parent (the authenticated `Home` / relevant list),
   not straight out of the app, so a cold-start deep link is not a dead end.
6. **Logged-out handling.** If the deep link arrives while unauthenticated, the user
   is routed to Login; on successful auth the **pending** deep link is consumed and
   the user continues to the intended destination.
7. **Idempotent consumption.** A given launch intent is routed exactly once.
   Rotation, recomposition, or returning from background must not re-trigger the same
   navigation. The intent's deep-link extras are cleared/marked-consumed after use.
8. **Malformed / unknown payload.** Missing type, unknown type, or missing/blank id
   never crashes; the app opens to a safe default (`Home` if authenticated, else
   Login) and the event is logged (§10).
9. **Single source of truth.** All routing flows through the one `TestLogonNavHost`;
   no second Activity or parallel navigation path is introduced.

## 4. Technical Design

### 4.1 Deep-link payload model & extras contract

```kotlin
// core-model: com.testlogon.android.navigation.deeplink (shared with AND-107)
import kotlinx.serialization.Serializable

@Serializable
sealed interface NotificationDeepLink {
    @Serializable data class Message(val threadId: String) : NotificationDeepLink
    @Serializable data class Broadcast(val broadcastId: String) : NotificationDeepLink
    @Serializable data class Alert(val alertId: String) : NotificationDeepLink
}

/** Single source of the Intent extras keys + values shared by AND-107 and AND-108. */
object DeepLinkContract {
    const val EXTRA_TYPE = "tl.deeplink.type"   // "message" | "broadcast" | "alert"
    const val EXTRA_ID   = "tl.deeplink.id"
    const val EXTRA_CONSUMED = "tl.deeplink.consumed"

    const val TYPE_MESSAGE = "message"
    const val TYPE_BROADCAST = "broadcast"
    const val TYPE_ALERT = "alert"
}
```

### 4.2 Building the PendingIntent (consumed by AND-107)

AND-107 calls this factory so the producer and consumer never diverge:

```kotlin
// app: com.testlogon.android.navigation.deeplink
object DeepLinkIntentFactory {
    fun pendingIntent(context: Context, link: NotificationDeepLink): PendingIntent {
        val intent = Intent(context, MainActivity::class.java).apply {
            flags = Intent.FLAG_ACTIVITY_SINGLE_TOP or Intent.FLAG_ACTIVITY_CLEAR_TOP
            putExtra(DeepLinkContract.EXTRA_TYPE, link.typeString())
            putExtra(DeepLinkContract.EXTRA_ID, link.id())
        }
        return PendingIntent.getActivity(
            context,
            link.requestCode(),                 // stable per (type,id) to avoid collisions
            intent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
        )
    }
}
```

`FLAG_IMMUTABLE` is mandatory (minSdk 24 / target 35). `SINGLE_TOP` ensures a warm
tap reuses the existing `MainActivity` and arrives via `onNewIntent`.

### 4.3 Parser (Intent → NotificationDeepLink?)

```kotlin
// app: com.testlogon.android.navigation.deeplink
object DeepLinkParser {
    /** Returns null if the intent carries no (valid) deep link. */
    fun parse(intent: Intent?): NotificationDeepLink? {
        intent ?: return null
        if (intent.getBooleanExtra(DeepLinkContract.EXTRA_CONSUMED, false)) return null
        val type = intent.getStringExtra(DeepLinkContract.EXTRA_TYPE) ?: return null
        val id = intent.getStringExtra(DeepLinkContract.EXTRA_ID)?.takeIf { it.isNotBlank() }
            ?: return null
        return when (type) {
            DeepLinkContract.TYPE_MESSAGE   -> NotificationDeepLink.Message(id)
            DeepLinkContract.TYPE_BROADCAST -> NotificationDeepLink.Broadcast(id)
            DeepLinkContract.TYPE_ALERT     -> NotificationDeepLink.Alert(id)
            else -> null
        }
    }

    fun markConsumed(intent: Intent?) {
        intent?.putExtra(DeepLinkContract.EXTRA_CONSUMED, true)
    }
}
```

### 4.4 Payload → NavRoute mapping (total, centralized)

```kotlin
// app: com.testlogon.android.navigation.deeplink
fun NotificationDeepLink.toRoute(): NavRoute = when (this) {
    is NotificationDeepLink.Message   -> MessageThread(threadId)
    is NotificationDeepLink.Broadcast -> BroadcastDetail(broadcastId)
    is NotificationDeepLink.Alert     -> AlertDetail(alertId)
}
```

### 4.5 Activity intent handling

```kotlin
@AndroidEntryPoint
class MainActivity : ComponentActivity() {

    // Hot channel of pending deep links; conflated so only the latest matters.
    private val deepLinks = MutableSharedFlow<NotificationDeepLink>(
        replay = 1, extraBufferCapacity = 1, onBufferOverflow = BufferOverflow.DROP_OLDEST,
    )

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        handleDeepLinkIntent(intent)            // cold start
        setContent {
            TestLogonTheme {
                Surface(Modifier.fillMaxSize()) {
                    val navController = rememberNavController()
                    TestLogonNavHost(navController = navController)
                    DeepLinkHandler(navController = navController, links = deepLinks)
                }
            }
        }
    }

    override fun onNewIntent(intent: Intent) {   // warm start
        super.onNewIntent(intent)
        setIntent(intent)
        handleDeepLinkIntent(intent)
    }

    private fun handleDeepLinkIntent(intent: Intent?) {
        val link = DeepLinkParser.parse(intent) ?: return
        DeepLinkParser.markConsumed(intent)      // idempotency at the intent layer
        deepLinks.tryEmit(link)
    }
}
```

### 4.6 Compose-side router

`DeepLinkHandler` collects emitted links and navigates once the nav graph is ready
and the auth gate is satisfied. It reads session state (from `core-data`, exposed via
a small `DeepLinkViewModel`) to decide auth routing and to hold a *pending* link
across the Login flow.

```kotlin
@Composable
fun DeepLinkHandler(
    navController: NavHostController,
    links: Flow<NotificationDeepLink>,
    viewModel: DeepLinkViewModel = hiltViewModel(),
) {
    val isAuthed by viewModel.isAuthenticated.collectAsStateWithLifecycle()
    LaunchedEffect(Unit) {
        links.collect { link -> viewModel.onDeepLink(link) }
    }
    // Drain pending link whenever auth becomes available.
    LaunchedEffect(isAuthed) {
        viewModel.pending.collect { link ->
            if (link == null) return@collect
            if (!isAuthed) {
                navController.navigate(Login) { launchSingleTop = true }
            } else {
                navController.navigateDeepLink(link.toRoute())  // builds synthetic back stack
                viewModel.clearPending()
            }
        }
    }
}
```

```kotlin
// Synthetic back stack: ensure Back from a detail returns to Home, not out of app.
fun NavHostController.navigateDeepLink(route: NavRoute) {
    navigate(route) {
        launchSingleTop = true
        // If the back stack is just the start dest (cold start), root it at Home
        // so the detail screen has a parent to return to.
        popUpTo(Home) { inclusive = false; saveState = false }
    }
}
```

For cold start where `Home` is not yet on the stack, the navigator first ensures
`Home` is the root (`navigate(Home){ popUpTo(graph.startDestId){inclusive=true} }`)
then pushes the detail route, yielding a `[Home, Detail]` stack.

### 4.7 ViewModel (auth gate + pending link)

```kotlin
@HiltViewModel
class DeepLinkViewModel @Inject constructor(
    sessionRepository: SessionRepository,           // from core-data (AND-auth)
) : ViewModel() {
    val isAuthenticated: StateFlow<Boolean> =
        sessionRepository.sessionState
            .map { it is SessionState.Authenticated }
            .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5_000), false)

    private val _pending = MutableStateFlow<NotificationDeepLink?>(null)
    val pending: StateFlow<NotificationDeepLink?> = _pending.asStateFlow()

    fun onDeepLink(link: NotificationDeepLink) { _pending.value = link }
    fun clearPending() { _pending.value = null }
}
```

## 5. API Contract

**No new backend HTTP endpoints are introduced by this ticket.** Routing is fully
in-process. Two contracts are nonetheless binding:

1. **Intent extras contract (`DeepLinkContract`, §4.1)** — the producer/consumer
   agreement between AND-107 (builds `PendingIntent`) and AND-108 (parses it). Keys:
   `tl.deeplink.type` ∈ {`message`,`broadcast`,`alert`}, `tl.deeplink.id` (non-blank
   string), `tl.deeplink.consumed` (bool, internal).

2. **FCM data payload shape (informational, owned by AND-107 / backend) —
   UNVERIFIED ASSUMPTION:** the draft showed a flat `{ "type": "message", "id": "...",
   "title": "...", "body": "..." }` data message. This exact wire shape is **not**
   confirmed by the backend. The backend's own notification model is `NotificationOut`
   (verified in `reference/src/api/types.ts: NotificationOut`):
   ```ts
   interface NotificationOut {
     notification_id: string;
     notification_type: string;            // discriminator, free-form string
     title: string;
     body: string;
     data: Record<string, unknown>;        // arbitrary per-type payload (e.g. ids)
     read: boolean;
     created_at: number;
     batch_key?: string | null;
     batch_count: number;
     batch_actors: string[];
   }
   ```
   i.e. the discriminator is `notification_type` (an open string set), and any entity
   id lives inside the free-form `data` map — there is no guaranteed top-level `id`
   field, nor a fixed `{message|broadcast|alert}` enum at the backend. The concrete FCM
   `data`→`{type,id}` mapping is therefore an **AND-107/backend-owned assumption** that
   must be pinned by AND-107 before launch (see §16 Open assumptions). AND-108 does not
   parse FCM directly; it only consumes the `Intent` AND-107 builds, so the internal
   `DeepLinkContract` (§4.1) remains valid regardless of the final FCM wire shape — only
   AND-107's translation step depends on it.

Any detail-screen content fetch is owned by the respective feature screen's
ViewModel, not by this router. **(CORRECTED)** The earlier draft's example
`GET /ui/messages/{id}` does not exist in the backend. The real detail endpoints
(verified in `reference/openapi.index.txt`) are, e.g.,
`GET /messaging/conversations/{conversation_id}` → `ConversationOut` for a message
thread, and `GET /broadcast/sessions/{session_id}` → `BroadcastSessionOut` for a
broadcast; alerts are served as a list via `GET /ui/alerts` → `AlertsResp` (no
per-alert detail endpoint). These are owned by feature tickets, not by this router.
Entity-not-found (404) after navigation is the feature screen's empty/error state,
surfaced via that screen's own `ApiResult<T>` handling. Note the backend's
authenticated endpoints accept `X-SESSION-ID` (and `X-CSRF-Token` for mutations; the
web client sends the CSRF token from the `ui_csrf` cookie — see `reference/src/api/client.ts`),
but none of that is the router's concern.

## 6. Data & State Management

- **Navigation state** remains owned solely by the single `NavHostController`
  (AND-022). AND-108 adds an entry path, not a parallel store.
- **Pending deep link** is held in `DeepLinkViewModel` (`StateFlow<NotificationDeepLink?>`),
  scoped to the Activity so it survives configuration change but is cleared once
  consumed. The conflated `MutableSharedFlow(replay=1)` in `MainActivity` bridges the
  imperative `onNewIntent` callback into the Compose collectors; conflation means a
  rapid second tap simply supersedes the first pending target.
- **Idempotency** is enforced at two layers: (a) `EXTRA_CONSUMED` on the `Intent`
  (so the same launch intent never re-parses after rotation re-reads `getIntent()`),
  and (b) `clearPending()` after a successful authed navigation.
- **Auth/session state** is read (not written) from `SessionRepository` in
  `core-data`. AND-108 introduces no DataStore/Room schema; if the auth ticket is not
  merged, a stub `SessionRepository` returning `Authenticated` is injected behind a
  Hilt interface and swapped later (§13).
- **No caching, paging, or media** is involved.

## 7. Error Handling & Resilience

- **Malformed payload** (missing/blank `type` or `id`, unknown `type`):
  `DeepLinkParser.parse` returns `null`; the app proceeds to its normal start
  (Home/Login). No emission, no crash. Logged at WARN (§10).
- **Logged-out tap:** route to `Login`, retain the pending link; on
  `SessionState.Authenticated` the `pending` collector resumes navigation. If the
  user abandons/fails login, the pending link is dropped when the Login flow is
  cancelled (cleared on returning to start).
- **Entity gone / backend 404:** out of scope for the router — navigation still
  succeeds; the destination screen renders its own error/empty state (AND-021 state
  composables). The router never blocks navigation on a network call.
- **Unreliable dev backend:** because AND-108 makes **no** network call, the dev
  host's ~20s timeouts/flakiness do not affect routing; the user always reaches the
  screen, which then handles load/timeout/retry. This decoupling is deliberate.
- **NavHost not yet composed at cold start:** the `replay=1` SharedFlow buffers the
  link until `DeepLinkHandler`'s collector attaches, so no link is lost in the race
  between `onCreate` parsing and first composition.
- **Double navigation / rapid taps:** all navigations use `launchSingleTop = true`;
  conflated flow drops superseded targets.
- This ticket adds no retries/backoff (no idempotent GETs of its own).

## 8. Security & Privacy

- **`PendingIntent` must be `FLAG_IMMUTABLE`** (enforced in §4.2) so other apps
  cannot mutate the target intent — required behavior on target 35.
- **No sensitive data in extras or routes.** Only opaque entity ids (`threadId`,
  `broadcastId`, `alertId`) travel through the intent and into route arguments.
  Passwords, OTP/`challenge_id`, session/CSRF cookies, and tokens are **never**
  encoded into deep-link extras or `NavRoute` arguments (consistent with AND-022 §8);
  route args are serialized into saved-state `Bundle`s that may persist to disk.
- **Auth gate prevents leakage:** a detail screen is only reachable after the auth
  check; an unauthenticated tap cannot bypass Login to view authed content. The
  detail content itself is still fetched with the authenticated cookie session by the
  feature screen, so an attacker forging an `Intent` with a guessed id gains nothing
  without a valid session.
- **No exported deep-link surface added:** `MainActivity` is launched via an internal
  `PendingIntent` only; no new `https`/custom-scheme `intent-filter` with
  `android:exported="true"` is declared by this ticket, so there is no external
  injection surface. (External App Links are a separate future ticket and would need
  their own validation.)
- **No logging of ids at WARN/ERROR in release** beyond the type discriminator (§10).

## 9. Accessibility & i18n

- Routing produces no new persistent UI of its own, but on arrival at the
  deep-linked screen, **focus moves to that screen's primary content** so TalkBack
  announces the destination after a tap (uses each screen's existing
  `focusRequester` root convention from AND-022 §9).
- Any transient routing message (e.g. a "Sign in to continue" prompt when a tap
  arrives logged-out) uses externalized strings in `app` `strings.xml`
  (`R.string.deeplink_login_required`); no hardcoded literals.
- Navigation transitions reuse `TLTransitions` (AND-022), which already collapse to
  zero duration under reduced-motion / animations-off; deep-link navigation inherits
  this and must not introduce a separate animated path.
- No locale-specific parsing: ids are opaque ASCII; `type` discriminators are
  fixed wire constants, never localized.

## 10. Telemetry & Logging

- On each handled tap, log (debug, `BuildConfig.DEBUG`-gated, tag `"TLDeepLink"`)
  the **type discriminator only** and the routing outcome (`routed`,
  `deferred_login`, `dropped_malformed`) — **never the entity id** (§8).
- Reuse the AND-022 `NavAnalytics` no-op interface: emit
  `NavAnalytics.onScreen(routeName)` for the resolved destination so a later
  analytics ticket can attribute notification-driven screen views without changing
  this code. Add a `source = "notification"` attribute via an overload
  (`onScreen(routeName, source)`).
- Malformed/unknown payloads log at WARN with type (or `"<null>"`) and outcome
  `dropped_malformed`. No analytics SDK is added in this ticket.

## 11. Testing Strategy

**Unit / JVM (`core-testing`):**
1. `parse_message_returnsMessageDeepLink` — Intent with type=`message`, id=`x`
   parses to `Message("x")`.
2. `parse_unknownType_returnsNull` and `parse_blankId_returnsNull`,
   `parse_missingType_returnsNull`.
3. `parse_consumedIntent_returnsNull` — `EXTRA_CONSUMED=true` yields null
   (idempotency).
4. `toRoute_mapping` — each `NotificationDeepLink` variant maps to the expected
   `NavRoute` (`Message→MessageThread`, etc.). Exhaustive `when` guarded by the
   sealed interface.
5. `intentFactory_roundTrip` — `DeepLinkIntentFactory.pendingIntent` extras parse
   back to the original `NotificationDeepLink` (producer↔consumer contract guard).

**Compose / navigation (`androidx.navigation:navigation-testing`
`TestNavHostController`, `createComposeRule`):**
6. `coldStart_message_opensMessageThread_withId` — launch `MainActivity` with a
   message deep-link Intent; assert current destination is `MessageThread` and arg
   equals the id. **(Core acceptance test — “opens the right screen”.)**
7. `coldStart_broadcast_opensBroadcastDetail` and `coldStart_alert_opensAlertDetail`.
8. `warmStart_onNewIntent_routes` — Activity already on `Home`; deliver intent via
   `onNewIntent`; assert routed without recreate.
9. `coldStart_back_returnsToHome` — after deep-linking to detail, press Back; assert
   destination is `Home` and back stack depth is 1 (synthetic back stack).
10. `malformedPayload_opensDefault` — unknown type → lands on `Home`/`Login`, no
    crash.
11. `loggedOut_defersToLogin_thenResumes` — tap while unauthenticated routes to
    `Login`; flip `SessionState` to `Authenticated`; assert it then navigates to the
    pending detail and clears pending.
12. `rotation_doesNotReRoute` — deep-link, recreate Activity; assert single
    navigation (no duplicate detail on back stack) — idempotency.

**Instrumented (`:app:connectedDebugAndroidTest`):** at least #6 and #9 on an API 24
emulator to cover real `PendingIntent`/process-restart behavior. CI must run the JVM
parser/mapping tests plus the core `coldStart_message_opensMessageThread_withId`
headlessly (Robolectric for nav-testing).

**Tooling:** `./gradlew :app:testDebugUnitTest` and
`:app:connectedDebugAndroidTest`.

## 12. Dependencies & Sequencing

- **Depends on AND-107** (P0, FCM handling): must post notifications and build the
  tap `PendingIntent`. AND-108 supplies the `DeepLinkContract` + `DeepLinkIntentFactory`
  that AND-107 calls — coordinate so AND-107 uses the factory rather than ad-hoc
  extras. The contract object can land first to unblock both in parallel.
- **Depends on AND-022** (P0, Nav host & routes): provides `TestLogonNavHost`,
  `NavRoute`/`TopLevelRoute`, `composable<T>`, `TLTransitions`, and the
  callback/navigator conventions extended here.
- **Soft-depends on feature route types** (`MessageThread`, `BroadcastDetail`,
  `AlertDetail`, `Home`) and the auth `SessionRepository`. Where a real type is not
  yet merged, use a same-shape placeholder behind a Hilt interface and swap on merge.
- **New Gradle additions:** none beyond AND-022's (`navigation-compose` 2.8.x,
  `navigation-testing`, `kotlinx-serialization`, `hilt-navigation-compose`). Reuses
  the existing version catalog (`gradle/libs.versions.toml`).
- **Sequencing:** implement after AND-022 merges; develop in parallel with AND-107 by
  agreeing the `DeepLinkContract` first. Blocks no other listed ticket but is a hard
  gate for the notifications epic (E15) "tap-to-open" acceptance.

## 13. Risks & Open Questions

- **R1 — Feature route types not merged in time.** *Mitigation:* placeholder routes
  of identical shape behind a Hilt-bound `DeepLinkRouteFactory` so the swap is a
  one-line binding change; mapping tests pin the shape.
- **R2 — Cold-start race** between `onCreate` intent parse and first NavHost
  composition. *Mitigation:* `replay=1` SharedFlow buffers the link; covered by test
  #6 on API 24.
- **R3 — Synthetic back stack correctness** across cold vs warm start (Back must
  reach Home, not exit). *Mitigation:* explicit `navigateDeepLink` `popUpTo(Home)`
  logic + tests #8/#9.
- **R4 — Re-routing on rotation** if `getIntent()` is re-read. *Mitigation:*
  `EXTRA_CONSUMED` marking + `clearPending()`; test #12.
- **R5 — `PendingIntent` mutability/flags** drift in AND-107. *Mitigation:* force all
  notification intents through `DeepLinkIntentFactory` (immutable, single-top); review
  AND-107 PR for direct `PendingIntent` construction.
- **Q1 — Logged-out abandon semantics:** drop the pending link on Login cancel
  (current spec) vs persist across app restarts? Default: drop; revisit if product
  wants durable resume.
- **Q2 — Multiple stacked notifications:** conflate to latest tap (current) vs queue
  all? Default: latest wins (a tap targets one screen). Revisit with grouped
  notifications.
- **Q3 — Should Back from a warm-start deep link reuse the existing stack** instead of
  rooting at Home? Default: if `Home` already on stack, navigate atop it; only
  synthesize `[Home, Detail]` on cold start.

## 14. Acceptance Criteria

1. Tapping a `message` notification opens `MessageThread` with the correct
   `threadId`; `broadcast` → `BroadcastDetail`; `alert` → `AlertDetail`. **(Core AC —
   covered by `coldStart_message_opensMessageThread_withId` and siblings.)**
2. Routing works on **cold start** (process dead) and **warm start** (`onNewIntent`)
   without creating a second Activity and without recreating an already-running one.
3. After a cold-start deep link to a detail screen, **Back returns to Home** (not out
   of the app); a synthetic `[Home, Detail]` back stack is produced.
4. A **logged-out** tap routes to Login and, after successful auth, resumes to the
   originally targeted destination exactly once.
5. **Malformed/unknown** payloads (missing/blank id, unknown type, missing type) open
   a safe default (Home/Login) and never crash.
6. The same launch intent is **routed exactly once**; rotation/recomposition does not
   re-navigate (idempotent via `EXTRA_CONSUMED` + `clearPending()`).
7. All notification `PendingIntent`s are built via `DeepLinkIntentFactory`
   (`FLAG_IMMUTABLE`, single-top); no sensitive data is placed in extras or route
   arguments — only opaque entity ids.
8. The `payload → route` mapping is centralized and total over the sealed
   `NotificationDeepLink` type; AND-107 consumes the shared `DeepLinkContract`.
9. All §11 tests pass in CI (JVM parser/mapping + core cold-start nav test
   headless; back-stack and idempotency instrumented on API 24).

## 15. Definition of Done

- All §14 acceptance criteria met and demonstrated by passing automated tests.
- Code merged to `android-port` under `android/app/.../navigation/deeplink/` and the
  shared model in `core-model`/`core-ui.navigation`, using package base
  `com.testlogon.android` exactly.
- AND-107 updated to build its tap `PendingIntent` via `DeepLinkIntentFactory` /
  `DeepLinkContract` (verified in AND-107 PR); no duplicate/ad-hoc extras keys exist.
- `./gradlew :app:assembleDebug` and `:app:testDebugUnitTest` green locally and in CI;
  core cold-start nav test runs headless in CI.
- No raw-string routes; no sensitive data in extras or route args; entity ids and
  route args not logged in release (type discriminator + outcome only).
- Public API (`NotificationDeepLink`, `DeepLinkContract`, `DeepLinkIntentFactory`,
  `DeepLinkParser`, `toRoute`, `navigateDeepLink`, `DeepLinkHandler`,
  `DeepLinkViewModel`) has KDoc, including the §8 "no sensitive data / immutable
  PendingIntent" notes.
- User-visible routing strings externalized to `strings.xml`; focus-on-arrival
  verified with TalkBack.
- Lint and ktlint/detekt pass with no new warnings; PR reviewed and approved.
- Feature-screen owners confirm the consumed route types (`MessageThread`,
  `BroadcastDetail`, `AlertDetail`) match the shapes used by the router (or the
  placeholder swap is tracked).

## 16. Citations & Assumption Audit

Each key technical claim, its verdict, and an exact source pointer. Sources:
OpenAPI index (`reference/openapi.index.txt`), OpenAPI full spec
(`reference/openapi.pretty.json`, `components.schemas.*`), the frontend reference app
(`reference/src/...`), and Android framework docs (labelled "framework ref").

1. **Claim:** No new backend HTTP endpoints are introduced; routing is fully in-process.
   **VERDICT: Verified.** The feature is purely an Android intent/navigation concern;
   nothing in the OpenAPI index corresponds to deep-link routing.
   *Source:* design-level (negative claim); detail endpoints below are all owned by
   other tickets.

2. **Claim (draft):** The web app's notification deep links map to `/messages/:id`,
   `/broadcasts/:id`, `/alerts/:id`. **VERDICT: Corrected.** The actual web routes are
   `messages/:conversationId` (param is `conversationId`); there is **no**
   `/broadcasts/:id` route (broadcast surface is `broadcast` and
   `broadcast/:sessionId/live-qa`) and **no** `/alerts/:id` route (`alerts` is
   list-only). *Source:* `reference/src/App.tsx` (routes `messages`,
   `messages/:conversationId`, `alerts`, `broadcast`, `broadcast/:sessionId/live-qa`).

3. **Claim:** A message "thread" is the routable message entity. **VERDICT: Corrected
   (terminology).** The backend entity is a *conversation*. The detail fetch is
   `GET /messaging/conversations/{conversation_id}` → `ConversationOut`. The Android
   `MessageThread(threadId)` route is acceptable as an internal name but its id is a
   *conversation id*. *Source:* OpenAPI `GET /messaging/conversations/{conversation_id}`
   (schema `ConversationOut`); `reference/src/api/types.ts: ConversationOut`.

4. **Claim (draft §5):** A detail content fetch looks like `GET /ui/messages/{id}`.
   **VERDICT: Corrected.** No such endpoint exists. Real detail endpoints:
   `GET /messaging/conversations/{conversation_id}` (`ConversationOut`),
   `GET /broadcast/sessions/{session_id}` (`BroadcastSessionOut`); alerts via
   `GET /ui/alerts` (`AlertsResp`, list only). *Source:* `reference/openapi.index.txt`
   lines for `/messaging/conversations/{conversation_id}`,
   `/broadcast/sessions/{session_id}`, and `reference/src/api/endpoints/alerts.ts`
   (`GET /ui/alerts`).

5. **Claim (draft §5):** The FCM `data` message is a flat
   `{type, id, title, body}` with `type ∈ {message,broadcast,alert}`.
   **VERDICT: Corrected → Unverified-assumption.** The backend notification model is
   `NotificationOut { notification_id, notification_type: string, title, body,
   data: Record<string, unknown>, read, created_at, batch_* }`: the discriminator is
   `notification_type` (open string set), and entity ids live inside the free-form
   `data` map — there is no fixed top-level `id` nor a `{message|broadcast|alert}` enum.
   The exact FCM→`{type,id}` mapping is owned by AND-107/backend and is **not** verifiable
   from these sources. *Source:* `reference/src/api/types.ts: NotificationOut`
   (lines ~5257-5268); OpenAPI `GET /ui/notifications` → `NotificationListResponse`.

6. **Claim (§2/§8):** The app/web is cookie-session based; mutations need CSRF.
   **VERDICT: Verified.** The web client sends `credentials: "include"` and a
   `X-CSRF-Token` header read from the `ui_csrf` cookie. *Source:*
   `reference/src/api/client.ts` (`credentials: "include"`, `getCookie("ui_csrf")`,
   `headers.set("X-CSRF-Token", csrf)`). Backend authed endpoints additionally accept
   `X-SESSION-ID` (e.g. OpenAPI `GET /messaging/conversations/{conversation_id}` params).
   Note: none of this is exercised by the router itself (correct as stated in §8).

7. **Claim (§4.1):** A self-defined Android Intent extras contract (`DeepLinkContract`:
   `tl.deeplink.type/id/consumed`) is the AND-107↔AND-108 boundary.
   **VERDICT: Verified (internal design).** This is an Android-internal contract, not a
   backend artifact; nothing in the sources contradicts it. It correctly does *not*
   assume the backend FCM shape (see #5). *Source:* design-level; consistency with
   `NotificationOut` noted in §5.

8. **Claim (§4.2/§8):** Notification `PendingIntent`s must use `FLAG_IMMUTABLE`; warm
   taps reuse the Activity via `FLAG_ACTIVITY_SINGLE_TOP` + `onNewIntent`.
   **VERDICT: Verified (framework ref).** `FLAG_IMMUTABLE` is required on Android 12+
   (API 31+) for any `PendingIntent`; single-top delivery via `onNewIntent` is standard.
   *Source:* framework ref — developer.android.com `PendingIntent` (FLAG_IMMUTABLE) and
   `Activity#onNewIntent` / launch mode docs.

9. **Claim (§4.5/§7):** A `MutableSharedFlow(replay=1)` bridges the imperative
   `onCreate`/`onNewIntent` parse into the Compose collector and buffers across the
   cold-start composition race. **VERDICT: Verified (framework ref / design).**
   *Source:* framework ref — Kotlin coroutines `SharedFlow` (replay) + Compose
   `LaunchedEffect`/`collectAsStateWithLifecycle`.

10. **Claim (§4.6/§5/§3):** Synthetic back stack `[Home, Detail]` via
    Navigation-Compose `navigate(...) { popUpTo(...) }`; entity-not-found is the feature
    screen's own state, not the router's. **VERDICT: Verified (framework ref / scoping).**
    *Source:* framework ref — developer.android.com Navigation Compose (type-safe routes,
    `popUpTo`, synthetic back stack). 404 handling correctly scoped out per #4 endpoints.

11. **Claim (§3.2 mapping):** `message→MessageThread(threadId)`,
    `broadcast→BroadcastDetail(broadcastId)`, `alert→AlertDetail(alertId)`, total over a
    sealed type. **VERDICT: Verified (internal) with Open-assumption on the broadcast/alert
    route shapes.** The mapping is internally total; however `BroadcastDetail(broadcastId)`
    and `AlertDetail(alertId)` presuppose Android per-id detail screens that have **no
    web counterpart** (web broadcast is session-keyed; web alerts is list-only). See Open
    assumptions. *Source:* `reference/src/App.tsx` (no `/broadcasts/:id`, no `/alerts/:id`).

### Corrections made

- §2 "Web reference": replaced the wrong `/messages/:id`, `/broadcasts/:id`,
  `/alerts/:id` route list with the verified web routes (`messages/:conversationId`;
  `broadcast` / `broadcast/:sessionId/live-qa`; list-only `alerts`) and flagged that
  Android per-id broadcast/alert detail routes have no direct web equivalent.
- §5 detail-fetch example: replaced the non-existent `GET /ui/messages/{id}` with the
  real endpoints (`/messaging/conversations/{conversation_id}` → `ConversationOut`,
  `/broadcast/sessions/{session_id}` → `BroadcastSessionOut`, `/ui/alerts` →
  `AlertsResp`) and added the `X-SESSION-ID` / `X-CSRF-Token` auth note.
- §5 FCM payload: replaced the asserted flat `{type,id,title,body}` shape with the
  real `NotificationOut` model (`notification_type` + free-form `data`) and downgraded
  the `{type,id}` wire mapping to an explicit AND-107/backend-owned assumption.
- "message thread" terminology clarified to "conversation" where it touches the backend.

### Open assumptions

- **FCM data → `{type,id}` mapping (AND-107/backend).** The exact FCM `data` keys that
  AND-107 reads to populate `DeepLinkContract` extras are not specified by any source;
  the backend model is open-ended (`notification_type` string + `data` map). Cannot be
  verified here; must be pinned in AND-107's spec/PR. *Why unverifiable:* no FCM payload
  schema exists in OpenAPI; `NotificationOut.data` is `Record<string, unknown>`.
- **Android `BroadcastDetail`/`AlertDetail` per-id routes.** The web app has no
  `/broadcasts/:id` or `/alerts/:id` detail route (broadcast is session-keyed; alerts is
  a list). Whether the Android app will have true per-id detail screens for these (vs
  routing a broadcast to its *session* screen, or an alert to the alerts *list*) is a
  feature-team decision not derivable from the reference app. *Why unverifiable:* the
  target Android feature routes are defined by other (possibly unmerged) tickets.
- **`SessionRepository` / `SessionState.Authenticated` API (§4.7).** The auth ticket's
  exact repository surface is referenced but not present in these sources (it is an
  Android-side artifact). *Why unverifiable:* no Android source tree is provided; only
  the web reference app and OpenAPI are authoritative here.
- **Feature route arg names (`threadId`/`conversationId`).** The router uses `threadId`;
  the web uses `conversationId`. The final Android arg name is owned by the message
  feature ticket. *Why unverifiable:* Android feature routes not in scope sources.

## 17. Test Plan

Test targets: **JVM** = local JVM/Robolectric (no device); **emu35** = headless AVD
`test35` (x86_64, Android 15 / API 35, KVM on the Ubuntu CI host); **device** =
physical Samsung Galaxy A15 5G (SM-A156U, serial R5CX821TA9R), Android 14 / API 34,
arm64-v8a, via adb on the build host. Because this ticket makes **no network calls**,
no MockWebServer/contract cases are required; the relevant "flaky host" check is that
routing is *independent* of the backend. "Traces" link to §14 Acceptance Criteria.

- **TC-AND-108-01 — Parser happy path + mapping (unit).**
  *Type:* unit. *Target:* JVM (Robolectric for `Intent`).
  *Preconditions:* `DeepLinkContract` constants defined.
  *Steps:* Build an `Intent` with `EXTRA_TYPE="message"`, `EXTRA_ID="conv_8f21c"`; call
  `DeepLinkParser.parse(intent)`, then `.toRoute()`. Repeat for `broadcast` and `alert`.
  *Expected:* parses to `Message("conv_8f21c")` etc.; `toRoute()` yields
  `MessageThread("conv_8f21c")`, `BroadcastDetail(id)`, `AlertDetail(id)` respectively.
  *Traces:* AC-1, AC-8.

- **TC-AND-108-02 — Parser validation/negative cases (unit).**
  *Type:* unit. *Target:* JVM.
  *Preconditions:* none.
  *Steps:* Call `parse` for: missing `EXTRA_TYPE`; unknown type `"foo"`; blank/whitespace
  `EXTRA_ID`; missing `EXTRA_ID`; `null` intent.
  *Expected:* every case returns `null`; no exception thrown.
  *Traces:* AC-5.

- **TC-AND-108-03 — Idempotent parse via EXTRA_CONSUMED (unit).**
  *Type:* unit. *Target:* JVM.
  *Preconditions:* a valid deep-link intent.
  *Steps:* `parse` once (non-null); call `markConsumed(intent)`; `parse` again on the
  same intent.
  *Expected:* first parse non-null, second parse returns `null` (consumed flag honored).
  *Traces:* AC-6.

- **TC-AND-108-04 — PendingIntent factory round-trip / producer-consumer guard (unit).**
  *Type:* unit/contract (internal Intent contract). *Target:* JVM (Robolectric
  `PendingIntent`/`Intent`).
  *Preconditions:* `DeepLinkIntentFactory` available.
  *Steps:* For each `NotificationDeepLink` variant, build via
  `DeepLinkIntentFactory.pendingIntent(...)`, extract the wrapped `Intent`, run
  `DeepLinkParser.parse`.
  *Expected:* parsed result equals the original variant; flags include
  `FLAG_IMMUTABLE` and the launch intent has `FLAG_ACTIVITY_SINGLE_TOP`.
  *Traces:* AC-7, AC-8.

- **TC-AND-108-05 — Cold start routes to MessageThread with correct id (Compose-UI).**
  *Type:* Compose-UI / navigation. *Target:* JVM (Robolectric +
  `TestNavHostController`) for CI; also run on emu35.
  *Preconditions:* authenticated session (stub `SessionRepository` → Authenticated).
  *Steps:* Launch `MainActivity` with a `message`/`conv_x` deep-link intent (process
  cold). Let the `NavHost` compose; let `DeepLinkHandler` drain.
  *Expected:* current destination is `MessageThread` with arg == `conv_x`, not the start
  destination. **(Core acceptance.)**
  *Traces:* AC-1, AC-2.

- **TC-AND-108-06 — Cold start routes broadcast and alert (Compose-UI).**
  *Type:* Compose-UI. *Target:* JVM/Robolectric; emu35.
  *Preconditions:* authenticated.
  *Steps:* Repeat TC-05 with `broadcast`/`b_x` and `alert`/`a_x`.
  *Expected:* destinations `BroadcastDetail(b_x)` and `AlertDetail(a_x)` respectively.
  (Implementers: confirm these Android routes exist or are placeholders — see §16 Open
  assumptions.)
  *Traces:* AC-1.

- **TC-AND-108-07 — Warm start via onNewIntent without recreate (Compose-UI/instrumented).**
  *Type:* instrumented. *Target:* emu35 (real Activity lifecycle).
  *Preconditions:* `MainActivity` already running on `Home`, authenticated.
  *Steps:* Deliver a deep-link intent through `onNewIntent` (single-top); observe routing.
  *Expected:* routes to the mapped detail; the Activity instance is **not** recreated
  (same `hashCode`/`onCreate` not re-invoked) and unrelated state is preserved.
  *Traces:* AC-2.

- **TC-AND-108-08 — Synthetic back stack: Back returns to Home (Compose-UI/instrumented).**
  *Type:* instrumented. *Target:* emu35.
  *Preconditions:* cold-start deep link to a detail (TC-05), authenticated.
  *Steps:* After landing on the detail, press system Back.
  *Expected:* destination becomes `Home`; back-stack depth is 1; Back does not exit the
  app. *Traces:* AC-3.

- **TC-AND-108-09 — Logged-out tap defers to Login then resumes once (Compose-UI).**
  *Type:* Compose-UI. *Target:* JVM/Robolectric with controllable `SessionState`.
  *Preconditions:* `SessionState` starts unauthenticated; a `message` deep link.
  *Steps:* Deliver the deep link; assert routed to `Login` and `pending` holds the link.
  Flip `SessionState` → `Authenticated`.
  *Expected:* navigates to the pending `MessageThread` **exactly once**, then
  `clearPending()` leaves `pending == null` (no re-navigation). *Traces:* AC-4.

- **TC-AND-108-10 — Malformed payload opens safe default, no crash (Compose-UI).**
  *Type:* Compose-UI. *Target:* JVM/Robolectric; emu35.
  *Preconditions:* authenticated and (separately) unauthenticated runs.
  *Steps:* Launch with unknown type / blank id intent.
  *Expected:* lands on `Home` (authed) or `Login` (unauthed); no crash; WARN log with
  outcome `dropped_malformed` and **no entity id** in the log. *Traces:* AC-5.

- **TC-AND-108-11 — Rotation / process-restart does not re-route (instrumented).**
  *Type:* instrumented. *Target:* emu35.
  *Preconditions:* deep-linked to a detail, authenticated.
  *Steps:* Trigger configuration change (rotation) and Activity recreate; `getIntent()`
  is re-read.
  *Expected:* exactly one navigation total; no duplicate detail entry on the back stack
  (idempotency via `EXTRA_CONSUMED` + `clearPending()`). *Traces:* AC-6.

- **TC-AND-108-12 — Routing is independent of backend availability ("flaky host"/offline).**
  *Type:* integration. *Target:* device (real, airplane mode toggled).
  *Preconditions:* device in airplane mode (no network), authenticated session cached.
  *Steps:* Tap a real notification (delivered while online, then go offline) / launch via
  the `PendingIntent`.
  *Expected:* the app still routes to the correct detail screen with the correct id; only
  the *content fetch* on that screen shows its own loading/error state — routing never
  blocks on or fails due to the network. *Traces:* AC-1, AC-2.
  *(Must run on device to exercise real radio/offline + real PendingIntent delivery.)*

- **TC-AND-108-13 — Security: no sensitive data in extras/routes; immutable PendingIntent
   (unit + manual).**
  *Type:* unit + manual inspection. *Target:* JVM (assertions) + manual review.
  *Preconditions:* factory + parser available.
  *Steps:* Build PendingIntents for all variants; assert flags contain `FLAG_IMMUTABLE`;
  assert extras contain only `tl.deeplink.type`/`id`/`consumed` and the id is opaque (no
  cookie/token/CSRF/`challenge_id`); grep route-arg serialization for sensitive keys.
  *Expected:* only opaque ids present; `FLAG_IMMUTABLE` set; no auth material anywhere.
  *Traces:* AC-7.

- **TC-AND-108-14 — Accessibility: focus + announcement on arrival (instrumented/e2e).**
  *Type:* instrumented/e2e (accessibility). *Target:* device (real TalkBack).
  *Preconditions:* TalkBack enabled; authenticated; a `message` notification posted.
  *Steps:* Tap the notification; observe focus and TalkBack output on the detail screen;
  also verify the logged-out path shows the externalized
  `R.string.deeplink_login_required` string (not a hardcoded literal).
  *Expected:* focus moves to the destination's primary content and TalkBack announces it;
  reduced-motion path uses zero-duration `TLTransitions`; login-prompt string is
  externalized. *Traces:* AC-2 (and §9 accessibility requirements).
  *(Run on device for real TalkBack/accessibility-service behavior.)*

### Coverage matrix (AC → TCs)

| §14 AC | Covered by |
|--------|------------|
| AC-1 (correct screen per type + id) | TC-01, TC-05, TC-06, TC-12 |
| AC-2 (cold + warm start, no double/recreate Activity) | TC-05, TC-07, TC-12, TC-14 |
| AC-3 (Back returns to Home; synthetic stack) | TC-08 |
| AC-4 (logged-out → Login → resume once) | TC-09 |
| AC-5 (malformed/unknown → safe default, no crash) | TC-02, TC-10 |
| AC-6 (routed exactly once; idempotent) | TC-03, TC-11 |
| AC-7 (FLAG_IMMUTABLE/single-top; no sensitive data) | TC-04, TC-13 |
| AC-8 (centralized total mapping; shared contract) | TC-01, TC-04 |
| AC-9 (tests pass in CI: JVM + core cold-start headless; back-stack/idempotency instrumented) | TC-01..04 + TC-05 (headless CI); TC-07, TC-08, TC-11 (instrumented) |
