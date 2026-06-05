---
id: AND-107
title: Notification channels + display
milestone: M2
epic: E15
priority: P1
size: M
status: draft
depends_on: [AND-105]
blocks: [AND-108]
---

# AND-107 — Notification channels + display

## 1. Overview & Goal

This ticket delivers the on-device notification presentation layer for the TestLogon
Android app: a fixed set of typed **notification channels** (messages, broadcasts,
alerts), the **POST_NOTIFICATIONS runtime permission** flow required on Android 13+
(API 33), and a reusable **`NotificationPresenter`** that turns an FCM data payload
into a correctly-categorized, channel-bound system notification.

AND-105 already provides Firebase Cloud Messaging wiring and a `TlFirebaseMessagingService`
that receives `RemoteMessage` objects in foreground and background. AND-107 consumes
those messages and is responsible for **how they are shown**: which channel they land
on, their importance/sound/vibration behavior, grouping, and the small-icon/color
branding. It explicitly does **not** own the tap-to-navigate behavior — that belongs to
AND-108 (deep-link routing), which depends on this ticket and consumes the
`PendingIntent` extras format defined here.

The goal is measurable: after this ticket, a test FCM `data` message of each of the three
kinds displays a notification on the correct channel with the correct importance, and on
Android 13+ the app requests `POST_NOTIFICATIONS` at the appropriate moment and degrades
gracefully if the user denies it.

## 2. Context & References

- **Repo / branch:** `spannella/testlogon`, app under `android/`, branch `android-port`.
- **Package base:** `com.testlogon.android` (all classes below live under this namespace).
- **Owning module:** a new `core-notifications` core module (layered `app -> feature-* ->
  core-*`), depending on `core-ui` (branding colors), `core-model` (payload types), and
  `core-data` (DataStore for permission-prompt bookkeeping). `app` and
  `core-network`/messaging service wire into it.
- **Upstream:** AND-105 (`core-notifications` / messaging service host), AND-004 (Gradle/
  flavor/Firebase config).
- **Downstream:** AND-108 (deep-link routing) reads the `PendingIntent` extras contract in
  §5; AND-106 (push token registration) is parallel and unrelated to display.
- **Web reference:** the FastAPI backend pushes notifications whose `data` payloads mirror
  the web app's notification kinds (`frontend/src/api/types.ts`); there is **no REST
  contract owned by this ticket** — the "contract" is the FCM data-message shape (§5).
- **Platform:** minSdk 24, compileSdk/targetSdk 35, Kotlin 2.0.21, Compose + Material 3,
  Hilt (KSP), Coroutines/Flow.

## 3. Functional Requirements

FR-1. On first app process start (and idempotently thereafter) the app registers exactly
three notification channels via `NotificationManagerCompat`:

| Channel id (const) | User-visible name | Importance | Sound | Vibration | Badge |
|---|---|---|---|---|---|
| `tl_messages` | Messages | `IMPORTANCE_HIGH` | default | yes | yes |
| `tl_broadcasts` | Broadcasts | `IMPORTANCE_DEFAULT` | default | no | yes |
| `tl_alerts` | Alerts | `IMPORTANCE_HIGH` | default | yes | yes |

FR-2. Channels are grouped under a single channel group `tl_general` ("TestLogon").
FR-3. Channel registration is a no-op on API < 26 (the platform ignores channels) but the
constants and routing logic still apply so notification importance is approximated via
`NotificationCompat.Builder.setPriority`.
FR-4. The `NotificationKind` of an incoming payload (`MESSAGE` | `BROADCAST` | `ALERT`)
deterministically maps to its channel id. An unknown/missing kind falls back to
`tl_broadcasts` (lowest-disruption visible channel) and is logged.
FR-5. On Android 13+ (API 33), before relying on notifications the app requests the
`POST_NOTIFICATIONS` runtime permission. The request is triggered (a) after successful
login/finalize on the first authenticated session, and (b) lazily before the first
notification of a session would be posted, whichever comes first.
FR-6. The app shows a one-time soft pre-prompt rationale (Compose dialog) before the system
permission dialog the **first** time only; subsequent sessions never re-prompt unless the
user enables it from an in-app settings affordance (out of scope for this ticket — covered
by a settings screen ticket; here we only expose the trigger function).
FR-7. If permission is denied, channels are still created and incoming messages are
silently dropped from display (no crash); a single debug log line records the drop.
FR-8. A posted notification uses: small icon `ic_stat_notification` (monochrome,
`core-ui`), brand color `TlBrand`, the payload `title`/`body`, auto-cancel on tap, and a
`PendingIntent` (extras per §5) that AND-108 resolves. Notifications are grouped per
channel with `setGroup`.
FR-9. Notification ids are deterministic per logical entity (`entityId.hashCode()`), so a
re-pushed update replaces rather than stacks.

## 4. Technical Design

New module `core-notifications`. Key types (all `com.testlogon.android.notifications`):

```kotlin
enum class NotificationKind { MESSAGE, BROADCAST, ALERT, UNKNOWN }

object TlChannels {
    const val GROUP_ID = "tl_general"
    const val MESSAGES = "tl_messages"
    const val BROADCASTS = "tl_broadcasts"
    const val ALERTS = "tl_alerts"

    fun channelIdFor(kind: NotificationKind): String = when (kind) {
        NotificationKind.MESSAGE -> MESSAGES
        NotificationKind.ALERT   -> ALERTS
        NotificationKind.BROADCAST, NotificationKind.UNKNOWN -> BROADCASTS
    }
}

/** Parsed, validated FCM data payload (see §5). */
data class PushPayload(
    val kind: NotificationKind,
    val entityId: String,
    val title: String,
    val body: String,
    val deepLink: String?,   // consumed by AND-108
)

interface NotificationChannelInitializer { fun ensureChannels() }

class NotificationPresenter @Inject constructor(
    @ApplicationContext private val context: Context,
    private val permission: NotificationPermissionState,
    private val initializer: NotificationChannelInitializer,
) {
    /** Returns true if a notification was posted, false if dropped (no permission / invalid). */
    fun show(payload: PushPayload): Boolean
}
```

`DefaultNotificationChannelInitializer` builds `NotificationChannelGroupCompat` +
three `NotificationChannelCompat.Builder` instances and calls
`NotificationManagerCompat.from(context).createNotificationChannelsCompat(...)`. It is
invoked from `Application.onCreate()` (via a Hilt entry point) and is idempotent —
re-creating an existing channel only updates the mutable name/description, never the
importance (Android pins importance after first creation).

Permission state lives in `NotificationPermissionState`:

```kotlin
class NotificationPermissionState @Inject constructor(
    @ApplicationContext private val context: Context,
    private val prefs: NotificationPrefs,          // DataStore-backed
) {
    fun isGranted(): Boolean =
        Build.VERSION.SDK_INT < 33 ||
        ContextCompat.checkSelfPermission(context, POST_NOTIFICATIONS) == PERMISSION_GRANTED

    val hasShownRationaleOnce: Flow<Boolean>
    suspend fun markRationaleShown()
}
```

UI side (Compose, in `app` or a shared `feature-notifications-permission` surface):

```kotlin
@Composable
fun NotificationPermissionGate(
    state: NotificationPermissionViewModel = hiltViewModel(),
    content: @Composable () -> Unit,
)
```

The gate uses `rememberLauncherForActivityResult(ActivityResultContracts.RequestPermission())`
and the ViewModel exposes `StateFlow<PermissionUiState>` (`{ shouldShowRationale: Boolean,
granted: Boolean }`). The gate is mounted high in the single-Activity Navigation-Compose
tree (post-auth graph), so the prompt fires once authenticated per FR-5.

The messaging service (AND-105) maps `RemoteMessage.data` to `PushPayload` via a
`PushPayloadParser` and calls `notificationPresenter.show(payload)` for **data** messages.
(If AND-105 sends `notification`-key messages, those are auto-displayed by the system on a
default channel only while backgrounded — this ticket standardizes on **data-only**
messages so channel routing is always under app control; this is documented as a
requirement back to the backend in §13.)

## 5. API Contract

No HTTP REST endpoint is owned by this ticket — token registration (`POST /ui/push/register`)
is AND-106. The contract here is the **FCM data-message shape** the backend must emit and
this code parses:

```json
{
  "data": {
    "kind": "message",            // "message" | "broadcast" | "alert"
    "entity_id": "msg_01HXYZ...", // stable id; drives notification id + dedupe
    "title": "New message from Ada",
    "body": "Are we still on for 3pm?",
    "deep_link": "testlogon://message/msg_01HXYZ"  // optional; AND-108 resolves
  }
}
```

Parsing rules:
- `kind` is lowercased and matched to `NotificationKind`; unmatched → `UNKNOWN` → routed to
  `tl_broadcasts` (FR-4) and logged at WARN.
- `entity_id`, `title`, `body` are required; a payload missing any required field is dropped
  and logged (returns `false` from `show`). `deep_link` is optional and passed through verbatim.
- All values arrive as strings (FCM data is `Map<String,String>`); no numeric coercion.

`PendingIntent` extras contract consumed by AND-108:

```kotlin
intent.putExtra("tl.notif.kind", payload.kind.name)
intent.putExtra("tl.notif.entityId", payload.entityId)
intent.putExtra("tl.notif.deepLink", payload.deepLink) // nullable
```
Target is the single `MainActivity` with `FLAG_IMMUTABLE` (required, API 31+) and a
request code derived from `entityId.hashCode()` to keep updates distinct per entity.

## 6. Data & State Management

- **DataStore (`NotificationPrefs`):** persists `notif_rationale_shown: Boolean` only.
  No notification content is persisted by this ticket (Room caching of message bodies is
  owned by the respective feature tickets).
- **In-memory:** `NotificationPermissionViewModel` holds `StateFlow<PermissionUiState>`,
  recomputed on `onResume` (the user may toggle permission in system settings while the app
  is backgrounded), via `ProcessLifecycleOwner` or the gate's `LifecycleResumeEffect`.
- Channels are platform state (owned by the OS once created); the app never reads them back
  except to verify existence in tests.
- Notification ids: `entityId.hashCode()`; group keys are the channel id. No global counter
  state needed.

## 7. Error Handling & Resilience

- **Permission denied / not yet granted:** `show()` returns `false`, drops silently, logs
  one debug line. No exception, no user-facing error.
- **Malformed payload:** dropped, logged at WARN with the offending key set (never logs full
  body — see §8). `show()` returns `false`.
- **Channel creation failure** (e.g., OEM quirk): wrapped in try/catch; failure is logged and
  the notification is still attempted with `setPriority` fallback so display degrades rather
  than crashes.
- **API-level branching:** all 33+ permission calls guarded by `Build.VERSION.SDK_INT`; all
  26+ channel objects via `*Compat` so no `if/else` on raw platform APIs.
- This ticket performs **no network I/O**, so the 20s-timeout / bounded-backoff / offline
  rules apply to the upstream FCM and token tickets, not here. Notification posting is local
  and synchronous.

## 8. Security & Privacy

- Notifications are user-visible on the lock screen; channels default to
  `VISIBILITY_PRIVATE` (`setLockscreenVisibility`) so titles/bodies are hidden behind the
  "sensitive content hidden" placeholder until unlocked. `tl_alerts` and `tl_messages`
  explicitly set `VISIBILITY_PRIVATE`; `tl_broadcasts` may use `VISIBILITY_PUBLIC`
  (non-sensitive marketing/announcement content).
- **Logging:** never log full `title`/`body` at INFO+; only kind, entityId, and channel id.
  Malformed-payload logs list present **keys**, not values.
- `PendingIntent` uses `FLAG_IMMUTABLE` to prevent extra tampering by other apps.
- No session cookies, CSRF tokens, or credentials are involved in this ticket; notification
  payloads carry no auth material (the deep link is an opaque app-scheme URI resolved
  in-process by AND-108, which must itself re-auth/authorize on open).
- `POST_NOTIFICATIONS` is the only new permission; declared in `core-notifications`
  `AndroidManifest.xml` with `<uses-permission android:name="android.permission.POST_NOTIFICATIONS"/>`.

## 9. Accessibility & i18n

- Channel `name`/`description`, the rationale dialog title/body/buttons, and any fallback
  notification strings are stored in `core-notifications/src/main/res/values/strings.xml`
  (and `values-*` for localization); no hard-coded user-visible strings.
- Notification `title`/`body` themselves come from the server payload (already localized
  server-side per the user's locale) and are passed through unchanged.
- The pre-prompt rationale Compose dialog uses Material 3 `AlertDialog` with proper
  `Modifier.semantics` content descriptions; buttons are reachable by TalkBack and meet 48dp
  touch targets.
- Small icon is a monochrome vector so it renders correctly under system theming and high
  contrast; brand color is supplied via `setColor` and respects dynamic color where applicable.

## 10. Telemetry & Logging

- Structured debug logs via the app's logger (Timber-style) tagged `TlNotif`:
  `posted{kind,channel,entityId}`, `dropped{reason}` where reason ∈
  `{no_permission, invalid_payload, channel_error}`.
- Permission outcome event: `notif_permission_result{granted: Boolean,
  shown_rationale: Boolean}` emitted from the permission launcher callback so product can
  measure opt-in rate. (Routed through whatever analytics sink AND-004/app provides; if none
  exists yet, log-only and leave a TODO referencing the analytics ticket.)
- No PII in any event; counts and enums only.

## 11. Testing Strategy

- **Unit (`core-testing`, JUnit + Truth):**
  - `TlChannels.channelIdFor` for every `NotificationKind` incl. `UNKNOWN` → broadcasts.
  - `PushPayloadParser`: valid each-kind, missing required field → null, unknown kind →
    `UNKNOWN`, deep_link present/absent.
  - `NotificationPermissionState.isGranted()` returns true unconditionally on SDK < 33
    (Robolectric `@Config(sdk = [24, 30])`) and reflects grant state on SDK 33+.
- **Robolectric:**
  - `DefaultNotificationChannelInitializer.ensureChannels()` creates exactly 3 channels in
    group `tl_general` with the importances in FR-1; idempotent on second call (still 3).
  - `NotificationPresenter.show()` posts to the expected channel
    (`ShadowNotificationManager.getActiveNotifications()`); dedupe id stable for same entityId;
    drops and returns false when permission ungranted (SDK 33 shadow).
- **Compose UI test (`createAndroidComposeRule`):** rationale dialog shows once, "Allow"
  triggers the permission contract (asserted via a fake launcher), "Not now" dismisses and
  sets `markRationaleShown`.
- **Instrumented smoke (manual + CI optional):** send a test FCM data message of each kind
  (Firebase console or `adb shell` `am broadcast` harness) and assert it lands on the right
  channel under Settings → Notifications.
- No MockWebServer needed here (no HTTP); that lives in AND-106.

## 12. Dependencies & Sequencing

- **Depends on AND-105** (FCM integration / `TlFirebaseMessagingService`): provides the
  `RemoteMessage` entry point that calls `NotificationPresenter.show`. This ticket adds the
  `PushPayloadParser` + `NotificationPresenter` call site into that service.
- **Depends transitively on AND-004** (Gradle/flavor/Firebase config) via AND-105.
- **Blocks AND-108** (deep-link routing): AND-108 consumes the `PendingIntent` extras
  contract (§5) and resolves `tl.notif.deepLink` / `kind` / `entityId` into a Navigation-Compose
  destination. Until AND-108 lands, tapping a notification opens `MainActivity` at its default
  start destination (acceptable interim behavior).
- Parallel-safe with AND-106 (token registration) — no shared code beyond the messaging
  service file; coordinate merge order on that one file.

## 13. Risks & Open Questions

- **R1 — notification vs data messages:** if the backend sends `notification`-key FCM
  messages, the system auto-displays them on a default channel while backgrounded, bypassing
  our routing. **Mitigation/requirement:** backend must send **data-only** messages so
  routing is deterministic. Open question to backend owner; tracked here.
- **R2 — channel importance is immutable post-creation:** if FR-1 importances change later,
  existing installs keep the old value. Acceptable for v1; a future migration would need new
  channel ids.
- **R3 — OEM notification throttling/heads-up suppression** on some devices may mask
  `IMPORTANCE_HIGH` behavior; covered by manual device matrix, not blocking.
- **OQ1:** Does `tl_broadcasts` content ever contain sensitive data? If yes, set it to
  `VISIBILITY_PRIVATE` too (§8). Default assumption: not sensitive.
- **OQ2:** Should denied-permission users see an in-app "enable notifications" banner? Out of
  scope here; flagged for the settings ticket.

## 14. Acceptance Criteria

- AC-1. A test FCM **data** message with `kind=message` posts a notification on the
  **Messages** (`tl_messages`) channel; `kind=broadcast` → **Broadcasts**; `kind=alert` →
  **Alerts** — verifiable in system Settings → Apps → TestLogon → Notifications and via
  Robolectric shadow assertions. (Maps to backlog acceptance "Notifications display on proper
  channels".)
- AC-2. On a fresh API 33+ install, the app **requests** `POST_NOTIFICATIONS` after first
  authenticated session, preceded once by the in-app rationale dialog. (Maps to "permission
  requested".)
- AC-3. On API < 33, no runtime permission is requested and notifications still display.
- AC-4. Denying permission causes incoming messages to be dropped silently with no crash and
  a single debug log line.
- AC-5. Channels are created idempotently (re-launch does not duplicate; count stays 3) under
  group `tl_general`.
- AC-6. A re-pushed message with the same `entity_id` updates the existing notification
  rather than stacking a duplicate.
- AC-7. The posted `PendingIntent` carries `tl.notif.kind`, `tl.notif.entityId`,
  `tl.notif.deepLink` extras and uses `FLAG_IMMUTABLE` (asserted in test), unblocking AND-108.

## 15. Definition of Done

- `core-notifications` module created, wired into `app` and the AND-105 messaging service;
  builds on Gradle 8.9 / AGP 8.7.3 / JDK 17 with KSP/Hilt.
- All §3 functional requirements implemented; all §14 acceptance criteria pass in CI.
- Unit + Robolectric + Compose tests in §11 added and green; coverage includes every
  `NotificationKind` branch and the SDK-version permission branches.
- `POST_NOTIFICATIONS` permission declared; all user-visible strings externalized to
  `strings.xml`; small icon + brand color from `core-ui`.
- Lint/detekt clean; no hard-coded package strings (all `com.testlogon.android.*`); no
  payload bodies logged above DEBUG.
- `PendingIntent` extras contract (§5) documented in code KDoc and referenced by AND-108.
- PR reviewed and merged to `android-port`; manual device smoke (one API < 33, one API 33+
  device/emulator) recorded in the PR description.
