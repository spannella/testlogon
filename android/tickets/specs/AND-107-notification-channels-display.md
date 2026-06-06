---
id: AND-107
title: Notification channels + display
milestone: M2
epic: E15
priority: P1
size: M
depends_on: [AND-105]
blocks: [AND-108]
status: reviewed
reviewed_on: 2026-06-06
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
- **Web reference:** the FastAPI backend models a notification as `NotificationOut`
  (`src/api/types.ts: NotificationOut` → `{ notification_id, notification_type, title, body,
  data, read, created_at, batch_key, batch_count, batch_actors }`). **Correction (review):**
  `notification_type` is a free-form **string**, not a fixed `message|broadcast|alert` enum —
  observed web values include `post`, `message`, `follower`, `ticket`
  (`src/pages/alerts/ActivityGroupCard.tsx`). The three Android channel "kinds" below are an
  **Android-side classification** layered on top of `notification_type`, not a backend enum;
  see §16. Also note the web client uses **Web Push (VAPID / service worker)**
  (`src/lib/pushSetup.ts`), not FCM — FCM is the Android transport choice (AND-105). There is
  **no REST contract owned by this ticket**; the "contract" is the FCM data-message shape (§5),
  which is an Android-defined mapping the backend must be asked to emit (see §13/R1).
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

No HTTP REST endpoint is owned by this ticket — token registration (`POST /ui/push/register`,
op `ui_register_push_ui_push_register_post`, req `PushRegisterReq = { token: string,
platform: string }` — **verified** against OpenAPI) is AND-106. The contract here is the
**FCM data-message shape** the backend must emit and this code parses. **Note (review):** the
key names below (`kind`, `entity_id`, `deep_link`) are an **Android-side proposal** and do not
exist verbatim in the backend's notification model, which uses `notification_type`,
`notification_id`, `title`, `body`, and a generic `data: Record<string, unknown>` map
(`src/api/types.ts: NotificationOut`). These keys must be agreed with the backend owner (§13/R1).
Suggested mapping: `kind` ⇐ derived from `notification_type`; `entity_id` ⇐ `notification_id`;
`deep_link` ⇐ a value inside `data`. The parser MUST tolerate the real backend names too:

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
- No session cookies, CSRF tokens, or credentials are involved in **this** ticket (it performs
  no HTTP I/O); notification payloads carry no auth material (the deep link is an opaque
  app-scheme URI resolved in-process by AND-108, which must itself re-auth/authorize on open).
  For context: the web client **does** use cookie auth + CSRF app-wide — `credentials: include`
  plus a `ui_csrf` cookie echoed as the `X-CSRF-Token` header (`src/api/client.ts`); that
  transport concern belongs to the HTTP tickets (AND-106 for `POST /ui/push/register`), not here.
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

## 16. Citations & Assumption Audit

Each key technical claim with its verdict and exact source pointer.

1. **Token registration endpoint is `POST /ui/push/register` with body `PushRegisterReq`.**
   VERDICT: Verified. SOURCE: OpenAPI `POST /ui/push/register`
   (op `ui_register_push_ui_push_register_post`, req `PushRegisterReq`); schema
   `PushRegisterReq = { token: string, platform: string }` (openapi.pretty.json) and
   `src/api/types.ts: PushRegisterReq`. (Endpoint is owned by AND-106, cited here only for §5 context.)
2. **There is no REST endpoint owned by this ticket; it does no network I/O.**
   VERDICT: Verified. SOURCE: OpenAPI index has no display/channel endpoint; the only push
   write paths are `/ui/push/register|revoke|test` (AND-106 scope).
3. **The backend notification model is `{ notification_id, notification_type, title, body, data, read, created_at, batch_key, batch_count, batch_actors }`.**
   VERDICT: Verified. SOURCE: `src/api/types.ts: NotificationOut`; mirrored in OpenAPI
   `GET /ui/notifications` resp `NotificationListResponse` (items: `NotificationOut`).
4. **`notification_type` is a fixed enum of `message | broadcast | alert`.**
   VERDICT: Corrected → it is a free-form **string**. SOURCE: `src/api/types.ts: NotificationOut.notification_type: string`
   and `SendNotificationReq.notification_type: string`; observed concrete values in web UI are
   `post`, `message`, `follower`, `ticket` (`src/pages/alerts/ActivityGroupCard.tsx`
   `ActivityIcon` switch). The three Android channels are an Android-side classification of that
   string, with a `tl_broadcasts` fallback for unmapped values (FR-4); this is intentional and
   now documented as such in §2/§5.
5. **The FCM data keys `kind`, `entity_id`, `deep_link` are the backend contract / "mirror the web app".**
   VERDICT: Unverified-assumption (Android-defined). SOURCE: no such keys appear in
   `NotificationOut` (uses `notification_id`, `notification_type`, generic `data` map). The web
   client never receives FCM data messages at all (see #6). Treated as an Android proposal that
   must be agreed with the backend owner; parser told to also accept the real names (§5, §13/R1).
6. **The web reference app's transport is FCM with `data` messages.**
   VERDICT: Corrected → the web client uses **Web Push (VAPID + service worker)**. SOURCE:
   `src/lib/pushSetup.ts` (`registerServiceWorker`, `subscribeToPush` with
   `applicationServerKey` VAPID, `POST /ui/push/register`), `GET /ui/push/vapid-key` in OpenAPI.
   FCM is the Android-only transport introduced by AND-105; there is no web FCM artifact to mirror.
7. **No session cookies / CSRF / credentials are involved in this ticket.**
   VERDICT: Verified (scoped) — true because this ticket does no HTTP. SOURCE: §7 (no network
   I/O). Context correction: the app *does* use cookie + CSRF auth elsewhere —
   `credentials: "include"` and `ui_csrf` cookie → `X-CSRF-Token` header
   (`src/api/client.ts` lines ~124, ~167-170). That belongs to the HTTP tickets, not here.
8. **Validation/error responses on the push/notification endpoints are HTTP 422 `HTTPValidationError`.**
   VERDICT: Verified (for the AND-106 endpoint referenced). SOURCE: OpenAPI index
   `POST /ui/push/register | resp=200:;422:HTTPValidationError`; schema `HTTPValidationError`
   (openapi.pretty.json, `detail: ValidationError[]`).
9. **`POST_NOTIFICATIONS` is a runtime permission introduced in Android 13 / API 33.**
   VERDICT: Verified (framework ref). SOURCE: Android docs
   https://developer.android.com/develop/ui/views/notifications/notification-permission
   (`android.permission.POST_NOTIFICATIONS`, requested at runtime on API 33+).
10. **Notification channels are required on API 26 (Android 8.0)+; ignored below.**
    VERDICT: Verified (framework ref). SOURCE: Android docs
    https://developer.android.com/develop/ui/views/notifications/channels . The spec's use of
    `NotificationChannelCompat`/`NotificationManagerCompat` correctly no-ops the channel APIs on
    API < 26 while still posting via `NotificationCompat.Builder.setPriority`.
11. **A `PendingIntent` must specify mutability (`FLAG_IMMUTABLE`/`FLAG_MUTABLE`) on API 31+ and immutable is required for these extras.**
    VERDICT: Verified (framework ref). SOURCE: Android docs
    https://developer.android.com/reference/android/app/PendingIntent#FLAG_IMMUTABLE and
    https://developer.android.com/about/versions/12/behavior-changes-12#pending-intent-mutability .
12. **Channel importance is immutable after first creation (only name/description update).**
    VERDICT: Verified (framework ref). SOURCE: Android docs
    https://developer.android.com/develop/ui/views/notifications/channels#UpdateChannel .
    Matches FR-1/§4 idempotency note and R2.
13. **`VISIBILITY_PRIVATE` / `setLockscreenVisibility` controls lock-screen content hiding.**
    VERDICT: Verified (framework ref). SOURCE: Android docs
    https://developer.android.com/reference/androidx/core/app/NotificationChannelCompat.Builder#setLockscreenVisibility(int) .
14. **The 20s-timeout / bounded-backoff / offline rules do not apply to this ticket.**
    VERDICT: Verified (scoped). SOURCE: this ticket performs no network I/O (§7); FCM delivery
    and token registration backoff belong to AND-105/AND-106.

### Corrections made
- §2 (Context): clarified that `notification_type` is a free-form string (not a 3-value enum)
  with observed web values, and that the web client uses Web Push/VAPID rather than FCM; FCM is
  the Android transport. (Audit #4, #6.)
- §5 (API Contract): added that `kind`/`entity_id`/`deep_link` are an Android-defined proposal,
  not backend field names (which are `notification_type`/`notification_id`/`title`/`body`/`data`),
  must be confirmed with the backend, and the parser must tolerate the real names; cited the
  verified `PushRegisterReq` shape for the AND-106 reference. (Audit #1, #4, #5.)
- §8 (Security): scoped the "no CSRF/cookies" claim to this ticket and noted the app-wide cookie+
  CSRF transport (`ui_csrf` → `X-CSRF-Token`, `credentials: include`) for accuracy. (Audit #7.)

### Open assumptions
- **A1 — FCM data-only message shape (§5).** The backend currently exposes a notification REST/
  read model only; no FCM payload schema exists in the sources. The exact `data` keys the
  Android push will receive are unverifiable until the backend FCM emitter is specified. Why
  unverifiable: no FCM emitter artifact in OpenAPI or frontend (web uses Web Push). Tracked as R1.
- **A2 — `notification_type` → channel mapping.** Which concrete `notification_type` strings map
  to `tl_messages` vs `tl_alerts` vs `tl_broadcasts` is an Android product decision; only the
  `message` value is directly attested in the web source. Others (and the `broadcast`/`alert`
  kinds) are assumed. Why unverifiable: backend type is an open string set.
- **A3 — Analytics sink for `notif_permission_result` (§10).** Existence of an analytics pipeline
  is conditional ("if none exists yet, log-only"); not confirmable from the provided sources.
- **A4 — `deep_link` location.** Assumed to ride inside the backend `data` map; exact key TBD
  with backend. Why unverifiable: generic `data: Record<string, unknown>` in `NotificationOut`.

## 17. Test Plan

Test targets: **JVM** = JVM unit/Robolectric (local, no device); **emu test35** = headless
emulator AVD `test35` (x86_64, Android 15 / API 35) for fast instrumented/Compose-UI in CI;
**device A15** = physical Samsung Galaxy A15 5G (SM-A156U, serial R5CX821TA9R, Android 14 /
API 34, arm64-v8a) for real-hardware behavior (real FCM delivery, notification taps, OEM
heads-up). No MockWebServer cases here — this ticket does no HTTP (a contract test for
`POST /ui/push/register` lives in AND-106).

- **TC-AND-107-01 — Channel id mapping is deterministic for every kind.**
  Type: unit (JVM). Target: `TlChannels.channelIdFor`. Preconditions: none.
  Steps: call `channelIdFor` for `MESSAGE`, `BROADCAST`, `ALERT`, `UNKNOWN`.
  Expected: `MESSAGE→tl_messages`, `ALERT→tl_alerts`, `BROADCAST→tl_broadcasts`,
  `UNKNOWN→tl_broadcasts`. Traces: AC-1.

- **TC-AND-107-02 — Payload parser: valid, missing-required, unknown-kind, deep_link optional.**
  Type: unit (JVM). Target: `PushPayloadParser`. Preconditions: none.
  Steps: parse a `Map<String,String>` for (a) each valid kind with all required keys, (b) missing
  `entity_id`/`title`/`body`, (c) `kind="weird"`, (d) with and without `deep_link`. Also parse a
  map using the **real backend names** (`notification_type`, `notification_id`) per §5 tolerance.
  Expected: (a) `PushPayload` with correct kind; (b) returns null/drop; (c) `kind=UNKNOWN`;
  (d) `deepLink` null when absent, verbatim when present; backend-named map parses successfully.
  Traces: AC-1, AC-4, AC-6.

- **TC-AND-107-03 — `isGranted()` is unconditionally true below API 33.**
  Type: unit/Robolectric (JVM, `@Config(sdk=[24,30])`). Target: `NotificationPermissionState.isGranted`.
  Preconditions: no `POST_NOTIFICATIONS` grant. Steps: call `isGranted()`.
  Expected: returns true (permission not required pre-33); no permission request issued. Traces: AC-3.

- **TC-AND-107-04 — `isGranted()` reflects real grant state on API 33+.**
  Type: Robolectric (JVM, `@Config(sdk=[33])`). Target: `NotificationPermissionState.isGranted`.
  Preconditions: toggle shadow grant. Steps: assert false when denied, true after granting
  `POST_NOTIFICATIONS`. Expected: matches shadow grant state. Traces: AC-2.

- **TC-AND-107-05 — Channels created idempotently: exactly 3 in group `tl_general`.**
  Type: Robolectric (JVM, `@Config(sdk=[26]+)`). Target: `DefaultNotificationChannelInitializer.ensureChannels`.
  Preconditions: fresh `ShadowNotificationManager`. Steps: call `ensureChannels()` twice; read
  channels + importances. Expected: exactly 3 channels (`tl_messages` HIGH, `tl_broadcasts`
  DEFAULT, `tl_alerts` HIGH) under group `tl_general`; second call keeps count at 3 and does not
  change importance. Traces: AC-5.

- **TC-AND-107-06 — `show()` posts to the correct channel per kind.**
  Type: Robolectric (JVM, `@Config(sdk=[33])`, permission granted). Target: `NotificationPresenter.show`.
  Preconditions: channels created, permission granted. Steps: `show()` a message/broadcast/alert
  payload; inspect `ShadowNotificationManager.getActiveNotifications()`.
  Expected: each notification carries its expected channel id; small icon `ic_stat_notification`,
  color `TlBrand`, auto-cancel set; returns true. Traces: AC-1.

- **TC-AND-107-07 — Same `entity_id` updates rather than stacks.**
  Type: Robolectric (JVM). Target: `NotificationPresenter.show` dedupe.
  Preconditions: permission granted. Steps: `show()` twice with identical `entity_id` and changed
  body. Expected: exactly one active notification with id `entityId.hashCode()`, showing the
  updated body. Traces: AC-6.

- **TC-AND-107-08 — Denied permission drops silently with one debug log, no crash.**
  Type: Robolectric (JVM, `@Config(sdk=[33])`, permission denied). Target: `NotificationPresenter.show`.
  Preconditions: `POST_NOTIFICATIONS` not granted. Steps: `show()` a valid payload; capture logs.
  Expected: returns false, zero active notifications, exactly one debug `dropped{reason=no_permission}`
  line, no exception. Traces: AC-4.

- **TC-AND-107-09 — `PendingIntent` extras + immutability contract.**
  Type: Robolectric (JVM). Target: `NotificationPresenter` PendingIntent builder.
  Preconditions: permission granted. Steps: `show()` a payload with a `deep_link`; capture the
  posted `PendingIntent`/`Intent`. Expected: extras `tl.notif.kind`, `tl.notif.entityId`,
  `tl.notif.deepLink` present and correct (deepLink may be null); flags include `FLAG_IMMUTABLE`;
  target is `MainActivity`; request code derived from `entityId.hashCode()`. Traces: AC-7.

- **TC-AND-107-10 — Rationale dialog shown once; Allow launches system request; Not-now persists flag.**
  Type: Compose-UI (emu test35, `createAndroidComposeRule`). Target: `NotificationPermissionGate`
  + `NotificationPermissionViewModel` with a fake permission launcher. Preconditions:
  `notif_rationale_shown=false`. Steps: render gate post-auth; assert rationale `AlertDialog`
  appears; tap "Allow" → assert fake `RequestPermission` contract invoked; in a second run tap
  "Not now" → assert dismissed and `markRationaleShown()` set (no re-prompt next mount).
  Expected: as stated; dialog never shown again once flag set. Traces: AC-2.

- **TC-AND-107-11 — Accessibility of rationale dialog.**
  Type: Compose-UI / instrumented a11y (emu test35; spot-check on device A15). Target: rationale
  `AlertDialog`. Preconditions: dialog visible. Steps: run accessibility checks
  (`enableAccessibilityChecks()`), traverse with TalkBack semantics. Expected: title/body/buttons
  have content descriptions, buttons ≥ 48dp touch targets, no a11y violations. Traces: AC-2.

- **TC-AND-107-12 — Real FCM data message lands on the correct channel (end-to-end).**
  Type: instrumented/e2e — **MUST run on device A15** (real FCM delivery + OEM notification
  shade; emulator FCM/heads-up behavior is not representative). Target: full path
  `TlFirebaseMessagingService → PushPayloadParser → NotificationPresenter`. Preconditions:
  signed-in build, `POST_NOTIFICATIONS` granted, device registered for FCM. Steps: send a
  data-only FCM message of each kind (Firebase console or test harness); observe the shade and
  Settings → Apps → TestLogon → Notifications. Expected: message→Messages channel (heads-up,
  sound+vibrate), broadcast→Broadcasts (no vibrate), alert→Alerts (heads-up); each on its named
  channel. Traces: AC-1.

- **TC-AND-107-13 — Fresh API 33+ install requests permission after first authenticated session.**
  Type: instrumented/e2e (emu test35 for the permission flow; also smoke on device A15).
  Target: post-auth gate. Preconditions: fresh install, permission undetermined.
  Steps: complete login/finalize; observe rationale then system permission dialog fires exactly
  once after auth. Expected: rationale precedes system dialog; request issued once per FR-5.
  Traces: AC-2.

- **TC-AND-107-14 — Lock-screen visibility / no payload bodies logged (security).**
  Type: instrumented (device A15, real lock screen). Target: channel `setLockscreenVisibility`
  + logging. Preconditions: device locked with secure keyguard. Steps: post a `tl_messages` and a
  `tl_broadcasts` notification while locked; inspect lock screen and logcat at INFO+.
  Expected: `tl_messages`/`tl_alerts` content hidden (`VISIBILITY_PRIVATE` placeholder);
  `tl_broadcasts` may show content; logcat at INFO+ contains no `title`/`body` values, only
  kind/entityId/channel. Traces: AC-1, AC-4.

### Coverage matrix
| Acceptance criterion (§14) | Covered by |
|---|---|
| AC-1 (kind→correct channel) | TC-01, TC-02, TC-06, TC-12, TC-14 |
| AC-2 (API 33+ requests permission after auth, with rationale) | TC-04, TC-10, TC-11, TC-13 |
| AC-3 (API < 33 no request, still displays) | TC-03 |
| AC-4 (deny → silent drop, no crash, one log) | TC-02, TC-08, TC-14 |
| AC-5 (idempotent channel creation, count stays 3) | TC-05 |
| AC-6 (same entity_id updates, no stacking) | TC-02, TC-07 |
| AC-7 (PendingIntent extras + FLAG_IMMUTABLE) | TC-09 |
