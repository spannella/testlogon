---
id: AND-105
title: FCM integration + Firebase config
milestone: M2
epic: E15
priority: P0
size: M
status: draft
depends_on: [AND-004]
blocks: [AND-106, AND-107, AND-108, AND-110, AND-297]
---

# AND-105 — FCM integration + Firebase config

## 1. Overview & Goal

This ticket establishes Firebase Cloud Messaging (FCM) as the push-delivery foundation for the TestLogon Android app. The deliverable is a wired-up Firebase project, per-flavor `google-services.json` config, the Firebase BoM + messaging dependency set, and a `FirebaseMessagingService` subclass that receives messages in both foreground and background and surfaces the FCM registration token to the rest of the app.

The explicit, testable goal is: **a test FCM message dispatched from the Firebase console (or `fcm.googleapis.com/v1`) is received by the app while it is in the foreground AND while it is backgrounded/killed.** No business behavior (token upload, channel UX, deep-link navigation) is in scope here — those are owned by AND-106, AND-107, and AND-108 respectively. AND-105 owns only the plumbing: the service must be alive, the SDK must initialize, the token must be obtainable, and inbound `RemoteMessage` payloads must reach a single internal sink that downstream tickets consume.

This is a P0 enabler in milestone M2, epic E15 (Push/Notifications). It is the root of the push dependency chain; nothing in the notifications display or routing stack can land until it is green.

## 2. Context & References

- **Repo / branch:** `spannella/testlogon`, Android app under `android/`, branch `android-port`.
- **Namespace / applicationId base:** `com.testlogon.android` (used verbatim for the Firebase Android app package name and across all source).
- **Stack:** Kotlin 2.0.21, Hilt (KSP), Coroutines/Flow, Gradle 8.9, AGP 8.7.3, JDK 17, minSdk 24 / compileSdk 35 / targetSdk 35.
- **Module layering:** `app -> feature-* -> core-*`. FCM service code lives in `core-data` (or a dedicated `core-push` module if the team prefers isolation — see §13); the `google-services` Gradle plugin is applied in `:app`.
- **Upstream dependency:** AND-004 (Hilt DI baseline) — `@HiltAndroidApp` Application and a building component graph are prerequisites because the messaging service and the message sink are Hilt-injected.
- **Downstream consumers (blocked by this ticket):**
  - AND-106 — Push token registration (`POST /ui/push/register`), consumes `onNewToken` + `getToken()`.
  - AND-107 — Notification channels + display, `POST_NOTIFICATIONS` runtime permission (Android 13+), consumes received `RemoteMessage` payloads.
  - AND-108 — Deep-link routing from taps, consumes notification `data` payload keys.
  - AND-110 — Push tests (end-to-end).
  - AND-297 — Incoming call (push + full-screen), consumes high-priority FCM messages.
- **External docs:** Firebase Android setup, FCM `FirebaseMessagingService`, FCM message types (notification vs. data messages).
- **Backend note:** the FastAPI dev backend (`http://18.222.237.167:8000`) is **not** involved in this ticket. Push is delivered via Google FCM infrastructure, not the app backend. The backend `POST /ui/push/register` contract is exercised in AND-106.

## 3. Functional Requirements

FR-1. The app SHALL include the Firebase platform: `google-services` Gradle plugin applied to `:app`, Firebase BoM, and `firebase-messaging` (+ `firebase-analytics` as the BoM-recommended companion only if required for messaging delivery diagnostics; otherwise omitted).

FR-2. A valid `google-services.json` SHALL be present for each build flavor, matching that flavor's `applicationId` (see §6 for flavor → package mapping). The build SHALL fail fast (via the `google-services` plugin) if a flavor's package name is absent from the config.

FR-3. A `TlFirebaseMessagingService` SHALL be declared in the merged manifest with the `com.google.firebase.MESSAGING_EVENT` intent filter and `exported="false"`.

FR-4. `onNewToken(token: String)` SHALL forward the new token to an injectable `PushTokenSink`. AND-105 provides a no-op/logging default; AND-106 replaces it with the real registrar.

FR-5. `onMessageReceived(message: RemoteMessage)` SHALL forward every inbound message to an injectable `PushMessageSink`. AND-105 provides a default that logs and (for **foreground notification-type** messages) does nothing more; AND-107 supplies the channel-aware notification builder.

FR-6. A `PushTokenProvider` SHALL expose a suspending `currentToken(): ApiResult<String>` that wraps `FirebaseMessaging.getInstance().token` (a `Task`) as a coroutine. This is the read path AND-106 uses on login.

FR-7. Firebase initialization SHALL occur automatically via the `FirebaseInitProvider` (default content provider) — no manual `FirebaseApp.initializeApp()` in `onCreate`. The app MUST verify init succeeds on cold start.

FR-8. **Foreground delivery:** a data-only or mixed message received while the app is in the foreground SHALL reach `onMessageReceived`. **Background delivery:** a message received while backgrounded/killed SHALL also reach `onMessageReceived` for data-only messages, and SHALL be auto-displayed by the system tray for notification-type messages.

FR-9. The service and sinks SHALL be testable without a live Firebase connection (sinks are interfaces; `RemoteMessage` is constructable via its `Builder`).

## 4. Technical Design

### 4.1 Gradle wiring

Root/version-catalog additions (`gradle/libs.versions.toml`):

```toml
[versions]
firebaseBom = "33.7.0"
googleServices = "4.4.2"

[libraries]
firebase-bom = { module = "com.google.firebase:firebase-bom", version.ref = "firebaseBom" }
firebase-messaging = { module = "com.google.firebase:firebase-messaging" }

[plugins]
google-services = { id = "com.google.gms.google-services", version.ref = "googleServices" }
```

`:app` `build.gradle.kts`:

```kotlin
plugins {
    alias(libs.plugins.google.services)
}
dependencies {
    implementation(platform(libs.firebase.bom))
    implementation(libs.firebase.messaging)
}
```

The `core-push` (or `core-data`) module depends on `firebase-messaging` as `api` so service/provider types are visible to `:app` only via the abstraction interfaces, not Firebase types directly where avoidable.

### 4.2 Service + sinks

```kotlin
package com.testlogon.android.core.push

@AndroidEntryPoint
class TlFirebaseMessagingService : FirebaseMessagingService() {

    @Inject lateinit var tokenSink: PushTokenSink
    @Inject lateinit var messageSink: PushMessageSink

    override fun onNewToken(token: String) {
        tokenSink.onTokenRefreshed(token)
    }

    override fun onMessageReceived(message: RemoteMessage) {
        messageSink.onMessage(PushMessage.from(message))
    }
}
```

```kotlin
interface PushTokenSink {
    fun onTokenRefreshed(token: String)
}

interface PushMessageSink {
    fun onMessage(message: PushMessage)
}

/** Stable internal model decoupled from FCM's RemoteMessage. */
data class PushMessage(
    val messageId: String?,
    val title: String?,
    val body: String?,
    val data: Map<String, String>,
    val sentTime: Long,
    val priority: Int,
) {
    companion object {
        fun from(rm: RemoteMessage): PushMessage = PushMessage(
            messageId = rm.messageId,
            title = rm.notification?.title,
            body = rm.notification?.body,
            data = rm.data,
            sentTime = rm.sentTime,
            priority = rm.priority,
        )
    }
}
```

### 4.3 Token provider

```kotlin
class PushTokenProvider @Inject constructor(
    private val messaging: FirebaseMessaging,
) {
    suspend fun currentToken(): ApiResult<String> = runCatching {
        messaging.token.await()        // kotlinx-coroutines-play-services Task.await()
    }.fold(
        onSuccess = { ApiResult.Success(it) },
        onFailure = { ApiResult.Error(PushError.TokenUnavailable(it)) },
    )
}
```

### 4.4 Hilt module (defaults for this ticket)

```kotlin
@Module
@InstallIn(SingletonComponent::class)
object PushModule {

    @Provides @Singleton
    fun provideFirebaseMessaging(): FirebaseMessaging = FirebaseMessaging.getInstance()

    @Provides @Singleton
    fun provideTokenSink(@ApplicationContext ctx: Context): PushTokenSink =
        LoggingPushTokenSink()      // replaced by AND-106's RegistrarTokenSink via @Binds override

    @Provides @Singleton
    fun provideMessageSink(): PushMessageSink =
        LoggingPushMessageSink()    // replaced by AND-107's NotificationDisplaySink
}
```

The default sinks `LoggingPushTokenSink` / `LoggingPushMessageSink` log at DEBUG (token redacted) and otherwise no-op. AND-106/AND-107 will swap the bindings; the seam is intentional so this ticket can ship and be verified independently.

### 4.5 Manifest

The service is declared in `core-push`'s manifest (merged into `:app`):

```xml
<service
    android:name="com.testlogon.android.core.push.TlFirebaseMessagingService"
    android:exported="false">
    <intent-filter>
        <action android:name="com.google.firebase.MESSAGING_EVENT" />
    </intent-filter>
</service>

<!-- default channel id + icon for system-displayed notification messages -->
<meta-data
    android:name="com.google.firebase.messaging.default_notification_channel_id"
    android:value="@string/default_notification_channel_id" />
<meta-data
    android:name="com.google.firebase.messaging.default_notification_icon"
    android:resource="@drawable/ic_notification" />
```

The `default_notification_channel_id` string references a channel; the channel object itself is created by AND-107. For AND-105 verification a placeholder channel (`"default"`) created in `Application.onCreate` is acceptable on Android 8+ so background notification messages have a valid channel.

## 5. API Contract

**No app-backend HTTP contract is owned by this ticket.** Push delivery uses Google's FCM service, not the TestLogon FastAPI backend. The token-upload contract (`POST /ui/push/register`) is owned by AND-106.

The relevant external contract is the FCM message envelope the app must parse. Test messages (FCM HTTP v1, `POST https://fcm.googleapis.com/v1/projects/<project-id>/messages:send`) take the shape:

```json
{
  "message": {
    "token": "<device-fcm-token>",
    "notification": { "title": "TL test", "body": "hello" },
    "data": { "type": "test", "route": "/notifications" },
    "android": { "priority": "high" }
  }
}
```

Contract assumptions this ticket locks in for downstream consumers:
- `notification.title` / `notification.body` map to `PushMessage.title` / `PushMessage.body`.
- `data` is an arbitrary `Map<String,String>`; reserved keys (`type`, `route`, `entity_id`) will be defined by AND-108. AND-105 only guarantees they pass through untransformed.
- A **data-only** message (no `notification` block) is required to test foreground+background delivery into `onMessageReceived`, because notification-type messages are intercepted by the system tray when backgrounded and do NOT invoke `onMessageReceived`.

## 6. Data & State Management

- **No Room/DataStore persistence in this ticket.** The FCM token is held only transiently via `PushTokenProvider.currentToken()`; persisting/uploading it is AND-106.
- **Flavor → package → config mapping.** Per-flavor `google-services.json` files live at:

  | Flavor | applicationId | google-services.json path |
  |--------|---------------|---------------------------|
  | `dev`  | `com.testlogon.android.dev`  | `app/src/dev/google-services.json` |
  | `staging` | `com.testlogon.android.staging` | `app/src/staging/google-services.json` |
  | `prod` | `com.testlogon.android` | `app/src/prod/google-services.json` (or `app/google-services.json`) |

  Each JSON must contain a `client` entry whose `client_info.android_client_info.package_name` equals the flavor `applicationId`. A single multi-package config file at `app/google-services.json` is acceptable if it enumerates all flavor packages; the per-source-set layout above is preferred for clarity. The exact flavor set is inherited from the build-config ticket (AND-002/AND-003 family); this spec assumes `dev`/`staging`/`prod` and MUST be reconciled with that ticket (see §13).
- **State exposed:** `PushTokenProvider` returns `ApiResult<String>`; `onNewToken` pushes through `PushTokenSink`. No `StateFlow<UiState>` is introduced here (no UI surface).

## 7. Error Handling & Resilience

- `FirebaseMessaging.token` can fail (missing Google Play services, no network, SERVICE_NOT_AVAILABLE). `PushTokenProvider` wraps the `Task` in `runCatching` and returns `ApiResult.Error(PushError.TokenUnavailable)` rather than throwing. **No retry loop in this ticket** — AND-106 owns bounded retry/backoff on the registration path.
- Missing/invalid `google-services.json`: build-time failure from the `google-services` plugin (fail fast, by design).
- Devices without Google Play services (FR coverage gap): `GoogleApiAvailability.getInstance().isGooglePlayServicesAvailable(context)` is checked once and the result logged; degraded behavior (no push) is acceptable for AND-105 and surfaced to the user only by later tickets.
- `onMessageReceived` MUST never throw out of the service callback; the sink call is wrapped so a sink bug cannot crash the messaging process.
- This ticket is independent of the unreliable dev backend, so the 20s-timeout/backoff guidance does not apply here; it applies to AND-106's `/ui/push/register` call.

## 8. Security & Privacy

- The FCM registration token is a **device secret** capable of receiving targeted pushes. It MUST NOT be logged at INFO/WARN/ERROR; the default `LoggingPushTokenSink` logs only a redacted prefix (`token.take(6) + "…"`) and only on DEBUG builds.
- The messaging service is `exported="false"` and reachable only via the signed Firebase intent — no other app can deliver to it.
- `google-services.json` for `prod`/`staging` contains the Firebase API key and project numbers. It is checked into the repo (standard Firebase practice; the API key is not a secret in the traditional sense and is scope-restricted in the Google Cloud console). Server-side FCM **sender credentials** (service-account JSON for `messages:send`) MUST NOT be committed and are not part of the app at all.
- No PII is processed in AND-105; `data` payload contents are passed through but not stored.
- App restriction: the Firebase Android API key should be restricted by package name + SHA-256 signing cert in the Google Cloud console for `prod`.

## 9. Accessibility & i18n

- **No app UI is introduced in this ticket**, so screen-level a11y (TalkBack, touch targets, contrast) is N/A and is owned by AND-107 (notification display) and AND-108 (tap routing).
- The only user-visible string seeds are the placeholder default notification channel name and the `default_notification_channel_id`. Any user-facing channel name string MUST be in `strings.xml` (not hardcoded) so AND-107/i18n tickets can localize. The `ic_notification` drawable must be a monochrome, alpha-only icon per Android notification icon guidelines.

## 10. Telemetry & Logging

- Log events (DEBUG, tag `TlPush`): `fcm_init_ok`, `fcm_token_refreshed` (redacted), `fcm_message_received` (messageId + priority + key set of `data`, never values), `fcm_token_fetch_failed` (error class only).
- If `firebase-analytics` is included via the BoM, FCM delivery/open analytics flow automatically; this is optional and SHOULD be disabled in `dev` to avoid noise. No custom analytics events are required by AND-105.
- A single startup log line records Google Play services availability status.

## 11. Testing Strategy

**Unit (JVM, `core-testing`):**
- `PushMessage.from(RemoteMessage)` correctly maps title/body/data/priority. `RemoteMessage` built via `RemoteMessage.Builder("test@fcm").addData(...).build()`.
- `TlFirebaseMessagingService.onNewToken` calls `PushTokenSink.onTokenRefreshed` with the exact token (fake sink, verify via Turbine/mock).
- `TlFirebaseMessagingService.onMessageReceived` forwards a constructed `RemoteMessage` to `PushMessageSink` as the mapped `PushMessage`.
- `PushTokenProvider.currentToken()` returns `ApiResult.Success` on a completed Task and `ApiResult.Error(TokenUnavailable)` on a failed Task (mock `FirebaseMessaging`, stub `Task`).
- Sink call wrapped so a throwing sink does not propagate out of `onMessageReceived`.

**Instrumented / manual acceptance (the gating test, also seeded for AND-110):**
- On a device/emulator with Google Play services, cold-start the app, fetch the token via a debug hook, and send a **data-only** message via the Firebase console or `messages:send`. Assert `fcm_message_received` logs while (a) app foregrounded, (b) app backgrounded, (c) app process killed.
- Send a **notification-type** message while backgrounded and assert a system-tray notification appears on the placeholder/default channel.
- Build-config test: assert `:app:processDevGoogleServices` (and staging/prod equivalents) succeeds, proving each flavor's package is present in its config.

**CI note:** FCM end-to-end cannot run on a vanilla CI emulator without Play services + a real send credential; the unit tests run in CI and the instrumented delivery test is documented as a manual/firebase-test-lab gate owned jointly with AND-110.

## 12. Dependencies & Sequencing

- **Depends on:** AND-004 (Hilt baseline) — required for `@AndroidEntryPoint` service injection and the `PushModule`. Also implicitly the build-flavor ticket (AND-002/AND-003 family) for flavor definitions; reconcile flavor names in §6.
- **Blocks:** AND-106 (token registration — swaps `PushTokenSink`), AND-107 (channels + display — swaps `PushMessageSink`, owns `POST_NOTIFICATIONS`), AND-108 (deep-link routing — defines `data` keys), AND-110 (push tests), AND-297 (incoming-call push — needs high-priority delivery proven here).
- **Sequencing:** Land Gradle/Firebase config + service + default sinks together. The default sinks are the explicit seam that lets AND-105 merge before AND-106/AND-107 exist. Do not introduce backend or UI in this PR.

## 13. Risks & Open Questions

- **Flavor set mismatch (Open):** §6 assumes `dev`/`staging`/`prod`. Confirm the actual flavor names and `applicationId` suffixes against the build-config ticket before generating Firebase apps; each flavor package needs its own Firebase Android app registration.
- **Module placement (Decision):** put FCM in a new `core-push` module vs. `core-data`. Recommendation: `core-push` to keep Firebase types from leaking into the data layer; minor extra module cost. Open for team ratification.
- **Google Play services absence:** delivery silently fails on Play-less devices (some emulators, some OEM/region builds). Out of scope to remediate here; flagged for AND-107 user messaging.
- **Notification vs data messages:** background `onMessageReceived` only fires for data-only messages. Test harness and AND-297 must standardize on data (or mixed) messages with app-side display; document for the backend/sender side.
- **Analytics dependency:** decide whether `firebase-analytics` rides along via BoM. Default: omit unless delivery diagnostics require it.
- **BoM version:** pin `33.7.0` now; track for upgrades alongside the Gradle/AGP toolchain.

## 14. Acceptance Criteria

AC-1. `:app` applies `com.google.gms.google-services`; `firebase-messaging` resolves via the Firebase BoM; project builds with Kotlin 2.0.21 / AGP 8.7.3 / JDK 17.
AC-2. Each configured flavor has a `google-services.json` whose package name matches its `applicationId`; `process<Flavor>GoogleServices` tasks succeed.
AC-3. `TlFirebaseMessagingService` appears in the merged manifest with the `MESSAGING_EVENT` intent filter and `exported="false"`.
AC-4. On cold start the app initializes Firebase (no `FirebaseApp` init exception) and `PushTokenProvider.currentToken()` returns `ApiResult.Success` with a non-empty token on a Play-services device.
AC-5. **A test FCM (data-only) message is received in `onMessageReceived` while the app is in the foreground.**
AC-6. **A test FCM message is received while the app is backgrounded/killed** — data-only via `onMessageReceived`, notification-type via the system tray on the default channel.
AC-7. `onNewToken` forwards the token to `PushTokenSink`; the token is never logged in full.
AC-8. Unit tests in §11 pass in CI; the manual/Firebase delivery test is documented and reproducible.
AC-9. No app-backend call and no UI surface are introduced by this ticket.

## 15. Definition of Done

- All §14 acceptance criteria verified, with AC-5 and AC-6 demonstrated on a real/Play-services device and captured (log/screenshot) in the PR.
- Code merged to `android-port` behind the standard review; `core-push` (or `core-data`) module, `PushModule`, service, sinks, and `PushTokenProvider` present with `com.testlogon.android` packages.
- Version catalog updated; `google-services.json` per flavor committed (no server sender credentials committed).
- Unit tests added and green in CI; instrumented delivery test documented in the test plan and cross-referenced from AND-110.
- Token-handling redaction confirmed; lint/detekt clean; no Firebase types leak past the abstraction seam intended for AND-106/AND-107.
- Downstream tickets (AND-106/107/108/297) can bind their real sinks against the published `PushTokenSink` / `PushMessageSink` / `PushMessage` interfaces without modifying AND-105 code.
