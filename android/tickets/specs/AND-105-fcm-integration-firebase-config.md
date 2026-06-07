---
id: AND-105
title: FCM integration + Firebase config
milestone: M2
epic: E15
priority: P0
size: M
status: reviewed
reviewed_on: 2026-06-06
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
  - AND-106 — Push token registration (`POST /ui/push/register`, request body `PushRegisterReq { token: string, platform: string }`, both required; verified against the backend OpenAPI and the web client, which sends `platform: "web"` — Android will send `platform: "android"`), consumes `onNewToken` + `getToken()`.
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

FR-8. **Foreground delivery:** a data-only or mixed message received while the app is in the foreground SHALL reach `onMessageReceived`. **Background delivery:** a message received while the app is merely backgrounded (process still alive) SHALL also reach `onMessageReceived` for data-only messages, and SHALL be auto-displayed by the system tray for notification-type messages. **Correction (verified against Android framework behavior):** if the app has been **force-stopped / swiped from recents on aggressive OEMs**, FCM does NOT deliver messages and `onMessageReceived` is NOT invoked until the app is relaunched — this is platform behavior, not a bug. The acceptance target for "killed" is therefore scoped to *background, process not force-stopped*; true force-stop behavior is documented and tested as a known limitation (especially on Samsung, see §7 and §13).

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
- A **data-only** message (no `notification` block) is required to test foreground+background delivery into `onMessageReceived`, because notification-type messages are intercepted by the system tray when backgrounded and do NOT invoke `onMessageReceived` (verified Android framework behavior).
- The web reference client does **not** use FCM at all: it uses the Web Push API (VAPID + a `PushSubscription`) and posts the serialized subscription JSON as `PushRegisterReq.token` with `platform: "web"` (`src/lib/pushSetup.ts`, `src/pages/alerts/PushDevices.tsx`). The Android contract diverges deliberately: the `token` is the FCM registration token and `platform` is `"android"`. There is no VAPID key on Android (`GET /ui/push/vapid-key` is web-only).

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
AC-6. **A test FCM message is received while the app is backgrounded (process alive, not force-stopped)** — data-only via `onMessageReceived`, notification-type via the system tray on the default channel. Force-stopped/swiped-away delivery is explicitly out of scope per FR-8 (Android platform behavior) and is documented as a known limitation rather than gated.
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

## 16. Citations & Assumption Audit

Each key technical claim, its verdict, and the authoritative source pointer.

1. **Claim:** The downstream token-upload endpoint is `POST /ui/push/register`. **Verdict: Verified.** **Source:** OpenAPI `POST /ui/push/register` (op `ui_register_push_ui_push_register_post`, `req=PushRegisterReq`, `resp=200;422:HTTPValidationError`); frontend `src/api/endpoints/push.ts: registerPush`.
2. **Claim:** The register request body shape is `{ token: string, platform: string }` (both required). **Verdict: Verified (and made explicit in §2).** **Source:** OpenAPI `components.schemas.PushRegisterReq` (properties `token`, `platform`; `required: [token, platform]`); frontend `src/api/types.ts: PushRegisterReq`.
3. **Claim:** The web client sends `platform: "web"`; Android must diverge and send `platform: "android"`. **Verdict: Verified (web) / Corrected-clarification (Android value).** **Source:** `src/pages/alerts/PushDevices.tsx` (`registerPush({ token: subscriptionJson, platform: "web" })`); platform string is a free-form `string` per `PushRegisterReq`, so `"android"` is a forward-looking assumption for AND-106, not a backend-enforced enum.
4. **Claim:** The web reference client uses Web Push / VAPID, NOT FCM, so the Android `token` semantics differ (FCM registration token vs. serialized `PushSubscription` JSON). **Verdict: Verified.** **Source:** `src/lib/pushSetup.ts` (`subscribeToPush` returns `JSON.stringify(subscription.toJSON())`, `applicationServerKey` from VAPID key); `src/api/endpoints/push.ts: getVapidKey` -> `GET /ui/push/vapid-key`; OpenAPI `GET /ui/push/vapid-key`.
5. **Claim:** AND-105 makes no app-backend HTTP call and introduces no UI (AC-9). **Verdict: Verified (by scope).** **Source:** No endpoint is invoked by this ticket; the only push endpoints (`/ui/push/register`, `/ui/push/revoke`, `/ui/push/devices`, `/ui/push/test`, `/ui/push/vapid-key`) are all consumed by later tickets per OpenAPI index lines 1773-1777.
6. **Claim:** Backend auth/transport for the (later) register call uses session cookies + CSRF, not a bearer-only model. **Verdict: Verified (context only; not exercised here).** **Source:** `src/api/client.ts` (`credentials: "include"`, `X-CSRF-Token` from `ui_csrf` cookie, `X-IMPERSONATION-TOKEN`); OpenAPI register params include `X-SESSION-ID`, `X-IMPERSONATION-TOKEN`, `user_sub`. AND-106 owns wiring this; AND-105 correctly defers.
7. **Claim:** The dev FastAPI backend (`http://18.222.237.167:8000`) is not involved in this ticket. **Verdict: Verified (by scope) / Unverified-assumption (the literal host string).** **Source:** No backend call is made; the host string is not present in `src/api/client.ts` (base URL is env-injected in the web app), so the exact host is an unverified config detail and is non-load-bearing for AND-105.
8. **Claim:** A data-only message reaches `onMessageReceived` in foreground and background; a notification-type message backgrounded is shown by the system tray and does NOT invoke `onMessageReceived`. **Verdict: Verified (framework behavior).** **Source:** framework ref — Firebase Cloud Messaging "Receive messages" / message-type table (https://firebase.google.com/docs/cloud-messaging/android/receive).
9. **Claim (original spec):** A message is received while the app is "killed". **Verdict: Corrected.** Force-stopped / swiped-away apps on aggressive OEMs do not receive FCM until relaunch; scope narrowed to "backgrounded, process not force-stopped". **Source:** framework ref — FCM "App in background" / lifecycle notes (https://firebase.google.com/docs/cloud-messaging/android/receive) and Android force-stop semantics.
10. **Claim:** Firebase initializes automatically via `FirebaseInitProvider` (no manual `FirebaseApp.initializeApp()`). **Verdict: Verified (framework behavior).** **Source:** framework ref — Firebase Android setup / automatic initialization via merged `ContentProvider` (https://firebase.google.com/docs/android/setup).
11. **Claim:** `FirebaseMessagingService` is registered via a `<service>` with the `com.google.firebase.MESSAGING_EVENT` intent filter and should be `exported="false"`. **Verdict: Verified (framework behavior).** **Source:** framework ref — FCM `FirebaseMessagingService` reference / client setup (https://firebase.google.com/docs/cloud-messaging/android/client).
12. **Claim:** `default_notification_channel_id` / `default_notification_icon` meta-data drive system-tray display for notification messages and a valid channel is needed on Android 8+. **Verdict: Verified (framework behavior).** **Source:** framework ref — FCM "Edit app manifest" / notification channels (https://firebase.google.com/docs/cloud-messaging/android/client) and Android `NotificationChannel` docs.
13. **Claim:** `FirebaseMessaging.token` is exposed as a `Task` and can be awaited via `kotlinx-coroutines-play-services` `Task.await()`. **Verdict: Verified (framework/library behavior).** **Source:** framework ref — `FirebaseMessaging.getToken()` returns `Task<String>` (https://firebase.google.com/docs/reference/android/com/google/firebase/messaging/FirebaseMessaging) + `kotlinx-coroutines-play-services` `await()`.
14. **Claim:** Pinned versions Firebase BoM `33.7.0`, google-services plugin `4.4.2`, Kotlin 2.0.21, AGP 8.7.3, compile/target SDK 35, minSdk 24. **Verdict: Unverified-assumption.** No authoritative source in this repo set pins these; they are toolchain choices to ratify against the build-config ticket (AND-002/003) and current Firebase releases. Flagged in §13.
15. **Claim:** The FCM registration token is a device secret and must not be logged in full; service is `exported="false"`. **Verdict: Verified (security best practice / framework behavior).** **Source:** framework ref — FCM token handling guidance + Android exported-component security (https://firebase.google.com/docs/cloud-messaging/android/client, https://developer.android.com/guide/topics/manifest/service-element).
16. **Claim:** `POST_NOTIFICATIONS` runtime permission is required on Android 13+ for displayed notifications. **Verdict: Verified (framework behavior); owned by AND-107 not AND-105.** **Source:** framework ref — Android 13 notification runtime permission (https://developer.android.com/develop/ui/views/notifications/notification-permission).

### Corrections made
- **§2 downstream reference:** added the verified `PushRegisterReq { token, platform }` shape and the web `platform: "web"` fact, clarifying the Android divergence (citation 2/3).
- **FR-8, §5, AC-6:** corrected the original "received while backgrounded/**killed**" claim. FCM does not deliver to force-stopped/swiped-away apps on aggressive OEMs; scope narrowed to "background, process not force-stopped", with force-stop documented as a known platform limitation (especially relevant to the Samsung physical test device) (citation 9).
- **§5:** added an explicit statement that the web client uses Web Push/VAPID rather than FCM, so the `token` semantics differ between platforms (citation 4).

### Open assumptions
- **Toolchain/version pins** (BoM 33.7.0, google-services 4.4.2, Kotlin/AGP/SDK levels): not verifiable from the provided sources; ratify against the build-config ticket and live Firebase release notes (citation 14).
- **Flavor set `dev`/`staging`/`prod` and applicationId suffixes:** assumed; must be reconciled with AND-002/AND-003 since each flavor package needs its own Firebase Android app registration (§13).
- **Module placement `core-push` vs `core-data`:** team decision, not source-verifiable (§13).
- **Dev backend host string `18.222.237.167:8000`:** not present in the frontend client (env-injected); non-load-bearing for AND-105 since no call is made (citation 7).
- **`platform: "android"` literal value:** forward assumption for AND-106; the backend field is a free-form string with no enforced enum (citation 3).

## 17. Test Plan

Test target legend: **JVM** = JVM unit/Robolectric (local, no device); **emu35** = headless emulator AVD `test35` (x86_64, API 35, KVM on CI); **device** = physical Samsung Galaxy A15 5G (SM-A156U, serial R5CX821TA9R, API 34, arm64-v8a) connected to the build host. Cases that depend on real FCM push delivery, Google Play services behavior, or OEM background management MUST run on **device** (the emulator's Play-services image is not guaranteed and Samsung's aggressive background policy cannot be reproduced on a vanilla AVD).

- **TC-AND-105-01** — Type: unit (JVM). Target: JVM. Precond: `PushMessage.from` available; `RemoteMessage` buildable. Steps: build `RemoteMessage.Builder("test@fcm").addData("type","test").addData("route","/notifications").build()`, set notification title/body via builder, call `PushMessage.from(rm)`. Expected: `title`/`body`/`data`/`messageId`/`sentTime`/`priority` map 1:1; `data` preserves keys/values untransformed. Traces: AC-5, AC-9 (contract pass-through).
- **TC-AND-105-02** — Type: unit (JVM). Target: JVM. Precond: fake `PushTokenSink`. Steps: instantiate `TlFirebaseMessagingService` (sinks injected via test), call `onNewToken("ABC123token")`. Expected: `PushTokenSink.onTokenRefreshed` invoked exactly once with the exact token string. Traces: AC-7.
- **TC-AND-105-03** — Type: unit (JVM). Target: JVM. Precond: fake `PushMessageSink`, throwing variant available. Steps: call `onMessageReceived(rm)` with (a) normal sink, (b) a sink that throws. Expected: (a) forwards mapped `PushMessage` once; (b) the exception is swallowed and does NOT propagate out of the callback (no crash). Traces: AC-5 (and §7 resilience).
- **TC-AND-105-04** — Type: unit (JVM). Target: JVM. Precond: mock `FirebaseMessaging`, stubbed `Task`. Steps: stub `token` to a completed `Task("tok")` then to a failed `Task`. Call `PushTokenProvider.currentToken()`. Expected: success path returns `ApiResult.Success("tok")`; failure path returns `ApiResult.Error(PushError.TokenUnavailable)` and never throws. Traces: AC-4.
- **TC-AND-105-05** — Type: unit (JVM). Target: JVM. Precond: `LoggingPushTokenSink` with a captured logger. Steps: call `onTokenRefreshed("SECRET_TOKEN_VALUE_1234567890")`, inspect emitted log. Expected: only a redacted prefix is logged (`take(6) + "…"`); the full token never appears; nothing logged above DEBUG. Traces: AC-7.
- **TC-AND-105-06** — Type: contract/MockWebServer (JVM/Robolectric). Target: JVM. Precond: documents that AND-105 makes no backend call; a MockWebServer is started and asserted to receive zero requests during init + a simulated message. Steps: cold-init the push graph, dispatch a fake message through the sink. Expected: MockWebServer records 0 requests; proves AC-9 (no backend call introduced). Traces: AC-9.
- **TC-AND-105-07** — Type: integration (manifest/merge). Target: emu35 (or JVM via merged-manifest assertion). Precond: app assembled. Steps: inspect the merged manifest. Expected: `TlFirebaseMessagingService` present with `<action android:name="com.google.firebase.MESSAGING_EVENT"/>` and `android:exported="false"`; `default_notification_channel_id` / `default_notification_icon` meta-data present. Traces: AC-3.
- **TC-AND-105-08** — Type: integration (Gradle build). Target: CI build host (JVM/Gradle). Precond: per-flavor `google-services.json` committed. Steps: run `:app:processDevGoogleServices`, `:app:processStagingGoogleServices`, `:app:processProdGoogleServices`; then run with a deliberately mismatched package to assert fail-fast. Expected: each task succeeds when the flavor `applicationId` matches a `client_info.android_client_info.package_name`; the mismatched run fails the build. Traces: AC-1, AC-2.
- **TC-AND-105-09** — Type: instrumented/e2e (real FCM delivery). Target: **device (REQUIRED)**. Precond: Galaxy A15 has Google Play services, app cold-started in foreground, FCM token captured via debug hook. Steps: send a **data-only** message via `fcm.googleapis.com/v1 .../messages:send` to the device token. Expected: `fcm_message_received` (TlPush) logs with messageId+priority+data key set while app is foregrounded; `onMessageReceived` fires. (Cannot run on emu35 — requires guaranteed Play services + real send credential.) Traces: AC-5.
- **TC-AND-105-10** — Type: instrumented/e2e. Target: **device (REQUIRED)**. Precond: as TC-09, then send app to background (process still alive). Steps: send a **data-only** message. Expected: `onMessageReceived` fires while backgrounded (logged). Traces: AC-6.
- **TC-AND-105-11** — Type: instrumented/e2e. Target: **device (REQUIRED)**. Precond: as TC-10, app backgrounded. Steps: send a **notification-type** message. Expected: a system-tray notification appears on the `default` channel with title/body; `onMessageReceived` is NOT invoked (framework behavior). Traces: AC-6.
- **TC-AND-105-12** — Type: instrumented/e2e (negative / known-limitation). Target: **device (REQUIRED — Samsung OEM behavior)**. Precond: app force-stopped (swipe from recents + force stop). Steps: send a data-only message; observe delivery. Expected: message is NOT delivered while force-stopped (documented platform limitation per FR-8/§13); upon relaunch, subsequent messages are delivered again. Asserts the corrected scope, not a passing delivery. Traces: AC-6 (limitation), §13.
- **TC-AND-105-13** — Type: instrumented (init + token). Target: device (preferred) / emu35 if it has Play services. Precond: clean cold start. Steps: launch app; call `PushTokenProvider.currentToken()`; also force a no-Play-services / offline condition (airplane mode) and call again. Expected: with Play services + network, `ApiResult.Success` with a non-empty token and a single `fcm_init_ok` log; offline/no-Play yields `ApiResult.Error(TokenUnavailable)` logged as `fcm_token_fetch_failed` (error class only) with no crash and no full-token leak. Traces: AC-4, AC-7 (flaky/offline path).
- **TC-AND-105-14** — Type: manual/security (permission + exported). Target: device. Precond: app installed. Steps: from a separate test app / `adb` attempt to send an intent to `TlFirebaseMessagingService`; verify it is not reachable; confirm logcat at INFO/WARN/ERROR never contains a full FCM token across a token-refresh cycle. Expected: external delivery is rejected (`exported="false"`); no full token at INFO+; redacted prefix only at DEBUG. Traces: AC-7 (security), AC-3.

Accessibility note: AND-105 introduces no app UI (§9), so screen-level a11y (TalkBack/contrast/touch targets) is N/A and deferred to AND-107/AND-108. The one a11y-adjacent asset check — the `ic_notification` drawable being monochrome/alpha-only per Android notification-icon guidelines — is verified as part of TC-AND-105-11 (correct rendering in the status bar / tray).

### Coverage matrix

| Acceptance criterion | Covered by |
|---|---|
| AC-1 (plugin applied; messaging resolves; builds) | TC-AND-105-08 |
| AC-2 (per-flavor google-services.json matches applicationId; process<Flavor>GoogleServices) | TC-AND-105-08 |
| AC-3 (service in merged manifest, MESSAGING_EVENT, exported=false) | TC-AND-105-07, TC-AND-105-14 |
| AC-4 (cold-start Firebase init; currentToken() Success) | TC-AND-105-04, TC-AND-105-13 |
| AC-5 (data-only message in foreground -> onMessageReceived) | TC-AND-105-01, TC-AND-105-03, TC-AND-105-09 |
| AC-6 (backgrounded/non-force-stopped delivery; tray for notification type; force-stop limitation) | TC-AND-105-10, TC-AND-105-11, TC-AND-105-12 |
| AC-7 (onNewToken -> sink; token never logged in full) | TC-AND-105-02, TC-AND-105-05, TC-AND-105-13, TC-AND-105-14 |
| AC-8 (unit tests pass in CI; manual delivery documented/reproducible) | TC-AND-105-01..06 (CI), TC-AND-105-09..13 (documented manual/e2e) |
| AC-9 (no app-backend call; no UI) | TC-AND-105-01 (pass-through), TC-AND-105-06 |
