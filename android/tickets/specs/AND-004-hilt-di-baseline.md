---
id: AND-004
title: Hilt DI baseline
milestone: M1
epic: E01
priority: P0
size: S
status: draft
depends_on: [AND-002]
blocks: [AND-009]
---

# AND-004 — Hilt DI baseline

## 1. Overview & Goal

This ticket introduces Hilt as the dependency-injection (DI) backbone for the TestLogon
native Android port and proves the component graph compiles and resolves at runtime. It is a
foundational scaffolding ticket: no user-facing feature ships, but every subsequent
feature (networking transport in E02, auth in E04/E05, ViewModels throughout) depends on a
working Hilt graph. The goal is a minimal, correct, KSP-based Hilt wiring on top of the
`app` module from AND-002, anchored by a `@HiltAndroidApp` Application class, with a single
trivial injected dependency demonstrated end-to-end (constructor injection into a
component, surfaced into the existing empty Compose host) and verified by an instrumented
smoke test.

Concretely, "done" means: Hilt + KSP plugins and dependencies are declared through the
version catalog from AND-001; the `Application` placeholder created in AND-002 becomes
`@HiltAndroidApp`; `MainActivity` is `@AndroidEntryPoint`; a no-op `@Module` provides a
trivial dependency; and `:app:assembleDebug` plus an instrumented `HiltAndroidTest`
resolve the graph without missing-binding or duplicate-binding errors. This unblocks
AND-009 (OkHttp client), which needs an `@InstallIn(SingletonComponent::class)` module to
host the network singletons.

The scope is deliberately narrow. Per-feature modules, ViewModel injection patterns
(`@HiltViewModel`), and the `core-*` module bindings are introduced by their owning tickets
(AND-009+ for networking, AND-028+ for repositories, AND-031/AND-040 for ViewModels). This
ticket establishes only the graph, the conventions, and the proof of resolution.

## 2. Context & References

- **Repo / branch:** `spannella/testlogon`, Android app under `android/`, branch
  `android-port`.
- **Canonical namespace / applicationId base:** `com.testlogon.android`. Hilt-generated
  components live under this package; the Application class is
  `com.testlogon.android.TestLogonApp`.
- **Stack:** Kotlin 2.0.21, Hilt with KSP (Kotlin Symbol Processing) — not kapt — JDK 17,
  Gradle 8.9, AGP 8.7.3, Jetpack Compose + Material 3, single-Activity Navigation-Compose.
- **Dependencies (tickets):**
  - **AND-002 (depends_on):** provides the `app` module, `AndroidManifest.xml`, the
    `Application` placeholder, and `MainActivity` with the empty Compose host that this
    ticket annotates and injects into.
  - **AND-001:** provides the Gradle version catalog (`gradle/libs.versions.toml`); all Hilt
    coordinates and the Hilt Gradle plugin alias are added there.
  - **AND-003:** establishes the `core-*` module layering. This ticket does not add Hilt
    modules to `core-*`; it only ensures `app` can host the `SingletonComponent` graph that
    those modules will later contribute to.
- **Blocks:** AND-009 (`Dependencies: AND-003,AND-004`) and, transitively, all of E02–E07
  that rely on injected singletons and ViewModels.
- **Hilt component model reference:** standard AndroidX Hilt component hierarchy
  (`SingletonComponent`, `ActivityRetainedComponent`, `ViewModelComponent`,
  `ActivityComponent`). This ticket only exercises `SingletonComponent`.

## 3. Functional Requirements

FR-1. The `app` module applies the Hilt Gradle plugin and the KSP plugin via version-catalog
aliases; Hilt's annotation processing runs through KSP, not kapt.

FR-2. The Application class is annotated `@HiltAndroidApp` and is registered as
`android:name` in `AndroidManifest.xml`. The class name is
`com.testlogon.android.TestLogonApp`.

FR-3. `MainActivity` (the launcher Activity from AND-002) is annotated `@AndroidEntryPoint`
so member/graph injection is available to it and to its Compose content.

FR-4. A single trivial dependency is provided through a Hilt `@Module` installed in
`SingletonComponent`. For this ticket it is an `AppInfoProvider` returning the
`applicationId`, version name, and build type — values that are real, cheap, and require no
network. This demonstrates `@Provides` (or `@Binds`) wiring without pulling in feature code.

FR-5. The trivial dependency resolves at runtime and its value is observable: the empty
Compose host renders the injected `AppInfoProvider.summary()` text (e.g.
`com.testlogon.android · debug · 1.0`) so resolution is visually and test-verifiable.

FR-6. The graph compiles with zero missing-binding, duplicate-binding, or scope errors. The
`@Singleton`-scoped binding is created exactly once per process.

FR-7. The Hilt test runner is wired so instrumented tests can use `@HiltAndroidTest`. A
custom `AndroidJUnitRunner` subclass swaps in `HiltTestApplication` for instrumented runs.

FR-8. Conventions are documented inline (KDoc on the Application and the module) so later
tickets place bindings consistently: networking singletons in `core-network` modules,
repositories in `core-data`, ViewModels via `@HiltViewModel`.

## 4. Technical Design

### 4.1 Gradle wiring (version catalog + module)

Add to `gradle/libs.versions.toml` (AND-001 owns the file; this ticket appends entries):

```toml
[versions]
hilt = "2.52"
ksp = "2.0.21-1.0.28"          # KSP aligned to Kotlin 2.0.21
hiltExt = "1.2.0"              # androidx.hilt (navigation-compose, if needed later)

[libraries]
hilt-android = { module = "com.google.dagger:hilt-android", version.ref = "hilt" }
hilt-compiler = { module = "com.google.dagger:hilt-android-compiler", version.ref = "hilt" }
hilt-android-testing = { module = "com.google.dagger:hilt-android-testing", version.ref = "hilt" }

[plugins]
hilt = { id = "com.google.dagger.hilt.android", version.ref = "hilt" }
ksp = { id = "com.google.devtools.ksp", version.ref = "ksp" }
```

Root `build.gradle.kts` declares the plugins `apply false`:

```kotlin
plugins {
    alias(libs.plugins.hilt) apply false
    alias(libs.plugins.ksp) apply false
}
```

`app/build.gradle.kts`:

```kotlin
plugins {
    alias(libs.plugins.android.application)
    alias(libs.plugins.kotlin.android)
    alias(libs.plugins.kotlin.compose)
    alias(libs.plugins.hilt)
    alias(libs.plugins.ksp)
}

android {
    namespace = "com.testlogon.android"
    defaultConfig {
        applicationId = "com.testlogon.android"
        testInstrumentationRunner = "com.testlogon.android.HiltTestRunner"
    }
}

dependencies {
    implementation(libs.hilt.android)
    ksp(libs.hilt.compiler)

    androidTestImplementation(libs.hilt.android.testing)
    kspAndroidTest(libs.hilt.compiler)
}
```

### 4.2 Application & Activity

```kotlin
package com.testlogon.android

import android.app.Application
import dagger.hilt.android.HiltAndroidApp

/**
 * Process-level entry point. @HiltAndroidApp generates the SingletonComponent and the
 * application-scoped graph that all core-* and feature-* modules contribute to.
 * Networking singletons (AND-009+), DataStore, and the cookie jar (AND-011) are installed
 * in SingletonComponent in their own tickets.
 */
@HiltAndroidApp
class TestLogonApp : Application()
```

```kotlin
package com.testlogon.android

import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import dagger.hilt.android.AndroidEntryPoint
import javax.inject.Inject

@AndroidEntryPoint
class MainActivity : ComponentActivity() {
    @Inject lateinit var appInfo: AppInfoProvider

    override fun onCreate(savedInstanceState: android.os.Bundle?) {
        super.onCreate(savedInstanceState)
        setContent { AppRoot(summary = appInfo.summary()) }
    }
}
```

`AndroidManifest.xml` (updated from AND-002 placeholder):

```xml
<application
    android:name=".TestLogonApp"
    android:label="@string/app_name"
    ... >
    <activity android:name=".MainActivity" android:exported="true">
        <intent-filter>
            <action android:name="android.intent.action.MAIN" />
            <category android:name="android.intent.category.LAUNCHER" />
        </intent-filter>
    </activity>
</application>
```

### 4.3 Trivial dependency + module

```kotlin
package com.testlogon.android.di

import com.testlogon.android.BuildConfig
import javax.inject.Inject
import javax.inject.Singleton

interface AppInfoProvider {
    fun summary(): String
}

@Singleton
class DefaultAppInfoProvider @Inject constructor() : AppInfoProvider {
    override fun summary(): String =
        "${BuildConfig.APPLICATION_ID} · ${BuildConfig.BUILD_TYPE} · ${BuildConfig.VERSION_NAME}"
}
```

```kotlin
package com.testlogon.android.di

import dagger.Binds
import dagger.Module
import dagger.hilt.InstallIn
import dagger.hilt.components.SingletonComponent
import javax.inject.Singleton

/** First SingletonComponent module. Later tickets add their own @InstallIn modules. */
@Module
@InstallIn(SingletonComponent::class)
abstract class AppModule {
    @Binds
    @Singleton
    abstract fun bindAppInfoProvider(impl: DefaultAppInfoProvider): AppInfoProvider
}
```

`@Binds` is preferred over `@Provides` here because the implementation uses constructor
injection — this is the convention later tickets should follow for interface→impl bindings.

### 4.4 Compose host

```kotlin
@Composable
fun AppRoot(summary: String) {
    MaterialTheme {              // Material 3 theme is replaced by AND-019
        Surface {
            Text(text = summary, modifier = Modifier.testTag("app_info_summary"))
        }
    }
}
```

## 5. API Contract

Not applicable. This ticket adds no backend interaction — no Retrofit interface, no
endpoint, no request/response shape. The HTTP transport that introduces the first
`@InstallIn(SingletonComponent::class)` network module and the Retrofit service interfaces
is owned by **AND-009** (OkHttp client) and **AND-010** (Retrofit + Moshi). The cookie-based
session endpoints (`POST /ui/session/start`, MFA, `POST /ui/session/finalize`,
`GET /ui/me`) are wired by **AND-027** onward. This spec only guarantees the graph into
which those bindings will be installed.

## 6. Data & State Management

No persisted data, Room entities, DataStore keys, or `StateFlow<UiState>` are introduced.
The only "state" is the process-scoped singleton lifecycle that Hilt manages: the
`@Singleton`-scoped `DefaultAppInfoProvider` is instantiated lazily on first injection and
lives for the process lifetime within `SingletonComponent`.

Conventions established for downstream tickets:

- **Scopes:** application-wide singletons (OkHttp, Moshi, cookie jar, DataStore, repositories)
  → `SingletonComponent` + `@Singleton`. Per-screen state holders → `@HiltViewModel`
  ViewModels in `ViewModelComponent`.
- **Module placement:** networking bindings belong to `core-network`, persistence/cache
  bindings to `core-data`, never duplicated in `app`. The `app`-level `AppModule` is for
  app-global glue only.
- **No field injection in ViewModels;** constructor injection only, surfaced via
  `StateFlow<UiState>` as defined by the module layering. This ticket does not implement a
  ViewModel but documents the rule to prevent drift.

## 7. Error Handling & Resilience

DI errors in Hilt are compile-time, not runtime, which is the resilience win: missing
bindings, duplicate bindings, and scope mismatches fail `:app:assembleDebug` / KSP rather
than crashing in production. Handling expectations for this ticket:

- A missing binding must produce a KSP/Hilt compile error naming the unsatisfied type; CI
  (AND-008) treats this as a hard failure.
- The trivial dependency performs no I/O, so there are no network timeouts, retries, or
  offline states to handle here. The ~20s timeout / bounded-backoff / offline-stale
  resilience posture for the unreliable dev host (`http://18.222.237.167:8000`) is owned by
  AND-009 and AND-016/AND-017 and is out of scope.
- Runtime guard: if `@AndroidEntryPoint` injection is misconfigured, Hilt throws at Activity
  creation. The instrumented smoke test (Section 11) catches this before merge.

## 8. Security & Privacy

Minimal surface. The trivial dependency exposes only non-sensitive build metadata
(`applicationId`, build type, version name) — no PII, no credentials, no tokens. Specific
requirements:

- No secrets are placed in Hilt modules or `BuildConfig` by this ticket.
- The `AppInfoProvider.summary()` string must not include device identifiers or anything
  PII-adjacent; it is build-static.
- Security-sensitive singletons — the persistent cookie jar (AND-011), the `ui_csrf` /
  `X-CSRF-Token` handling (AND-012), and the 401 refresh authenticator (AND-013) — are
  installed in this same `SingletonComponent` later. This ticket must leave the graph clean
  so those bindings can be added without scope leaks (e.g. no accidental wider visibility of
  credential-bearing types).

## 9. Accessibility & i18n

The injected summary text is debug scaffolding, not shipping UI, so full a11y/i18n is
deferred to the real theme and screens (AND-019, AND-030, AND-039). For this ticket:

- The summary `Text` carries a stable `testTag("app_info_summary")` for testability and does
  not suppress TalkBack (it remains a readable node).
- The string is developer-facing build metadata and is intentionally not localized; it must
  not be added to `strings.xml` translation catalogs (i18n plumbing is AND-111/AND-112). No
  hardcoded user-facing copy is introduced.
- No RTL-specific layout is added; the placeholder uses default direction-agnostic layout.

## 10. Telemetry & Logging

No analytics or telemetry events are emitted. Logging is limited to a single optional
debug-only confirmation that the graph initialized, gated on `BuildConfig.DEBUG`:

```kotlin
if (BuildConfig.DEBUG) android.util.Log.d("TestLogonApp", "Hilt graph ready: ${appInfo.summary()}")
```

This log contains no PII. The redacted auth telemetry/logging framework is owned by AND-052;
this ticket must not introduce ad-hoc logging that would later need redaction.

## 11. Testing Strategy

**Build-time verification (primary).** `./gradlew :app:assembleDebug` exercises KSP + Hilt
code generation; a successful build proves the graph has no missing/duplicate bindings. CI
(AND-008) runs this on a fresh checkout.

**Instrumented smoke test (graph resolution).** A `HiltAndroidTest` confirms the singleton
resolves and reaches the UI.

Test runner:

```kotlin
package com.testlogon.android

import android.app.Application
import android.content.Context
import androidx.test.runner.AndroidJUnitRunner
import dagger.hilt.android.testing.HiltTestApplication

class HiltTestRunner : AndroidJUnitRunner() {
    override fun newApplication(cl: ClassLoader?, name: String?, ctx: Context?): Application =
        super.newApplication(cl, HiltTestApplication::class.java.name, ctx)
}
```

Test:

```kotlin
@HiltAndroidTest
class HiltGraphSmokeTest {
    @get:Rule(order = 0) val hiltRule = HiltAndroidRule(this)
    @get:Rule(order = 1) val composeRule = createAndroidComposeRule<MainActivity>()

    @Inject lateinit var appInfo: AppInfoProvider

    @Before fun setUp() = hiltRule.inject()

    @Test fun appInfo_isInjected_andNotBlank() {
        assertThat(appInfo.summary()).contains("com.testlogon.android")
    }

    @Test fun summary_isRenderedInHost() {
        composeRule.onNodeWithTag("app_info_summary").assertExists()
    }
}
```

**Unit test (provider logic).** A pure JVM test asserts `DefaultAppInfoProvider.summary()`
formats `applicationId · buildType · versionName` correctly (BuildConfig values stubbed or
asserted by substring).

Acceptance-mapped checks: graph compiles (FR-6), singleton resolves (FR-4/FR-5), runner
swaps `HiltTestApplication` (FR-7). Instrumented execution on the headless emulator is wired
broadly by AND-051; this ticket only contributes its test.

## 12. Dependencies & Sequencing

- **Upstream (must land first):** AND-002 (app module, Application placeholder, MainActivity,
  manifest) — directly extended here. AND-001 (version catalog) — Hilt/KSP aliases added
  there.
- **Sibling, not blocking:** AND-003 (core modules) can land in parallel; this ticket does
  not add Hilt code to `core-*`.
- **Downstream (blocked by this):** AND-009 (OkHttp client + first SingletonComponent network
  module) lists `AND-003,AND-004` as dependencies and is the primary consumer. Transitively,
  AND-010–AND-018 (transport), AND-027–AND-032 (auth repository/ViewModels via
  `@HiltViewModel`), AND-040 (MfaViewModel), and AND-008/AND-050/AND-051 (CI) all assume a
  working graph.
- **Sequencing note:** keep `AppModule` minimal so AND-009 can introduce
  `NetworkModule`/`CoreNetworkModule` cleanly without refactoring app-level bindings.

## 13. Risks & Open Questions

- **R1 — KSP/Kotlin version skew.** KSP must match Kotlin 2.0.21 exactly
  (`2.0.21-1.0.x`); a mismatch breaks Hilt processing. Mitigation: pin via catalog, verify
  on a clean build (AND-007 clean-clone requirement).
- **R2 — kapt drift.** Mixing kapt for Hilt would conflict with the KSP-only mandate.
  Mitigation: declare only `ksp(libs.hilt.compiler)`; add a detekt/CI check (AND-005) flagging
  any `kapt(` usage.
- **R3 — Test runner not applied.** If `testInstrumentationRunner` is left at the default,
  `@HiltAndroidTest` fails at runtime. Mitigation: set the runner in `app/build.gradle.kts`
  and assert via the smoke test.
- **R4 — Scope creep.** Temptation to add network/cookie bindings now. Mitigation: scope is
  the trivial provider only; defer to AND-009+.
- **Q1 — Hilt version pin.** 2.52 assumed compatible with AGP 8.7.3 / Kotlin 2.0.21; confirm
  against the build-server toolchain during AND-008 bring-up and bump in the catalog if
  needed.
- **Q2 — androidx.hilt-navigation-compose.** Needed only when the first `@HiltViewModel` is
  consumed in Compose (AND-031). Catalog entry (`hiltExt`) is staged here but not applied;
  owning ticket activates it.

## 14. Acceptance Criteria

AC-1. (Backlog) The app runs with Hilt: launching the debug APK does not crash and the
`@HiltAndroidApp`/`@AndroidEntryPoint` wiring initializes the graph.

AC-2. (Backlog) A trivial injected dependency resolves: `AppInfoProvider` is injected into
`MainActivity` and its `summary()` returns a non-blank string containing
`com.testlogon.android`.

AC-3. `./gradlew :app:assembleDebug` succeeds with KSP-generated Hilt code and no
missing/duplicate-binding errors.

AC-4. `AndroidManifest.xml` registers `android:name=".TestLogonApp"`, and
`TestLogonApp` is `@HiltAndroidApp`.

AC-5. Hilt + KSP are declared solely through the version catalog; the build uses `ksp(...)`
for the Hilt compiler and contains no `kapt` usage.

AC-6. `testInstrumentationRunner` is `com.testlogon.android.HiltTestRunner`, which substitutes
`HiltTestApplication`; `HiltGraphSmokeTest` passes on the emulator (graph resolves and the
summary node renders).

AC-7. The injected summary is visible in the Compose host with `testTag("app_info_summary")`.

AC-8. No backend calls, secrets, PII, or telemetry are introduced; the only log is
DEBUG-gated and contains build metadata only.

## 15. Definition of Done

- All Section 14 acceptance criteria pass, including the backlog ACs (AC-1, AC-2).
- Code merged to `android-port` under `android/app/...` using the
  `com.testlogon.android` namespace throughout.
- Version catalog updated with `hilt`, `ksp`, and `hilt-android-testing` entries; root and
  `app` build scripts apply the Hilt and KSP plugins.
- `TestLogonApp` (`@HiltAndroidApp`), `MainActivity` (`@AndroidEntryPoint`), `AppModule`
  (`@InstallIn(SingletonComponent::class)`), `AppInfoProvider`/`DefaultAppInfoProvider`,
  `HiltTestRunner`, and `HiltGraphSmokeTest` exist and are wired as specified.
- `./gradlew :app:assembleDebug` and `:app:testDebugUnitTest` are green; the instrumented
  smoke test passes on the headless emulator.
- KDoc documents the scope/module-placement conventions for downstream tickets (network →
  `core-network`, persistence → `core-data`, ViewModels → `@HiltViewModel`).
- No `kapt` usage; detekt/Spotless (AND-005) clean if those tasks are present.
- CI (AND-008) reproduces the build green on a fresh checkout.
- Leaves a clean `SingletonComponent` ready for AND-009 to add the first network module with
  no app-level refactor required.
