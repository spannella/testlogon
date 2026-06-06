---
id: AND-002
title: Application module configuration
milestone: M1 (Auth Foundation)
epic: E01 (Project scaffolding & build tooling)
priority: P0
size: M
status: reviewed
reviewed_on: 2026-06-06
depends_on:
  - AND-001
blocks:
  - AND-003
  - AND-004
  - AND-019
  - AND-022
  - AND-030
---

# AND-002 — Application module configuration

## 1. Overview & Goal

This ticket stands up the single application module (`:app`) for the native Android
port of TestLogon. AND-001 produced the Gradle root: the settings file, the
`gradle/libs.versions.toml` version catalog, the wrapper pinned to Gradle 8.9, the
root `build.gradle.kts` declaring AGP 8.7.x / Kotlin 2.0.x plugins with
`apply false`, and shared `gradle.properties`. AND-002 turns that empty shell into
a buildable, launchable Android application.

The concrete goal is a `:app` module that:

- Applies the Android application and Kotlin Android plugins, plus the Kotlin 2.0
  Compose compiler plugin (`org.jetbrains.kotlin.plugin.compose`).
- Targets `compileSdk = 35`, `minSdk = 24`, `targetSdk = 35`, compiles against
  Java 17 bytecode with `jvmTarget = "17"`.
- Enables Jetpack Compose via `buildFeatures.compose = true` and pulls Compose
  artifacts through the Compose BOM.
- Declares the package namespace `com.spannella.testlogon`.
- Ships an `AndroidManifest.xml`, an `Application` placeholder class
  (`TestLogonApp`), and a launcher `MainActivity` that hosts an empty Material 3
  Compose surface.

Success is defined narrowly and verifiably: `./gradlew :app:assembleDebug`
produces `app-debug.apk`, and installing/launching it on the emulator shows a
blank (themed) Compose screen with no crash. This ticket deliberately adds no
networking, DI graph, navigation, or real UI — those arrive in AND-003/004/019/022.
It exists to give every later feature ticket a host module that already compiles
and runs.

## 2. Context & References

**Web reference (frontend/).** The React/Vite/TS web client under `frontend/`
defines the brand/product surface we are porting. For this ticket only the app
shell matters: `frontend/index.html` (root mount + document title), `src/main.tsx`
(root render via `createRoot(...).render(<App/>)`) and `src/App.tsx` (root app
component — analogous to our `MainActivity` + root composable), and
`frontend/public/` (app icons / theme color, used later by AND-019). No API calls
are mirrored here. The app display name should read **TestLogon** to match the web
client's brand wordmark (see `src/components/layout/Sidebar.tsx` and
`src/components/layout/AppShell.tsx`, which render "TestLogon"). NOTE
(correction): the original claim that `index.html`'s `<title>` is "TestLogon"
could not be verified — `index.html` is not present in the extracted reference
(`reference/src/` only), and `src/App.tsx` actually sets the document
`<title>Control Panel</title>` via the page-meta helper. The Android
`@string/app_name` = "TestLogon" remains correct, justified by the brand wordmark
rather than the page title.

**Backend.** Dev backend is `http://18.222.237.167:8000` (plaintext HTTP,
unreliable host). It is irrelevant to AND-002 except that its cleartext URL
forces a later decision (see §8): the network-security-config / cleartext
allowance lands in the networking ticket, NOT here. We do not add
`usesCleartextTraffic` in this ticket.

**Related AND tickets.**
- **AND-001** (blocked-by): root Gradle setup + version catalog. AND-002 consumes
  `libs.versions.toml`; any missing alias is added there or in this ticket's
  catalog edit.
- **AND-003** (core modules): `core-ui`, `core-model`, etc. `:app` will later
  depend on these; for now `:app` is standalone.
- **AND-004** (Hilt): converts `TestLogonApp` into a `@HiltAndroidApp` and
  `MainActivity` into `@AndroidEntryPoint`. We keep the class shapes Hilt-ready.
- **AND-019** (theme): replaces the inline `MaterialTheme` with `TestLogonTheme`.
- **AND-022** (nav host): replaces the empty surface with a `NavHost`.
- **AND-030** (CI): runs `:app:assembleDebug` in CI; our module must build headless.

**Build-server notes.** Builds run on Ubuntu with JDK 17 and Android SDK 35
preinstalled. A headless KVM AVD named **test35** is the launch/instrumentation
target. The module must build with no GUI, no interactive SDK-license prompts
(licenses pre-accepted on the server), and must not require any SDK component
beyond platform 35 + build-tools. JDK 17 is mandatory — AGP 8.7 rejects JDK < 17.

## 3. Functional Requirements

FR-1. The `:app` module builds an installable debug APK via
`./gradlew :app:assembleDebug`.

FR-2. The APK declares a single launcher activity (`MainActivity`) with the
`MAIN` / `LAUNCHER` intent filter, so it appears in the device launcher.

FR-3. Launching the app shows a blank Compose surface (a full-screen
`Surface`/`Scaffold` filled with the theme background) without crashing.

FR-4. The application namespace and `applicationId` are
`com.spannella.testlogon`. Debug builds get the `.debug` application-id suffix so
debug and (future) release can co-install.

FR-5. The app name shown under the icon is "TestLogon", resolved from a string
resource (`@string/app_name`), not hard-coded in the manifest.

FR-6. The custom `Application` subclass (`TestLogonApp`) is registered in the
manifest and is instantiated on process start. It is empty except for a debug
log line and is structured so AND-004 can add `@HiltAndroidApp` with no signature
change.

FR-7. The build uses Compose (BOM-managed) and the Kotlin 2.0 Compose compiler
plugin. No `kotlinCompilerExtensionVersion` is set (that property is invalid in
the Kotlin 2.0 plugin model).

FR-8. `compileSdk = 35`, `minSdk = 24`, `targetSdk = 35`; Java 17 source/target
compatibility and `jvmTarget = "17"`.

FR-9. The module supports both `debug` and `release` build types (release is
left unsigned / minify-off in this ticket; full release config is out of scope).

## 4. Technical Design

Module layout created by this ticket:

```
android/
  app/
    build.gradle.kts
    src/main/
      AndroidManifest.xml
      java/com/spannella/testlogon/
        TestLogonApp.kt
        MainActivity.kt
        ui/RootScreen.kt
      res/values/
        strings.xml
        themes.xml            # minimal Material3 parent for the manifest android:theme
    src/test/java/com/spannella/testlogon/        # JVM unit test placeholder (AND later)
    src/androidTest/java/com/spannella/testlogon/  # instrumented Compose test placeholder
```

`android/settings.gradle.kts` (from AND-001) must already `include(":app")`. If
it does not, add it under this ticket.

### 4.1 `app/build.gradle.kts` (content sketch)

```kotlin
plugins {
    alias(libs.plugins.android.application)
    alias(libs.plugins.kotlin.android)
    alias(libs.plugins.kotlin.compose)   // Kotlin 2.0 Compose compiler plugin
}

android {
    namespace = "com.spannella.testlogon"
    compileSdk = 35

    defaultConfig {
        applicationId = "com.spannella.testlogon"
        minSdk = 24
        targetSdk = 35
        versionCode = 1
        versionName = "0.1.0"
        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
        vectorDrawables { useSupportLibrary = true }
    }

    buildTypes {
        debug {
            applicationIdSuffix = ".debug"
            isMinifyEnabled = false
        }
        release {
            isMinifyEnabled = false   // hardened in a later release ticket
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro",
            )
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    kotlin {
        compilerOptions {
            jvmTarget.set(org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_17)
        }
    }

    buildFeatures {
        compose = true
        buildConfig = true
    }

    packaging {
        resources {
            excludes += "/META-INF/{AL2.0,LGPL2.1}"
        }
    }
}

dependencies {
    implementation(platform(libs.androidx.compose.bom))
    androidTestImplementation(platform(libs.androidx.compose.bom))

    implementation(libs.androidx.core.ktx)
    implementation(libs.androidx.lifecycle.runtime.ktx)
    implementation(libs.androidx.activity.compose)
    implementation(libs.androidx.compose.ui)
    implementation(libs.androidx.compose.ui.graphics)
    implementation(libs.androidx.compose.ui.tooling.preview)
    implementation(libs.androidx.compose.material3)

    debugImplementation(libs.androidx.compose.ui.tooling)
    debugImplementation(libs.androidx.compose.ui.test.manifest)

    testImplementation(libs.junit)
    androidTestImplementation(libs.androidx.junit)
    androidTestImplementation(libs.androidx.espresso.core)
    androidTestImplementation(libs.androidx.compose.ui.test.junit4)
}
```

Note: use either the `kotlin { compilerOptions { ... } }` block (shown) or a
`tasks.withType<KotlinCompile>` block — not both. The `kotlin {}` extension is
the AGP-8.7 / Kotlin-2.0 recommended form.

### 4.2 `AndroidManifest.xml`

Because `namespace` is set in Gradle, the manifest needs no `package` attribute
and declares no permissions in this ticket.

```xml
<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android">

    <application
        android:name=".TestLogonApp"
        android:allowBackup="true"
        android:icon="@mipmap/ic_launcher"
        android:label="@string/app_name"
        android:roundIcon="@mipmap/ic_launcher_round"
        android:supportsRtl="true"
        android:theme="@style/Theme.TestLogon">

        <activity
            android:name=".MainActivity"
            android:exported="true"
            android:label="@string/app_name"
            android:theme="@style/Theme.TestLogon">
            <intent-filter>
                <action android:name="android.intent.action.MAIN" />
                <category android:name="android.intent.category.LAUNCHER" />
            </intent-filter>
        </activity>
    </application>
</manifest>
```

`android:exported="true"` is mandatory on the launcher activity for
`targetSdk >= 31`. We rely on the default-generated adaptive launcher icon from
the project template (`@mipmap/ic_launcher`); if AND-001 did not generate
mipmaps, add the default Android Studio launcher mipmaps as part of this ticket
so the manifest references resolve.

### 4.3 `res/values/strings.xml` and `themes.xml`

```xml
<!-- strings.xml -->
<resources>
    <string name="app_name">TestLogon</string>
</resources>
```

```xml
<!-- themes.xml -->
<resources>
    <style name="Theme.TestLogon" parent="android:Theme.Material.Light.NoActionBar" />
</resources>
```

This XML theme exists only to satisfy `android:theme` at the manifest/window
level (splash background, no action bar). The Compose-side Material 3 theming
arrives in AND-019; here we use the inline `MaterialTheme {}` default.

### 4.4 `TestLogonApp.kt` (Application class)

```kotlin
package com.spannella.testlogon

import android.app.Application
import android.util.Log

class TestLogonApp : Application() {

    override fun onCreate() {
        super.onCreate()
        if (BuildConfig.DEBUG) {
            Log.d(TAG, "TestLogonApp.onCreate — process started")
        }
    }

    companion object {
        private const val TAG = "TestLogonApp"
    }
}
```

Kept deliberately minimal. AND-004 will annotate this class `@HiltAndroidApp`;
the only change required there is the annotation + Hilt plugin, so we freeze the
class name and package now.

### 4.5 `MainActivity.kt` + `RootScreen.kt`

```kotlin
package com.spannella.testlogon

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.ui.Modifier
import com.spannella.testlogon.ui.RootScreen

class MainActivity : ComponentActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        setContent {
            MaterialTheme {
                Surface(modifier = Modifier.fillMaxSize()) {
                    RootScreen()
                }
            }
        }
    }
}
```

```kotlin
package com.spannella.testlogon.ui

import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.layout.layoutId
import androidx.compose.foundation.layout.Box

@Composable
fun RootScreen(modifier: Modifier = Modifier) {
    // Intentionally empty: a full-bleed blank surface.
    // AND-022 replaces this with the app NavHost.
    Box(modifier = modifier.fillMaxSize().layoutId("root_surface"))
}
```

The `layoutId("root_surface")` test tag gives the instrumented test in §11
something deterministic to assert on. `MainActivity` extends `ComponentActivity`
(not `AppCompatActivity`) — the Compose-native base — which is also what
`@AndroidEntryPoint` expects in AND-004.

## 5. Build & Tooling Details

**Version catalog (`gradle/libs.versions.toml`).** AND-002 ensures these aliases
exist (add any missing ones). Versions are illustrative of the BOM-aligned set
for compileSdk 35 / Kotlin 2.0.x; pin exact patches at implementation time.

```toml
[versions]
agp = "8.7.3"
kotlin = "2.0.21"
coreKtx = "1.13.1"
lifecycleRuntimeKtx = "2.8.7"
activityCompose = "1.9.3"
composeBom = "2024.10.01"
junit = "4.13.2"
androidxJunit = "1.2.1"
espressoCore = "3.6.1"

[libraries]
androidx-core-ktx = { group = "androidx.core", name = "core-ktx", version.ref = "coreKtx" }
androidx-lifecycle-runtime-ktx = { group = "androidx.lifecycle", name = "lifecycle-runtime-ktx", version.ref = "lifecycleRuntimeKtx" }
androidx-activity-compose = { group = "androidx.activity", name = "activity-compose", version.ref = "activityCompose" }
androidx-compose-bom = { group = "androidx.compose", name = "compose-bom", version.ref = "composeBom" }
androidx-compose-ui = { group = "androidx.compose.ui", name = "ui" }
androidx-compose-ui-graphics = { group = "androidx.compose.ui", name = "ui-graphics" }
androidx-compose-ui-tooling = { group = "androidx.compose.ui", name = "ui-tooling" }
androidx-compose-ui-tooling-preview = { group = "androidx.compose.ui", name = "ui-tooling-preview" }
androidx-compose-ui-test-manifest = { group = "androidx.compose.ui", name = "ui-test-manifest" }
androidx-compose-ui-test-junit4 = { group = "androidx.compose.ui", name = "ui-test-junit4" }
androidx-compose-material3 = { group = "androidx.compose.material3", name = "material3" }
junit = { group = "junit", name = "junit", version.ref = "junit" }
androidx-junit = { group = "androidx.test.ext", name = "junit", version.ref = "androidxJunit" }
androidx-espresso-core = { group = "androidx.test.espresso", name = "espresso-core", version.ref = "espressoCore" }

[plugins]
android-application = { id = "com.android.application", version.ref = "agp" }
kotlin-android = { id = "org.jetbrains.kotlin.android", version.ref = "kotlin" }
kotlin-compose = { id = "org.jetbrains.kotlin.plugin.compose", version.ref = "kotlin" }
```

The Compose-versioned libraries (`ui`, `material3`, etc.) intentionally omit
explicit versions — the **Compose BOM** governs them. The BOM is applied with
`implementation(platform(libs.androidx.compose.bom))` and again for
`androidTestImplementation` so test artifacts align.

**Compose compiler plugin (Kotlin 2.0 model).** From Kotlin 2.0, the Compose
compiler is a standalone Gradle plugin (`org.jetbrains.kotlin.plugin.compose`)
versioned with the Kotlin version. Do **not** set
`composeOptions.kotlinCompilerExtensionVersion` — that property belongs to the
pre-2.0 model and is rejected/ignored here. Optional compiler reports
(`composeCompiler { ... }`) are out of scope for AND-002.

**`buildConfig`.** `buildFeatures.buildConfig = true` is set so `BuildConfig.DEBUG`
is generated (referenced in `TestLogonApp`). AGP 8.x defaults this to off, hence
the explicit flag.

**Packaging options.** The `packaging.resources.excludes` for the META-INF
license files prevents duplicate-file packaging failures once test/coroutines
artifacts arrive; harmless now, prevents churn later.

**Java 17.** `compileOptions` sets source/target 17 and the `kotlin` extension
sets `jvmTarget = JVM_17`. `gradle.properties` (AND-001) should already point
`org.gradle.java.home` or rely on the server's JDK 17. AGP 8.7 hard-requires
JDK 17 to run Gradle.

## 6. Data & State Management

Not applicable at this layer. AND-002 introduces no persistence, no in-memory
state holders, and no ViewModels. `RootScreen` is stateless.

Downstream: Room (cache DB) and DataStore (preferences) are introduced in the
core-data / persistence tickets (AND-003 family); ViewModel + UI-state modeling
(`StateFlow`-backed) arrives with the first feature screen (auth, M1). Paging 3
arrives with list-bearing features. None of those touch this module's build until
their tickets add the dependencies — at which point `:app` will depend on
`:core-data` rather than pulling those libs directly.

## 7. Error Handling & Resilience

There is no runtime error surface in this ticket beyond "the process must not
crash on launch." The only failure modes are build-time (misconfigured Gradle)
and a startup crash (bad manifest/theme reference), both caught by §11's
assemble + launch checks.

Networking resilience — the timeout/retry/offline behavior the unreliable dev
host (`http://18.222.237.167:8000`) demands, plus the 401 ->
`POST /ui/session/refresh` -> retry interceptor — is entirely out of scope and
lands in the core-network ticket (OkHttp client, interceptors, Retrofit). This
spec only guarantees the host module exists for that code to live in.

## 8. Security & Privacy

No secrets, API keys, tokens, or credentials are introduced in this ticket; none
are committed. The module requests **no permissions** (not even `INTERNET`) —
that is added in the networking ticket alongside the network security config.

Cleartext traffic: the dev backend is plaintext HTTP, but AND-002 adds **no**
`android:usesCleartextTraffic="true"` and **no** `networkSecurityConfig`. We
keep the secure-by-default posture (cleartext blocked since targetSdk 28+). The
deliberate, scoped cleartext allowance for the dev host (ideally a debug-only
`network_security_config.xml` whitelisting `18.222.237.167`, not a blanket
flag) is specified in the network-security ticket. Calling that out here prevents
someone from "fixing" connectivity later by flipping the global cleartext flag.

`allowBackup="true"` is the template default and acceptable for a shell with no
data; the persistence ticket should revisit it (likely set to `false` or add a
backup rules file) once session/cache data exists.

## 9. Accessibility & i18n

Baseline only. `app_name` lives in `res/values/strings.xml` so it is
localizable; no other user-visible strings exist yet. `android:supportsRtl="true"`
is set in the manifest so future layouts mirror correctly in RTL locales.

`MainActivity` uses `enableEdgeToEdge()`, establishing the edge-to-edge baseline
expected on modern Android; insets handling for real content is a per-screen
concern handled in feature tickets. The empty `RootScreen` has no interactive or
focusable elements, so there is nothing to label for TalkBack yet. Locale config
(per-app language, `locales_config.xml`) and a full string-resource discipline
are deferred to AND-019 / feature tickets. No hard-coded user-facing strings are
permitted even in this shell — the one string is a resource.

## 10. Telemetry & Logging

No analytics/telemetry SDK is added. Logging baseline: `BuildConfig.DEBUG`-gated
`Log.d` in `TestLogonApp.onCreate` confirms process start during bring-up. No
logging occurs in release builds (the guard skips it). A structured logging
facade (e.g. Timber) and any crash/analytics reporting are deferred to a later
observability ticket; if adopted, `TestLogonApp.onCreate` is the planned init
site. No PII is logged (there is no user data at this layer).

## 11. Testing Strategy

**Build verification (primary acceptance).**
```
cd android
./gradlew :app:assembleDebug
```
Must succeed and produce `android/app/build/outputs/apk/debug/app-debug.apk`.

**Launch on emulator test35 (headless build server).**
```
adb -s test35 install -r android/app/build/outputs/apk/debug/app-debug.apk
adb -s test35 shell am start -n com.spannella.testlogon.debug/com.spannella.testlogon.MainActivity
adb -s test35 logcat -d | grep -E "TestLogonApp|AndroidRuntime"
```
Expect the `TestLogonApp.onCreate` debug line and **no** `AndroidRuntime` fatal
exception. (Note the `.debug` applicationId suffix in the component path.)

**Trivial Compose instrumented test placeholder**
(`src/androidTest/.../RootScreenTest.kt`):
```kotlin
package com.spannella.testlogon

import androidx.compose.ui.test.junit4.createAndroidComposeRule
import androidx.compose.ui.test.onRoot
import androidx.compose.ui.test.assertExists
import org.junit.Rule
import org.junit.Test

class RootScreenTest {
    @get:Rule val composeRule = createAndroidComposeRule<MainActivity>()

    @Test fun launches_blankSurface() {
        composeRule.onRoot().assertExists()
    }
}
```
Run with `./gradlew :app:connectedDebugAndroidTest` against test35. This asserts
the activity composes without crashing — the meaningful signal at this stage.

**JVM unit test placeholder** (`src/test/.../ExampleUnitTest.kt`): a single
trivial assertion so `./gradlew :app:testDebugUnitTest` wires up correctly for
later tickets. Lint (`./gradlew :app:lintDebug`) should be clean or have only
template-level warnings.

## 12. Dependencies & Sequencing

**Blocked by:** AND-001 (root Gradle, version catalog, wrapper, `gradle.properties`).
AND-002 cannot start until `:app` can be `include`d and the catalog resolves.

**Blocks:**
- **AND-004 (Hilt):** needs `TestLogonApp` + `MainActivity` to annotate.
- **AND-019 (theme):** needs `MainActivity.setContent`/`MaterialTheme` site to
  replace with `TestLogonTheme`.
- **AND-022 (nav host):** needs `RootScreen` to replace with `NavHost`.
- **AND-030 (CI):** needs a buildable `:app` to run `assembleDebug` in CI.
- Every feature module (M1 auth onward) depends transitively on a runnable `:app`.

**Relates to:** AND-003 (core modules) — once those exist, `:app` swaps direct
Compose/lifecycle deps for `:core-ui` etc. and stops declaring some libraries
itself.

Recommended order: AND-001 -> **AND-002** -> AND-003 -> AND-004 -> AND-019 ->
AND-022.

## 13. Risks & Open Questions

R-1. **Compose BOM vs compiler-plugin/Kotlin skew.** The chosen Compose BOM must
be compatible with Kotlin 2.0.21 and AGP 8.7. Mitigation: pin BOM
`2024.10.01`-class and run `assembleDebug` early; bump together if a
runtime-class mismatch appears.

R-2. **Missing launcher mipmaps.** If AND-001 did not generate template
launcher icons, the manifest's `@mipmap/ic_launcher` won't resolve and the build
fails. Mitigation: include default adaptive-icon mipmaps in this ticket.

R-3. **JDK on build server.** If Gradle picks up a non-17 JDK, AGP 8.7 fails.
Mitigation: verify `./gradlew -version` shows JVM 17; set `org.gradle.java.home`
if needed.

R-4. **`kotlin {}` DSL form.** Mixing the `kotlin { compilerOptions }` block with
a legacy `kotlinOptions` block causes a configuration error. Use exactly one.

Open questions:
- OQ-1: Confirm `versionName` scheme — is `0.1.0` acceptable for the port, or
  should it mirror the web app version? (Default: `0.1.0`.)
- OQ-2: Should debug builds keep the `.debug` applicationId suffix given the
  backend has no per-app-id allow-listing? (Default: yes — enables co-install.)
- OQ-3: `allowBackup` — leave `true` now and harden in persistence ticket, or set
  `false` immediately? (Default: leave `true`, revisit later.)

## 14. Acceptance Criteria

- [ ] `android/settings.gradle.kts` includes `:app`; `./gradlew projects` lists it.
- [ ] `app/build.gradle.kts` applies `android.application`, `kotlin.android`, and
      `kotlin.compose` plugins via catalog aliases.
- [ ] `compileSdk = 35`, `minSdk = 24`, `targetSdk = 35`; `namespace` and
      `applicationId` are `com.spannella.testlogon`; debug uses `.debug` suffix.
- [ ] `compileOptions` are Java 17 and Kotlin `jvmTarget = "17"`.
- [ ] `buildFeatures.compose = true` and `buildFeatures.buildConfig = true`.
- [ ] Compose dependencies are BOM-managed (no explicit versions on Compose libs).
- [ ] No `kotlinCompilerExtensionVersion` is present anywhere.
- [ ] `AndroidManifest.xml` registers `.TestLogonApp` and an exported
      `.MainActivity` with MAIN/LAUNCHER; `android:label="@string/app_name"`.
- [ ] `app_name` resolves to "TestLogon" from `strings.xml`; no hard-coded
      user-facing strings.
- [ ] `TestLogonApp` and `MainActivity` exist with the package/signatures shown;
      `MainActivity` calls `setContent { MaterialTheme { Surface { RootScreen() } } }`.
- [ ] No permissions, no `usesCleartextTraffic`, no secrets committed.
- [ ] `./gradlew :app:assembleDebug` succeeds and emits `app-debug.apk`.
- [ ] App installs and launches on emulator **test35** to a blank Compose screen
      with no `AndroidRuntime` fatal in logcat; `TestLogonApp.onCreate` log shows
      in debug.
- [ ] `./gradlew :app:connectedDebugAndroidTest` passes the `RootScreenTest`
      placeholder; `./gradlew :app:testDebugUnitTest` passes the unit placeholder.

## 15. Definition of Done

- All §14 acceptance criteria checked.
- Files created: `app/build.gradle.kts`, `app/src/main/AndroidManifest.xml`,
  `TestLogonApp.kt`, `MainActivity.kt`, `ui/RootScreen.kt`,
  `res/values/strings.xml`, `res/values/themes.xml`, launcher mipmaps (if absent),
  and the unit + instrumented test placeholders; `libs.versions.toml` updated with
  any missing aliases.
- `./gradlew :app:assembleDebug` and `:app:lintDebug` are green locally and on the
  Ubuntu build server; APK verified launching on **test35**.
- Class names/packages frozen so AND-004 (Hilt), AND-019 (theme), and AND-022
  (nav) plug in without renames.
- Changes committed on branch `android-port` (no merge to default), PR opened
  referencing AND-002, CI (`assembleDebug`) green, and reviewed/approved.

## 16. Citations & Assumption Audit

This is a build/scaffolding ticket: it intentionally mirrors **no** API endpoints
or DTOs (§2: "No API calls are mirrored here"). Consequently most claims are
framework/tooling facts plus a few web-shell behavioral claims. Each key claim
below carries a VERDICT and an exact SOURCE pointer.

1. **The web client's root render is `createRoot(...).render(<App/>)`, analogous to
   `MainActivity` + root composable.** — VERIFIED. Source: `src/main.tsx`
   (imports `createRoot` from `react-dom/client`, line 15; renders `<App/>` from
   `./App`, line 22).
2. **App display name should be "TestLogon".** — VERIFIED (basis corrected).
   Source: `src/components/layout/Sidebar.tsx:286` and
   `src/components/layout/AppShell.tsx:267` render the wordmark "TestLogon". The
   Android `@string/app_name` = "TestLogon" is justified by this brand wordmark.
3. **`index.html`'s `<title>` is "TestLogon".** — CORRECTED → Unverified-assumption.
   `index.html` is not present in the extracted reference (only `reference/src/`).
   `src/App.tsx:265` actually sets `<title>Control Panel</title>`. §2 amended to
   stop asserting the title and to cite the brand wordmark instead.
4. **§7: the 401 → `POST /ui/session/refresh` → retry interceptor is the web
   client's auth-recovery contract.** — VERIFIED. Source: OpenAPI
   `POST /ui/session/refresh` (op=`ui_session_refresh_ui_session_refresh_post`,
   resp=200, no request body); frontend `src/api/client.ts:121-130`
   (`refreshSession()` POSTs `/ui/session/refresh` with `credentials: "include"`,
   logs out on failure) and `src/api/endpoints/auth.ts:60`
   (`api.post<StatusResp>("/ui/session/refresh")`). The wrapper comment at
   `src/api/client.ts:132-139` documents "Automatic token refresh on 401" and
   "CSRF token from `ui_csrf` cookie". (This endpoint is explicitly out of scope
   for AND-002; cited only to confirm the §7 forward-reference is accurate.)
5. **Dev backend is `http://18.222.237.167:8000` (plaintext HTTP).** —
   Unverified-assumption. This host string does not appear anywhere in
   `reference/src/` (the web client uses a build-time `withApiBase()` / API-base
   indirection, `src/api/client.ts`). It is a deployment/config value, not a
   source-level contract; treated as given by the ticket. Irrelevant to AND-002's
   build (no networking added here).
6. **Cleartext traffic is blocked by default; staying secure-by-default needs no
   manifest flag (§2, §8).** — VERIFIED (framework ref). Android blocks cleartext
   HTTP by default for apps targeting API 28+ (Android 9); `targetSdk = 35`
   inherits this. Framework ref:
   https://developer.android.com/privacy-and-security/security-config and
   `android:usesCleartextTraffic` default (false for targetSdk ≥ 28). The spec's
   "since targetSdk 28+" wording is accurate.
7. **`android:exported="true"` is mandatory on a launcher (intent-filtered)
   activity for `targetSdk ≥ 31` (§4.2).** — VERIFIED (framework ref).
   https://developer.android.com/guide/topics/manifest/activity-element#exported
8. **From Kotlin 2.0 the Compose compiler is a standalone Gradle plugin
   (`org.jetbrains.kotlin.plugin.compose`) versioned with Kotlin;
   `kotlinCompilerExtensionVersion` is obsolete (§4.1, §5, FR-7).** — VERIFIED
   (framework ref).
   https://developer.android.com/develop/ui/compose/compiler and
   https://kotlinlang.org/docs/compose-compiler-migration-guide.html
9. **AGP 8.7 requires JDK 17 to run Gradle (§2, §5, R-3).** — VERIFIED
   (framework ref). AGP 8.x minimum JDK is 17:
   https://developer.android.com/build/releases/gradle-plugin (compatibility
   table). The build-server "JDK 17 preinstalled" detail is an environment
   assumption taken from the ticket.
10. **`buildFeatures.buildConfig` defaults to off in AGP 8.x, so it must be
    enabled to use `BuildConfig.DEBUG` (§5, FR-7/FR-6).** — VERIFIED
    (framework ref). https://developer.android.com/build/releases/gradle-plugin
    (8.0 default behavior changes: `buildConfig` now off by default).
11. **`ComponentActivity` is the Compose-native base and what
    `@AndroidEntryPoint` expects (§4.5).** — VERIFIED (framework ref).
    https://developer.android.com/develop/ui/compose/setup (uses
    `ComponentActivity` + `setContent`); Hilt supports any `ComponentActivity`
    subclass: https://developer.android.com/training/dependency-injection/hilt-android
12. **Compose artifacts should be governed by the Compose BOM (§4.1, §5,
    AC: "no explicit versions on Compose libs").** — VERIFIED (framework ref).
    https://developer.android.com/develop/ui/compose/bom
13. **`enableEdgeToEdge()` establishes the modern edge-to-edge baseline (§4.5,
    §9).** — VERIFIED (framework ref).
    https://developer.android.com/develop/ui/views/layout/edge-to-edge
14. **Emulator/build-server specifics: headless KVM AVD named `test35`, licenses
    pre-accepted, platform 35 + build-tools only (§2).** — Unverified-assumption
    (environment). Not checkable from the provided sources; taken from the
    ticket's build-server notes.

### Corrections made

- **§2 (Context & References):** Removed the inaccurate claim that
  `frontend/index.html`'s `<title>` is "TestLogon". `index.html` is absent from
  the extracted reference and `src/App.tsx:265` sets `<title>Control Panel</title>`.
  Re-justified `@string/app_name = "TestLogon"` via the brand wordmark in
  `Sidebar.tsx:286` / `AppShell.tsx:267`, and corrected the `main.tsx`/`App.tsx`
  description to the actual `createRoot(...).render(<App/>)` shape. No other
  factual claims required correction; all framework/tooling claims verified as
  written.

### Open assumptions

- **Dev backend URL `http://18.222.237.167:8000`** (claim 5): not present in
  source; a deployment value. Why unverifiable: the web client resolves its API
  base indirectly (`withApiBase()`), so no literal host appears in `reference/src/`.
  Low impact — AND-002 adds no networking.
- **Build-server environment** (claim 14): `test35` AVD, JDK 17 preinstalled,
  pre-accepted SDK licenses, platform 35 + build-tools availability. Why
  unverifiable: external CI/host configuration outside the provided artifacts.
  Tracked as a precondition for the launch/instrumentation acceptance checks.
- **Exact dependency versions** in §5's catalog (AGP 8.7.3, Kotlin 2.0.21, BOM
  2024.10.01, etc.): self-described by the spec as "illustrative … pin exact
  patches at implementation time." Why unverifiable: no `libs.versions.toml`
  artifact provided; mutual BOM/Kotlin/AGP compatibility (R-1) must be confirmed
  by running `assembleDebug` at implementation time.

## 17. Test Plan

IDs `TC-AND-002-NN`. "Traces: AC-#" references the §14 acceptance-criteria list in
order (AC-1 = first checkbox … AC-14 = last checkbox). Because this ticket has no
network surface, contract/MockWebServer cases are minimal; the "flaky-dev-host /
offline" dimension is covered as an explicit negative (the shell must not depend
on the network) rather than a live call.

- **TC-AND-002-01 — Module is included & resolvable.**
  Type: integration (Gradle).
  Preconditions: AND-001 root present; JDK 17 on PATH.
  Steps: run `./gradlew projects`; run `./gradlew :app:help`.
  Expected: `:app` is listed; configuration resolves with no version-catalog or
  missing-alias errors.
  Traces: AC-1, AC-2.

- **TC-AND-002-02 — Build configuration values are correct.**
  Type: unit (build-script assertion / inspection).
  Preconditions: TC-01 passes.
  Steps: inspect resolved AGP model (e.g. `./gradlew :app:properties` or a
  build-logic check) for `compileSdk`, `minSdk`, `targetSdk`, `namespace`,
  `applicationId`, debug `applicationIdSuffix`, Java 17 `compileOptions`,
  `jvmTarget=17`, `buildFeatures.compose=true`, `buildFeatures.buildConfig=true`.
  Expected: compileSdk/targetSdk=35, minSdk=24, namespace & applicationId =
  `com.spannella.testlogon`, debug suffix `.debug`, Java 17 + jvmTarget 17,
  compose & buildConfig enabled.
  Traces: AC-3, AC-4, AC-5.

- **TC-AND-002-03 — No legacy Compose compiler option present.**
  Type: unit (static check / grep gate in CI).
  Preconditions: repo checked out.
  Steps: assert no occurrence of `kotlinCompilerExtensionVersion` and no
  `composeOptions { }` block in `app/build.gradle.kts`; assert
  `alias(libs.plugins.kotlin.compose)` is applied.
  Expected: zero matches for the legacy property; Kotlin 2.0 Compose plugin
  applied.
  Traces: AC-7.

- **TC-AND-002-04 — Compose dependencies are BOM-managed.**
  Type: contract (dependency-graph).
  Preconditions: TC-01 passes.
  Steps: run `./gradlew :app:dependencies --configuration debugRuntimeClasspath`;
  inspect that `androidx.compose.*` artifacts have versions supplied by the
  imported `compose-bom` platform and that the catalog entries for Compose libs
  declare no explicit version.
  Expected: Compose UI/material3 versions originate from the BOM; no hard-coded
  Compose versions in `libs.versions.toml` for those libraries.
  Traces: AC-6.

- **TC-AND-002-05 — Debug APK assembles (primary acceptance).**
  Type: integration (Gradle build).
  Preconditions: TC-01 passes; Android SDK platform 35 + build-tools available.
  Steps: `./gradlew :app:assembleDebug`.
  Expected: BUILD SUCCESSFUL; `android/app/build/outputs/apk/debug/app-debug.apk`
  exists.
  Traces: AC-12.

- **TC-AND-002-06 — Manifest registers app/activity correctly.**
  Type: contract (manifest assertion against merged manifest).
  Preconditions: TC-05 produced a merged manifest.
  Steps: inspect `app/build/intermediates/merged_manifest*/AndroidManifest.xml`:
  `application android:name=.TestLogonApp`, single activity `.MainActivity` with
  `android:exported="true"`, a MAIN/LAUNCHER intent-filter, and
  `android:label="@string/app_name"` on both application and activity.
  Expected: all present; exactly one launcher activity.
  Traces: AC-8, AC-10.

- **TC-AND-002-07 — `app_name` resolves to "TestLogon"; no hard-coded UI
  strings.**
  Type: unit (resource + static check).
  Preconditions: repo checked out.
  Steps: assert `res/values/strings.xml` defines `app_name=TestLogon`; grep
  manifest and Kotlin sources for hard-coded user-facing literals.
  Expected: `app_name` = "TestLogon" from the resource; no hard-coded user-facing
  strings.
  Traces: AC-9.

- **TC-AND-002-08 — Source shapes frozen for downstream tickets.**
  Type: unit (static check).
  Preconditions: repo checked out.
  Steps: assert `TestLogonApp.kt` (package `com.spannella.testlogon`, extends
  `Application`) and `MainActivity.kt` (extends `ComponentActivity`, calls
  `setContent { MaterialTheme { Surface { RootScreen() } } }`) exist with the
  shown signatures.
  Expected: classes/packages/signatures match §4.4/§4.5 (Hilt/theme/nav-ready).
  Traces: AC-10 (and supports AC-13's RootScreen presence).

- **TC-AND-002-09 — App installs and launches to a blank Compose screen (no
  crash).**
  Type: instrumented/e2e (emulator test35).
  Preconditions: APK from TC-05; emulator `test35` booted; `adb` connected.
  Steps: `adb install -r app-debug.apk`;
  `adb shell am start -n com.spannella.testlogon.debug/com.spannella.testlogon.MainActivity`;
  `adb logcat -d`.
  Expected: activity launches to a blank themed surface; **no** `AndroidRuntime`
  FATAL exception; the `.debug` applicationId component path resolves.
  Traces: AC-13, AC-4.

- **TC-AND-002-10 — Debug log line emitted; release is silent.**
  Type: instrumented (emulator).
  Preconditions: debug APK installed (TC-09).
  Steps: launch app; `adb logcat -d -s TestLogonApp`. Then for a release build,
  assemble + (locally) launch and confirm the line is absent.
  Expected: debug shows `TestLogonApp.onCreate — process started`; release build
  logs nothing (guarded by `BuildConfig.DEBUG`).
  Traces: AC-13.

- **TC-AND-002-11 — Compose instrumented placeholder passes.**
  Type: Compose-UI / instrumented.
  Preconditions: emulator test35; androidTest deps present.
  Steps: `./gradlew :app:connectedDebugAndroidTest`.
  Expected: `RootScreenTest.launches_blankSurface` passes
  (`composeRule.onRoot().assertExists()`), confirming the activity composes
  without crashing.
  Traces: AC-14, AC-13.

- **TC-AND-002-12 — JVM unit placeholder passes.**
  Type: unit.
  Preconditions: TC-01.
  Steps: `./gradlew :app:testDebugUnitTest`.
  Expected: the placeholder unit test passes; the unit-test task is wired.
  Traces: AC-14.

- **TC-AND-002-13 — Security/permission posture: no permissions, no cleartext, no
  secrets.**
  Type: contract (merged-manifest + static scan).
  Preconditions: merged manifest from TC-05.
  Steps: assert merged manifest declares **no** `<uses-permission>` (not even
  `INTERNET`), **no** `android:usesCleartextTraffic`, and **no**
  `networkSecurityConfig`; scan the diff for committed secrets/keys.
  Expected: zero permissions, no cleartext flag/config, no secrets. Confirms the
  secure-by-default posture (claim 6).
  Traces: AC-11.

- **TC-AND-002-14 — Offline / flaky-dev-host independence + accessibility
  baseline.**
  Type: instrumented + manual (accessibility).
  Preconditions: emulator test35; APK installed.
  Steps: disable all networking on the emulator (airplane mode), then launch the
  app and verify it still reaches the blank surface (the shell must make no
  network call — consistent with §7/§8 and claim 5). Then run an accessibility
  pass: enable TalkBack and confirm no spurious announcements; verify
  `enableEdgeToEdge()` is active and `android:supportsRtl="true"` is in the merged
  manifest (pseudo-RTL via Developer Options shows no layout failure).
  Expected: app launches with no network; no crash offline; no a11y violations on
  the empty surface; RTL/edge-to-edge baseline present.
  Traces: AC-13, AC-10 (supportsRtl), AC-11 (no network dependency).

### Coverage matrix

| §14 AC | Covered by |
| --- | --- |
| AC-1 (settings includes `:app`; `gradlew projects` lists it) | TC-01 |
| AC-2 (build.gradle applies the 3 plugins via aliases) | TC-01, TC-03 |
| AC-3 (compileSdk/minSdk/targetSdk; namespace/appId; `.debug`) | TC-02 |
| AC-4 (Java 17 + jvmTarget 17) | TC-02, TC-09 |
| AC-5 (compose + buildConfig enabled) | TC-02 |
| AC-6 (Compose deps BOM-managed) | TC-04 |
| AC-7 (no `kotlinCompilerExtensionVersion`) | TC-03 |
| AC-8 (manifest: TestLogonApp + exported MainActivity MAIN/LAUNCHER, label) | TC-06 |
| AC-9 (`app_name`="TestLogon"; no hard-coded strings) | TC-07 |
| AC-10 (TestLogonApp/MainActivity signatures; setContent chain) | TC-06, TC-08, TC-14 |
| AC-11 (no permissions, no cleartext, no secrets) | TC-13, TC-14 |
| AC-12 (`assembleDebug` emits `app-debug.apk`) | TC-05 |
| AC-13 (installs/launches blank screen on test35; onCreate log) | TC-09, TC-10, TC-11, TC-14 |
| AC-14 (`connectedDebugAndroidTest` + `testDebugUnitTest` pass) | TC-11, TC-12 |
