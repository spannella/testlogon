---
id: AND-001
title: Gradle project skeleton
milestone: M1 (Auth Foundation)
epic: E01 (Project scaffolding & build tooling)
priority: P0
size: M
status: reviewed
reviewed_on: 2026-06-06
depends_on: []
blocks: [AND-002, AND-003, AND-004, AND-008]
---

# AND-001 — Gradle project skeleton

## 1. Overview & Goal

Stand up the foundational Gradle build for the native Android port of TestLogon under
`android/` in the `spannella/testlogon` monorepo, on the `android-port` branch. This ticket
produces an empty-but-buildable, multi-module-ready Gradle project whose toolchain versions
exactly match the Ubuntu build server (JDK 17, Android SDK 35, headless KVM emulator
`test35`). It establishes a Gradle **version catalog** (`gradle/libs.versions.toml`) as the
single, authoritative source of all dependency and plugin versions so that every later
module and feature ticket consumes pinned versions rather than hard-coding them.

The scope is deliberately narrow: **build tooling only**. No application code, no manifest
wiring beyond what an empty `:app` requires, no DI, no network. The deliverable is the
plumbing that AND-002 (Hilt + app module), AND-003 (core-network), and the rest of E01/M1
build upon.

**Success in one line:** a fresh clone of `android-port` runs `./gradlew help` (and
`./gradlew :app:tasks`) successfully with no manual SDK/version edits, on both a developer
machine and the Ubuntu build server.

## 2. Context & References

**Web reference (read-only, for parity, not consumed here).** The React/Vite/TS app lives
under `frontend/`. API surface to mirror in later tickets: `frontend/src/api/endpoints/*.ts`
and shared DTOs in `frontend/src/api/types.ts`. None of these affect AND-001 directly — they
matter only insofar as the catalog must later carry Retrofit/Moshi/OkHttp versions used to
talk to the backend (dev host `http://18.222.237.167:8000`, OpenAPI at `/openapi.json`).
AND-001 only *reserves* those catalog entries; wiring is downstream.

> Review note: the base URL is **not** hardcoded in the web client — `src/api/client.ts`
> reads it from `import.meta.env.VITE_API_BASE_URL` (empty ⇒ same-origin relative paths).
> The `18.222.237.167:8000` host is an environment/build-server detail, not a source-verified
> constant. Auth transport in the web client is **cookie-based** (`credentials: "include"`)
> with CSRF via the `ui_csrf` cookie echoed as the `X-CSRF-Token` request header — this is the
> contract the downstream OkHttp cookie + CSRF interceptor tickets (AND-003+) must mirror.

**Related tickets.**
- **AND-002** — Hilt DI + `:app` Application class. Depends on the catalog plugin aliases
  (`hilt`, `ksp`) and the `:app` module created here.
- **AND-003** — `core-network` (Retrofit/OkHttp/Moshi, cookie + CSRF interceptors). Depends on
  the network catalog bundle defined (versions only) here.
- **AND-008** — CI pipeline (GitHub Actions). Consumes the `./gradlew help`/`assemble` tasks
  and Gradle remote build cache config introduced here; adds Gradle build scans.

**Build-server notes.** Ubuntu host with JDK 17 and Android SDK platform 35 preinstalled;
`ANDROID_SDK_ROOT`/`ANDROID_HOME` are exported in CI. A headless KVM emulator AVD named
`test35` (API 35) is available for instrumented runs (used from AND-006 onward, not here).
The toolchain pinned below must equal the server's: **Gradle 8.9, AGP 8.7.x, Kotlin 2.0.x,
JDK 17, compileSdk/targetSdk 35, minSdk 24.**

## 3. Functional Requirements

FR-1. The Gradle root is `android/`. All paths below are relative to `android/`.
FR-2. A committed Gradle wrapper pinned to **8.9** (`gradle-wrapper.properties`,
`gradle-wrapper.jar`, `gradlew`, `gradlew.bat`) so no system Gradle is required.
FR-3. `settings.gradle.kts` declares plugin management, dependency-resolution repositories,
the version catalog, the root project name, and includes `:app` plus the five core module
stubs (`:core-network`, `:core-model`, `:core-ui`, `:core-data`, `:core-testing`). Modules
may be declared-but-empty (created fully in later tickets) — but at minimum `:app` must be a
buildable empty Android application.
FR-4. Root `build.gradle.kts` registers (but does not apply at root) all plugins via the
catalog using `apply false`, and provides shared configuration only where it is safe and
generic.
FR-5. `gradle.properties` configures JVM args, AndroidX, Kotlin code style, and turns on
Gradle **configuration cache** and **build cache**.
FR-6. `gradle/libs.versions.toml` is the single source of versions: `[versions]`,
`[libraries]`, `[bundles]`, `[plugins]`. No version string may appear in any `build.gradle.kts`.
FR-7. `./gradlew help` and `./gradlew :app:tasks` succeed from a clean clone.
FR-8. `./gradlew :app:assembleDebug` produces a debug APK from the empty `:app` (sanity, may
be deferred to AND-002 if `:app` is intentionally left codeless here — see §13).

## 4. Technical Design

Directory layout to create:

```
android/
├── gradlew
├── gradlew.bat
├── settings.gradle.kts
├── build.gradle.kts
├── gradle.properties
├── gradle/
│   ├── libs.versions.toml
│   └── wrapper/
│       ├── gradle-wrapper.jar
│       └── gradle-wrapper.properties
├── app/
│   ├── build.gradle.kts
│   └── src/main/AndroidManifest.xml
├── core-network/        (build.gradle.kts stub)
├── core-model/          (build.gradle.kts stub)
├── core-ui/             (build.gradle.kts stub)
├── core-data/           (build.gradle.kts stub)
└── core-testing/        (build.gradle.kts stub)
```

### 4.1 `gradle/wrapper/gradle-wrapper.properties`

```properties
distributionBase=GRADLE_USER_HOME
distributionPath=wrapper/dists
distributionUrl=https\://services.gradle.org/distributions/gradle-8.9-bin.zip
networkTimeout=10000
validateDistributionUrl=true
zipStoreBase=GRADLE_USER_HOME
zipStorePath=wrapper/dists
distributionSha256Sum=d725d707bfabd4dfdc958c624003b3c80accc03f7037b5122c4b1d0ef15cedeb
```

Generate via `gradle wrapper --gradle-version 8.9 --distribution-type bin` from a host with
Gradle 8.9, then commit all four wrapper files (including `gradle-wrapper.jar`). The
`distributionSha256Sum` pins the distribution for reproducibility/provenance (verify against
the published checksum on services.gradle.org before committing).

### 4.2 `settings.gradle.kts`

```kotlin
pluginManagement {
    repositories {
        google {
            content {
                includeGroupByRegex("com\\.android.*")
                includeGroupByRegex("com\\.google.*")
                includeGroupByRegex("androidx.*")
            }
        }
        mavenCentral()
        gradlePluginPortal()
    }
}

dependencyResolutionManagement {
    repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)
    repositories {
        google()
        mavenCentral()
    }
    // libs.versions.toml is auto-loaded by convention; no explicit versionCatalogs block needed.
}

rootProject.name = "testlogon-android"

include(":app")
include(":core-network")
include(":core-model")
include(":core-ui")
include(":core-data")
include(":core-testing")
```

`FAIL_ON_PROJECT_REPOS` forbids per-module repository declarations, centralizing
provenance. Repository content filtering keeps Android/AndroidX artifacts resolving from
`google()` and avoids accidental Maven Central spoofing of those groups.

### 4.3 Root `build.gradle.kts`

```kotlin
plugins {
    alias(libs.plugins.android.application) apply false
    alias(libs.plugins.android.library) apply false
    alias(libs.plugins.kotlin.android) apply false
    alias(libs.plugins.kotlin.compose) apply false
    alias(libs.plugins.ksp) apply false
    alias(libs.plugins.hilt) apply false
}
```

No `allprojects {}` repository block (forbidden by `FAIL_ON_PROJECT_REPOS`). No
`subprojects {}` cross-configuration — module config is per-module to keep the
configuration cache happy and avoid eager project realization.

### 4.4 `app/build.gradle.kts` (empty-but-buildable application)

```kotlin
plugins {
    alias(libs.plugins.android.application)
    alias(libs.plugins.kotlin.android)
    alias(libs.plugins.kotlin.compose)
}

android {
    namespace = "com.testlogon.android"
    compileSdk = 35

    defaultConfig {
        applicationId = "com.testlogon.android"
        minSdk = 24
        targetSdk = 35
        versionCode = 1
        versionName = "0.1.0"
        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
    }

    buildTypes {
        debug { isMinifyEnabled = false }
        release {
            isMinifyEnabled = true
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

    buildFeatures { compose = true }
}

kotlin {
    jvmToolchain(17)
}
```

`app/src/main/AndroidManifest.xml` is a minimal manifest (`<manifest><application
android:label="TestLogon"/></manifest>`); no launcher Activity is required for AND-001 (the
single Activity arrives in AND-002/AND-004). Compose dependencies are added in AND-002 — the
`kotlin.compose` plugin can be applied now (Kotlin 2.0 model: the Compose compiler is a
Gradle plugin, not a `composeOptions { kotlinCompilerExtensionVersion }` entry).

### 4.5 Core module stubs

Each `core-*/build.gradle.kts` for now is a minimal Android/Kotlin library that compiles
empty:

```kotlin
plugins {
    alias(libs.plugins.android.library)
    alias(libs.plugins.kotlin.android)
}
android {
    namespace = "com.testlogon.android.core.model" // adjust per module
    compileSdk = 35
    defaultConfig { minSdk = 24 }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
}
kotlin { jvmToolchain(17) }
```

(`core-model` may later become a pure-JVM `java-library`; keep it an Android library for now
to avoid churn until AND-003 decides.)

### 4.6 `gradle/libs.versions.toml`

```toml
[versions]
agp = "8.7.3"
kotlin = "2.0.21"
ksp = "2.0.21-1.0.27"          # MUST track Kotlin version exactly
hilt = "2.52"
hiltNavigationCompose = "1.2.0"
coroutines = "1.9.0"
composeBom = "2024.10.01"
activityCompose = "1.9.3"
navigationCompose = "2.8.4"
lifecycle = "2.8.7"
retrofit = "2.11.0"
okhttp = "4.12.0"
moshi = "1.15.1"
room = "2.6.1"
datastore = "1.1.1"
coil = "2.7.0"
media3 = "1.4.1"
paging = "3.3.4"
coreKtx = "1.13.1"
junit = "4.13.2"
androidxTestExt = "1.2.1"
espresso = "3.6.1"

[libraries]
androidx-core-ktx = { group = "androidx.core", name = "core-ktx", version.ref = "coreKtx" }
androidx-activity-compose = { group = "androidx.activity", name = "activity-compose", version.ref = "activityCompose" }
compose-bom = { group = "androidx.compose", name = "compose-bom", version.ref = "composeBom" }
compose-ui = { group = "androidx.compose.ui", name = "ui" }
compose-material3 = { group = "androidx.compose.material3", name = "material3" }
navigation-compose = { group = "androidx.navigation", name = "navigation-compose", version.ref = "navigationCompose" }
hilt-android = { group = "com.google.dagger", name = "hilt-android", version.ref = "hilt" }
hilt-compiler = { group = "com.google.dagger", name = "hilt-compiler", version.ref = "hilt" }
retrofit = { group = "com.squareup.retrofit2", name = "retrofit", version.ref = "retrofit" }
retrofit-moshi = { group = "com.squareup.retrofit2", name = "converter-moshi", version.ref = "retrofit" }
okhttp = { group = "com.squareup.okhttp3", name = "okhttp", version.ref = "okhttp" }
okhttp-logging = { group = "com.squareup.okhttp3", name = "logging-interceptor", version.ref = "okhttp" }
moshi = { group = "com.squareup.moshi", name = "moshi", version.ref = "moshi" }
moshi-codegen = { group = "com.squareup.moshi", name = "moshi-kotlin-codegen", version.ref = "moshi" }
room-runtime = { group = "androidx.room", name = "room-runtime", version.ref = "room" }
room-ktx = { group = "androidx.room", name = "room-ktx", version.ref = "room" }
room-compiler = { group = "androidx.room", name = "room-compiler", version.ref = "room" }
datastore-preferences = { group = "androidx.datastore", name = "datastore-preferences", version.ref = "datastore" }
coil-compose = { group = "io.coil-kt", name = "coil-compose", version.ref = "coil" }
media3-exoplayer = { group = "androidx.media3", name = "media3-exoplayer", version.ref = "media3" }
media3-exoplayer-hls = { group = "androidx.media3", name = "media3-exoplayer-hls", version.ref = "media3" }
media3-ui = { group = "androidx.media3", name = "media3-ui", version.ref = "media3" }
paging-runtime = { group = "androidx.paging", name = "paging-runtime", version.ref = "paging" }
paging-compose = { group = "androidx.paging", name = "paging-compose", version.ref = "paging" }
coroutines-android = { group = "org.jetbrains.kotlinx", name = "kotlinx-coroutines-android", version.ref = "coroutines" }
junit = { group = "junit", name = "junit", version.ref = "junit" }
coroutines-test = { group = "org.jetbrains.kotlinx", name = "kotlinx-coroutines-test", version.ref = "coroutines" }
androidx-test-ext = { group = "androidx.test.ext", name = "junit", version.ref = "androidxTestExt" }
espresso-core = { group = "androidx.test.espresso", name = "espresso-core", version.ref = "espresso" }

[bundles]
network = ["retrofit", "retrofit-moshi", "okhttp", "okhttp-logging", "moshi"]
compose = ["compose-ui", "compose-material3", "androidx-activity-compose"]
room = ["room-runtime", "room-ktx"]
media3 = ["media3-exoplayer", "media3-exoplayer-hls", "media3-ui"]

[plugins]
android-application = { id = "com.android.application", version.ref = "agp" }
android-library = { id = "com.android.library", version.ref = "agp" }
kotlin-android = { id = "org.jetbrains.kotlin.android", version.ref = "kotlin" }
kotlin-compose = { id = "org.jetbrains.kotlin.plugin.compose", version.ref = "kotlin" }
ksp = { id = "com.google.devtools.ksp", version.ref = "ksp" }
hilt = { id = "com.google.dagger.hilt.android", version.ref = "hilt" }
```

Libraries/bundles beyond what AND-001 needs are declared now so downstream tickets only
*reference* them — satisfying "single source of versions" up front. They cost nothing until a
module declares the dependency.

### 4.7 `gradle.properties`

```properties
org.gradle.jvmargs=-Xmx4g -Dfile.encoding=UTF-8 -XX:+UseParallelGC
org.gradle.parallel=true
org.gradle.caching=true
org.gradle.configuration-cache=true
android.useAndroidX=true
android.nonTransitiveRClass=true
kotlin.code.style=official
ksp.useKSP2=true
```

## 5. Build & Tooling Details

| Tool / layer        | Version            | Notes |
|---------------------|--------------------|-------|
| Gradle wrapper      | 8.9                | matches build server |
| Android Gradle Plugin (AGP) | 8.7.3      | requires Gradle 8.9+, JDK 17 |
| Kotlin              | 2.0.21             | Compose compiler is a plugin |
| KSP                 | 2.0.21-1.0.27      | must equal Kotlin version prefix |
| Compose compiler plugin | bundled w/ Kotlin 2.0.21 | via `kotlin.plugin.compose` |
| JDK                 | 17 (toolchain)     | `jvmToolchain(17)` |
| compileSdk / targetSdk | 35              | platform 35 on server |
| minSdk              | 24                 | |
| Hilt / Dagger       | 2.52               | uses KSP, applied AND-002 |
| Compose BOM         | 2024.10.01         | aligns all compose artifacts |

**Compatibility rationale.** AGP 8.7.x is built and tested against Gradle 8.9 and JDK 17;
running AGP 8.7 on an older Gradle fails fast. Kotlin 2.0 moves the Compose compiler out of
`composeOptions` into the standalone `org.jetbrains.kotlin.plugin.compose` plugin whose
version is the Kotlin version — eliminating the old AGP↔Compose-compiler version matrix. KSP
versions are Kotlin-coupled (`<kotlin>-<ksp>`), so bumping Kotlin requires a matching KSP bump
in the same `[versions]` change. `jvmToolchain(17)` makes the build provision/verify JDK 17
independent of the developer's `JAVA_HOME`, guaranteeing parity with the server.

## 6. Data & State Management

Not applicable at the application-data layer — AND-001 ships no runtime state, Room, or
DataStore (those are reserved in the catalog for AND-003+).

**Build state**, however, is in scope. Configuration cache (`org.gradle.configuration-cache=
true`) serializes the task graph so repeat invocations skip configuration; the project must
stay configuration-cache-compatible (no reading `Task.project` at execution time, no
cross-project mutation in `subprojects {}` — hence the per-module config in §4.3/§4.5). The
local build cache (`org.gradle.caching=true`) reuses task outputs; AND-008 adds a *remote*
build cache so CI and developers share outputs. Gradle User Home on the server is persisted
between CI runs to retain the wrapper distribution and dependency cache.

## 7. Error Handling & Resilience

- **Reproducibility:** every plugin/dependency version is pinned in the catalog (no `+` or
  dynamic ranges); the wrapper distribution is pinned by `distributionSha256Sum`. This makes
  builds deterministic across machines.
- **Offline builds:** `./gradlew --offline help` must succeed once the dependency cache is
  warm. The dev backend is unreliable, but it is irrelevant to the build — no network call to
  `18.222.237.167` happens during a Gradle build.
- **Dependency locking (recommended, optional in this ticket):** enable
  `dependencyLocking { lockAllConfigurations() }` and commit `gradle.lockfile`s, refreshed via
  `./gradlew dependencies --write-locks`. If deferred, raise as an open question (§13) and
  track under AND-008. Locking guarantees the resolved graph cannot drift even if a transitive
  publishes a new version.
- **Wrapper integrity:** `validateDistributionUrl=true` plus the SHA-256 sum cause the wrapper
  to abort on a tampered/mismatched distribution.
- **Fail-fast repos:** `FAIL_ON_PROJECT_REPOS` turns an accidental rogue repository into a
  configuration-time error rather than a silent supply-chain risk.

## 8. Security & Privacy

- **No secrets in repo.** No API keys, keystores, or tokens are committed. The dev backend is
  plaintext HTTP and unauthenticated at build time; nothing build-related references it. Any
  future signing config reads from environment variables / a Gradle-properties file outside VCS
  (gitignored), introduced in the release/signing ticket — not here.
- **Dependency provenance.** Resolution is restricted to `google()` and `mavenCentral()` with
  content filtering on the Google repo; `gradlePluginPortal()` is used only for plugin
  resolution in `pluginManagement`. No custom/unverified repositories.
- **Provenance verification (recommended):** Gradle dependency verification
  (`gradle/verification-metadata.xml`, `--write-verification-metadata sha256`) can be enabled to
  checksum-verify every artifact. Flagged as a follow-up if not landed here (see §13).
- **`.gitignore`** must exclude `.gradle/`, `build/`, `local.properties`, `*.keystore`,
  `*.jks` so local SDK paths and caches never enter VCS. `gradle/wrapper/gradle-wrapper.jar`
  is intentionally committed.

## 9. Accessibility & i18n

Not applicable at the build-tooling layer — there is no UI in AND-001. Accessibility
(content descriptions, touch targets, TalkBack, dynamic type) and i18n (string resources,
`values/strings.xml`, locale handling, RTL) are owned by the Compose UI tickets:
`core-ui` setup and the first feature screens (AND-004 onward). This ticket only ensures
`android.useAndroidX=true` and Material 3 versions are available in the catalog so those
tickets inherit the accessible Material components.

## 10. Telemetry & Logging

- **Build scans:** AND-008 wires the Develocity / `com.gradle.develocity` (or
  `--scan`) plugin in `settings.gradle.kts` for CI build insight; AND-001 leaves a comment
  placeholder and reserves the catalog plugin entry. No scan publishing is enabled by default
  (avoids leaking build metadata externally without consent).
- **CI logging hooks:** CI runs with `--stacktrace` and `--warning-mode=all` so failures and
  deprecations surface in logs. `org.gradle.console=plain` may be set in the CI environment
  (not committed) for clean log capture.
- No application/runtime telemetry exists yet (no analytics SDK in the catalog); that is a
  separate, later decision and explicitly out of scope.

## 11. Testing Strategy

Verification is build-level only:

1. **Clean clone, configure:** from `android/`,
   `./gradlew help` → BUILD SUCCESSFUL, no version errors.
2. **Catalog resolves:** `./gradlew :app:tasks` and `./gradlew :app:dependencies` →
   succeed; confirm versions printed equal `libs.versions.toml`.
3. **Toolchain parity:** `./gradlew -q javaToolchains` shows JDK 17 selected.
4. **Smoke task:** `./gradlew :app:assembleDebug` (if `:app` is buildable here) produces
   `app/build/outputs/apk/debug/app-debug.apk`; otherwise `./gradlew :app:lintDebug` /
   `:core-model:compileDebugKotlin` as the smoke target.
5. **Config cache:** run `help` twice; second run logs "Reusing configuration cache".
6. **Offline:** with caches warm, `./gradlew --offline help` succeeds.
7. **Server parity:** the same commands pass on the Ubuntu build server (JDK17/SDK35).
8. **CI hook (AND-008):** GitHub Actions on `android-port` runs `./gradlew help assembleDebug
   --stacktrace`; AND-001 must leave the build green for that job to be added.

No unit/instrumented test code is authored here; `core-testing` and test bundles are
declared in the catalog for AND-003+ to consume.

## 12. Dependencies & Sequencing

- **Blocked by:** none. This is the first build ticket in E01/M1.
- **Blocks:**
  - **AND-002** — Hilt + `:app` Application/Activity (needs catalog `hilt`/`ksp`, `:app`).
  - **AND-003** — `core-network` (needs `network` bundle versions + module stub).
  - **AND-004** — Navigation-Compose / first screen (needs Compose catalog + `:app`).
  - **AND-008** — CI pipeline & build scans (needs wrapper, tasks, build cache).
  - All later `core-*`/`feature-*` modules (need the catalog + settings include pattern).
- **Ordering:** must merge to `android-port` before any other E01 ticket starts to avoid
  catalog merge conflicts.

## 13. Risks & Open Questions

- **R1 — AGP/Gradle drift vs. server.** If the server's SDK/JDK differs from the pins, builds
  fail. *Mitigation:* `jvmToolchain(17)` + pinned wrapper; confirm server SDK 35 + JDK 17
  before merge.
- **R2 — KSP/Kotlin version skew.** Bumping Kotlin without the matching KSP version breaks
  symbol processing in AND-002+. *Mitigation:* catalog comment requiring paired bumps; CI
  catches at build.
- **R3 — Configuration-cache incompatibility creeping in.** Later tickets may add non-CC-safe
  config. *Mitigation:* keep per-module config; CI runs with CC on.
- **OQ1 — Enable dependency locking now or in AND-008?** Recommend now for reproducibility;
  needs sign-off (cost: lockfile maintenance).
- **OQ2 — Enable Gradle dependency verification metadata now?** Strong supply-chain win but
  upfront effort generating/maintaining `verification-metadata.xml`. Likely AND-008.
- **OQ3 — Should `:app` be fully buildable (manifest + empty Activity) in AND-001, or codeless
  until AND-002?** Recommend a minimal buildable `:app` so `assembleDebug` is the smoke test;
  confirm with reviewer.
- **OQ4 — `core-model` as `java-library` vs Android library?** Defer to AND-003.

## 14. Acceptance Criteria

- [ ] `android/` contains `settings.gradle.kts`, root `build.gradle.kts`, `gradle.properties`,
      `gradle/libs.versions.toml`, and a committed wrapper pinned to Gradle **8.9**.
- [ ] Wrapper `distributionUrl` is `gradle-8.9-bin.zip` with a valid `distributionSha256Sum`.
- [ ] Catalog pins AGP **8.7.x**, Kotlin **2.0.x**, KSP matching Kotlin, JDK target **17**,
      compileSdk/targetSdk **35**, minSdk **24**.
- [ ] No version string appears in any `build.gradle.kts`; all come from `libs.versions.toml`.
- [ ] `settings.gradle.kts` uses `FAIL_ON_PROJECT_REPOS`, `google()`+`mavenCentral()`, and
      includes `:app` and the five `core-*` modules.
- [ ] From a **fresh clone**, `./gradlew help` succeeds.
- [ ] `./gradlew :app:tasks` and `:app:dependencies` succeed and show catalog versions.
- [ ] A smoke build (`:app:assembleDebug` or agreed alternative) succeeds.
- [ ] Second `./gradlew help` reuses the configuration cache.
- [ ] `./gradlew --offline help` succeeds with warm caches.
- [ ] `.gitignore` excludes `.gradle/`, `build/`, `local.properties`, keystores; wrapper jar
      is committed.
- [ ] No secrets, keys, or backend credentials are present in any committed file.
- [ ] All commands pass identically on the Ubuntu build server.

## 15. Definition of Done

- All §14 acceptance criteria checked on a developer machine **and** the Ubuntu build server.
- Code reviewed and merged to `android-port`; commits scoped to `android/`.
- Catalog reviewed as the single source of versions; downstream tickets (AND-002/003/004/008)
  confirmed they can reference it without local version literals.
- Open questions OQ1–OQ4 either resolved in this PR or filed as tracked follow-ups linked to
  this ticket.
- Build is green and reproducible; `./gradlew help` documented in `android/README` (one line)
  or the ticket as the canonical "does it build" command for AND-008's CI to adopt.

## 16. Citations & Assumption Audit

AND-001 is a **build-tooling chore**: it ships no API client code, so it makes no concrete
claims about endpoint paths, HTTP methods, request/response field shapes, or auth flows that
execute at runtime. The verifiable claims fall into two buckets: (a) the few statements about
the web client / backend it makes *by way of context* (verifiable against the frontend source
and OpenAPI index), and (b) toolchain/version compatibility facts (verifiable only against
vendor/framework documentation — labeled "framework ref"). Each is audited below.

1. **Claim:** The web client talks to the backend with Retrofit/OkHttp/Moshi-equivalent
   transport, and downstream tickets need cookie + CSRF interceptors.
   **VERDICT:** Verified. **SOURCE:** `src/api/client.ts` — `fetch(..., { credentials: "include" })`
   (cookie-based), CSRF read from the `ui_csrf` cookie (`getCookie("ui_csrf")`) and sent as the
   `X-CSRF-Token` header. This confirms the cookie-jar + CSRF-interceptor design the catalog
   reserves OkHttp/Retrofit/Moshi versions for.

2. **Claim:** Backend dev host is `http://18.222.237.167:8000` with OpenAPI at `/openapi.json`.
   **VERDICT:** Corrected / Unverified-assumption. **SOURCE:** `src/api/client.ts` resolves the
   base URL from `import.meta.env.VITE_API_BASE_URL` (falls back to same-origin relative paths) —
   the host is **not** a source constant. The specific IP/port is an environment detail not present
   in the frontend source; treated as a build/CI environment assumption. (OpenAPI is provided as a
   static index/spec under `reference/openapi.index.txt` / `reference/openapi.pretty.json`; the
   `/openapi.json` path is the conventional FastAPI default and is plausible but not source-verified.)

3. **Claim:** The web app's API surface to mirror lives in `frontend/src/api/endpoints/*.ts`
   with shared DTOs in `frontend/src/api/types.ts`.
   **VERDICT:** Verified. **SOURCE:** reference snapshot `src/api/endpoints/` (directory of `*.ts`
   endpoint modules) and `src/api/types.ts` both exist with the described roles. (AND-001 only
   *reserves* catalog versions for this; no endpoint is consumed here.)

4. **Claim:** Backend is FastAPI/DynamoDB.
   **VERDICT:** Unverified-assumption. **SOURCE:** the OpenAPI index/spec confirm a REST API with
   `HTTPValidationError`-shaped 422 responses (FastAPI's default validation-error envelope, e.g.
   `reference/openapi.index.txt` shows `resp=...;422:HTTPValidationError`), consistent with FastAPI;
   the persistence layer (DynamoDB) is not observable from any provided source. Not load-bearing
   for AND-001.

5. **Claim:** Gradle wrapper pinned to **8.9**; AGP **8.7.3** requires Gradle 8.9+ and JDK 17.
   **VERDICT:** Verified (framework ref). **SOURCE:** Android Gradle plugin release/compatibility
   notes — AGP 8.7 minimum Gradle is 8.9, minimum JDK 17
   (https://developer.android.com/build/releases/gradle-plugin and the AGP–Gradle compatibility table).

6. **Claim:** Kotlin **2.0.21**, with the Compose compiler delivered as the
   `org.jetbrains.kotlin.plugin.compose` Gradle plugin (versioned to the Kotlin version) rather than
   `composeOptions { kotlinCompilerExtensionVersion }`.
   **VERDICT:** Verified (framework ref). **SOURCE:** Kotlin 2.0 Compose Compiler Gradle plugin docs
   (https://kotlinlang.org/docs/compose-compiler-migration-guide.html). The plugin version equals the
   Kotlin version, so `kotlin = "2.0.21"` ⇒ `kotlin-compose` plugin `version.ref = "kotlin"` is correct.

7. **Claim:** KSP **2.0.21-1.0.27** must track the Kotlin version exactly.
   **VERDICT:** Verified (framework ref). **SOURCE:** KSP releases use the `<kotlin>-<ksp>` scheme and
   each KSP build targets one Kotlin version (https://github.com/google/ksp/releases). The `2.0.21-…`
   prefix matches `kotlin = "2.0.21"`; bumping Kotlin requires a paired KSP bump (R2).

8. **Claim:** Hilt/Dagger **2.52** integrates via KSP.
   **VERDICT:** Verified (framework ref). **SOURCE:** Dagger Hilt supports KSP-based code generation
   (https://dagger.dev/dev-guide/ksp). Version `2.52` exists; actual application is deferred to AND-002.

9. **Claim:** Compose BOM **2024.10.01** aligns Compose artifact versions; per-artifact Compose
   libraries (`compose-ui`, `compose-material3`) are declared without explicit versions.
   **VERDICT:** Verified (framework ref). **SOURCE:** Compose BOM mechanism
   (https://developer.android.com/jetpack/compose/bom) — the BOM constrains member artifact versions, so
   the version-less `[libraries]` entries are correct *provided the BOM is imported as a platform in the
   consuming module* (that import is downstream in AND-002, an open assumption for AND-001).

10. **Claim:** `RepositoriesMode.FAIL_ON_PROJECT_REPOS` forbids per-module repositories and the
    version catalog at `gradle/libs.versions.toml` is auto-loaded as `libs` without an explicit
    `versionCatalogs {}` block.
    **VERDICT:** Verified (framework ref). **SOURCE:** Gradle docs — dependency-resolution management /
    `FAIL_ON_PROJECT_REPOS` (https://docs.gradle.org/current/userguide/dependency_resolution.html) and the
    convention that a `gradle/libs.versions.toml` file is auto-registered as the `libs` catalog
    (https://docs.gradle.org/current/userguide/platforms.html#sub:conventional-dependencies-toml).

11. **Claim:** `minSdk 24`, `compileSdk/targetSdk 35`, JDK 17 toolchain match the Ubuntu build
    server.
    **VERDICT:** Unverified-assumption. **SOURCE:** no machine-readable description of the build
    server's installed SDK/JDK is in the provided sources; this rests on the §2 build-server note. The
    *internal consistency* (SDK 35 + JDK 17 + AGP 8.7 + Gradle 8.9) is valid (see items 5–6), but server
    parity itself is an assumption to confirm before merge (R1).

12. **Claim:** `distributionSha256Sum` value
    `d725d707bfabd4dfdc958c624003b3c80accc03f7037b5122c4b1d0ef15cedeb` is the checksum for
    `gradle-8.9-bin.zip`.
    **VERDICT:** Unverified-assumption. **SOURCE:** must be checked against the published checksum at
    `https://services.gradle.org/distributions/gradle-8.9-bin.zip.sha256` before commit (the spec already
    flags this in §4.1). Not verifiable from the offline reference set.

### Corrections made

- **§2** — Removed the implication that the backend base URL is a hardcoded constant in the web
  client. The real client (`src/api/client.ts`) reads it from `VITE_API_BASE_URL` and otherwise uses
  same-origin relative paths; the `18.222.237.167:8000` host is reclassified as an environment/build
  detail (audit item 2). Added a review note documenting the verified cookie + `X-CSRF-Token`/`ui_csrf`
  auth transport (audit item 1) so downstream interceptor tickets cite the correct contract. Dropped
  the unverifiable "DynamoDB" qualifier from the inline backend description (the FastAPI shape is
  observable; the datastore is not — audit item 4).

### Open assumptions

- **OA-1** — Build-server toolchain (SDK 35, JDK 17, AGP/Gradle compatibility on Ubuntu) is asserted,
  not source-verified; confirm on the server before merge (audit item 11 / R1).
- **OA-2** — `distributionSha256Sum` for `gradle-8.9-bin.zip` is unverified offline; verify against
  services.gradle.org at commit time (audit item 12).
- **OA-3** — Dev backend host/port `18.222.237.167:8000` and the `/openapi.json` path are not present
  in the frontend source; they are environment conventions (audit items 2 & 4).
- **OA-4** — Framework version facts (items 5–10) are cited from vendor docs by knowledge, not fetched
  live in this review; re-confirm exact patch availability (AGP 8.7.3, KSP 2.0.21-1.0.27, Compose BOM
  2024.10.01) at implementation time.

## 17. Test Plan

All cases are **build-level**; AND-001 ships no runtime/UI code, so there are no
contract/MockWebServer, Compose-UI, instrumented-e2e, or accessibility cases (explicitly N/A —
those begin at AND-003/AND-004). Test IDs trace to the §14 Acceptance Criteria (AC), numbered
top-to-bottom AC-1 … AC-13.

- **TC-AND-001-01** — Type: integration (clean-clone build).
  **Preconditions:** fresh clone of `android-port`, no warm Gradle caches, JDK 17 + Android SDK 35
  available; no manual edits.
  **Steps:** from `android/`, run `./gradlew help`.
  **Expected:** `BUILD SUCCESSFUL`; wrapper downloads `gradle-8.9-bin.zip` and passes the
  `distributionSha256Sum` check; no version-resolution errors.
  **Traces:** AC-1, AC-2, AC-6.

- **TC-AND-001-02** — Type: integration (task graph + module includes).
  **Preconditions:** TC-01 passed (configures successfully).
  **Steps:** run `./gradlew :app:tasks` and `./gradlew projects`.
  **Expected:** `:app` and the five `core-*` modules (`:core-network`, `:core-model`, `:core-ui`,
  `:core-data`, `:core-testing`) are listed; `:app:tasks` enumerates Android application tasks.
  **Traces:** AC-5, AC-7.

- **TC-AND-001-03** — Type: integration (catalog is single source of versions).
  **Preconditions:** TC-01 passed.
  **Steps:** run `./gradlew :app:dependencies`; then grep all `*.gradle.kts` for inline version
  literals (e.g. quoted `x.y.z` in dependency/plugin coordinates).
  **Expected:** resolved versions equal `gradle/libs.versions.toml`; **no** version string appears in
  any `build.gradle.kts` (all via `libs.*` aliases).
  **Traces:** AC-3, AC-4, AC-7.

- **TC-AND-001-04** — Type: unit (catalog/Kotlin-version coupling).
  **Preconditions:** none beyond repo checkout.
  **Steps:** assert in `libs.versions.toml` that `ksp` starts with the `kotlin` value
  (`2.0.21` ⇒ `ksp = "2.0.21-…"`) and `agp` is `8.7.x`, `compileSdk/targetSdk = 35`, `minSdk = 24`,
  JDK target 17. (Can be a small script or a CI guard.)
  **Expected:** all version-coupling invariants hold; mismatched Kotlin/KSP fails the check.
  **Traces:** AC-3.

- **TC-AND-001-05** — Type: integration (toolchain parity).
  **Preconditions:** JDK 17 installed/provisionable.
  **Steps:** run `./gradlew -q javaToolchains`.
  **Expected:** JDK 17 is selected/available for the build per `jvmToolchain(17)`.
  **Traces:** AC-3, AC-13.

- **TC-AND-001-06** — Type: integration (smoke build / APK).
  **Preconditions:** `:app` left buildable (per OQ3 resolution); SDK 35 present.
  **Steps:** run `./gradlew :app:assembleDebug` (or the agreed alternative `:app:lintDebug` /
  `:core-model:compileDebugKotlin` if `:app` is codeless).
  **Expected:** `BUILD SUCCESSFUL`; if `assembleDebug`, `app/build/outputs/apk/debug/app-debug.apk`
  exists.
  **Traces:** AC-8.

- **TC-AND-001-07** — Type: integration (configuration-cache reuse).
  **Preconditions:** `org.gradle.configuration-cache=true`.
  **Steps:** run `./gradlew help` twice in succession.
  **Expected:** first run "Calculating task graph…"/stores the cache entry; second run logs
  "Reusing configuration cache." with no CC-incompatibility warnings.
  **Traces:** AC-9.

- **TC-AND-001-08** — Type: integration (offline / flaky-host resilience).
  **Preconditions:** dependency + wrapper caches warm (TC-01 ran once); network to the dev backend
  and/or Maven repos unavailable.
  **Steps:** run `./gradlew --offline help`.
  **Expected:** `BUILD SUCCESSFUL` with no network access; confirms the build never contacts
  `18.222.237.167` and tolerates an offline/flaky environment.
  **Traces:** AC-6 (offline variant), AC-9.

- **TC-AND-001-09** — Type: contract/static (repository lockdown).
  **Preconditions:** repo checkout.
  **Steps:** (a) confirm `settings.gradle.kts` sets `repositoriesMode = FAIL_ON_PROJECT_REPOS` and
  declares only `google()` + `mavenCentral()` (+ `gradlePluginPortal()` under `pluginManagement`);
  (b) add a temporary `repositories {}` block to a module's `build.gradle.kts` and run any configure
  task.
  **Expected:** baseline passes; the injected per-module repository causes a configuration-time
  failure (proving `FAIL_ON_PROJECT_REPOS` is enforced). Revert the injection after.
  **Traces:** AC-5.

- **TC-AND-001-10** — Type: manual/static (security — no secrets, `.gitignore` correctness).
  **Preconditions:** repo checkout.
  **Steps:** inspect `.gitignore` for `.gradle/`, `build/`, `local.properties`, `*.keystore`/`*.jks`;
  scan tracked files for API keys/tokens/keystores; confirm `gradle/wrapper/gradle-wrapper.jar` **is**
  tracked.
  **Expected:** ignore rules present; no secrets or backend credentials in any committed file; wrapper
  jar committed.
  **Traces:** AC-10, AC-11.

- **TC-AND-001-11** — Type: security/static (wrapper integrity).
  **Preconditions:** `validateDistributionUrl=true` and `distributionSha256Sum` set.
  **Steps:** (a) verify `distributionUrl` ends in `gradle-8.9-bin.zip`; (b) compare
  `distributionSha256Sum` against the published `.sha256` for that distribution; (c) (negative) corrupt
  the sum locally and run `./gradlew help`.
  **Expected:** (a)/(b) match; (c) the wrapper aborts with a checksum-mismatch error. Revert after.
  **Traces:** AC-2.

- **TC-AND-001-12** — Type: integration (build-server parity).
  **Preconditions:** access to the Ubuntu build server (JDK 17, SDK 35, `ANDROID_SDK_ROOT`/
  `ANDROID_HOME` exported).
  **Steps:** on the server, from a fresh clone run `./gradlew help :app:tasks assembleDebug
  --stacktrace`.
  **Expected:** identical `BUILD SUCCESSFUL` results to the developer machine; confirms toolchain
  parity (closes OA-1).
  **Traces:** AC-13, AC-1, AC-7, AC-8.

### Coverage matrix

| §14 Acceptance Criterion (AC) | Covered by |
|---|---|
| AC-1 — required files + wrapper pinned to Gradle 8.9 | TC-01, TC-12 |
| AC-2 — `distributionUrl` = `gradle-8.9-bin.zip` + valid SHA-256 | TC-01, TC-11 |
| AC-3 — catalog pins AGP 8.7.x / Kotlin 2.0.x / KSP-matches / JDK 17 / SDK 35 / minSdk 24 | TC-03, TC-04, TC-05 |
| AC-4 — no version string in any `build.gradle.kts` | TC-03 |
| AC-5 — `FAIL_ON_PROJECT_REPOS`, `google()`+`mavenCentral()`, `:app` + five `core-*` | TC-02, TC-09 |
| AC-6 — fresh clone `./gradlew help` succeeds | TC-01, TC-08 |
| AC-7 — `:app:tasks`/`:app:dependencies` succeed, show catalog versions | TC-02, TC-03, TC-12 |
| AC-8 — smoke build (`assembleDebug` or agreed alternative) succeeds | TC-06, TC-12 |
| AC-9 — second `help` reuses configuration cache | TC-07, TC-08 |
| AC-10 — `.gitignore` excludes caches/keystores; wrapper jar committed | TC-10 |
| AC-11 — no secrets/keys/backend credentials committed | TC-10 |
| AC-12 — (all commands pass identically on the Ubuntu build server) | TC-12 |
| AC-13 — server parity / consistency of toolchain | TC-05, TC-12 |

> Note: §14 lists thirteen checkboxes; AC-12 ("All commands pass identically on the Ubuntu build
> server") and the toolchain-parity intent (AC-13) are both exercised by TC-12. If §14 is later
> renumbered, keep this matrix's TC mappings aligned.
