---
id: AND-003
title: Core module structure
milestone: M1 (Auth Foundation)
epic: E01 (Project scaffolding & build tooling)
priority: P0
size: M
status: draft
depends_on: [AND-001]
blocks: [AND-004, AND-009, AND-018, AND-019, AND-115, AND-046]
---

# AND-003 — Core module structure

## 1. Overview & Goal

This ticket establishes the multi-module skeleton for the native Android port of TestLogon. It creates five Android library modules — `core-model`, `core-network`, `core-data`, `core-ui`, and `core-testing` — with correct Gradle namespaces, minimal but well-formed `build.gradle.kts` files, and a `build-logic` included build providing convention plugins that centralize shared configuration. It then wires the existing `app` module to consume the core modules.

The goal is a compilable, navigable, and enforceable module graph that subsequent feature and infrastructure tickets can populate without re-litigating structure. AND-003 deliberately ships **structure, not behavior**: each module contains only the minimum needed to compile (a namespace, plugin application, and, where useful, a placeholder type or package marker). The networking client (AND-009), Moshi models (AND-018), Compose design system (AND-019), Room/DataStore data layer (AND-115), Hilt graph (AND-004), and test harness (AND-046) all land in later tickets that build on these modules.

Success means a clean layered architecture (`app -> feature -> core`, with `core-*` depending only on lower `core-*`), a Gradle sync that completes without warnings about misconfigured modules, and `./gradlew :app:assembleDebug` succeeding with the new modules on the classpath.

## 2. Context & References

**Layering rationale.** TestLogon is a large creator-economy app; a single-module `app` would become a build-time and merge-conflict bottleneck. We adopt the now-standard Now-in-Android-style layering: a thin `app` shell, `feature-*` modules per user-facing area, and `core-*` modules for cross-cutting infrastructure. Strict, unidirectional dependencies keep build caching effective (a change in one feature does not invalidate sibling features) and make ownership and testing boundaries obvious.

**Related tickets.**
- **AND-001** (Gradle/AGP/JDK toolchain & wrapper) — *blocks this ticket.* Provides Gradle 8.9 wrapper, AGP 8.7.x, JDK 17 toolchain, and the version catalog (`gradle/libs.versions.toml`). `build-logic` and every module here consume that catalog.
- **AND-002** (`app` module) — the single-Activity Compose host. AND-003 wires `app`'s `dependencies {}` to the core modules.
- **AND-004** (Hilt DI) — adds the Hilt Gradle plugin and KSP; AND-003 leaves a `hilt` convention plugin *seam* but does not implement Hilt wiring.
- **AND-009** (networking), **AND-018** (model), **AND-019** (ui), **AND-115** (data), **AND-046** (testing) — each fills in the corresponding `core-*` module created here.

**Reference material.** Web frontend (`frontend/`, React/Vite/TS) defines the domain vocabulary (creators, posts, sessions, CSRF) reflected in `core-model`. Backend is FastAPI + DynamoDB at the unreliable dev host `http://18.222.237.167:8000` (plaintext HTTP), which motivates resilience contracts that live in `core-network`/`core-model` (see §7).

## 3. Functional Requirements

FR-1. Five Android library modules exist at `android/core-model`, `android/core-network`, `android/core-data`, `android/core-ui`, `android/core-testing`, each with a unique namespace under `com.testlogon.core.*`.

FR-2. A `build-logic` composite (included) build exists at `android/build-logic` and publishes convention plugins applied by every module.

FR-3. Each module applies the appropriate convention plugin and declares only its allowed dependencies via the version catalog (no hard-coded versions in module build files).

FR-4. `settings.gradle.kts` registers all five modules and includes `build-logic`.

FR-5. `app` declares `implementation(project(...))` on the core modules it needs and continues to assemble.

FR-6. The dependency direction is enforceable: no `core-*` module depends on `app` or any `feature-*`; `core-ui`, `core-data`, `core-network` may depend on `core-model`; `core-testing` is consumed only as `testImplementation`/`androidTestImplementation`.

FR-7. `./gradlew assembleDebug` and `./gradlew :app:dependencies` complete successfully; the project syncs in Android Studio without module-configuration errors.

## 4. Technical Design

All modules use AGP's `com.android.library`. We do **not** hand-write `compileSdk`/`minSdk`/Kotlin options per module; those are set once in convention plugins. Module build files stay short and declarative.

### 4.1 build-logic convention plugins

`build-logic` is a standalone Gradle build included via `includeBuild("build-logic")` in `settings.gradle.kts`. It contains one `build.gradle.kts` (a `kotlin-dsl` project) and a small set of `Plugin<Project>` classes registered under stable plugin IDs.

`android/build-logic/build.gradle.kts` (sketch):

```kotlin
plugins {
    `kotlin-dsl`
}

dependencies {
    compileOnly(libs.android.gradlePlugin)   // com.android.tools.build:gradle
    compileOnly(libs.kotlin.gradlePlugin)    // org.jetbrains.kotlin:kotlin-gradle-plugin
    compileOnly(libs.ksp.gradlePlugin)
}

gradlePlugin {
    plugins {
        register("androidLibrary") {
            id = "testlogon.android.library"
            implementationClass = "AndroidLibraryConventionPlugin"
        }
        register("androidLibraryCompose") {
            id = "testlogon.android.library.compose"
            implementationClass = "AndroidLibraryComposeConventionPlugin"
        }
        register("kotlinLibrary") {
            id = "testlogon.kotlin.library"
            implementationClass = "KotlinLibraryConventionPlugin"
        }
        register("androidHilt") {            // seam for AND-004; no-op until then
            id = "testlogon.android.hilt"
            implementationClass = "AndroidHiltConventionPlugin"
        }
    }
}
```

`AndroidLibraryConventionPlugin` applies `com.android.library` + `org.jetbrains.kotlin.android`, then sets `compileSdk = 35`, `defaultConfig.minSdk = 24`, `targetSdk = 35`, Java/Kotlin toolchain to JDK 17, `compilerOptions.jvmTarget = JVM_17`, `testOptions`, and adds `core-testing` is **not** auto-applied (modules opt in to avoid cycles). `AndroidLibraryComposeConventionPlugin` applies the base plugin plus `org.jetbrains.kotlin.plugin.compose`, enables `buildFeatures.compose = true`, and adds the Compose BOM + tooling. `KotlinLibraryConventionPlugin` (for `core-model`) applies only `org.jetbrains.kotlin.jvm` so the model layer is a pure-Kotlin JVM module with no Android dependency. `AndroidHiltConventionPlugin` is registered now but its body is a TODO comment until AND-004.

This keeps each module's `build.gradle.kts` to a `plugins {}` block, a `namespace`, and `dependencies {}`.

### 4.2 core-model

**Purpose.** Pure domain & DTO data classes and cross-cutting result/error types shared by every layer. No Android, no I/O.
**Namespace / module type.** Kotlin JVM library; package root `com.testlogon.core.model`. (No `android {}` namespace; it is not an Android module.)
**Key contents (this ticket = scaffolding only):** package markers `com.testlogon.core.model` and `com.testlogon.core.model.result`; a placeholder `sealed interface ApiResult<out T>` skeleton and `data class DomainError` stub (filled by AND-018/AND-007). Annotations only — Moshi codegen lives in `core-network`/AND-018.

```kotlin
plugins {
    id("testlogon.kotlin.library")
}
dependencies {
    implementation(libs.kotlinx.coroutines.core) // for Flow/Result helpers only
}
```

### 4.3 core-network

**Purpose.** HTTP stack contracts: Retrofit/OkHttp/Moshi setup, cookie-based auth interceptor (session + `ui_csrf` -> `X-CSRF-Token`), 401 -> `POST /ui/session/refresh` -> retry policy, timeout/retry/offline handling for the unreliable dev host. Implementations land in AND-009.
**Namespace.** `com.testlogon.core.network` (Android library).
**Key contents (scaffolding):** packages `...network`, `...network.interceptor`, `...network.di`; placeholder `object NetworkConstants { const val BASE_URL = "http://18.222.237.167:8000/" }` and an empty `NetworkModule` marker for AND-004.

```kotlin
plugins {
    id("testlogon.android.library")
}
android { namespace = "com.testlogon.core.network" }
dependencies {
    implementation(project(":core-model"))
    implementation(libs.bundles.retrofit)   // retrofit, converter-moshi
    implementation(libs.okhttp)
    implementation(libs.okhttp.logging)
    implementation(libs.moshi)
    implementation(libs.kotlinx.coroutines.core)
    testImplementation(project(":core-testing"))
}
```

### 4.4 core-data

**Purpose.** Repository implementations, Room cache, DataStore prefs, and mapping between DTOs (`core-model`) and persisted/UI state. Depends on `core-network` + `core-model`. Concrete repos/DAOs land in AND-115.
**Namespace.** `com.testlogon.core.data` (Android library).
**Key contents (scaffolding):** packages `...data`, `...data.repository`, `...data.local`, `...data.datastore`, `...data.di`; placeholder `interface SessionRepository`.

```kotlin
plugins {
    id("testlogon.android.library")
}
android { namespace = "com.testlogon.core.data" }
dependencies {
    implementation(project(":core-model"))
    implementation(project(":core-network"))
    implementation(libs.room.runtime)
    implementation(libs.room.ktx)
    implementation(libs.datastore.preferences)
    implementation(libs.security.crypto)     // EncryptedSharedPreferences (see §8)
    implementation(libs.kotlinx.coroutines.core)
    testImplementation(project(":core-testing"))
}
```

### 4.5 core-ui

**Purpose.** Shared Compose design system: Material 3 theme, typography, color, spacing, reusable components (buttons, loaders, error/offline banners), Coil image wrappers, accessibility helpers, and string-resource conventions. No business logic, no networking. Filled by AND-019.
**Namespace.** `com.testlogon.core.ui` (Android library, Compose enabled).
**Key contents (scaffolding):** packages `...ui.theme`, `...ui.component`, `...ui.util`; placeholder `TestLogonTheme {}` composable stub.

```kotlin
plugins {
    id("testlogon.android.library.compose")
}
android { namespace = "com.testlogon.core.ui" }
dependencies {
    implementation(project(":core-model")) // for shared UI state/error enums only
    implementation(platform(libs.compose.bom))
    implementation(libs.bundles.compose)   // ui, material3, tooling-preview
    implementation(libs.coil.compose)
    debugImplementation(libs.compose.ui.tooling)
    androidTestImplementation(project(":core-testing"))
}
```

### 4.6 core-testing

**Purpose.** Shared test infrastructure consumed by other modules' test source sets only: MockWebServer dispatchers, JSON fixtures/loaders, coroutine test rules (`MainDispatcherRule`), fake builders, and Compose test helpers. Filled by AND-046.
**Namespace.** `com.testlogon.core.testing` (Android library).
**Key contents (scaffolding):** packages `...testing`, `...testing.network`, `...testing.rule`, `...testing.fixture`; placeholder `MainDispatcherRule`.

```kotlin
plugins {
    id("testlogon.android.library")
}
android { namespace = "com.testlogon.core.testing" }
dependencies {
    implementation(project(":core-model"))
    api(libs.junit)
    api(libs.kotlinx.coroutines.test)
    api(libs.mockwebserver)
    api(libs.turbine)
    api(libs.androidx.test.ext)
}
```

Note: `core-testing` uses `api(...)` so consumers transitively get JUnit/MockWebServer in their test classpath, and is referenced only as `testImplementation`/`androidTestImplementation` elsewhere — never `implementation` (it must not enter production code).

### 4.7 Module dependency graph (text diagram)

```
                         app
                          |
                 (later) feature-*  ----------------+
                          |                          |
        +-----------------+---------+----------+      |
        v                 v         v          v      v
     core-ui          core-data  core-network  core-model
        |                 |          |            ^
        |                 +----------+------------+
        +-----------------(core-model only)-------+

   core-testing  <--- testImplementation/androidTestImplementation only
                      (from core-network, core-data, core-ui, app, feature-*)
   core-testing ---> core-model

  Direction: app -> feature -> core-{ui,data,network} -> core-model
  core-model depends on nothing (Kotlin JVM, coroutines-core only).
```

## 5. Module Boundaries & Dependency Rules

**Allowed edges.**
- `app` -> any `core-*` (and later, `feature-*`).
- `feature-*` -> `core-ui`, `core-data`, `core-model` (and `core-network` only if a feature legitimately needs raw API types — discouraged; prefer going through `core-data`).
- `core-ui` -> `core-model`. `core-data` -> `core-network`, `core-model`. `core-network` -> `core-model`.
- `core-model` -> nothing internal.
- `core-testing` -> `core-model`; consumed only via test configurations.

**Forbidden edges.** `core-* -> app`; `core-* -> feature-*`; any cycle; `core-model -> any Android module`; `core-network -> core-ui` or `core-data` (network must not know about persistence or presentation); `implementation(project(":core-testing"))` in any production configuration.

**Enforcement (this ticket).**
1. **Build-time:** the dependency graph itself fails to resolve on a cycle, and convention plugins keep `core-model` Android-free (no `com.android.library`), so an accidental Android import won't compile there.
2. **Lightweight check:** add a Gradle task `:checkModuleBoundaries` (a simple verification reading each module's declared project dependencies against an allow-map) wired into `check`. A fuller solution (e.g., a dependency-rules ArchUnit/Konsist test, or `dependency-analysis-gradle-plugin`) is recorded as an open question for AND-046; this ticket ships the allow-map check to prevent regressions cheaply.
3. **Code review:** PR template note that new `project(...)` edges must respect §5.

## 6. Data & State Management

`core-model` owns the **shape** of data: domain entities, API DTOs, UI-facing state/enum types, and result wrappers. It is persistence- and transport-agnostic so all layers can reference one canonical type set without duplicating definitions.

`core-data` owns the **lifecycle and source of truth**: Room entities/DAOs (cache for posts, creators, feed pages via Paging 3 later), DataStore for preferences, and repositories that expose `Flow`/suspend APIs mapping network DTOs and cached rows into domain models. The offline-first contract — serve cache, refresh in background, reconcile — is a `core-data` responsibility (implemented in AND-115). `core-network` returns DTOs only; it never persists. This split keeps `core-model` recompilation cheap (it changes rarely) and isolates schema/migration churn to `core-data`.

## 7. Error Handling & Resilience

The shared result and error vocabulary lives in **`core-model`** so every layer speaks it without depending on Android or Retrofit. The scaffold introduces:

```kotlin
sealed interface ApiResult<out T> {
    data class Success<T>(val data: T) : ApiResult<T>
    data class Failure(val error: DomainError) : ApiResult<Nothing>
}
sealed interface DomainError {            // expanded in AND-007/AND-009
    data object Network : DomainError      // timeout / offline (dev host unreliable)
    data object Unauthorized : DomainError // 401 after refresh attempt fails
    data class Http(val code: Int) : DomainError
    data class Unknown(val cause: Throwable?) : DomainError
}
```

`core-network` (AND-009) maps OkHttp/Retrofit exceptions and HTTP statuses into `DomainError`, owns timeout/retry config and the single-shot `401 -> /ui/session/refresh -> retry` flow. `core-data` translates `ApiResult.Failure(Network)` into cache-fallback behavior. `core-ui` renders `DomainError` via shared error/offline banner components. Centralizing the type in `core-model` ensures the resilience design for the flaky plaintext dev host is expressed once and consumed everywhere.

## 8. Security & Privacy

Encrypted storage and crypto utilities live in **`core-data`**, which already owns persistence. The session cookie and `ui_csrf` token are stored via `EncryptedSharedPreferences` (androidx.security:security-crypto) or an encrypted DataStore wrapper, exposed only through a `SessionRepository`/token-store interface so other modules never touch raw secrets. `core-network` consumes the token store via interface (injected in AND-004) and attaches the `X-CSRF-Token` header; it holds no persisted secrets itself. The plaintext-HTTP dev host is a dev-only concession: `NetworkConstants.BASE_URL` is overridable per build type so production points at HTTPS, and a `usesCleartextTraffic`/network-security-config allowance is scoped to debug (handled in AND-002/AND-009, referenced here). No PII or secrets belong in `core-model`, `core-ui`, or `core-testing`.

## 9. Accessibility & i18n

`core-ui` is the home for accessibility and internationalization conventions. Responsibilities established here (implemented in AND-019): shared `string` resources and a no-hard-coded-strings convention so all user-facing text is localizable; minimum touch-target sizing (48dp) baked into shared components; content-description helpers for icon buttons and images (including Coil image wrappers); support for dynamic font scaling via Material 3 typography; RTL-safe layouts using start/end paddings; and theme support (light/dark, dynamic color). Because these conventions live in `core-ui`, every feature inherits accessible defaults rather than re-implementing them. This ticket only stamps the package/theme stub so those concerns have a clear destination.

## 10. Telemetry & Logging

A minimal shared logging interface is declared in **`core-model`** (transport-agnostic, no Android `Log` dependency) so all modules — including pure-Kotlin ones — can log against one abstraction:

```kotlin
interface Logger {
    fun d(tag: String, msg: String)
    fun e(tag: String, msg: String, t: Throwable? = null)
}
```

The Android/Timber-backed implementation and analytics/telemetry sinks are provided in `core-data` (or a future `core-analytics`) and bound via Hilt in AND-004. Network request/response logging uses OkHttp's `HttpLoggingInterceptor` inside `core-network`, gated to debug builds. Keeping the interface in `core-model` avoids every module taking an Android logging dependency and keeps `core-network`/`core-data` testable.

## 11. Testing Strategy

**core-testing contents (scaffolded now, populated in AND-046):**
- `network/` — `MockWebServer` extensions, a `enqueueJson(path)` helper, and a dispatcher that maps request paths to fixture files (mirrors the FastAPI routes, incl. `/ui/session/refresh`).
- `fixture/` — JSON fixtures loaded from test resources plus a `loadJson(name)` reader; fake/builder factories for domain models.
- `rule/` — `MainDispatcherRule` (swaps `Dispatchers.Main` for a test dispatcher), and a Turbine-friendly Flow assertion helper.
- Compose: shared `createAndroidComposeRule` helpers and semantics matchers for `core-ui`/feature tests.

**Per-module setup (this ticket).** Each Android `core-*` (except `core-testing` itself) adds `testImplementation(project(":core-testing"))`; `core-ui` adds `androidTestImplementation(project(":core-testing"))`. `core-model` adds `testImplementation(libs.junit)` directly (pure JVM). A trivial smoke test (`assertTrue(true)` or instantiating a placeholder type) is added to each module so `./gradlew test` exercises every test source set and proves the test classpath resolves. Verification for AND-003 is primarily build/graph correctness; substantive unit tests arrive with the feature tickets.

## 12. Dependencies & Sequencing

**Blocked by:** AND-001 (Gradle 8.9 wrapper, AGP 8.7.x, JDK 17 toolchain, `libs.versions.toml`). `build-logic` cannot reference catalog accessors or the AGP/Kotlin plugin artifacts until AND-001 lands.

**Coordinates with:** AND-002 (`app` module must exist to wire dependencies; if AND-002 is in flight, deliver core modules first and add `app` edges in a follow-up commit). AND-004 (Hilt) consumes the `testlogon.android.hilt` plugin seam created here.

**Blocks:**
- AND-018 (Moshi models) — needs `core-model`.
- AND-009 (networking client/interceptors) — needs `core-network` + `core-model`.
- AND-019 (Compose design system) — needs `core-ui`.
- AND-115 (Room/DataStore data layer) — needs `core-data` + `core-network` + `core-model`.
- AND-046 (test harness) — needs `core-testing`.
- AND-004 (Hilt graph) — needs the module skeleton to host DI modules.
- Effectively every feature-* ticket, since features consume `core-ui`/`core-data`/`core-model`.

**Suggested order within this ticket:** (1) `build-logic` + convention plugins; (2) `core-model`; (3) `core-network`, `core-ui` (parallel); (4) `core-data`; (5) `core-testing`; (6) `settings.gradle.kts` + `app` wiring; (7) boundary check task; (8) smoke tests + full `assembleDebug`/`test` run.

## 13. Risks & Open Questions

- **Over-modularization.** Five core modules plus future features adds Gradle configuration overhead and cognitive load. Mitigation: convention plugins keep per-module config near-zero; we resist creating more core modules (`core-analytics`, `core-common`) until a concrete need appears.
- **Build times / sync overhead.** More modules can slow cold builds. Mitigation: enable Gradle configuration cache and parallel execution (set in AND-001's `gradle.properties`); convention plugins ensure consistent, cacheable config; keep `core-model` dependency-light so it rarely triggers downstream rebuilds.
- **Boundary enforcement strength.** The allow-map check is lightweight, not exhaustive. Open question: adopt `dependency-analysis-gradle-plugin` or a Konsist/ArchUnit rule set (decide in AND-046).
- **Hilt seam scope.** Whether Hilt config belongs in a convention plugin vs. per-module application is deferred to AND-004; the no-op plugin must not accidentally apply Hilt before then.
- **core-ui pulling core-model.** Risk of leaking domain logic into UI. Mitigation: restrict `core-ui` to UI state/enum types from `core-model`; flag any repository/network type usage in review.
- **Cleartext base URL.** Open question: confirm production HTTPS endpoint so `NetworkConstants.BASE_URL` build-type overrides are correct (owner: backend/AND-009).

## 14. Acceptance Criteria

- [ ] `android/build-logic` exists, applies `kotlin-dsl`, and registers plugins with IDs `testlogon.android.library`, `testlogon.android.library.compose`, `testlogon.kotlin.library`, `testlogon.android.hilt`.
- [ ] `settings.gradle.kts` includes `build-logic` via `includeBuild` and registers `:core-model`, `:core-network`, `:core-data`, `:core-ui`, `:core-testing`.
- [ ] Each module has a unique namespace: `com.testlogon.core.{model|network|data|ui|testing}` (`core-model` is a Kotlin JVM module with package root `com.testlogon.core.model`).
- [ ] No module file hard-codes `compileSdk`/`minSdk`/`targetSdk`/JVM target or library versions; all come from convention plugins + the version catalog. (minSdk 24, compileSdk 35, targetSdk 35, JDK 17.)
- [ ] Dependency edges match §4.7: `core-model` has no internal deps; `core-network`/`core-data`/`core-ui` depend on `core-model`; `core-data` depends on `core-network`; `core-testing` depends only on `core-model` and is referenced solely via test configurations.
- [ ] No `core-*` module depends on `app` or any `feature-*`; no cycles. `./gradlew :checkModuleBoundaries` passes.
- [ ] `app` declares `implementation(project(...))` on the core modules it needs and `./gradlew :app:assembleDebug` succeeds.
- [ ] `./gradlew test` runs every module's test source set (smoke tests) successfully.
- [ ] Android Studio Gradle sync completes with no module-configuration errors or warnings.
- [ ] `ApiResult`/`DomainError` and `Logger` stubs compile in `core-model`; `MainDispatcherRule` stub compiles in `core-testing`.

## 15. Definition of Done

- All acceptance criteria pass on CI and locally on JDK 17 / Gradle 8.9.
- The five modules, `build-logic`, convention plugins, `settings.gradle.kts`, and `app` wiring are merged to `android-port` via reviewed PR(s); commits scoped to `android/`.
- Convention plugin IDs and the module dependency graph are documented in `android/README.md` (or the module's section), including the §5 dependency rules.
- `./gradlew assembleDebug`, `./gradlew test`, and `./gradlew :checkModuleBoundaries` are green; configuration cache and parallel build verified.
- Placeholder types are marked with TODO comments referencing the owning follow-up ticket (AND-018, AND-009, AND-019, AND-115, AND-046, AND-004) so downstream work has clear entry points.
- No production dependency on `core-testing`; no Android dependency in `core-model`.
- PR description links AND-001 (dependency) and notes the modules it unblocks; reviewers from the platform/build owners sign off on module boundaries.
