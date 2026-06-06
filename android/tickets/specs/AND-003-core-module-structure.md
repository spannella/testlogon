---
id: AND-003
title: Core module structure
milestone: M1 (Auth Foundation)
epic: E01 (Project scaffolding & build tooling)
priority: P0
size: M
status: reviewed
reviewed_on: 2026-06-06
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

**Purpose.** HTTP stack contracts: Retrofit/OkHttp/Moshi setup, auth interceptor, and a single-shot `401 -> POST /ui/session/refresh -> retry` policy, plus timeout/retry/offline handling for the unreliable dev host. Implementations land in AND-009.

> **Verified auth transport (per `src/api/client.ts`).** The web client is **not cookie-only**. Each request carries: (a) `Authorization: Bearer <accessToken>` from the auth store when present; (b) cookies via `credentials: "include"`; (c) `X-CSRF-Token` set from the `ui_csrf` cookie value; and (d) `X-IMPERSONATION-TOKEN` when an impersonation session is active. The Android interceptor seam reserved here must accommodate **all four**, not just a session cookie. CSRF and the refresh flow are confirmed; see §16.
**Namespace.** `com.testlogon.core.network` (Android library).
**Key contents (scaffolding):** packages `...network`, `...network.interceptor`, `...network.di`; placeholder `object NetworkConstants { const val BASE_URL = "http://18.222.237.167:8000/" }` and an empty `NetworkModule` marker for AND-004.

> **Note (unverified).** The dev-host IP/port `18.222.237.167:8000` is an Android-side assumption — it is **not** present in the frontend source, which resolves its base URL from the `VITE_API_BASE_URL` env var (`src/api/client.ts: API_BASE_URL`). Confirm the value with the backend owner (see §16 Open assumptions and §13 "Cleartext base URL").

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

## 16. Citations & Assumption Audit

This is a scaffolding/chore ticket, so most content (module layout, Gradle plugins, JDK/SDK levels) is framework/build configuration rather than backend contract. The audit below covers the spec's concrete claims about the backend API, auth/CSRF transport, web-app behavior, and the framework choices, verified against the OpenAPI index/spec and the frontend reference source.

1. **CSRF token is read from the `ui_csrf` cookie and sent as the `X-CSRF-Token` header.** VERDICT: **Verified.** SOURCE: `src/api/client.ts` (`getCookie("ui_csrf")` then `headers.set("X-CSRF-Token", csrf)`); also `src/stores/offlineStore.ts: getCsrfFromCookie` parses the same `ui_csrf` cookie.
2. **On 401, the client performs `POST /ui/session/refresh` once and retries the original request.** VERDICT: **Verified.** SOURCE: `src/api/client.ts: refreshSession` (`fetch("/ui/session/refresh", { method: "POST", credentials: "include" })`) and the 401 branch in `api()`. The refresh is single-shot via a shared `refreshPromise`; on refresh failure the client logs out (`session_expired`). The Android "single-shot 401 -> refresh -> retry" contract in §7 matches.
3. **`POST /ui/session/refresh` exists, takes no request body, returns 200.** VERDICT: **Verified.** SOURCE: OpenAPI `POST /ui/session/refresh` (`op=ui_session_refresh_ui_session_refresh_post | req= | resp=200:`).
4. **Session lifecycle endpoints exist (start/finalize/logout/refresh/sessions).** VERDICT: **Verified.** SOURCE: OpenAPI `POST /ui/session/start` (`req=UiSessionStartReq | resp=200:UiSessionStartResp`), `POST /ui/session/finalize` (`req=UiSessionFinalizeReq`), `POST /ui/session/logout`, `GET /ui/sessions`, `POST /ui/sessions/revoke`.
5. **Domain vocabulary (creators, posts/feed, sessions, CSRF) reflected in `core-model` is real.** VERDICT: **Verified.** SOURCE: OpenAPI `GET /feed` (`op=view_feed_feed_get`), `GET/POST /api/creators/{creator_id}/...` (plans, subscriptions, earnings, tiers), and the session endpoints above.
6. **Auth transport is "cookie-based (session + ui_csrf)".** VERDICT: **Corrected.** The web client sends, per request: `Authorization: Bearer <accessToken>` (from the auth store), cookies via `credentials: "include"`, `X-CSRF-Token` (from `ui_csrf`), and `X-IMPERSONATION-TOKEN` when impersonating. It is bearer-token + cookie + CSRF + impersonation, not cookie-only. SOURCE: `src/api/client.ts: api()` (Authorization header set from `useAuthStore`, impersonation header from `useImpersonationStore`, CSRF header, `credentials: "include"`). The §4.3 purpose line was corrected and a note added.
7. **`X-IMPERSONATION-TOKEN` / `X-SESSION-ID` are part of the request contract.** VERDICT: **Verified.** SOURCE: OpenAPI authenticated endpoints list `params=...,X-SESSION-ID,X-IMPERSONATION-TOKEN` (e.g. `GET /feed`, `POST /ui/session/logout`); `src/api/client.ts` sets `X-IMPERSONATION-TOKEN`.
8. **Validation error shape for 4xx is FastAPI's `HTTPValidationError` (`{ detail: ValidationError[] }`); domain/permission errors use a `detail.code` discriminator.** VERDICT: **Verified.** SOURCE: OpenAPI `components.schemas.HTTPValidationError` (`detail` is an array of `ValidationError`); `src/api/client.ts: normalizeErrorDetail` / `mapAuthorizationError` handle `detail` as string | array-of-`{msg}` | object-with-`code` (e.g. `role_required`, `role_required_scope`, `geo_blocked`, `helpdesk_claim_required`). The §7 `DomainError` mapping should consume these shapes.
9. **403 responses may carry `detail.code === "geo_blocked"` (geo-blocking) handled specially.** VERDICT: **Verified.** SOURCE: `src/api/client.ts` 403 branch (`rawDetail.code === "geo_blocked"`).
10. **Network errors (offline / dev-host failure) surface distinctly from HTTP errors.** VERDICT: **Verified.** SOURCE: `src/api/client.ts` wraps `fetch` rejections as `ApiError(0, "Network error", err)`; supports the §7 `DomainError.Network` mapping and the offline-first §6 contract.
11. **Dev host base URL is `http://18.222.237.167:8000` (plaintext HTTP).** VERDICT: **Unverified-assumption.** The frontend does not hard-code this; it resolves `API_BASE_URL` from `VITE_API_BASE_URL` (`src/api/client.ts`). The IP/port and the cleartext concession are Android-side assumptions to confirm with the backend owner.
12. **Backend is FastAPI + DynamoDB.** VERDICT: **Partially verified / assumption.** The OpenAPI shape (FastAPI's `HTTPValidationError`/`ValidationError`, operation-id naming) is consistent with FastAPI. SOURCE: `openapi.pretty.json` schema names. DynamoDB is a persistence detail not observable from the API contract — treat as an unverified assumption.
13. **Module layout, convention-plugin IDs, JDK 17 / compileSdk 35 / minSdk 24, Now-in-Android-style layering.** VERDICT: **Unverified-assumption (framework choice).** These are build/architecture decisions, not derivable from the backend or frontend sources. SOURCE: framework ref — Android Gradle plugin / convention-plugins guidance (https://developer.android.com/build) and Now in Android (https://github.com/android/nowinandroid). They depend on AND-001's version catalog; values must match what AND-001 actually ships.

### Corrections made

- **§4.3 (core-network purpose):** Changed "cookie-based auth interceptor (session + `ui_csrf` -> `X-CSRF-Token`)" to reflect the actual web transport — `Authorization: Bearer` + cookies + `X-CSRF-Token` + `X-IMPERSONATION-TOKEN` — and added a verified-transport note so the Android interceptor seam accommodates all four (claim 6).
- **§4.3 (NetworkConstants):** Added a note that the hard-coded dev-host IP `18.222.237.167:8000` is an Android-side assumption (frontend uses the `VITE_API_BASE_URL` env var) and must be confirmed (claim 11).
- No endpoint paths, methods, or the CSRF/refresh design needed correction — those were already accurate.

### Open assumptions

- **Dev-host IP/port and cleartext-HTTP policy** (claim 11): not present in the sources; the frontend is env-configured. Owner: backend / AND-009. Also tracked in §13.
- **Production HTTPS endpoint** for build-type `BASE_URL` overrides (§8/§13): not in sources.
- **DynamoDB persistence** (claim 12): not observable from the API contract.
- **AND-001 toolchain values** (Gradle 8.9 / AGP 8.7.x / JDK 17 / SDK 35 / version catalog accessors): assumed from the dependency ticket; this spec inherits whatever AND-001 ships. If AND-001 differs, §4.1/§14 levels must be updated.
- **`testlogon.*` convention-plugin IDs and the `core-*` module split** are this team's design choices, not externally verifiable.

## 17. Test Plan

Because AND-003 ships **structure, not behavior**, verification is predominantly build/Gradle-graph correctness plus a few stubs that must compile and run. Contract/MockWebServer and Compose-UI cases below are written as the **seam-validation** form appropriate to scaffolding (proving the test classpath and harness resolve), with the substantive behavioral assertions deferred to the owning feature tickets (AND-009/-018/-019/-115/-046). Each case traces to the §14 Acceptance Criteria (numbered AC-1..AC-9 in §14 order).

- **TC-AND-003-01 — build-logic registers all convention plugins.** Type: integration (Gradle). Preconditions: AND-001 merged; `android/build-logic` present. Steps: run `./gradlew :build-logic:tasks` and assert the four plugin IDs are registered (`testlogon.android.library`, `testlogon.android.library.compose`, `testlogon.kotlin.library`, `testlogon.android.hilt`); a probe module applying each ID configures without error. Expected: all four resolve; `androidHilt` is a no-op (applies no Hilt plugin/KSP). Traces: AC-1.
- **TC-AND-003-02 — settings registers modules and includeBuild.** Type: integration (Gradle). Preconditions: repo synced. Steps: run `./gradlew projects`. Expected: `:core-model`, `:core-network`, `:core-data`, `:core-ui`, `:core-testing` listed and `build-logic` included via `includeBuild`. Traces: AC-2.
- **TC-AND-003-03 — namespaces and module types are correct.** Type: unit (build-config assertion). Preconditions: modules present. Steps: assert each Android module's `android.namespace` equals `com.testlogon.core.{network|data|ui|testing}`; assert `core-model` is a Kotlin-JVM module with **no** `android {}` block and package root `com.testlogon.core.model`. Expected: all match; `core-model` has no AGP plugin applied. Traces: AC-3.
- **TC-AND-003-04 — no hard-coded SDK/JVM/version values in module files.** Type: unit (static check). Preconditions: modules present. Steps: scan each module `build.gradle.kts` for literal `compileSdk`/`minSdk`/`targetSdk`/`jvmTarget`/version strings; confirm SDK/JVM come only from convention plugins and all deps use `libs.*` catalog accessors. Expected: zero hard-coded versions/levels in module files; convention plugins set minSdk 24 / compileSdk 35 / targetSdk 35 / JDK 17. Traces: AC-4.
- **TC-AND-003-05 — dependency edges match the §4.7 graph.** Type: integration (Gradle). Preconditions: modules wired. Steps: run `./gradlew :core-data:dependencies` / `:core-network:dependencies` / `:core-ui:dependencies` / `:core-testing:dependencies`. Expected: `core-model` has no internal project deps; `core-network`,`core-data`,`core-ui` depend on `core-model`; `core-data` depends on `core-network`; `core-testing` depends only on `core-model`. Traces: AC-5.
- **TC-AND-003-06 — checkModuleBoundaries fails on forbidden edges, passes on the real graph.** Type: integration (Gradle). Preconditions: `:checkModuleBoundaries` task wired into `check`. Steps: (a) run on the current graph -> passes; (b) inject a forbidden edge (`core-model -> app`, or `implementation(project(":core-testing"))` in production config, or a cycle) on a scratch branch -> run task. Expected: (a) success; (b) task fails with a message naming the offending edge; no cycle resolves. Traces: AC-6.
- **TC-AND-003-07 — app assembles with core modules on the classpath.** Type: integration (Gradle). Preconditions: AND-002 `app` exists and declares `implementation(project(...))` on needed core modules. Steps: run `./gradlew :app:assembleDebug`. Expected: build succeeds; APK includes core-module classes; `core-testing` is absent from the production/runtime classpath. Traces: AC-7.
- **TC-AND-003-08 — every module's test source set runs (smoke).** Type: unit. Preconditions: each Android `core-*` has `testImplementation(project(":core-testing"))`, `core-ui` adds `androidTestImplementation(...)`, `core-model` has `testImplementation(libs.junit)`, and each module has a trivial smoke test. Steps: run `./gradlew test`. Expected: every module's test task executes and passes; the test classpath (JUnit/MockWebServer via `core-testing` `api(...)`) resolves transitively. Traces: AC-8.
- **TC-AND-003-09 — core-testing is test-scope only and not in production.** Type: integration (security/boundary). Preconditions: graph wired. Steps: run `./gradlew :core-network:dependencies` and inspect `implementation`/`runtimeClasspath` vs `testImplementation`; confirm `core-testing` (and its `api` deps: JUnit, MockWebServer, Turbine) never appear on a production configuration of any module. Expected: `core-testing` only on test/androidTest classpaths. Traces: AC-6.
- **TC-AND-003-10 — Android Studio / Gradle sync is clean.** Type: manual. Preconditions: project opened in Android Studio (JDK 17, Gradle 8.9). Steps: trigger Gradle sync; review the sync/build log. Expected: sync completes with no module-configuration errors or warnings; configuration cache and parallel execution active (per AND-001). Traces: AC-8 (sync), AC-9 (stubs available to the IDE).
- **TC-AND-003-11 — core-model stubs compile and behave as a sealed hierarchy.** Type: unit. Preconditions: `core-model` builds. Steps: instantiate `ApiResult.Success("x")` and `ApiResult.Failure(DomainError.Http(500))`; `when`-match over `DomainError` (`Network`/`Unauthorized`/`Http`/`Unknown`) and assert exhaustiveness compiles without an `else`; assert `Logger` interface has `d`/`e` signatures with no Android `Log` import. Expected: compiles and runs; no Android dependency leaks into `core-model`. Traces: AC-9.
- **TC-AND-003-12 — MainDispatcherRule stub compiles and swaps Main.** Type: unit (in `core-testing`). Preconditions: `core-testing` builds with `kotlinx-coroutines-test`. Steps: apply `MainDispatcherRule` in a sample test; launch a coroutine on `Dispatchers.Main` and assert it runs on the test dispatcher; confirm Main is reset after the rule. Expected: compiles; Main is replaced during and restored after the test. Traces: AC-9.
- **TC-AND-003-13 — MockWebServer/offline seam resolves (flaky-host readiness).** Type: contract/MockWebServer (seam). Preconditions: `core-testing` exposes MockWebServer via `api(...)`; a consuming module test source set. Steps: from a `core-network` test, start a `MockWebServer`, enqueue a 200 and a simulated connection failure/timeout, and assert the harness is reachable and a request can be dispatched. Expected: MockWebServer is on the test classpath and usable; this proves the seam for the real `DomainError.Network` + dev-host-flaky/offline behavior implemented in AND-009. Traces: AC-8 (classpath); supports §7 resilience. (Behavioral 401->refresh->retry and offline-fallback assertions are deferred to AND-009/AND-115.)
- **TC-AND-003-14 — core-ui Compose harness resolves (UI/accessibility seam).** Type: Compose-UI (instrumented, seam). Preconditions: `core-ui` Compose-enabled; `androidTestImplementation(project(":core-testing"))` wired; `TestLogonTheme {}` stub present. Steps: set content to `TestLogonTheme { /* placeholder */ }` using `createAndroidComposeRule`; assert it renders. Expected: Compose test classpath (compose-ui-test + helpers) resolves and the theme stub composes. Traces: AC-7/AC-8. (Substantive accessibility checks — 48dp touch targets, content descriptions, dynamic font scaling, RTL per §9 — are deferred to AND-019; this case only proves the Compose/accessibility test harness is in place.)

### Coverage matrix

| §14 Acceptance Criterion | Covered by |
| --- | --- |
| AC-1 build-logic + 4 plugin IDs | TC-01 |
| AC-2 settings registers modules + includeBuild | TC-02 |
| AC-3 unique namespaces / core-model is Kotlin-JVM | TC-03 |
| AC-4 no hard-coded SDK/JVM/versions | TC-04 |
| AC-5 dependency edges match §4.7 | TC-05 |
| AC-6 no app/feature deps, no cycles, checkModuleBoundaries passes; testing test-scope only | TC-06, TC-09 |
| AC-7 app declares core deps + assembleDebug succeeds | TC-07, TC-14 |
| AC-8 ./gradlew test runs all test source sets | TC-08, TC-10, TC-13, TC-14 |
| AC-9 Studio sync clean / ApiResult+DomainError+Logger+MainDispatcherRule stubs compile | TC-10, TC-11, TC-12 |
