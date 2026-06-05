---
id: AND-010
title: Retrofit + Moshi setup
milestone: M1
epic: E02
priority: P0
size: M
status: draft
depends_on: [AND-009, AND-006]
blocks: [AND-014, AND-015]
---

# AND-010 — Retrofit + Moshi setup

## 1. Overview & Goal

This ticket establishes the typed HTTP layer for the TestLogon native Android port:
a Hilt-provided `Retrofit` instance backed by a Moshi `Converter.Factory`, with the
base URL sourced from `BuildConfig.API_BASE_URL`, and Moshi configured to use the
Kotlin codegen (KSP) adapter generator rather than reflection.

The goal is a **single, canonical, dependency-injected Retrofit/Moshi pair** that every
`feature-*` module's API definitions and every `core-data` repository will consume. After
this ticket lands, an engineer can declare a Retrofit service interface, define Moshi
`@JsonClass(generateAdapter = true)` DTOs, and have request/response bodies serialize and
deserialize correctly against the FastAPI dev backend without any per-call wiring.

This is deliberately a **plumbing** ticket. It does not define application endpoints, error
mapping, the typed `ApiResult` wrapper, runtime host switching, the CSRF interceptor, the
401-refresh authenticator, or the cookie jar. Those are owned by downstream tickets
(AND-011 through AND-018) and are referenced here only where this ticket must leave a clean
seam for them. The deliverable is verified by a unit test in which a sample typed endpoint
round-trips JSON through Moshi and a `MockWebServer`.

Scope, in one line from the backlog: *Retrofit with Moshi converter; base URL from
`BuildConfig`; Moshi with Kotlin codegen.*

## 2. Context & References

- **Repo / location:** `spannella/testlogon`, monorepo subfolder `android/`, branch
  `android-port`. All code in this ticket lives in module **`core-network`**.
- **Canonical package:** `com.testlogon.android` everywhere a package appears. Files in this
  ticket sit under `com.testlogon.android.core.network`.
- **Stack pins relevant here:** Kotlin 2.0.21, Retrofit **2.11.0**, OkHttp **4.12.0**,
  Moshi **1.15.x** (`moshi`, `moshi-kotlin-codegen` via KSP), Hilt DI (KSP), Coroutines/Flow,
  JDK 17, AGP 8.7.3, Gradle 8.9, minSdk 24 / compileSdk 35.
- **Module layering:** `app -> feature-* -> core-*`. `core-network` depends on `core-model`
  (DTO/contract types) and on Hilt. No `feature-*` or `app` symbols may leak into
  `core-network`.
- **Upstream dependencies:**
  - **AND-006** — supplies `BuildConfig.API_BASE_URL` per flavor (`dev`→`http://18.222.237.167:8000`,
    `staging`, `prod`). This ticket reads that field; it does not define flavors.
  - **AND-009** — supplies the Hilt-provided singleton `OkHttpClient` (~20s connect/read/write
    timeouts, debug-only redacting `HttpLoggingInterceptor`). Retrofit must be built **on top
    of that exact client instance**, not a fresh one.
- **Downstream consumers (left-as-seam, not implemented here):**
  - **AND-014** Host-selection interceptor (runtime base URL) — depends on AND-010.
  - **AND-015** API error model & `detail` mapping — depends on AND-010.
  - **AND-011/012/013** cookie jar, CSRF interceptor, 401 authenticator attach to the shared
    `OkHttpClient` (AND-009), so they flow into Retrofit automatically once present.
  - **AND-018** `ApiResult<T>` lives in `core-model`; Retrofit services here return suspend
    functions whose bodies AND-018 will wrap.
- **Backend:** FastAPI + DynamoDB; dev host is plaintext HTTP and unreliable. OpenAPI at
  `/openapi.json`. Web reference for endpoint shapes: `frontend/src/api/endpoints/*.ts`,
  shared types `frontend/src/api/types.ts`.

## 3. Functional Requirements

FR-1. A single `@Singleton` `Retrofit` instance is provided through Hilt and injectable
anywhere in the dependency graph.

FR-2. Retrofit's base URL is `BuildConfig.API_BASE_URL` (from AND-006), normalized to a
trailing slash so relative `@GET("ui/me")`-style paths resolve correctly.

FR-3. Retrofit uses the **shared** singleton `OkHttpClient` from AND-009 as its `callFactory`,
so all timeouts, logging, and (later) interceptors/authenticator/cookie jar apply uniformly.

FR-4. JSON (de)serialization uses Moshi via `MoshiConverterFactory.create(moshi)`.

FR-5. Moshi is provided as an `@Singleton` and configured for **Kotlin codegen**: DTOs
annotated `@JsonClass(generateAdapter = true)` resolve to generated adapters; the
`KotlinJsonAdapterFactory` (reflection) is **not** added, so a missing codegen annotation
fails fast rather than silently falling back to reflection.

FR-6. A reusable factory exists to create typed service interfaces, e.g. a
`fun <T> create(service: Class<T>): T` helper or direct `retrofit.create(...)` usage from a
Hilt provider.

FR-7. A **sample** typed endpoint (`SampleApi`) and matching DTO exist for verification only,
modeling `GET /ui/me`'s envelope shape closely enough to prove codegen + Retrofit wiring. It is
clearly marked as sample/seed and lives in test or in a clearly-named demo file that downstream
real endpoints will replace.

FR-8. Suspend functions are first-class: Retrofit must support `suspend fun ...(): T` service
methods (Retrofit 2.6+ native coroutine support; no `Call` adapters required for the happy path).

## 4. Technical Design

All production code lands in `core-network/src/main/kotlin/com/testlogon/android/core/network/`.

### 4.1 Hilt module

```kotlin
package com.testlogon.android.core.network.di

import com.squareup.moshi.Moshi
import com.testlogon.android.core.network.BuildConfig
import dagger.Module
import dagger.Provides
import dagger.hilt.InstallIn
import dagger.hilt.components.SingletonComponent
import okhttp3.OkHttpClient
import retrofit2.Retrofit
import retrofit2.converter.moshi.MoshiConverterFactory
import javax.inject.Singleton

@Module
@InstallIn(SingletonComponent::class)
object NetworkModule {

    @Provides
    @Singleton
    fun provideMoshi(): Moshi =
        Moshi.Builder()
            // Codegen only — intentionally NO KotlinJsonAdapterFactory.
            // Custom adapters (e.g. Instant) are added by downstream tickets.
            .build()

    @Provides
    @Singleton
    fun provideMoshiConverterFactory(moshi: Moshi): MoshiConverterFactory =
        MoshiConverterFactory.create(moshi)

    @Provides
    @Singleton
    @BaseUrl
    fun provideBaseUrl(): String = normalizeBaseUrl(BuildConfig.API_BASE_URL)

    @Provides
    @Singleton
    fun provideRetrofit(
        client: OkHttpClient,                 // from AND-009 NetworkClientModule
        converterFactory: MoshiConverterFactory,
        @BaseUrl baseUrl: String,
    ): Retrofit =
        Retrofit.Builder()
            .baseUrl(baseUrl)
            .callFactory(client)              // share the singleton client lazily
            .addConverterFactory(converterFactory)
            .build()
}
```

```kotlin
package com.testlogon.android.core.network.di

import javax.inject.Qualifier

@Qualifier
@Retention(AnnotationRetention.BINARY)
annotation class BaseUrl
```

Notes:
- `callFactory(client)` is preferred over `client(client)` only insofar as both share the same
  instance; we use `.client(client)` semantics — either is acceptable as long as the singleton
  is reused. The point is **no new `OkHttpClient`**.
- `@BaseUrl` qualifier isolates the URL string so AND-014 can later swap the provider (or layer
  a host-selection interceptor on the OkHttp side) with minimal churn.

### 4.2 Base URL normalization

```kotlin
package com.testlogon.android.core.network

/** Retrofit requires the base URL to end in '/'. Idempotent. */
internal fun normalizeBaseUrl(raw: String): String =
    if (raw.endsWith("/")) raw else "$raw/"
```

`BuildConfig.API_BASE_URL` for `dev` is `http://18.222.237.167:8000` (no trailing slash);
normalization yields `http://18.222.237.167:8000/`. Service paths are declared **without** a
leading slash (`@GET("ui/me")`) so they append to the full base path.

### 4.3 Service factory provider

Real feature services are provided in their own modules; the canonical pattern:

```kotlin
@Provides
@Singleton
fun provideSampleApi(retrofit: Retrofit): SampleApi = retrofit.create(SampleApi::class.java)
```

### 4.4 Sample endpoint (verification seed)

```kotlin
package com.testlogon.android.core.network.sample

import com.squareup.moshi.JsonClass
import retrofit2.http.GET

interface SampleApi {
    @GET("ui/me")
    suspend fun me(): MeDto
}

@JsonClass(generateAdapter = true)
data class MeDto(
    val username: String,
    val roles: List<String> = emptyList(),
    val mfaEnrolled: Boolean = false,
)
```

`MeDto` mirrors the relevant `GET /ui/me` fields from the web reference; it is a seed that real
auth DTOs (in the auth feature) will supersede. It exists so the round-trip test has a concrete,
representative target rather than a contrived type.

### 4.5 Gradle wiring (`core-network/build.gradle.kts`)

```kotlin
plugins {
    alias(libs.plugins.android.library)
    alias(libs.plugins.kotlin.android)
    alias(libs.plugins.ksp)
    alias(libs.plugins.hilt)
}

android {
    namespace = "com.testlogon.android.core.network"
    buildFeatures { buildConfig = true } // exposes API_BASE_URL inherited per flavor
}

dependencies {
    implementation(project(":core-model"))
    implementation(platform(libs.okhttp.bom))
    implementation(libs.okhttp)
    implementation(libs.retrofit)                 // 2.11.0
    implementation(libs.retrofit.converter.moshi) // 2.11.0
    implementation(libs.moshi)                    // 1.15.x
    ksp(libs.moshi.kotlin.codegen)                // 1.15.x — codegen, not reflection
    implementation(libs.hilt.android)
    ksp(libs.hilt.compiler)

    testImplementation(project(":core-testing"))
    testImplementation(libs.okhttp.mockwebserver)
    testImplementation(libs.junit)
    testImplementation(libs.kotlinx.coroutines.test)
}
```

Version-catalog entries (`gradle/libs.versions.toml`) for `retrofit`,
`retrofit-converter-moshi`, `moshi`, `moshi-kotlin-codegen`, and `okhttp-mockwebserver` are
added in this ticket if not already present.

## 5. API Contract

This ticket defines **no application endpoints**; it provides the transport that carries them.
The only contract exercised is the verification sample, modeled on the real:

`GET /ui/me`
Response `200`:

```json
{
  "username": "alice@example.com",
  "roles": ["user"],
  "mfaEnrolled": true
}
```

decodes to `MeDto(username="alice@example.com", roles=["user"], mfaEnrolled=true)` via the
generated Moshi adapter. Request bodies are exercised symmetrically in the round-trip test by
serializing a DTO and asserting the Moshi-produced JSON.

Real endpoint contracts (session start/finalize/refresh, MFA, error `detail` shapes) are owned
by the auth feature tickets and **AND-015** (error model). The FastAPI `detail` union
(`string | [{msg}] | {code,...}`) is explicitly out of scope here.

## 6. Data & State Management

`core-network`'s Retrofit/Moshi pair is **stateless** beyond singleton identity. No Room, no
DataStore, no cookies in this ticket.

- **Threading:** suspend service methods are dispatched by Retrofit's own executor; callers are
  expected to invoke from a coroutine on an injected IO dispatcher (provided elsewhere). This
  ticket does not impose a dispatcher.
- **Serialization config:** Moshi is built once; adapters are generated at compile time. Unknown
  JSON keys are ignored by default (Moshi skips), and absent fields fall back to Kotlin defaults
  (e.g. `roles = emptyList()`), which is the desired lenient behavior against an evolving backend.
- **Persistence:** none. Cookie persistence is AND-011; cache is Room per `core-data`.
- **State exposed to UI:** none. `StateFlow<UiState>` / `ApiResult<T>` wrapping happens in
  `core-data` repositories (AND-018) consuming these services.

## 7. Error Handling & Resilience

Within this ticket the responsibilities are narrow:

- **Deserialization failures** surface as `com.squareup.moshi.JsonDataException` /
  `JsonEncodingException` thrown from the converter; **HTTP non-2xx** surfaces as
  `retrofit2.HttpException`; **transport failures** as `java.io.IOException`
  (`SocketTimeoutException`, `UnknownHostException`). This ticket does **not** translate these —
  it ensures they propagate cleanly so AND-015 (`ApiError`) and AND-018 (`ApiResult`) can map
  them.
- **Timeouts / backoff:** owned by AND-009 (the shared client, ~20s timeouts). Bounded backoff
  retry for idempotent GETs and offline/stale UI states are repository/UI concerns, not
  transport setup.
- **Lenient parsing:** Moshi ignores unknown keys and applies defaults, preventing brittle
  failures when the unreliable dev backend adds fields. Strictness is intentionally not enabled.
- **Resilience seam:** because Retrofit is built on the shared `OkHttpClient`, the future
  401-refresh `Authenticator` (AND-013), CSRF interceptor (AND-012), and persistent cookie jar
  (AND-011) attach to that client and take effect for Retrofit calls without any change here.

## 8. Security & Privacy

- **No secrets** are introduced. No auth headers, tokens, or cookies are set in this ticket;
  cookie/CSRF handling belongs to AND-011/AND-012.
- **Cleartext HTTP:** the `dev` base URL is plaintext `http://18.222.237.167:8000`. Cleartext
  is permitted only for the `dev` flavor via the network-security-config / manifest
  `usesCleartextTraffic` scoping owned by AND-006; `staging`/`prod` must be HTTPS. This ticket
  asserts (via a test) that the resolved base URL for non-dev flavors uses `https`.
- **Logging:** request/response logging and header redaction (auth, `Cookie`, `Set-Cookie`,
  `X-CSRF-Token`) are configured on the OkHttp client in AND-009; Retrofit inherits it. No
  additional logging is added here.
- **No PII handling:** `MeDto` sample is test data; no real user data is persisted or logged.

## 9. Accessibility & i18n

Not applicable — this is a headless transport ticket with no UI surface, no user-facing strings,
and no rendered content. Accessibility and localization are owned by `core-ui` and the
`feature-*` screens. Any user-facing error strings derived from network failures are defined by
AND-015 (error mapping), which is responsible for their localization.

## 10. Telemetry & Logging

- **Debug HTTP logging** is inherited from AND-009's redacting `HttpLoggingInterceptor`
  (debug builds only). This ticket adds no new interceptor.
- **No analytics events** are emitted by the transport layer. Request-level telemetry (latency,
  failure counts) is a cross-cutting concern that, if added later, will be an interceptor on the
  shared client — not part of this setup.
- **Build-time signal:** KSP must report that Moshi adapters were generated for annotated DTOs;
  a build that produces zero generated adapters for an annotated class indicates misconfiguration.

## 11. Testing Strategy

All tests are JVM unit tests in `core-network/src/test/...` (no instrumentation needed).

**T-1 (acceptance) — Typed endpoint round-trips JSON via MockWebServer.**
```kotlin
@Test
fun sampleEndpoint_roundTripsJson() = runTest {
    val server = MockWebServer().apply {
        enqueue(MockResponse().setBody(
            """{"username":"alice@example.com","roles":["user"],"mfaEnrolled":true}"""
        ))
        start()
    }
    val moshi = Moshi.Builder().build()
    val retrofit = Retrofit.Builder()
        .baseUrl(server.url("/"))
        .addConverterFactory(MoshiConverterFactory.create(moshi))
        .build()
    val api = retrofit.create(SampleApi::class.java)

    val me = api.me()

    assertEquals("alice@example.com", me.username)
    assertEquals(listOf("user"), me.roles)
    assertTrue(me.mfaEnrolled)
    assertEquals("/ui/me", server.takeRequest().path)
    server.shutdown()
}
```

**T-2 — Serialization (request side) produces expected JSON.** Adapt the generated `MeDto`
adapter, serialize an instance, assert the JSON string — proves codegen adapter exists and is
used (not reflection).

**T-3 — Codegen, not reflection.** Assert that a DTO **without** `@JsonClass(generateAdapter
= true)` is not silently handled: a test that attempts to adapt an un-annotated Kotlin data
class against the production `provideMoshi()` Moshi expects an `IllegalArgumentException`
(no adapter found), confirming reflection fallback is absent.

**T-4 — Base URL normalization.** `normalizeBaseUrl("http://h:8000")` == `"http://h:8000/"`
and is idempotent for an already-slashed input.

**T-5 — Lenient parsing.** A response body with an extra unknown field and a missing optional
field decodes successfully with defaults applied (`roles == emptyList()`).

**T-6 — Hilt graph smoke test.** A `@HiltAndroidTest` (Robolectric or a minimal
`SingletonComponent` test harness from `core-testing`) injects `Retrofit` and `Moshi` and
asserts they are non-null singletons (same instance on repeated injection), and that the
injected Retrofit's base URL equals the normalized `BuildConfig.API_BASE_URL`.

**T-7 — Shared client.** Assert the provided Retrofit's call factory is the same
`OkHttpClient` instance produced by AND-009's module (verified via Hilt injection comparison),
guaranteeing no duplicate client.

Coverage target: the small surface (`NetworkModule`, `normalizeBaseUrl`, sample API) should be
≥90% line-covered.

## 12. Dependencies & Sequencing

**Hard upstream (must merge first):**
- **AND-006** — `BuildConfig.API_BASE_URL` must exist and resolve per flavor. Blocking.
- **AND-009** — the singleton `OkHttpClient` must be Hilt-provided. Blocking; Retrofit reuses it.

**Implicit upstream:** AND-003 (core module structure incl. `core-network`, `core-model`,
`core-testing`) and AND-004 (Hilt baseline / `@HiltAndroidApp`) must already be in place; both
are transitive prerequisites of AND-009.

**Downstream (this ticket blocks):**
- **AND-014** Host-selection interceptor — builds on the `@BaseUrl` seam / shared client.
- **AND-015** API error model & `detail` mapping — wraps `HttpException`/`JsonDataException`
  surfaced here.
- Feature API service modules and **AND-018** (`ApiResult<T>` in `core-model`) consume the
  Retrofit provided here.

**Sequencing within the ticket:** (1) add version-catalog + Gradle deps; (2) `provideMoshi`
+ codegen verified by a DTO; (3) `provideRetrofit` on the shared client; (4) sample API +
tests. No parallelizable subtasks of note.

## 13. Risks & Open Questions

- **R-1 Reflection fallback drift.** If a contributor later adds `KotlinJsonAdapterFactory`,
  missing `@JsonClass` annotations would silently work via reflection, defeating codegen
  guarantees and bloating runtime. Mitigation: T-3 guards against it; add a code-review note /
  Konsist rule if needed.
- **R-2 Base URL trailing-slash + leading-slash path mistakes.** A service using `@GET("/ui/me")`
  with an absolute path can drop the base path. Mitigation: convention (no leading slash),
  documented in `core-network` README (AND-007 owns READMEs), and T-1 asserts the resolved path.
- **R-3 Client duplication.** Building `Retrofit.Builder().build()` without passing the shared
  client creates a default `OkHttpClient`, bypassing timeouts/logging/cookies. Mitigation: T-7.
- **R-4 Moshi version / codegen-KSP compatibility.** Moshi 1.15 codegen must be wired via KSP
  (not kapt) under Kotlin 2.0.21. Mitigation: pin in catalog; CI build proves generation.
- **Q-1** Should a `Types`/custom adapter set (e.g. `Instant`/`OffsetDateTime` for backend
  timestamps) be added now or with the first real DTO that needs it? *Proposed:* defer to the
  first consuming feature ticket to avoid speculative config; the Moshi builder seam supports it.
- **Q-2** Does any endpoint return a non-JSON body (e.g. HLS playlist text) that needs a
  scalar/string converter alongside Moshi? *Proposed:* Media3 handles HLS directly (out of band);
  add a `ScalarsConverterFactory` only if an endpoint demands it (tracked when encountered).

## 14. Acceptance Criteria

- **AC-1 (backlog).** A sample typed Retrofit endpoint round-trips JSON in a unit test: a
  `suspend fun me(): MeDto` call against `MockWebServer` returns a correctly deserialized
  `MeDto`, and the outbound request path/method are asserted (T-1).
- **AC-2.** `Retrofit` and `Moshi` are provided as `@Singleton` via Hilt and injectable across
  the graph; repeated injection yields the same instances (T-6).
- **AC-3.** Retrofit's base URL equals `normalizeBaseUrl(BuildConfig.API_BASE_URL)` and ends
  with `/`; `dev` resolves to `http://18.222.237.167:8000/` (T-4, T-6).
- **AC-4.** Retrofit is built on the **shared** AND-009 `OkHttpClient`; no second client is
  constructed (T-7).
- **AC-5.** Moshi uses **Kotlin codegen**: annotated DTOs (de)serialize via generated adapters,
  and an un-annotated class is rejected (no reflection fallback) (T-2, T-3).
- **AC-6.** Unknown/missing JSON fields parse leniently with Kotlin defaults applied (T-5).
- **AC-7.** All listed unit tests pass in CI; module builds clean under AGP 8.7.3 / Gradle 8.9 /
  JDK 17 with KSP-generated Moshi adapters present.

## 15. Definition of Done

- `NetworkModule` (Retrofit, Moshi, `MoshiConverterFactory`, `@BaseUrl`), `normalizeBaseUrl`,
  and the `SampleApi`/`MeDto` seed are implemented in `core-network` under
  `com.testlogon.android.core.network`.
- Version-catalog entries and `core-network/build.gradle.kts` deps (Retrofit 2.11, Moshi 1.15
  codegen via KSP, MockWebServer test dep) are added; `buildFeatures.buildConfig = true`.
- Tests T-1 through T-7 are implemented and green in CI; coverage on the new surface ≥90%.
- No `KotlinJsonAdapterFactory` present; no duplicate `OkHttpClient` created.
- `./gradlew :core-network:assemble :core-network:testDebugUnitTest` passes locally and in CI
  with no new lint/detekt violations (AND-005 config).
- Code reviewed and merged to `android-port`; downstream tickets AND-014 and AND-015 are
  unblocked (the `@BaseUrl` seam and propagating exceptions are in place).
- A one-paragraph note in the `core-network` README (owned by AND-007) documents the
  no-leading-slash path convention and the codegen-only Moshi policy.
