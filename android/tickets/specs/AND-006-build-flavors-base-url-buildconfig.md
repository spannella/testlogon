---
id: AND-006
title: Build flavors & base-URL BuildConfig
milestone: M1 (Auth Foundation)
epic: E01 (Project scaffolding & build tooling)
priority: P0
size: S
status: reviewed
reviewed_on: 2026-06-06
depends_on:
  - AND-002
blocks:
  - AND-010
---

# AND-006 — Build flavors & base-URL BuildConfig

## 1. Overview & Goal

This ticket introduces a build-time mechanism that exposes the backend base URL to
application and library code as `BuildConfig.API_BASE_URL`, switched per
environment (`dev` / `staging` / `prod`). It exists so that the networking layer
(AND-009 OkHttp, AND-010 Retrofit) can read a single, type-checked, compile-time
constant for the Retrofit base URL instead of hard-coding the unreliable dev host
in source.

The concrete deliverable is a Gradle product-flavor dimension named `environment`
with three flavors — `dev`, `staging`, `prod` — each contributing a
`buildConfigField` of type `String` named `API_BASE_URL`. The `dev` flavor
resolves to `http://18.222.237.167:8000` (the plaintext, flaky dev backend). The
`staging` and `prod` flavors carry placeholder HTTPS URLs that are correct in
shape but explicitly marked as not-yet-provisioned (see §13 OQ-1). The `dev`
flavor is the default selected variant for local development and CI.

Success is verifiable and narrow: after this ticket, `BuildConfig.API_BASE_URL`
exists in the generated `BuildConfig` for every variant, resolves to the correct
host string per flavor, ends with a trailing `/` (so Retrofit's base-URL rules
behave predictably), and a JVM unit test asserts the constant for the
`dev` variant. This ticket does **not** create the OkHttp client, Retrofit
instance, or any network call — it only provisions the URL constant and the
flavor wiring those tickets consume.

Per the canonical project decision, the module namespace / `applicationId` base is
`com.testlogon.android` everywhere a package appears in this spec.

## 2. Context & References

**Backend.** The dev backend is `http://18.222.237.167:8000` — **plaintext HTTP**
and an unreliable dev host. This URL is the authoritative `dev` value for
`API_BASE_URL`. Because it is cleartext, consuming it at runtime forces a
network-security-config / cleartext-allowance decision; that decision is owned by
the networking ticket (AND-009), **not** here. AND-006 only encodes the string;
it adds no `usesCleartextTraffic` flag and no `networkSecurityConfig` (see §8).

**Web reference (`frontend/`).** The React/Vite web client selects its API base
via Vite env (`import.meta.env.VITE_API_BASE_URL`, consumed in
`src/api/client.ts`, with a duplicate copy in `src/api/endpoints/profile.ts`).
The Android port mirrors that "base URL is an environment-injected constant, not
a literal" pattern, using Gradle flavors + `BuildConfig` as the Android-idiomatic
equivalent. **Trailing-slash note (verified):** the web client does **not** rely
on a trailing slash — `client.ts` normalizes it away
(`API_BASE_URL = (...VITE_API_BASE_URL ?? "").toString().replace(/\/$/, "")`) and
re-inserts the separator in `withApiBase()`. Android's **trailing-`/` requirement
(§5/§6) is a Retrofit-specific contract**, not inherited from the web client; the
two differ deliberately and both are correct for their respective HTTP stacks. No
API endpoint paths are defined in this ticket.

**Related AND tickets.**
- **AND-002** (blocked-by): created the `:app` module, set `namespace`/
  `applicationId = com.testlogon.android`, and enabled `buildFeatures.buildConfig
  = true`. AND-006 extends that same `app/build.gradle.kts`.
- **AND-009** (OkHttp client + timeouts + logging): builds the `OkHttpClient`
  with ~20s timeouts and the redacting logging interceptor. Owns the cleartext /
  network-security-config decision for the dev host.
- **AND-010** (Retrofit + Moshi): **the primary consumer** — reads
  `BuildConfig.API_BASE_URL` for `Retrofit.Builder().baseUrl(...)`. AND-010
  lists AND-006 and AND-009 as dependencies. The trailing-slash contract in §5 /
  §6 exists for AND-010's benefit.
- **AND-007** (wrapper, .gitignore, README): the `android/README.md` documents
  the flavors and the flaky-host base-URL switch produced here. AND-006 supplies
  the facts; AND-007 writes the prose. Keep the two consistent.

**Build-server notes.** Builds run headless on Ubuntu with JDK 17 and Android SDK
35, AGP 8.7.3, Gradle 8.9 wrapper. Adding a flavor dimension multiplies the
variant matrix (3 flavors × 2 build types = 6 variants); CI selects the
`devDebug` variant explicitly to avoid building all six.

## 3. Functional Requirements

FR-1. A single product-flavor dimension named `environment` is declared in
`app/build.gradle.kts`.

FR-2. Three flavors exist on that dimension: `dev`, `staging`, `prod`.

FR-3. Each flavor declares `buildConfigField("String", "API_BASE_URL", "\"<url>\"")`
with the per-environment value:
- `dev` → `"http://18.222.237.167:8000/"`
- `staging` → `"https://staging.api.testlogon.example/"` (placeholder, see §13)
- `prod` → `"https://api.testlogon.example/"` (placeholder, see §13)

FR-4. `BuildConfig.API_BASE_URL` is generated for all six variants and is a
non-null `String`.

FR-5. The `dev` flavor is the default variant chosen when no flavor is specified
(via `flavorDimensions` ordering + a `getDefaultProductFlavors`/IDE default), so
local `./gradlew :app:assembleDebug` and CI resolve to `devDebug`.

FR-6. Each `API_BASE_URL` value ends with a trailing `/` so Retrofit's
`baseUrl()` (AND-010) composes relative paths correctly.

FR-7. `applicationId` differentiation per flavor is provided so multiple
environments can co-install: each non-prod flavor adds an `applicationIdSuffix`
(`.dev`, `.staging`; `prod` keeps the base id). Combined with AND-002's debug
`.debug` suffix, e.g. `devDebug` → `com.testlogon.android.dev.debug`.

FR-8. A human-readable `versionNameSuffix` per non-prod flavor (`-dev`,
`-staging`) marks installed builds (optional but recommended; see §13 OQ-2).

FR-9. No flavor introduces source-set divergence in this ticket: the
`src/dev`, `src/staging`, `src/prod` source sets are **not** created. The only
per-flavor difference is `buildConfigField` + id/version suffix. (Flavor-specific
resources/code are deferred to whatever ticket genuinely needs them.)

FR-10. `buildFeatures.buildConfig = true` remains set (inherited from AND-002);
this ticket confirms it, since `buildConfigField` requires it.

## 4. Technical Design

All changes are confined to `android/app/build.gradle.kts` plus one new JVM unit
test file. No manifest, no Kotlin source, no resources change.

### 4.1 `app/build.gradle.kts` — flavor block (additions)

Added inside the existing `android { }` block from AND-002:

```kotlin
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
        // No API_BASE_URL here: it is flavor-specific so that a missing
        // flavor selection fails loudly rather than silently using a default.
    }

    flavorDimensions += "environment"

    productFlavors {
        create("dev") {
            dimension = "environment"
            applicationIdSuffix = ".dev"
            versionNameSuffix = "-dev"
            buildConfigField(
                "String",
                "API_BASE_URL",
                "\"http://18.222.237.167:8000/\"",
            )
        }
        create("staging") {
            dimension = "environment"
            applicationIdSuffix = ".staging"
            versionNameSuffix = "-staging"
            buildConfigField(
                "String",
                "API_BASE_URL",
                "\"https://staging.api.testlogon.example/\"",
            )
        }
        create("prod") {
            dimension = "environment"
            // no suffix: prod keeps the canonical applicationId
            buildConfigField(
                "String",
                "API_BASE_URL",
                "\"https://api.testlogon.example/\"",
            )
        }
    }

    buildFeatures {
        compose = true
        buildConfig = true   // required for buildConfigField; confirmed from AND-002
    }
}
```

Notes:
- The third `buildConfigField` argument is the **literal Java/Kotlin source**
  emitted into `BuildConfig`. For a `String` it must include the surrounding
  escaped quotes (`"\"...\""`), otherwise the generated code is an unresolved
  symbol and the build fails. This is the most common authoring mistake (see
  §13 R-2).
- `flavorDimensions += "environment"` (single dimension) avoids a combinatorial
  blow-up. Build type (`debug`/`release`) is orthogonal and supplied by AGP.

### 4.2 Generated output

For the `devDebug` variant, AGP generates
`app/build/generated/source/buildConfig/dev/debug/com/testlogon/android/BuildConfig.java`
(path varies by AGP version) containing approximately:

```java
public final class BuildConfig {
  public static final boolean DEBUG = Boolean.parseBoolean("true");
  public static final String APPLICATION_ID = "com.testlogon.android.dev.debug";
  public static final String BUILD_TYPE = "debug";
  public static final String FLAVOR = "dev";
  public static final int VERSION_CODE = 1;
  public static final String VERSION_NAME = "0.1.0-dev";
  // Field from product flavor: dev
  public static final String API_BASE_URL = "http://18.222.237.167:8000/";
}
```

### 4.3 Consumption pattern (documented here, implemented in AND-010)

AND-010 will read the constant via a Hilt provider, e.g.:

```kotlin
// core-network (AND-010) — shown for context, NOT created in this ticket
@Provides
@BaseUrl
fun provideBaseUrl(): String = BuildConfig.API_BASE_URL

@Provides
fun provideRetrofit(client: OkHttpClient, moshi: Moshi, @BaseUrl baseUrl: String): Retrofit =
    Retrofit.Builder()
        .baseUrl(baseUrl)        // trailing slash guaranteed by AND-006
        .client(client)
        .addConverterFactory(MoshiConverterFactory.create(moshi))
        .build()
```

Because `core-network` is a library module, it generates **its own**
`BuildConfig` only if it also enables `buildConfig` and declares the field.
The cleaner pattern AND-010 should adopt is to read `:app`'s value and pass it
down via DI (a `@BaseUrl String`), or to re-declare the same `buildConfigField`
in `core-network`. The decision is AND-010's; AND-006 guarantees the `:app`
constant exists and is correct. This is called out in §13 OQ-3.

### 4.4 Variant filtering (optional, recommended)

To keep CI fast, AND-006 may add a variant filter so only intended variants are
configured. Optional, non-blocking:

```kotlin
androidComponents {
    beforeVariants { variant ->
        // Example: never produce a staging release locally/CI in M1.
        if (variant.flavorName == "staging" && variant.buildType == "release") {
            variant.enable = false
        }
    }
}
```

## 5. API Contract

No HTTP API surface is defined or called in this ticket. The "contract" AND-006
owns is the **build-config contract** consumed by AND-010:

| Field | Type | Guarantee |
|-------|------|-----------|
| `BuildConfig.API_BASE_URL` | `String` (non-null) | Present in every variant; absolute URL with scheme + host (+ port for dev); **ends with `/`**. |
| `BuildConfig.FLAVOR` | `String` | One of `dev`, `staging`, `prod`. |

The actual REST endpoints (`/ui/session/start`, `/ui/session/finalize`,
`/ui/me`, `/ui/mfa/*`, `/ui/session/refresh`, etc.) and their request/response
JSON shapes are defined and consumed by the auth/networking feature tickets
(AND-009 / AND-010 and the M1 auth tickets), not here. AND-006 only supplies the
scheme+authority prefix those paths are appended to.

## 6. Data & State Management

No runtime data, persistence, or in-memory state is introduced. The base URL is a
compile-time constant in `BuildConfig`, not a runtime-mutable preference.

A deliberate design note for downstream: AND-006 makes the base URL a **build
constant**, not a DataStore-backed runtime setting. If a later ticket needs an
in-app "override server URL" debug toggle (useful given the flaky dev host), that
runtime override belongs in a debug-settings ticket layered over DataStore, with
`BuildConfig.API_BASE_URL` as its default seed value. Such an override is
explicitly out of scope here (see §13 OQ-4). Room (cache) and DataStore (prefs)
are untouched by this ticket.

## 7. Error Handling & Resilience

There is no runtime error surface in this ticket. The relevant failure modes are
build-time:

- **Malformed `buildConfigField` literal** (missing escaped quotes) → Kotlin
  compile error in generated `BuildConfig`. Caught by `:app:assembleDevDebug`.
- **Missing trailing slash** on a URL value → not a build failure, but a latent
  defect for AND-010 (Retrofit will drop the last path segment of `baseUrl` when
  composing relative paths). Guarded by the unit test in §11 asserting the value
  ends with `/`.
- **`buildConfig` feature disabled** → `buildConfigField` is silently ignored /
  `BuildConfig` lacks the field; the §11 test referencing `BuildConfig.API_BASE_URL`
  fails to compile, surfacing the problem.

The networking resilience the flaky dev host demands — ~20s timeouts, bounded
backoff retry for idempotent GETs, 401 → `POST /ui/session/refresh` → retry,
offline/stale UI states — is entirely owned by AND-009 and the auth tickets. The
*reason* that resilience is needed (the unreliable host) is exactly why the dev
URL is isolated as a switchable constant here.

## 8. Security & Privacy

No secrets, API keys, tokens, or credentials are introduced or committed. The
base URLs are non-sensitive host strings already known across the codebase and
the web client.

**Cleartext.** The `dev` value is plaintext HTTP. AND-006 adds **no**
`android:usesCleartextTraffic="true"` and **no** `networkSecurityConfig` — that
secure-by-default posture (and the scoped, debug-only cleartext allowance for
`18.222.237.167`) is owned by AND-009. Encoding the cleartext URL in a flavor
field does **not** by itself permit cleartext traffic at runtime; the connection
will still be blocked until AND-009's network-security-config explicitly allows
that host. This separation is intentional: it prevents a future "fix" that flips
a global cleartext flag.

Because `API_BASE_URL` is compiled into `BuildConfig`, the staging/prod hosts are
trivially extractable from the APK. That is acceptable (hostnames are not
secrets), but it is the reason no token/secret is ever placed in a
`buildConfigField`.

## 9. Accessibility & i18n

Not applicable. This ticket introduces no user-visible UI, strings, or
interactive elements — only Gradle configuration and a unit test. The
`versionNameSuffix` (`-dev`, `-staging`) may appear in system Settings → Apps,
but it is a build identifier, not a localizable product string, and is intentionally
not translated.

## 10. Telemetry & Logging

No analytics/telemetry SDK is added. A single optional, `BuildConfig.DEBUG`-gated
log line confirming the active environment is acceptable and recommended at app
start (the `TestLogonApp.onCreate` site from AND-002):

```kotlin
if (BuildConfig.DEBUG) {
    Log.d("TestLogonApp", "env=${BuildConfig.FLAVOR} baseUrl=${BuildConfig.API_BASE_URL}")
}
```

The base URL is not PII and is safe to log in debug. No logging occurs in release
builds (guarded). Note: this log line is optional polish; the AND-002 spec froze
`TestLogonApp` shape, so adding this line is a minor, compatible edit and may be
deferred to AND-009 where the network layer logs its configuration.

## 11. Testing Strategy

**Build verification (primary acceptance).**
```
cd android
./gradlew :app:assembleDevDebug
./gradlew :app:assembleStagingDebug
./gradlew :app:assembleProdRelease
```
All must configure and assemble; the variant matrix resolves with no
"flavor must specify dimension" error.

**JVM unit test (the meaningful assertion).** Because `BuildConfig` is generated
per variant, a default-variant unit test asserts the `dev` value. New file
`app/src/test/java/com/testlogon/android/BuildConfigTest.kt`:

```kotlin
package com.testlogon.android

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class BuildConfigTest {

    @Test fun api_base_url_isPresent_andTrailingSlashed() {
        val url = BuildConfig.API_BASE_URL
        assertTrue("API_BASE_URL must not be blank", url.isNotBlank())
        assertTrue("API_BASE_URL must end with '/': $url", url.endsWith("/"))
    }

    @Test fun dev_variant_pointsAtDevHost() {
        // Default unit-test variant is devDebug (dev is the default flavor).
        assertEquals("dev", BuildConfig.FLAVOR)
        assertEquals("http://18.222.237.167:8000/", BuildConfig.API_BASE_URL)
    }
}
```

Run with `./gradlew :app:testDevDebugUnitTest`. The second test is variant-coupled
and is correct only for the `dev` flavor; if CI ever runs `testProdDebugUnitTest`,
the `FLAVOR`/host asserts must be guarded or the test scoped to the `dev`
source set (`app/src/testDev/...`). Default CI runs `testDevDebugUnitTest`, so the
flat placement is acceptable for M1 (see §13 R-3).

**Sanity check via printout (optional).** A throwaway Gradle/adb check:
```
./gradlew :app:assembleDevDebug
adb shell am start -n com.testlogon.android.dev.debug/com.testlogon.android.MainActivity
```
confirms the suffixed `applicationId` installs and launches (regression guard on
FR-7).

**Lint.** `./gradlew :app:lintDevDebug` clean (no new warnings introduced by the
flavor block).

## 12. Dependencies & Sequencing

**Blocked by:** **AND-002** — the `:app` module, its `android {}` block,
`namespace`/`applicationId = com.testlogon.android`, and
`buildFeatures.buildConfig = true` must exist before flavors can be added.

**Blocks:** **AND-010** (Retrofit + Moshi) — explicitly depends on AND-006 for
`BuildConfig.API_BASE_URL` as the Retrofit base URL. AND-010 also depends on
AND-009 (OkHttp). AND-006 and AND-009 are independent of each other and may
proceed in parallel; AND-010 needs both.

**Relates to:** **AND-007** (README) — documents the flavors and the flaky-host
base-URL switch produced here; keep the README's flavor table consistent with
this spec's values. **AND-009** owns the cleartext / network-security-config
allowance that makes the `dev` URL actually reachable at runtime.

Recommended order: AND-002 → **AND-006** (parallel with AND-009) → AND-010.

## 13. Risks & Open Questions

R-1. **Variant matrix growth.** 3 flavors × 2 build types = 6 variants slows
configuration and CI if all are built. Mitigation: CI builds only `devDebug`
(and later the specific release variant needed); optional `beforeVariants` filter
(§4.4) disables unused combinations.

R-2. **`buildConfigField` quoting.** The value argument is raw generated source;
a `String` needs escaped quotes (`"\"...\""`). Omitting them yields an unresolved
symbol and a confusing build error. Mitigation: the §11 test compiles against the
field, and `assembleDevDebug` is in acceptance.

R-3. **Variant-coupled unit test.** `dev_variant_pointsAtDevHost` only passes for
the `dev` flavor. Mitigation: CI runs `testDevDebugUnitTest`; if multi-flavor unit
testing is added later, move flavor-specific asserts into `src/testDev/`.

R-4. **`core-network` BuildConfig vs `:app` BuildConfig.** A library module has
its own `BuildConfig`; the field defined on `:app` is not automatically visible to
`core-network`. Mitigation: AND-010 either passes the value down via DI
(`@BaseUrl String`) or re-declares the field. AND-006 guarantees only the `:app`
value.

Open questions:
- OQ-1: **Real staging/prod hosts.** `staging`/`prod` use placeholder HTTPS URLs
  (`*.testlogon.example`). Confirm the actual provisioned hostnames before any
  staging/prod build ships. (Default: placeholders, flagged as TODO in README.)
- OQ-2: **`versionNameSuffix`.** Append `-dev`/`-staging` to `versionName`?
  (Default: yes — makes installed env obvious in Settings.)
- OQ-3: **Single source of truth.** Should `core-network` re-declare
  `API_BASE_URL` or consume `:app`'s via DI? (Default: DI — decided in AND-010.)
- OQ-4: **Runtime URL override.** Add a debug-only in-app server-URL override
  (DataStore-backed) given the flaky dev host? (Default: out of scope; revisit in
  a debug-settings ticket.)

## 14. Acceptance Criteria

- [ ] `app/build.gradle.kts` declares `flavorDimensions += "environment"` and
      three `productFlavors`: `dev`, `staging`, `prod`, each with
      `dimension = "environment"`.
- [ ] Each flavor declares `buildConfigField("String", "API_BASE_URL", ...)`;
      `dev` → `"http://18.222.237.167:8000/"`, `staging` → its HTTPS placeholder,
      `prod` → its HTTPS placeholder.
- [ ] `BuildConfig.API_BASE_URL` resolves per flavor; the default selected
      variant is `dev` and points at the dev host
      (`http://18.222.237.167:8000/`).
- [ ] Every `API_BASE_URL` value ends with a trailing `/`.
- [ ] `buildFeatures.buildConfig = true` is set; `BuildConfig.API_BASE_URL`
      generates for all six variants and is non-null `String`.
- [ ] Non-prod flavors apply `applicationIdSuffix` (`.dev`, `.staging`) so
      `devDebug` → `com.testlogon.android.dev.debug`; `prod` keeps the base
      `applicationId`.
- [ ] `./gradlew :app:assembleDevDebug`, `:app:assembleStagingDebug`, and
      `:app:assembleProdRelease` configure and assemble without flavor-dimension
      errors.
- [ ] `app/src/test/java/com/testlogon/android/BuildConfigTest.kt` exists and
      `./gradlew :app:testDevDebugUnitTest` passes (asserts presence, trailing
      slash, `dev` flavor → dev host).
- [ ] No `usesCleartextTraffic`, no `networkSecurityConfig`, no secrets, and no
      per-flavor source sets are added in this ticket.
- [ ] `:app:lintDevDebug` introduces no new warnings.

## 15. Definition of Done

- All §14 acceptance criteria checked.
- Files changed: `android/app/build.gradle.kts` (flavor dimension + three flavors
  + confirmed `buildConfig` feature); new
  `android/app/src/test/java/com/testlogon/android/BuildConfigTest.kt`.
- `./gradlew :app:assembleDevDebug` and `:app:testDevDebugUnitTest` are green
  locally and on the Ubuntu build server; `staging`/`prod` variants assemble.
- Flavor values frozen and consistent with the AND-007 README table; staging/prod
  placeholder hosts flagged as TODO (OQ-1).
- AND-010 can read `BuildConfig.API_BASE_URL` (trailing-slash guarantee honored)
  with no further changes to `:app`.
- Changes committed on branch `android-port` (no merge to default), PR opened
  referencing AND-006, CI (`assembleDevDebug` + `testDevDebugUnitTest`) green,
  reviewed and approved.

## 16. Citations & Assumption Audit

This ticket is a build-config ticket: it provisions `BuildConfig.API_BASE_URL`
and Gradle flavors. It defines **no HTTP API surface**. The auditable claims are
therefore (a) the web-client base-URL pattern it mirrors, (b) the few REST paths
it name-drops in §5 as "owned elsewhere", and (c) the Android/Gradle framework
mechanics. Each is checked below.

1. **Claim:** The web client selects its API base via Vite env
   `import.meta.env.VITE_API_BASE_URL`, consumed in `src/api/client.ts`.
   **VERDICT: Verified.**
   **SOURCE:** `src/api/client.ts:7`
   (`const API_BASE_URL = ((import.meta as any).env?.VITE_API_BASE_URL ?? "")...`).

2. **Claim (corrected):** The web client treats the base URL as
   environment-injected and the Android trailing-slash rule mirrors web behavior.
   **VERDICT: Corrected.** The web client explicitly **strips** any trailing
   slash (`.replace(/\/$/, "")`) and re-adds the path separator in
   `withApiBase()`; it does *not* require a trailing slash. Android's trailing-`/`
   requirement is a **Retrofit-specific** contract, not inherited from web. §2 was
   amended to state this distinction.
   **SOURCE:** `src/api/client.ts:7-14` (`withApiBase`); there is a duplicate
   `API_BASE_URL` normalizer in `src/api/endpoints/profile.ts:63-72`.

3. **Claim:** The trailing-slash matters because Retrofit's `baseUrl()` drops the
   last path segment of a non-`/`-terminated base when composing relative paths.
   **VERDICT: Verified (framework ref).**
   **SOURCE:** framework ref — Retrofit `Retrofit.Builder.baseUrl`
   (https://square.github.io/retrofit/2.x/retrofit/retrofit2/Retrofit.Builder.html#baseUrl-okhttp3.HttpUrl-).

4. **Claim:** `POST /ui/session/start` exists (§5).
   **VERDICT: Verified.**
   **SOURCE:** OpenAPI `POST /ui/session/start` | op=`ui_session_start_ui_session_start_post`
   | req=`UiSessionStartReq` | resp=`200:UiSessionStartResp;422:HTTPValidationError`.

5. **Claim:** `POST /ui/session/finalize` exists (§5).
   **VERDICT: Verified.**
   **SOURCE:** OpenAPI `POST /ui/session/finalize` | op=`ui_session_finalize_ui_session_finalize_post`
   | req=`UiSessionFinalizeReq` | resp=`200:;422:HTTPValidationError`.

6. **Claim:** `GET /ui/me` exists (§5).
   **VERDICT: Verified.**
   **SOURCE:** OpenAPI `GET /ui/me` | op=`ui_me_ui_me_get` | resp=`200:;422:HTTPValidationError`
   | params=`user_sub,X-SESSION-ID,X-IMPERSONATION-TOKEN`.

7. **Claim:** `POST /ui/session/refresh` exists, and a 401 → refresh → retry flow
   is the resilience pattern (§7).
   **VERDICT: Verified (path) / Unverified-assumption (the 401-retry flow).** The
   path exists; the OpenAPI entry shows `req=` (no body) and `resp=200:` (no typed
   schema). The "401 → refresh → retry" behavior is an Android networking design
   choice owned by AND-009/AND-010, not something this build-config ticket
   implements, and is not asserted by the OpenAPI index.
   **SOURCE:** OpenAPI `POST /ui/session/refresh` | op=`ui_session_refresh_ui_session_refresh_post`
   | req= | resp=`200:`.

8. **Claim:** `/ui/mfa/*` endpoints exist (§5).
   **VERDICT: Verified.**
   **SOURCE:** OpenAPI lines incl. `POST /ui/mfa/email/begin`,
   `POST /ui/mfa/sms/begin`, `POST /ui/mfa/totp/verify`,
   `POST /ui/mfa/recovery/{factor}` (op prefixes `ui_email_*`, `ui_sms_*`,
   `ui_totp_*`, `ui_recovery_*`).

9. **Claim:** The dev backend is `http://18.222.237.167:8000` (plaintext, flaky)
   and is the authoritative `dev` value.
   **VERDICT: Verified (against ticket) / Unverified-assumption (against
   reference repo).** The value comes from the AND-006 backlog ticket
   (`specs-src/AND-006.md` line 12), which is authoritative for this deployment
   detail. It does **not** appear anywhere in the frontend reference source or the
   OpenAPI spec (grep for `18.222.237.167` → no matches), so it cannot be
   cross-checked against those sources.
   **SOURCE:** `specs-src/AND-006.md:12`
   (`dev → http://18.222.237.167:8000`); reference repo: no match.

10. **Claim:** `staging`/`prod` hosts (`*.testlogon.example`) are placeholders.
    **VERDICT: Unverified-assumption (explicitly).** Marked as placeholders by the
    spec itself (§13 OQ-1). No provisioned staging/prod hostname exists in any
    source. Correctly flagged TODO.
    **SOURCE:** none available — author-declared placeholder (spec §3 / §13 OQ-1).

11. **Claim:** Gradle `buildConfigField("String", "API_BASE_URL", "\"...\"")`
    requires `buildFeatures.buildConfig = true` and the 3rd arg is literal emitted
    source (needing escaped quotes for a `String`).
    **VERDICT: Verified (framework ref).**
    **SOURCE:** framework ref — AGP `ProductFlavor.buildConfigField` /
    `buildFeatures { buildConfig = true }`
    (https://developer.android.com/build/gradle-tips#share-custom-fields-and-resource-values-with-your-app-code,
    https://developer.android.com/reference/tools/gradle-api/current/com/android/build/api/dsl/BuildFeatures).

12. **Claim:** A single flavor dimension yields 3 flavors × 2 build types = 6
    variants; the default unit-test variant is `devDebug` when `dev` is the first
    declared flavor.
    **VERDICT: Verified (framework ref).** Variant count is arithmetic from the
    flavor/build-type matrix; the default variant follows AGP's "first-declared
    flavor per dimension" rule.
    **SOURCE:** framework ref — Android build variants
    (https://developer.android.com/build/build-variants#product-flavors).

13. **Claim:** Cleartext (`http://`) traffic is blocked by default on Android and
    encoding the URL alone does not permit it; an allowance is owned by AND-009.
    **VERDICT: Verified (framework ref).** Cleartext is disallowed by default for
    `targetSdk ≥ 28` absent a network-security-config / `usesCleartextTraffic`.
    The cross-ticket ownership (AND-009) is an internal planning assumption.
    **SOURCE:** framework ref — Network security config / cleartext default
    (https://developer.android.com/training/articles/security-config).

### Corrections made

- **§2 (web-client trailing slash):** Corrected the implication that Android's
  trailing-`/` rule mirrors the web client. The web client *strips* the trailing
  slash (`client.ts:7`); the Android requirement is a Retrofit-specific contract.
  Added an explicit "Trailing-slash note (verified)" paragraph and corrected the
  reference path (`src/api/client.ts`, not `frontend/src/api/client.ts`; the repo
  layout under `reference/src/` has no `frontend/` prefix). Also noted the
  duplicate normalizer in `src/api/endpoints/profile.ts`.

All other concrete claims (§5 endpoint existence, Gradle/AGP mechanics, cleartext
default) were found accurate and required no inline change.

### Open assumptions

- **Dev host `18.222.237.167:8000`:** verifiable only against the source ticket,
  not against the OpenAPI spec or frontend source (no occurrence there). Treated
  as authoritative because it is a deployment fact owned by the backlog ticket.
- **`staging`/`prod` hostnames:** placeholders; no provisioned value exists in any
  source (spec §13 OQ-1). Must be confirmed before any staging/prod build ships.
- **401 → `/ui/session/refresh` → retry resilience flow (§7):** the path exists,
  but the retry behavior is a downstream networking design (AND-009/AND-010) and
  is not asserted by any authoritative source for this ticket.
- **Cross-ticket ownership boundaries** (AND-002 having set
  `buildConfig = true`/`applicationId`; AND-009 owning cleartext config; AND-010
  consuming the constant) are internal planning assumptions, not verifiable from
  the reference repo or OpenAPI.

## 17. Test Plan

Acceptance Criteria referenced below are the nine checkboxes in §14, numbered
AC-1..AC-9 top-to-bottom:
AC-1 flavor dimension + 3 flavors; AC-2 per-flavor `buildConfigField` values;
AC-3 default variant `dev` → dev host; AC-4 every value trailing-`/`;
AC-5 `buildConfig=true` + non-null `String` for all six variants;
AC-6 `applicationIdSuffix` (`.dev`/`.staging`, prod unsuffixed);
AC-7 `assembleDevDebug`/`assembleStagingDebug`/`assembleProdRelease` configure &
assemble; AC-8 `BuildConfigTest.kt` exists + `testDevDebugUnitTest` passes;
AC-9 no cleartext flag / no network-security-config / no secrets / no per-flavor
source sets; (plus the lint criterion, treated as AC-9's companion).

- **TC-AND-006-01** — Type: unit (JVM, `testDevDebugUnitTest`)
  - Preconditions: `dev` flavor declared; project configures.
  - Steps: Run `./gradlew :app:testDevDebugUnitTest` exercising
    `BuildConfigTest.dev_variant_pointsAtDevHost`.
  - Expected: `BuildConfig.FLAVOR == "dev"` and
    `BuildConfig.API_BASE_URL == "http://18.222.237.167:8000/"`.
  - Traces: AC-3, AC-8.

- **TC-AND-006-02** — Type: unit (JVM)
  - Preconditions: as above.
  - Steps: Run `BuildConfigTest.api_base_url_isPresent_andTrailingSlashed`.
  - Expected: `API_BASE_URL` is non-blank and `endsWith("/")` is true.
  - Traces: AC-4, AC-5, AC-8.

- **TC-AND-006-03** — Type: unit (JVM, parameterized/added)
  - Preconditions: staging & prod flavors declared. (May require a
    `testStagingDebugUnitTest` / `testProdReleaseUnitTest` run, since `BuildConfig`
    is variant-scoped.)
  - Steps: For `staging` run `testStagingDebugUnitTest`; for `prod` run
    `testProdReleaseUnitTest`; assert `API_BASE_URL` equals the declared HTTPS
    placeholder and ends with `/`, and `FLAVOR` matches.
  - Expected: staging → `https://staging.api.testlogon.example/`;
    prod → `https://api.testlogon.example/`; both trailing-slashed; non-null.
  - Traces: AC-2, AC-4, AC-5.

- **TC-AND-006-04** — Type: contract/MockWebServer (deferred-consumer smoke)
  - Preconditions: AND-010 Retrofit present OR a throwaway local
    `Retrofit.Builder().baseUrl(BuildConfig.API_BASE_URL)` in a test.
  - Steps: Build Retrofit with `BuildConfig.API_BASE_URL` (dev value) and a
    MockWebServer base; issue a request to a relative path `ui/me`; capture the
    recorded request path.
  - Expected: Resolved URL preserves the full host+port and appends `ui/me`
    (i.e. no dropped path segment) — proves the trailing-`/` guarantee is honored
    by Retrofit. (Validates the *purpose* of AC-4; the network call itself is
    AND-010's, this is the contract assertion AND-006 enables.)
  - Traces: AC-4.

- **TC-AND-006-05** — Type: integration (Gradle build)
  - Preconditions: clean checkout, JDK 17, SDK 35, AGP 8.7.3.
  - Steps: Run `./gradlew :app:assembleDevDebug :app:assembleStagingDebug
    :app:assembleProdRelease`.
  - Expected: All three configure and assemble with **no** "flavor must specify
    dimension" / unresolved-symbol error; APKs produced.
  - Traces: AC-1, AC-7.

- **TC-AND-006-06** — Type: integration (Gradle build, negative/error-shape)
  - Preconditions: temporarily remove the escaped quotes from the `dev`
    `buildConfigField` value (`"http://...:8000/"` → `http://...:8000/`).
  - Steps: Run `./gradlew :app:assembleDevDebug`.
  - Expected: Build **fails** with a Kotlin/Java compile error in generated
    `BuildConfig` (unresolved symbol). Restoring the quotes restores green.
    (Validates the §7/§13 R-2 build-time error mode.)
  - Traces: AC-2, AC-7.

- **TC-AND-006-07** — Type: integration (Gradle config, negative)
  - Preconditions: temporarily set `buildFeatures.buildConfig = false`.
  - Steps: Run `./gradlew :app:testDevDebugUnitTest`.
  - Expected: Compilation fails because `BuildConfig.API_BASE_URL` does not exist
    (test references a missing field). Restoring `buildConfig = true` restores
    green. (Validates AC-5 dependency on the feature flag.)
  - Traces: AC-5, AC-8.

- **TC-AND-006-08** — Type: instrumented/e2e (applicationId co-install)
  - Preconditions: device/emulator; `assembleDevDebug` + `assembleStagingDebug`
    built.
  - Steps: `adb install` the devDebug APK, then the stagingDebug APK; query
    `adb shell pm list packages | grep testlogon`; launch
    `com.testlogon.android.dev.debug/.MainActivity`.
  - Expected: Both packages co-exist —
    `com.testlogon.android.dev.debug` and `com.testlogon.android.staging.debug`
    installed simultaneously without uninstall conflict; dev launches.
  - Traces: AC-6.

- **TC-AND-006-09** — Type: manual (prod applicationId unsuffixed)
  - Preconditions: `assembleProdRelease` built (or `prodDebug`).
  - Steps: Inspect the generated `BuildConfig`/merged manifest `APPLICATION_ID`
    for a prod variant.
  - Expected: prod `applicationId` is exactly `com.testlogon.android` (no
    `.prod`); only the AND-002 build-type suffix (`.debug`) may apply for
    prodDebug, never a flavor suffix.
  - Traces: AC-6.

- **TC-AND-006-10** — Type: security/permission (no cleartext flag, no secrets)
  - Preconditions: branch diff for AND-006 available; `devDebug` APK built.
  - Steps: (a) Grep the diff + merged manifest for `usesCleartextTraffic` and
    `networkSecurityConfig`; (b) grep flavor block / `BuildConfig` for any
    token/key/secret; (c) confirm no `src/dev`, `src/staging`, `src/prod` source
    sets were created.
  - Expected: No `usesCleartextTraffic`, no `networkSecurityConfig`, no secret in
    any `buildConfigField`, no per-flavor source set. Cleartext to the dev host
    remains *blocked at runtime* (owned by AND-009).
  - Traces: AC-9.

- **TC-AND-006-11** — Type: integration (lint)
  - Preconditions: project configures.
  - Steps: Run `./gradlew :app:lintDevDebug`.
  - Expected: Completes with **no new** warnings attributable to the flavor block.
  - Traces: AC-9 (lint companion criterion).

- **TC-AND-006-12** — Type: contract (flaky-dev-host isolation, design assertion)
  - Preconditions: dev flavor built.
  - Steps: Confirm the dev host string exists **only** as a `buildConfigField`
    value and is not hard-coded in any Kotlin source (grep source tree for
    `18.222.237.167`).
  - Expected: The flaky/plaintext dev host is isolated to the switchable
    `BuildConfig` constant — switching flavors (or a future runtime override per
    §6) requires no source edit. (Validates the §1/§7 isolation rationale for the
    unreliable/offline-prone host.)
  - Traces: AC-2, AC-3.

### Coverage matrix

| Acceptance criterion (§14) | Covered by |
|---|---|
| AC-1 flavor dimension + 3 flavors | TC-05 |
| AC-2 per-flavor `buildConfigField` values | TC-03, TC-06, TC-12 |
| AC-3 default variant `dev` → dev host | TC-01, TC-12 |
| AC-4 every value trailing-`/` | TC-02, TC-03, TC-04 |
| AC-5 `buildConfig=true` + non-null `String`, all variants | TC-02, TC-03, TC-07 |
| AC-6 `applicationIdSuffix` (prod unsuffixed) | TC-08, TC-09 |
| AC-7 three assemble tasks succeed | TC-05, TC-06 |
| AC-8 `BuildConfigTest.kt` exists + `testDevDebugUnitTest` passes | TC-01, TC-02, TC-07 |
| AC-9 no cleartext/nsc/secrets/source-sets (+ lint) | TC-10, TC-11 |
