# TestLogon — Native Android App

Native Kotlin/Jetpack Compose port of the TestLogon auth app. Multi-module Gradle project
driving the cookie-based session flow (login → MFA → finalize → `/ui/me`) against the FastAPI
backend.

## 1. Module map

```
:app            → application module: MainActivity, navigation, auth feature screens,
                  ViewModels (LoginViewModel, MfaViewModel), and the data.auth repository layer.
   │
   ├── :feature-* (folded into :app for M1 — feature.* packages live under :app)
   │
   └── :core-network → OkHttp/Retrofit, cookie jar, CSRF, retry, health, SettingsStore (base URL)
       :core-model   → ApiResult / ApiError / domain enums (pure Kotlin, no Android deps where possible)
       :core-data    → cross-cutting data utilities + auth telemetry (redacted logging)
       :core-ui      → Compose design system (theme, inputs, scaffold, state composables)
       :core-testing → shared test fakes, MockWebServer harness, dispatcher rules
```

Layering: `:app → :core-*`. Core modules never depend on `:app`.

## 2. Prerequisites

- **JDK 17** (Temurin recommended). `JAVA_HOME` must point at a 17 JDK.
- **Android SDK with API 35** (compileSdk/targetSdk 35, minSdk 24), build-tools, platform-tools.
- The Gradle wrapper pins **Gradle 8.9** — do not install Gradle globally; use `./gradlew`.
- An `ANDROID_HOME`/`ANDROID_SDK_ROOT` env var, or a `local.properties` with `sdk.dir`
  (untracked — see below). On first build Android Studio creates this for you.

`local.properties` (untracked) example:

```properties
sdk.dir=/Users/you/Library/Android/sdk
```

## 3. Build

```bash
cd android
./gradlew assembleDebug          # build the debug APK
# Windows:
gradlew.bat assembleDebug
```

The debug APK lands in `app/build/outputs/apk/debug/`.

## 4. Run on a device / emulator

```bash
# Headless CI / local emulator named "test35" (API 35) — see android/ci (AND-051):
emulator -avd test35 -no-window -no-audio -no-boot-anim &
./gradlew installDebug
adb shell am start -n com.testlogon.android/.MainActivity

# Or on a connected physical device with USB debugging enabled:
./gradlew installDebug
```

## 5. Testing

```bash
./gradlew testDebugUnitTest                 # all JVM unit tests across every module
./gradlew :app:testDebugUnitTest            # just the app module
./gradlew connectedDebugAndroidTest         # instrumented tests on a connected device/emulator
```

## 6. Base-URL switch (dev / staging / prod)

The backend base URL is a **compile-time default** exposed as `BuildConfig.API_BASE_URL`
(declared in both `:app` and `:core-network`). The default is the flaky plaintext dev host:

```
http://18.222.237.167:8000/
```

> **Note — product flavors are deferred.** This project intentionally does **not** use Gradle
> product flavors (`dev`/`staging`/`prod`) yet. Adding a flavor dimension would rename the build
> variants (`devDebug`, …) and break `assembleDebug`/`testDebugUnitTest` and the CI scripts.
> Instead, environment selection is a **runtime** concern handled by `SettingsStore`
> (`:core-network`), which seeds its default from `BuildConfig.API_BASE_URL` and supports an
> in-app override (Server URL settings screen). When real staging/prod hosts are provisioned,
> flavors can be introduced as a follow-up.

How to point the app at a different backend:

| Environment | URL                                   | How to select                                  |
|-------------|---------------------------------------|------------------------------------------------|
| dev         | `http://18.222.237.167:8000/`         | Default (compile-time `BuildConfig.API_BASE_URL`) |
| local mock  | `http://10.0.2.2:8000/` (emulator)    | Server URL settings screen (runtime override)  |
| staging     | (not yet provisioned — TODO)          | Runtime override once provisioned              |
| prod        | (not yet provisioned — TODO)          | Runtime override once provisioned              |

`10.0.2.2` is the host-loopback alias from inside the Android emulator. The runtime override is
persisted via `SettingsStore` and read by the OkHttp host-selection interceptor on every request.

> The dev host is **plaintext HTTP** and unreliable: requests can take ~20s and may drop. This is
> expected — do not file false bug reports for transient dev-host failures. Cleartext traffic to
> the dev host is permitted via the network-security config (owned by the networking layer).

## 7. Code quality (AND-005)

Formatting and static analysis are **separate** from the build (they do **not** run as part of
`assembleDebug`):

```bash
./gradlew spotlessCheck      # verify Kotlin formatting (ktlint via Spotless)
./gradlew spotlessApply      # auto-fix formatting in place (recommended pre-commit)
./gradlew detekt             # static analysis across all modules
./gradlew spotlessCheck detekt   # the full quality gate
```

Config locations:

- `.editorconfig` — shared ktlint/IDE rules.
- `config/detekt/detekt.yml` — detekt rules (lenient baseline for the current scaffold).
- `config/detekt/baseline.xml` — empty baseline; regenerate with `./gradlew detektBaseline`
  only when deliberately accepting pre-existing debt.
- `config/lint/lint.xml` — shared Android Lint severity map (placeholder; policy TBD).

detekt reports (HTML + SARIF) are written to each module's `build/reports/detekt/`.

## 8. CI

GitHub Actions workflow lives at `_github/workflows/android.yml` in this tree and **should be
moved to the repo-root `.github/workflows/android.yml`** (GitHub only discovers workflows at the
repo root). It runs, on push/PR to `android-port`:

1. **build-and-unit-test** — JDK 17 + Android SDK, `./gradlew assembleDebug testDebugUnitTest`.
2. **instrumented-tests** — `connectedDebugAndroidTest` on a headless API-34 emulator
   (`reactivecircus/android-emulator-runner`).

## 9. Troubleshooting

- **`SDK location not found`** — create `local.properties` with `sdk.dir=...` or set
  `ANDROID_HOME`.
- **Network errors against the dev host** — the dev backend is flaky/plaintext; retry, or point
  at a local mock via the Server URL settings screen (section 6).
- **Gradle version mismatch** — always use `./gradlew` (pins Gradle 8.9); do not run a globally
  installed `gradle`.
