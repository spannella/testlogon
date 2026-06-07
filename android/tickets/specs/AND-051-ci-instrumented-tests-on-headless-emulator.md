---
id: AND-051
title: "CI: instrumented tests on headless emulator"
milestone: M1
epic: E07
priority: P1
size: M
status: reviewed
reviewed_on: 2026-06-06
depends_on: [AND-008, AND-048]
blocks: []
---

# AND-051 — CI: instrumented tests on headless emulator

## 1. Overview & Goal

This ticket extends the existing continuous-integration pipeline (delivered by AND-008, which runs `assembleDebug` + `testDebugUnitTest` on the `andrioiddev` build server) so that **instrumented / connected Android tests** also run automatically on every relevant push. Today the pipeline only exercises JVM-only unit tests; the Compose UI tests authored under AND-048 and any future `androidTest` sources can only be verified on a developer workstation with a physical device or a manually-started emulator. That gap means regressions in navigation, Compose rendering, Hilt wiring, Room migrations, and cookie-based session flows are not caught before merge.

The goal is to make `./gradlew connectedDebugAndroidTest` run **reliably and headlessly** on the build server against a hardware-accelerated (KVM) Android emulator, gating the `android-port` branch and pull requests. "Headless" means no display server, no human interaction, and a clean cold-boot or snapshot-restored emulator each run, with deterministic teardown so a crashed emulator never wedges the build agent.

Concretely, this ticket delivers: (a) a reproducible AVD named `test35` (API 35, the project `targetSdk`), (b) a CI job/stage that boots that AVD headless, waits for full boot, runs the connected test task, collects results and logcat, and tears the emulator down, and (c) the build-server provisioning notes (KVM, SDK packages, `cmdline-tools`) required for it. Out of scope: authoring new tests (owned by AND-048 and later `androidTest` tickets), publishing artifacts, and release signing.

## 2. Context & References

- **Repo / location:** `spannella/testlogon`, monorepo; Android app under `android/`, branch `android-port`. CI scripts live under `android/ci/` and (if the build server is GitHub-Actions-backed) `.github/workflows/`.
- **Stack:** Kotlin 2.0.21, AGP 8.7.3, Gradle 8.9 wrapper, JDK 17, compileSdk/targetSdk 35, minSdk 24, Hilt (KSP), Jetpack Compose + Material 3, Room 2.6, DataStore.
- **Upstream dependencies:**
  - **AND-008** — established the CI pipeline (`assembleDebug`, `testDebugUnitTest`, Gradle caching) on `andrioiddev`. This ticket adds a stage to that same pipeline and reuses its Gradle cache, JDK, and SDK setup.
  - **AND-048** — Compose UI tests for login (`feature-auth` `androidTest`). These are the first instrumented tests this job must execute and pass headlessly.
- **Test infra:** AndroidX Test (`androidx.test:runner`, `androidx.test:core`), Compose UI test (`androidx.compose.ui:ui-test-junit4`), `androidx.test.ext:junit`, Espresso, Hilt testing (`com.google.dagger:hilt-android-testing`), and the shared `core-testing` module. The instrumentation runner is the Hilt custom runner (see §4).
- **Tooling references:** Android Emulator (`emulator`), `avdmanager`, `sdkmanager` from `cmdline-tools/latest`, `adb`, and the `system-images;android-35;google_apis;x86_64` package. KVM (`/dev/kvm`) must be present and writable by the CI user on the `andrioiddev` host.

## 3. Functional Requirements

1. **FR-1 — AVD provisioning.** The job MUST create (if absent) a deterministic AVD named `test35`: API 35, `google_apis` x86_64 system image, a fixed device profile (`pixel_6`), 2048 MB RAM, 2048 MB internal storage, fixed density. AVD creation MUST be idempotent (skip if `test35` already exists with the correct image).
2. **FR-2 — Headless boot.** The emulator MUST boot with `-no-window -no-audio -no-boot-anim -gpu swiftshader_indirect` (or `host` where a GPU is available) and `-no-snapshot-save`, with KVM acceleration. The job MUST block until `sys.boot_completed == 1` and the package manager is ready before launching tests.
3. **FR-3 — Run connected tests.** The job MUST run `./gradlew connectedDebugAndroidTest` (Gradle-managed install + instrumentation) against the booted emulator and propagate the task exit code as the stage result.
4. **FR-4 — Result collection.** On success or failure, the job MUST collect: per-module `connected/` test HTML+XML reports, the merged JUnit XML, and `adb logcat` output. These MUST be published as build artifacts.
5. **FR-5 — Deterministic teardown.** The emulator MUST be killed (`adb emu kill`, then `adb kill-server`) in an `always()` / `finally` block so a failed test run never leaves a zombie emulator on the agent.
6. **FR-6 — Gating.** The stage MUST run on pushes to `android-port` and on PRs targeting it, and MUST fail the overall pipeline when instrumented tests fail or the emulator fails to boot within the timeout.
7. **FR-7 — Reproducibility.** A fresh checkout on a correctly-provisioned `andrioiddev` agent MUST produce the same green/red result with no manual steps (consistent with the AND-008 reproducibility bar).

## 4. Technical Design

This is a **CI/build chore**; the "design" is the AVD definition, the boot/teardown orchestration, and the Gradle wiring — not application Kotlin. There is, however, one required source artifact: the **Hilt instrumentation test runner**, needed so AND-048's tests run under a Hilt-injected `Application`.

**Custom test runner** (`core-testing`, `src/main` so all `androidTest` configs share it):

```kotlin
package com.testlogon.android.core.testing

import android.app.Application
import android.content.Context
import androidx.test.runner.AndroidJUnitRunner
import dagger.hilt.android.testing.HiltTestApplication

class HiltTestRunner : AndroidJUnitRunner() {
    override fun newApplication(
        cl: ClassLoader?, className: String?, context: Context?,
    ): Application = super.newApplication(cl, HiltTestApplication::class.java.name, context)
}
```

Each module's `defaultConfig` sets `testInstrumentationRunner = "com.testlogon.android.core.testing.HiltTestRunner"`.

**Emulator orchestration** is owned by a script (`android/ci/run-instrumented.sh`) so it is identical whether invoked by GitHub Actions, Jenkins, or directly on `andrioiddev`:

```bash
#!/usr/bin/env bash
set -euo pipefail
SDK="${ANDROID_SDK_ROOT:?}"; AVD=test35; PORT=5554
IMAGE="system-images;android-35;google_apis;x86_64"

"$SDK/cmdline-tools/latest/bin/sdkmanager" --install "$IMAGE" "platform-tools" "emulator"
if ! "$SDK/cmdline-tools/latest/bin/avdmanager" list avd | grep -q "Name: $AVD"; then
  echo "no" | "$SDK/cmdline-tools/latest/bin/avdmanager" create avd \
    -n "$AVD" -k "$IMAGE" -d pixel_6 --force
fi

"$SDK/emulator/emulator" -avd "$AVD" -port "$PORT" \
  -no-window -no-audio -no-boot-anim -no-snapshot-save \
  -gpu swiftshader_indirect -accel on -read-only &
EMU_PID=$!
trap '"$SDK/platform-tools/adb" -s emulator-$PORT emu kill || true; \
      kill $EMU_PID 2>/dev/null || true' EXIT

ADB="$SDK/platform-tools/adb"
"$ADB" wait-for-device
timeout 600 bash -c 'until [ "$('"$ADB"' -s emulator-'"$PORT"' shell getprop sys.boot_completed | tr -d "\r")" = 1 ]; do sleep 3; done'
"$ADB" -s emulator-$PORT shell input keyevent 82 || true

./gradlew --no-daemon connectedDebugAndroidTest
```

On a GitHub-Actions-backed `andrioiddev`, the preferred alternative is **Gradle Managed Devices (GMD)** plus `reactivecircus/android-emulator-runner`, but the script above is the canonical fallback and the source of truth for boot flags and timeouts; either path MUST honor the same AVD name, image, flags, and 600 s boot timeout.

**GMD option (build.gradle, optional fast path):**

```kotlin
android {
    testOptions {
        managedDevices.devices {
            create<com.android.build.api.dsl.ManagedVirtualDevice>("test35") {
                device = "Pixel 6"; apiLevel = 35; systemImageSource = "google_apis"
            }
        }
    }
}
```

When GMD is used the task becomes `./gradlew test35DebugAndroidTest`; the CI stage selects one path via a `CI_EMULATOR_MODE` variable (`gmd` | `manual`) defaulting to `manual` to keep emulator lifecycle explicit.

**Pipeline placement:** the stage runs after `assembleDebug`/`testDebugUnitTest` (AND-008) so unit failures fail fast and cheaply before the slower emulator stage starts.

## 5. API Contract

N/A for application/network APIs. This ticket touches no FastAPI endpoint (`/ui/session/start`, `/ui/me`, etc.); those are owned by feature/data tickets (e.g. AND-031 auth, AND-046 login screen). The instrumented tests *executed* by this job may exercise mocked or live backend calls, but their network contracts are owned by AND-048 and downstream feature tickets. The only "contracts" relevant here are tool CLIs: `emulator`, `adb`, `avdmanager`, `sdkmanager`, and the Gradle `connectedDebugAndroidTest` / `test35DebugAndroidTest` task interface.

## 6. Data & State Management

No application data, Room schema, or DataStore involvement. The relevant state is **CI/agent state**:

- **AVD state** lives at `$ANDROID_AVD_HOME/test35.avd` (or `~/.android/avd/`). Boot uses `-read-only` so concurrent jobs cannot corrupt the snapshot; `-no-snapshot-save` guarantees a clean image next run.
- **Emulator runtime state** (cold-booted each run) is ephemeral; the job MUST NOT depend on prior install or login state. Room/DataStore created by the app-under-test are wiped with the emulator.
- **Gradle build cache / `~/.gradle`** is shared with the AND-008 stage and keyed identically so dependency resolution is reused; the emulator system image is cached at the SDK level on the agent (not in the Gradle cache).
- **Port allocation:** fixed `emulator-5554` for the single-emulator default; if matrix/sharding is added later, ports MUST be derived from the shard index.

## 7. Error Handling & Resilience

- **Boot timeout (FR-2/FR-6):** if `sys.boot_completed` is not reached within **600 s**, the job kills the emulator and fails the stage with a distinct message (`EMULATOR_BOOT_TIMEOUT`) so flakiness is distinguishable from genuine test failures in the build log.
- **KVM unavailable:** the job pre-flights `test -w /dev/kvm` (or `kvm-ok`); absence is a hard, fast failure with remediation text rather than a silent slow software-rendered run.
- **Flaky-emulator retry:** the *boot-and-run* sequence (not individual tests) MAY retry **once** on `EMULATOR_BOOT_TIMEOUT` or `INSTALL_FAILED`/`device offline` errors. Test *assertions* are never retried — a failing test fails the build.
- **Zombie cleanup (FR-5):** `trap ... EXIT` / `always()` kills the emulator and `adb` server; a pre-run cleanup step also kills any stale `emulator-5554` from a previously-crashed job before booting.
- **Disk/quota:** the job checks free space before boot (system image + AVD ≈ several GB) and fails clearly if insufficient.
- This mirrors the "unreliable dev host" posture of the wider project: bounded timeouts and bounded retries, no infinite waits.

## 8. Security & Privacy

- No production credentials. Tests against the dev backend (a plaintext-HTTP dev host; the exact base URL is configured per environment, not hard-coded — see §16 open assumption A-1) MUST use throwaway/dev test accounts only; no real user PII is entered. Test credentials, if any, come from CI secrets, never committed.
- The emulator runs in a CI sandbox; cookie jars / DataStore created during tests are destroyed with the ephemeral emulator and never exported as artifacts. Logcat artifacts (FR-4) MUST be scrubbed of any `Authorization` (Bearer token), `Cookie`/`Set-Cookie` (including the session cookie and the `ui_csrf` cookie), `X-CSRF-Token`, and `X-IMPERSONATION-TOKEN` values — these are the actual sensitive headers/cookies the web client transmits (verified against `src/api/client.ts`; see §16). The logging policy (no secret logging) is enforced by app code, and CI additionally treats logcat as potentially sensitive: artifacts are retained only on the private CI store, not on public PRs.
- KVM access requires the CI user be in the `kvm` group; document this as a deliberate, minimal privilege grant on `andrioiddev`.

## 9. Accessibility & i18n

N/A — no user-facing UI is produced by this ticket. Accessibility of the screens *under test* is owned by their feature tickets (e.g. AND-046/AND-048 login). Note for future: this headless instrumented harness is the correct place to later run Compose accessibility / TalkBack-semantics assertions, but adding such checks is out of scope here.

## 10. Telemetry & Logging

- **Build-log output:** the job logs emulator boot duration, the resolved AVD name/image, the Gradle task invoked, and total instrumented-test wall time.
- **Artifacts (FR-4):** per-module `build/reports/androidTests/connected/**` (HTML), `build/outputs/androidTest-results/connected/**/*.xml` (JUnit XML for CI test-result parsing), and a captured `logcat-test35.txt`. These are uploaded with a retention window matching the AND-008 unit-test reports.
- **Test result surfacing:** JUnit XML is consumed by the CI test reporter so individual instrumented test pass/fail and timing appear in the PR check summary.
- No application analytics/telemetry are introduced.

## 11. Testing Strategy

The deliverable *is* test infrastructure, so "testing" means verifying the harness itself:

1. **Smoke gate:** the AND-048 login UI suite is the canonical workload — a green `connectedDebugAndroidTest`/`test35DebugAndroidTest` run with those tests passing proves the harness end-to-end (boot → install → instrument → report → teardown).
2. **Trivial sentinel test:** add one always-pass `androidTest` (e.g. `EmulatorSmokeTest` asserting `InstrumentationRegistry.getInstrumentation().targetContext.packageName == "com.testlogon.android"`) in `core-testing` so the job can be validated even before/around feature tests exist.
3. **Negative verification:** temporarily introduce a deliberately-failing instrumented assertion locally and confirm the stage goes red and surfaces the failure in the JUnit report (do not commit).
4. **Teardown verification:** confirm no `emulator`/`qemu` process and no `emulator-5554` device remain after both a passing and a failing run (`adb devices` empty post-job).
5. **Reproducibility (FR-7):** run the full job twice on a fresh checkout of `android-port` and confirm identical results and no manual intervention.
6. **Boot-timeout path:** simulate by lowering the timeout once and confirm the `EMULATOR_BOOT_TIMEOUT` message and clean teardown.

## 12. Dependencies & Sequencing

- **Depends on AND-008** (P0): the base CI pipeline, Gradle caching, JDK 17, and SDK setup on `andrioiddev`. This ticket adds a stage to that pipeline rather than creating a parallel one.
- **Depends on AND-048** (P0): the first real instrumented suite the job must run green; the Hilt test runner (§4) and `core-testing` instrumentation deps may be introduced here or by AND-048 — coordinate to avoid duplication. If AND-048 already added `HiltTestRunner`, this ticket only wires the emulator/CI stage.
- **Blocks:** future instrumented-test tickets (additional `feature-*` `androidTest` suites, Room migration tests, navigation tests) rely on this job to gate them; they need no further CI work once this lands.
- **Sequencing:** land after AND-008 is green; integrate alongside or immediately after AND-048 so there is a real suite to validate the harness. The unit-test stage (AND-008) runs first in the pipeline; this connected stage runs second.

## 13. Risks & Open Questions

- **R-1 — KVM on `andrioiddev`:** if the build host is itself a VM, nested virtualization / `/dev/kvm` may be unavailable, forcing slow SwiftShader emulation. *Open question:* is `andrioiddev` bare-metal or nested-virt capable? If neither, evaluate a dedicated emulator agent or a cloud device farm (Firebase Test Lab / Gradle Managed Devices on a KVM runner).
- **R-2 — Emulator flakiness:** headless emulators are historically flaky (boot hangs, ANRs). Mitigated by the single boot-level retry (§7) and fixed timeouts; persistent flakiness may require snapshot pre-warming.
- **R-3 — Runtime cost:** cold boot + install + instrumentation can add several minutes per pipeline run. *Open question:* acceptable PR-feedback latency budget? Consider running connected tests only on `android-port` pushes (not every PR commit) if latency is unacceptable, but this weakens gating.
- **R-4 — System-image churn:** `system-images;android-35;google_apis;x86_64` revisions change; pin where the tooling allows and cache the image on the agent to keep runs reproducible (FR-7).
- **R-5 — GMD vs manual path drift:** maintaining both `manual` and `gmd` modes risks divergence; resolve by choosing one as canonical after R-1 is answered.

## 14. Acceptance Criteria

1. **AC-1 (maps to ticket AC + FR-1/2/3):** The instrumented suite runs on the KVM-accelerated `test35` emulator in CI headlessly — `./gradlew connectedDebugAndroidTest` (or `test35DebugAndroidTest`) executes against a booted `test35` AVD with no window and no manual steps.
2. **AC-2 (FR-3/FR-6):** The AND-048 login instrumented tests pass in the CI run, and the stage exit code reflects the test result (green when they pass, red when any instrumented test fails).
3. **AC-3 (FR-4/§10):** Connected-test HTML+XML reports and `logcat-test35.txt` are published as build artifacts and the JUnit results appear in the CI check summary.
4. **AC-4 (FR-5):** After every run (pass or fail), no emulator/`qemu` process and no `emulator-5554` device remain on the agent.
5. **AC-5 (FR-6):** The stage gates pushes to `android-port` and PRs targeting it; an instrumented failure or boot timeout fails the overall pipeline.
6. **AC-6 (FR-7):** A fresh checkout reproduces the same result on a correctly-provisioned agent with zero manual intervention.
7. **AC-7 (§7):** A failure to boot within 600 s produces the `EMULATOR_BOOT_TIMEOUT` failure and a clean teardown, distinguishable from test failures.

## 15. Definition of Done

- `android/ci/run-instrumented.sh` (and/or the GMD `managedDevices` block + workflow step) committed under branch `android-port`, wired into the AND-008 pipeline as a post-unit-test stage.
- `HiltTestRunner` present in `core-testing` and referenced by every `androidTest` `defaultConfig` via `testInstrumentationRunner`; instrumentation deps declared.
- `EmulatorSmokeTest` sentinel committed and passing in CI.
- CI run on `android-port` is green with AND-048's suite executing on `test35`; a deliberately-broken test demonstrably turns the stage red (verified, not committed).
- Artifacts (reports + scrubbed logcat) upload and JUnit results render in the check summary.
- Teardown leaves no zombie emulator (verified on both pass and fail).
- `andrioiddev` provisioning notes (KVM/`kvm` group, `cmdline-tools/latest`, `system-images;android-35;google_apis;x86_64`, free-disk requirement) documented in `android/ci/README.md`.
- Reproducible on a fresh checkout (AC-6); R-1 (KVM availability) confirmed or escalated.
- Code review approved; pipeline merged to `android-port`.

## 16. Citations & Assumption Audit

This is a CI/build-infrastructure ticket; it introduces **no** application network calls of its own (§5 correctly states N/A). The only backend-contract claims appear in §5 (endpoints the *tests under test* may hit) and §8 (the sensitive headers/cookies logcat must scrub). Those were verified against the authoritative sources below. Framework/tooling claims (emulator flags, Gradle tasks, Hilt runner, GMD) are verified against Android developer documentation and labelled "framework ref".

1. **Claim (§5):** The app's auth/session endpoints include `POST /ui/session/start` and `GET /ui/me`. — **VERDICT: Verified.** Source: OpenAPI `POST /ui/session/start` (op=`ui_session_start_ui_session_start_post`, req=`UiSessionStartReq`, resp=`200:UiSessionStartResp;422:HTTPValidationError`) and `GET /ui/me` (op=`ui_me_ui_me_get`, resp=`200;422:HTTPValidationError`, params=`user_sub,X-SESSION-ID,X-IMPERSONATION-TOKEN`) in `openapi.index.txt`.
2. **Claim (§5):** Session refresh exists as an endpoint the client uses. — **VERDICT: Verified.** Source: frontend `src/api/client.ts: refreshSession()` calls `POST /ui/session/refresh` with `credentials: "include"`.
3. **Claim (§8, original):** Sensitive values to scrub from logcat are `Authorization`, `Cookie`, `Set-Cookie`, `X-CSRF-Token`. — **VERDICT: Corrected (incomplete).** The web client also transmits `X-IMPERSONATION-TOKEN` and reads CSRF from a cookie named `ui_csrf`; the scrub list was expanded to cover them. Source: `src/api/client.ts` — `Authorization: Bearer ${accessToken}` (line ~159), `X-CSRF-Token` from `getCookie("ui_csrf")` (lines ~168-170), `X-IMPERSONATION-TOKEN` (line ~164), session cookie via `credentials: "include"` (line ~183).
4. **Claim (§8, original):** The dev backend base URL is `http://18.222.237.167:8000`. — **VERDICT: Unverified-assumption.** The frontend does not hard-code this; it resolves the base URL from `VITE_API_BASE_URL` at build time. Source: `src/api/client.ts: API_BASE_URL = import.meta.env?.VITE_API_BASE_URL`. The specific IP could not be confirmed from the sources; reworded as a per-environment value (see Open assumptions A-1). The "plaintext HTTP" characterization is plausible (dev) but also not provable from these sources.
5. **Claim (§5/§11):** Validation/error responses from these endpoints use the FastAPI `HTTPValidationError` shape. — **VERDICT: Verified.** Source: `components.schemas.HTTPValidationError` in `openapi.pretty.json` = `{ detail: ValidationError[] }`; every `/ui/*` op lists `422:HTTPValidationError`.
6. **Claim (§4):** A custom `AndroidJUnitRunner` subclass that swaps in `HiltTestApplication` is required to run Hilt-injected instrumented tests. — **VERDICT: Verified (framework ref).** Standard Hilt testing pattern. Source: Android docs "Hilt testing guide" (https://developer.android.com/training/dependency-injection/hilt-testing#instrumented-tests) and "AndroidJUnitRunner" (https://developer.android.com/training/testing/instrumented-tests/androidx-test-libraries/runner).
7. **Claim (§3/§4):** `connectedDebugAndroidTest` installs and runs `androidTest` instrumentation against a connected device/emulator; Gradle Managed Devices produces a per-device task `test35DebugAndroidTest`. — **VERDICT: Verified (framework ref).** Source: Android docs "Test from the command line" / "Gradle Managed Devices" (https://developer.android.com/studio/test/gradle-managed-devices).
8. **Claim (§4):** Emulator headless flags `-no-window -no-audio -no-boot-anim -no-snapshot-save -gpu swiftshader_indirect -accel on` and readiness via `getprop sys.boot_completed`. — **VERDICT: Verified (framework ref).** Source: Android docs "Start the emulator from the command line" (https://developer.android.com/studio/run/emulator-commandline) and "AVD / hardware acceleration" (https://developer.android.com/studio/run/emulator-acceleration). `sys.boot_completed` polling is the documented boot-ready signal.
9. **Claim (§2/§4):** System image `system-images;android-35;google_apis;x86_64` is installable via `sdkmanager` and an AVD created via `avdmanager`. — **VERDICT: Verified (framework ref).** Source: Android docs "sdkmanager" and "avdmanager" (https://developer.android.com/tools/sdkmanager, https://developer.android.com/tools/avdmanager).
10. **Claim (§8):** KVM (`/dev/kvm`) is required for hardware-accelerated x86_64 emulation on the Linux build host. — **VERDICT: Verified (framework ref).** Source: Android docs "Configure hardware acceleration for the Android Emulator" (https://developer.android.com/studio/run/emulator-acceleration#vm-linux).
11. **Claim (§2):** Project stack — Kotlin 2.0.21, AGP 8.7.3, Gradle 8.9, JDK 17, compile/target SDK 35, minSdk 24, Hilt+KSP, Compose/Material3, Room 2.6, DataStore. — **VERDICT: Unverified-assumption (out of source scope).** These are project-config claims inherited from AND-008/AND-048; the OpenAPI/frontend sources provided cannot confirm Android build-config versions. Carried forward as stated by upstream tickets (see A-2).

### Corrections made
- **§8 scrub list:** expanded from `{Authorization, Cookie, Set-Cookie, X-CSRF-Token}` to additionally include `X-IMPERSONATION-TOKEN` and to name the `ui_csrf` cookie explicitly, matching the headers/cookies actually emitted by `src/api/client.ts` (citation 3).
- **§8 dev base URL:** replaced the hard-coded `http://18.222.237.167:8000` with a per-environment description, because the frontend resolves the base URL from `VITE_API_BASE_URL` and the literal IP is not present in the provided sources (citation 4).
- No changes to §5 endpoint paths/methods — they were verified correct as written.

### Open assumptions
- **A-1 — Dev backend URL/scheme.** The exact dev host (`18.222.237.167:8000`) and plaintext-HTTP assumption are not provable from the OpenAPI spec or frontend (which uses `VITE_API_BASE_URL`). Why unverifiable: deployment/env config is outside the provided sources. Impact: low — this ticket runs ephemeral emulators against whatever dev host the test config points to; it does not depend on a specific IP.
- **A-2 — Android build-config versions (§2).** Kotlin/AGP/Gradle/SDK/Hilt/Room versions come from upstream AND-008/AND-048 and cannot be checked against the OpenAPI/frontend sources. Why unverifiable: no Android build files were provided in the reference set. Impact: low for this chore, but the GMD/`apiLevel = 35` and `system-images;android-35` choices must stay consistent with the real `targetSdk` when those files are available.
- **A-3 — `andrioiddev` host capabilities (R-1).** Whether the build host exposes `/dev/kvm` (bare-metal vs nested virt) is an operational fact about CI infrastructure, not derivable from any code/spec source. Why unverifiable: requires inspecting the actual build agent. Impact: high for runtime (SwiftShader fallback is far slower) — tracked as R-1 and gated by the §7 KVM pre-flight.
- **A-4 — CI backend (GitHub Actions vs Jenkins).** §2/§4 hedge between Actions and a generic agent; the canonical artifact set could not be confirmed. Why unverifiable: CI platform config not in scope. Impact: low — the `run-instrumented.sh` script is platform-agnostic by design.

## 17. Test Plan

Because the deliverable is CI test *infrastructure*, the "system under test" is the harness (boot → install → instrument → collect → teardown), not application screens. Cases below validate the harness; the application-behavior cases (login UI) are the *workload* used to prove it. Test-target legend per the available CI/dev fleet: **JVM/Robolectric** (local, no device), **emulator AVD `test35`** (headless x86_64, API 35, KVM, on the build server), **physical device** (Samsung Galaxy A15 5G, SM-A156U, arm64-v8a, API 34).

> Note on device selection: this ticket's whole purpose is the **headless emulator**, so almost every case runs on the `test35` emulator by design. Two cases (TC-09, TC-10) additionally exercise the **physical device** to validate arm64-v8a / API-34 portability of the same instrumented suite, since the emulator is x86_64/API-35 only and cannot surface ABI- or API-level regressions.

- **TC-AND-051-01 — Happy-path connected run boots and goes green.**
  Type: integration. Target: emulator `test35`. Preconditions: fresh `android-port` checkout on a KVM-capable agent; `/dev/kvm` writable; AND-048 suite + `EmulatorSmokeTest` present. Steps: run `android/ci/run-instrumented.sh` (`CI_EMULATOR_MODE=manual`). Expected: AVD `test35` created if absent (idempotent), emulator boots `-no-window` with `sys.boot_completed=1` inside 600 s, `./gradlew connectedDebugAndroidTest` runs, all instrumented tests pass, stage exit code 0. Traces: AC-1, AC-2.

- **TC-AND-051-02 — Sentinel smoke test executes against the app package.**
  Type: instrumented/e2e. Target: emulator `test35`. Preconditions: harness booted. Steps: run `EmulatorSmokeTest`. Expected: `InstrumentationRegistry.getInstrumentation().targetContext.packageName == "com.testlogon.android"`; test passes; proves install+instrumentation path independent of feature tests. Traces: AC-1.

- **TC-AND-051-03 — Hilt runner injects HiltTestApplication.**
  Type: instrumented/e2e. Target: emulator `test35`. Preconditions: each `androidTest` `defaultConfig` sets `testInstrumentationRunner = "com.testlogon.android.core.testing.HiltTestRunner"`. Steps: run a Hilt-annotated instrumented test (AND-048 login). Expected: the running `Application` is `HiltTestApplication`; `@Inject`/`@BindValue` dependencies resolve; no "Hilt … did not use HiltTestApplication" error. Traces: AC-2.

- **TC-AND-051-04 — Failing instrumented assertion turns the stage red.**
  Type: integration (negative). Target: emulator `test35`. Preconditions: a deliberately-failing `androidTest` introduced locally (NOT committed). Steps: run the connected task. Expected: Gradle task exits non-zero, stage is red, the failure appears in the JUnit XML and PR check summary with the failing test name; passing tests still report individually. Traces: AC-2, AC-3.

- **TC-AND-051-05 — Artifacts and JUnit results are collected on pass and fail.**
  Type: integration. Target: emulator `test35`. Preconditions: TC-01 (pass) and TC-04 (fail) runs available. Steps: after each run, inspect uploaded artifacts. Expected: per-module `build/reports/androidTests/connected/**` HTML, `build/outputs/androidTest-results/connected/**/*.xml`, and `logcat-test35.txt` are uploaded in both cases (`always()`); JUnit XML renders in the check summary. Traces: AC-3.

- **TC-AND-051-06 — Deterministic teardown leaves no zombie emulator.**
  Type: integration. Target: emulator `test35`. Preconditions: completed pass run and completed fail run. Steps: after each, run `adb devices` and check host process list for `emulator`/`qemu`. Expected: no `emulator-5554` device listed, no `emulator`/`qemu` process; `trap … EXIT`/`always()` killed it on both paths. Traces: AC-4.

- **TC-AND-051-07 — Boot-timeout path is distinguishable and self-cleaning.**
  Type: integration (resilience / flaky-host). Target: emulator `test35`. Preconditions: boot timeout temporarily lowered (e.g. 5 s) or boot deliberately stalled. Steps: run the harness. Expected: stage fails with the distinct `EMULATOR_BOOT_TIMEOUT` message (not a test-failure message), emulator is killed, no zombie remains; per §7 the boot-and-run sequence MAY retry once but a hard timeout still fails the stage. Traces: AC-7, AC-4.

- **TC-AND-051-08 — KVM pre-flight hard-fails fast with remediation.**
  Type: integration (security/permission + resilience). Target: emulator `test35` host. Preconditions: simulate `/dev/kvm` absent or not writable (CI user removed from `kvm` group / `test -w /dev/kvm` false). Steps: run the harness. Expected: job fails fast at the pre-flight with explicit remediation text (add CI user to `kvm` group), does NOT silently fall back to slow SwiftShader, no emulator started. Traces: AC-1 (acceleration precondition), AC-7-adjacent (clear, bounded failure).

- **TC-AND-051-09 — Same instrumented suite passes on the physical arm64 device.**
  Type: instrumented/e2e. Target: **physical device** (SM-A156U, arm64-v8a, API 34) — MUST run on the physical device; the `test35` emulator is x86_64/API-35 and cannot expose ABI/API portability issues. Preconditions: device connected via adb to the build host; debuggable. Steps: `./gradlew connectedDebugAndroidTest` (or `connectedDebugAndroidTest` targeting the device serial `R5CX821TA9R`). Expected: AND-048 + sentinel suite passes on arm64-v8a/API 34; no `INSTALL_FAILED_NO_MATCHING_ABIS`; results collected as on emulator. Traces: AC-2, AC-6.

- **TC-AND-051-10 — Offline / flaky-host transport behavior under test.**
  Type: contract/MockWebServer + instrumented. Target: emulator `test35` (network behavior is host-independent; runnable here) — physical device acceptable but not required. Preconditions: instrumented test points the app at a MockWebServer; emulate (a) network unreachable and (b) HTTP `422 HTTPValidationError` (`{ "detail": [ … ] }`) and `401` from `/ui/session/start`/`/ui/me`. Steps: run the test under each condition. Expected: offline yields the app's network-error path (the web client raises `ApiError(0, "Network error")`); `422` surfaces a validation error mapped from the `detail[]` array; `401` (when previously authenticated) triggers a single `POST /ui/session/refresh` retry then logout on failure — matching `src/api/client.ts`. The harness itself reports these as ordinary pass/fail (assertions never retried at the CI level). Traces: AC-2.

- **TC-AND-051-11 — Sensitive headers/cookies are scrubbed from logcat artifact.**
  Type: integration (security). Target: emulator `test35`. Preconditions: an instrumented test that performs an authenticated request so `Authorization: Bearer …`, the session cookie, `ui_csrf` cookie, `X-CSRF-Token`, and `X-IMPERSONATION-TOKEN` could appear in logs. Steps: run the suite, then grep the uploaded `logcat-test35.txt`. Expected: none of those token/cookie *values* appear in the artifact; the scrubbing/no-secret-logging policy holds (per corrected §8). Traces: AC-3 (artifact correctness), §8.

- **TC-AND-051-12 — Reproducibility: two fresh-checkout runs match.**
  Type: integration. Target: emulator `test35`. Preconditions: two independent fresh checkouts of `android-port` on a correctly-provisioned agent. Steps: run the full job twice, zero manual steps. Expected: identical green/red outcome and the same set of passed tests; no interactive prompts; AVD reuse is idempotent (no duplicate/divergent `test35`). Traces: AC-6.

- **TC-AND-051-13 — Gating: stage runs on `android-port` push and PRs targeting it.**
  Type: manual (CI config verification). Target: CI config (no device). Preconditions: workflow/pipeline config committed. Steps: inspect the stage's trigger filters; push a trivial commit to `android-port` and open a PR targeting it. Expected: the connected stage triggers in both; an instrumented failure or boot timeout fails the overall pipeline; the stage runs *after* AND-008's unit stage (fail-fast ordering). Traces: AC-5.

- **TC-AND-051-14 — Stale-emulator pre-clean before boot.**
  Type: integration (resilience). Target: emulator `test35`. Preconditions: a stale `emulator-5554` left running from a simulated previously-crashed job. Steps: start a new harness run. Expected: pre-run cleanup kills the stale `emulator-5554`/`adb` before booting, the new run proceeds normally to green, port `5554` is reused cleanly. Traces: AC-4, AC-6.

### Coverage matrix

| Acceptance criterion (§14) | Covered by |
| --- | --- |
| AC-1 (headless KVM run, no manual steps) | TC-01, TC-02, TC-08 |
| AC-2 (AND-048 tests pass; exit code reflects result) | TC-01, TC-03, TC-04, TC-09, TC-10 |
| AC-3 (reports + scrubbed logcat published; JUnit in summary) | TC-04, TC-05, TC-11 |
| AC-4 (no zombie emulator/device after any run) | TC-06, TC-07, TC-14 |
| AC-5 (gates `android-port` pushes/PRs; failures fail pipeline) | TC-13 |
| AC-6 (fresh-checkout reproducibility, zero manual) | TC-09, TC-12, TC-14 |
| AC-7 (`EMULATOR_BOOT_TIMEOUT` + clean teardown, distinguishable) | TC-07, TC-08 |

> Accessibility: this ticket produces no UI, so there are no Compose/TalkBack accessibility assertions here (see §9). Accessibility of the screens executed as workload (AND-046/AND-048 login) is owned by those tickets; this harness is the documented future home for running such checks headlessly.
