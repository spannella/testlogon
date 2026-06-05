---
id: AND-051
title: "CI: instrumented tests on headless emulator"
milestone: M1
epic: E07
priority: P1
size: M
status: draft
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

- No production credentials. Tests against the dev backend (`http://18.222.237.167:8000`, plaintext HTTP) MUST use throwaway/dev test accounts only; no real user PII is entered. Test credentials, if any, come from CI secrets, never committed.
- The emulator runs in a CI sandbox; cookie jars / DataStore created during tests are destroyed with the ephemeral emulator and never exported as artifacts. Logcat artifacts (FR-4) MUST be scrubbed of any `Authorization`, `Cookie`, `Set-Cookie`, or `X-CSRF-Token` values — the logging policy (no secret logging) is enforced by app code, and CI additionally treats logcat as potentially sensitive: artifacts are retained only on the private CI store, not on public PRs.
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
