---
id: AND-008
title: "CI: build + unit test on build server"
milestone: M1
epic: E01
priority: P0
size: M
status: reviewed
reviewed_on: 2026-06-06
depends_on: [AND-002]
blocks: [AND-003, AND-004, AND-005, AND-006, AND-007]
---

# AND-008 — CI: build + unit test on build server

## 1. Overview & Goal

Establish an automated, reproducible Continuous Integration (CI) pipeline for the
TestLogon native Android port. The pipeline runs on the self-hosted build server
addressed as `andrioiddev` (the host alias is reproduced verbatim from the backlog;
see Risk R1) and must, on every push and pull request targeting the `android-port`
branch, execute a debug build (`assembleDebug`) and the JVM unit test suite
(`testDebugUnitTest`) against the `android/` subfolder of the `spannella/testlogon`
monorepo. The job must cache Gradle artifacts to keep wall-clock time bounded and
must produce a green result on the current scaffold from a completely fresh
checkout with no machine-local state.

This is a P0 chore: it is the quality gate that every subsequent feature ticket
(networking, auth, feature modules) relies on for fast, deterministic feedback. It
gates merges but ships no user-facing code. The deliverable is a CI workflow
definition plus any supporting Gradle configuration (caching, deterministic JVM
settings, CI-friendly logging) committed under version control so the pipeline is
itself reviewable and reproducible.

Goal statement: a developer opening a PR against `android-port` sees a single
required status check that builds the debug APK and runs all unit tests, completes
in a bounded time budget on a warm cache, and can be re-run identically on a clean
clone of the repo with `JAVA_HOME` pointed at JDK 17 and no other prerequisites.

## 2. Context & References

- Repo: `spannella/testlogon`; Android app lives in the monorepo subfolder
  `android/` on branch `android-port`. All Gradle invocations run with
  `android/` as the working directory.
- Toolchain (must be pinned exactly in CI): Kotlin 2.0.21, AGP 8.7.3,
  Gradle 8.9 (wrapper), JDK 17, compileSdk/targetSdk 35, minSdk 24, KSP for Hilt.
- Module layering target: `app -> feature-* -> core-*`
  (`core-network`, `core-model`, `core-ui`, `core-data`, `core-testing`).
  At AND-008's point in the sequence only the `app` module from AND-002 is
  guaranteed present; the workflow must build/test whatever modules exist, not a
  hardcoded module list.
- Canonical namespace / applicationId base: `com.testlogon.android`.
- Upstream dependency: **AND-002** (Application module configuration) provides the
  `app` module, `compileSdk 35 / minSdk 24 / targetSdk 35`, Compose enabled, the
  Gradle wrapper, and a launchable blank Compose `MainActivity`. AND-008 consumes
  the wrapper and the `:app:assembleDebug` / `:app:testDebugUnitTest` tasks
  produced there.
- Downstream: this pipeline becomes the required check that AND-003..AND-007
  (and beyond) must pass; those tickets own their own test code, AND-008 only owns
  the runner.
- Reference: web app under `frontend/` is unaffected. The dev backend
  (`http://18.222.237.167:8000`) is **not** contacted by this job — unit tests are
  hermetic JVM tests with no network. Instrumented/connected tests are explicitly
  out of scope (see Section 3).

## 3. Functional Requirements

FR-1. A version-controlled CI workflow file exists under `android/.github/` (or
repo-root `.github/workflows/` if the build server's orchestrator scopes from repo
root — see R1) named `android-ci.yml`, triggered on `pull_request` and `push` to
`android-port`, with `paths` filtered to `android/**` and the workflow file itself
so unrelated monorepo changes do not spend build minutes.

FR-2. The job runs, in order, from working directory `android/`:
1. Checkout (full, clean — `clean: true`, no persisted credentials beyond read).
2. Provision JDK 17 (Temurin) and export `JAVA_HOME`.
3. Restore Gradle caches.
4. Validate the Gradle wrapper checksum.
5. `./gradlew assembleDebug testDebugUnitTest --stacktrace`.
6. Save Gradle caches.
7. Always upload test reports and (on the build step) the lint/test XML as
   artifacts.

FR-3. Both `assembleDebug` and `testDebugUnitTest` must execute in a single
Gradle invocation so the configuration phase and dependency graph are shared,
reducing wall time. A non-zero Gradle exit code fails the job.

FR-4. Gradle dependency and build caches are persisted across runs keyed on the
contents of all `*.gradle*`, `gradle/wrapper/gradle-wrapper.properties`, and
`gradle/libs.versions.toml` files, with a restore fallback to the most recent
partial-match cache.

FR-5. The pipeline is reproducible: a fresh `git clone`, `cd android`,
`./gradlew assembleDebug testDebugUnitTest` with JDK 17 on PATH must produce the
same green result locally as in CI. No step may depend on pre-installed SDK
components beyond what the Android Gradle plugin auto-provisions or what the
documented runner image supplies. `android/.gitignore` must already exclude
`local.properties`; CI relies on `ANDROID_HOME`/`ANDROID_SDK_ROOT` env, never on
a committed `local.properties` `sdk.dir`.

FR-6. Test results are summarized into the run output (pass/fail counts) and the
HTML/XML reports from `app/build/reports/tests/` and `app/build/test-results/`
are uploaded as artifacts with `if: always()` so failures are diagnosable.

FR-7. Concurrency: in-flight runs for the same PR ref are cancelled when a new
commit is pushed (`concurrency` group keyed on workflow + ref,
`cancel-in-progress: true`).

Out of scope: instrumented/`connectedAndroidTest` (no emulator/device in this
ticket), Play/signing/release builds, code-coverage gating thresholds, static
analysis gating (lint/detekt as a hard gate) — these are deferred to later chore
tickets and are not required for AND-008 to be green.

## 4. Technical Design

### 4.1 Workflow definition

Implemented as a GitHub Actions-compatible workflow (the `andrioiddev` build
server is assumed to run a GitHub-Actions-compatible runner; if it runs a
different orchestrator the same steps map 1:1 — see R1). File:
`android/.github/workflows/android-ci.yml` (or root `.github/workflows/`).

```yaml
name: Android CI
on:
  push:
    branches: [android-port]
    paths: ['android/**', '.github/workflows/android-ci.yml']
  pull_request:
    branches: [android-port]
    paths: ['android/**', '.github/workflows/android-ci.yml']
concurrency:
  group: android-ci-${{ github.ref }}
  cancel-in-progress: true
permissions:
  contents: read
jobs:
  build-and-test:
    runs-on: [self-hosted, andrioiddev]
    timeout-minutes: 30
    defaults:
      run:
        working-directory: android
    env:
      GRADLE_OPTS: >-
        -Dorg.gradle.daemon=false
        -Dorg.gradle.workers.max=4
      JAVA_TOOL_OPTIONS: -Dfile.encoding=UTF-8
    steps:
      - uses: actions/checkout@v4
        with: { clean: true, persist-credentials: false }
      - uses: actions/setup-java@v4
        with: { distribution: temurin, java-version: '17' }
      - uses: gradle/actions/wrapper-validation@v4
      - uses: gradle/actions/setup-gradle@v4
        with:
          cache-read-only: ${{ github.event_name != 'push' }}
          gradle-home-cache-cleanup: true
      - name: Build + unit test
        run: ./gradlew assembleDebug testDebugUnitTest --stacktrace --no-daemon
      - name: Upload test reports
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: unit-test-reports
          path: |
            android/**/build/reports/tests/
            android/**/build/test-results/
          retention-days: 7
      - name: Upload debug APK
        if: success()
        uses: actions/upload-artifact@v4
        with:
          name: app-debug-apk
          path: android/app/build/outputs/apk/debug/*.apk
          retention-days: 7
```

`gradle/actions/setup-gradle@v4` supplies the cache layer (FR-4) keyed
automatically on the Gradle files and wrapper; `cache-read-only` is enabled for PR
events so only trusted `push` runs write the shared cache (security: prevents PR
cache poisoning).

### 4.2 Gradle CI configuration

Add/confirm `android/gradle.properties` settings to make CI deterministic and
fast. These are committed (not CI-only) so local runs match (FR-5):

```properties
org.gradle.jvmargs=-Xmx3g -XX:MaxMetaspaceSize=1g -Dfile.encoding=UTF-8
org.gradle.parallel=true
org.gradle.caching=true
org.gradle.configuration-cache=true
android.useAndroidX=true
kotlin.code.style=official
```

Daemon is disabled per-invocation in CI (`--no-daemon` / `GRADLE_OPTS`) because the
runner is ephemeral per job; the daemon adds no benefit and risks stale-state
non-reproducibility. Memory is bounded to fit the build server.

### 4.3 Function/test signatures used by the gate

AND-008 owns no production Kotlin, but it must keep working as test code appears.
A trivial sanity unit test should exist in `app` (added here if AND-002 left none)
so `testDebugUnitTest` is non-empty and the gate proves the test runner actually
executes:

```kotlin
package com.testlogon.android

import org.junit.Assert.assertEquals
import org.junit.Test

class CiSanityTest {
    @Test fun arithmetic_holds() = assertEquals(4, 2 + 2)
}
```

This lives at `android/app/src/test/java/com/testlogon/android/CiSanityTest.kt`
and is superseded by real tests in downstream tickets.

## 5. API Contract

N/A. This ticket adds no application networking and contacts no HTTP endpoint.
The FastAPI dev backend (`http://18.222.237.167:8000`, OpenAPI `/openapi.json`)
and the cookie/CSRF session flow are irrelevant here — unit tests are hermetic JVM
tests with no network access. The HTTP client and contract are owned by the
networking ticket (`core-network`, AND-004 in the M1 sequence). The only "API"
AND-008 consumes is the Gradle task interface from AND-002:
`:app:assembleDebug` and `:app:testDebugUnitTest`.

## 6. Data & State Management

No app runtime state (no `StateFlow<UiState>`, Room, or DataStore). The only
persistent state is CI build state:

- **Gradle cache** (`~/.gradle/caches`, `~/.gradle/wrapper`, project `build/`
  via the action) — persisted across runs, keyed on hashed Gradle/version-catalog
  files; restore-keys allow partial reuse. Cache is write-enabled only on `push`
  to `android-port`, read-only on PRs.
- **Artifacts** — `unit-test-reports` (always) and `app-debug-apk` (on success),
  7-day retention. These are ephemeral diagnostic outputs, not source of truth.
- No secrets are stored or required; `permissions: contents: read` only.

Reproducibility invariant: deleting the entire Gradle cache must still yield a
green run (slower). The cache is an optimization, never a correctness dependency
(verified in Testing Strategy).

## 7. Error Handling & Resilience

- **Build/test failure:** any non-zero `./gradlew` exit fails the job; `--stacktrace`
  surfaces the cause. Test reports upload with `if: always()` so a red run is
  diagnosable from artifacts.
- **Flaky/slow runner:** `timeout-minutes: 30` caps a hung job. Note the
  bounded-backoff-retry / 20s-timeout guidance from the project context applies to
  *app runtime network calls against the unreliable dev backend*, NOT to this CI
  job — CI does no network I/O to that host and must not auto-retry build failures
  (a green-on-retry build masks nondeterminism). Step-level retries are prohibited.
- **Concurrency:** superseded PR commits cancel older runs to save capacity.
- **Wrapper tampering:** `wrapper-validation` fails the job if
  `gradle-wrapper.jar` checksum does not match the pinned distribution.
- **Cache corruption:** `gradle-home-cache-cleanup: true` plus restore-keys allow
  graceful degradation to a clean download rather than a hard failure.
- **Self-hosted disk pressure:** documented runbook step to prune the runner's
  Gradle home; not automated in this ticket (R2).

## 8. Security & Privacy

- `permissions: contents: read` — the workflow has no write scope; it cannot push,
  comment, or publish.
- `persist-credentials: false` on checkout so the `GITHUB_TOKEN` is not left in the
  local git config of the (persistent) self-hosted workspace.
- PR runs use `cache-read-only: true`, preventing a malicious fork PR from writing
  poisoned entries into the shared Gradle cache.
- No secrets, signing keys, keystores, or backend credentials are referenced;
  debug builds use the default AGP debug keystore which is non-sensitive.
- All third-party actions are pinned to a major version (`@v4`); upgrading to full
  SHA pinning is recommended hardening (R3) but not required for green.
- No PII or user data flows through this job. Uploaded artifacts (APK, test XML)
  contain no secrets.
- Self-hosted runner caveat: untrusted fork PRs executing on a self-hosted runner
  is a known risk — restrict the runner to the `spannella/testlogon` repo and
  require approval for first-time contributors (R1/R3).

## 9. Accessibility & i18n

N/A for this ticket — there is no user-facing UI or copy delivered. Accessibility
(TalkBack, touch targets, content descriptions) and localization are owned by the
`core-ui` and feature tickets. The one indirect contribution: by making
`testDebugUnitTest` a required gate, AND-008 provides the harness that downstream
accessibility/semantics unit tests (e.g., Compose semantics assertions) will run
under. Build output and logs are English-only and developer-facing.

## 10. Telemetry & Logging

- **CI logs:** `--stacktrace` for actionable failures; avoid `--info`/`--debug` by
  default to keep logs readable (they can be enabled ad hoc via workflow dispatch
  input if added later).
- **Build scan:** optionally emit a Gradle build scan link via
  `gradle/actions/setup-gradle`'s scan support for triage; not required for green.
- **Job summary:** test pass/fail counts are visible in the Gradle output and the
  uploaded HTML report. A `$GITHUB_STEP_SUMMARY` line reporting build duration and
  test totals is a nice-to-have, not mandatory.
- No app-runtime analytics/telemetry SDK is involved; application-level telemetry
  is out of scope and owned by later tickets. No logs leave the build server except
  the standard CI run logs and retained artifacts.

## 11. Testing Strategy

The "tests" for a CI ticket are validations of the pipeline itself:

1. **Green on scaffold (FR-1..FR-3):** open a no-op PR against `android-port`;
   assert the `Android CI` check runs and passes, executing both `assembleDebug`
   and `testDebugUnitTest` (verify both task names appear in the log).
2. **Reproducible on fresh checkout (Acceptance):** on a clean machine/container,
   `git clone`, `cd android`, JDK 17 on PATH, run
   `./gradlew assembleDebug testDebugUnitTest` — must pass with no manual SDK setup
   beyond `ANDROID_HOME`. No `local.properties` committed.
3. **Cache-independence:** clear the runner Gradle home, re-run — still green,
   proving the cache is an optimization not a dependency (FR-5/Section 6 invariant).
4. **Red on real failure:** temporarily add a failing unit test
   (`assertEquals(5, 2 + 2)`); assert the job goes red and the failing test appears
   in the uploaded `unit-test-reports` artifact; revert.
5. **Path filtering:** push a change touching only `frontend/`; assert the Android
   CI workflow does **not** run.
6. **Concurrency:** push two commits in quick succession to a PR; assert the older
   run is cancelled.
7. **Wrapper validation:** (review-only) confirm `wrapper-validation` step present
   and passing.
8. **Sanity test executes:** confirm `CiSanityTest` is reported as run (non-empty
   test count) so an accidentally-empty source set cannot make the gate vacuously
   green.

Each is a concrete, observable pass/fail check on a CI run.

## 12. Dependencies & Sequencing

- **Depends on AND-002** (Application module configuration): provides the `app`
  module, Gradle wrapper (8.9), Compose/Kotlin 2.0 setup, and the
  `:app:assembleDebug` / `:app:testDebugUnitTest` tasks this job invokes. AND-008
  cannot go green before AND-002 lands. AND-002 in turn depends on AND-001
  (project scaffold).
- **Blocks** the feature/networking tickets that rely on a working required check
  (AND-003 onward in M1 / epic E01); those tickets contribute their own test code
  but inherit this runner. The module-list-agnostic build (`assembleDebug`
  across the project, not a hardcoded `:app`) means new `core-*`/`feature-*`
  modules are picked up automatically with no workflow change.
- Sequencing: land immediately after AND-002 so all subsequent PRs are gated.
- External prerequisites: a registered self-hosted runner labelled `andrioiddev`
  with JDK 17 obtainable (via `setup-java`) and the Android SDK present (or
  auto-provisioned by AGP). Provisioning that runner is an infra prerequisite, not
  a code dependency.

## 13. Risks & Open Questions

- **R1 (Open):** the backlog spells the build host `andrioiddev` (note transposed
  letters). Is this the literal runner label/hostname, or a typo for
  `androiddev`? The workflow uses `[self-hosted, andrioiddev]` verbatim; confirm
  the actual label before merge and adjust the `runs-on` value. Also confirm the
  orchestrator is GitHub Actions vs. another CI (Jenkins/GitLab) — if different,
  port the identical step sequence.
- **R2 (Open):** self-hosted runner disk/Gradle-home growth over time;
  needs a documented prune runbook or scheduled cleanup (deferred).
- **R3 (Risk):** self-hosted runners execute untrusted fork-PR code. Mitigate by
  restricting the runner to this repo, requiring maintainer approval for
  first-time contributors, and `cache-read-only` on PRs. Full SHA-pinning of
  actions is recommended follow-up hardening.
- **R4 (Risk):** monorepo `paths` filter must correctly scope to `android/**`;
  misconfiguration either over-runs (wasted minutes) or under-runs (missed gate).
  Covered by Testing Strategy item 5.
- **Open Q:** should lint/detekt be added as a hard gate now or in a follow-up
  chore? Current decision: follow-up, to keep AND-008 minimal and green-able.

## 14. Acceptance Criteria

AC-1. A committed workflow (`android-ci.yml`) triggers on `push`/`pull_request` to
`android-port`, scoped to `android/**`, running on the `andrioiddev` self-hosted
runner. (FR-1, FR-7)

AC-2. The job runs `./gradlew assembleDebug testDebugUnitTest` in one invocation
from `android/`, with JDK 17 provisioned and Gradle wrapper validated; both task
names are observable in the run log. (FR-2, FR-3) — **backlog: CI runs green on
the scaffold.**

AC-3. Gradle caches are restored and saved across runs (read-only on PRs), keyed on
hashed Gradle/version-catalog files. (FR-4)

AC-4. The pipeline is **reproducible on a fresh checkout**: `git clone` + `cd
android` + JDK 17 + `./gradlew assembleDebug testDebugUnitTest` passes with no
machine-local prerequisites beyond `ANDROID_HOME`; no `local.properties` is
committed. (FR-5) — **backlog: reproducible on a fresh checkout.**

AC-5. Unit-test reports upload as artifacts on every run (`if: always()`); the
debug APK uploads on success. A non-empty test count is reported (at least
`CiSanityTest`). (FR-6, FR-8)

AC-6. A deliberately failing unit test turns the job red and is visible in the
uploaded report; reverting returns it to green. (Testing 4)

AC-7. Clearing the runner's Gradle cache still yields a green run. (Section 6
invariant, Testing 3)

## 15. Definition of Done

- Workflow file and any `gradle.properties` / sanity-test changes committed on a
  branch off `android-port` and merged via PR.
- The PR's own `Android CI` check is green (dogfooding the gate).
- All Acceptance Criteria (AC-1..AC-7) verified, with evidence: a green run link
  on the scaffold, a fresh-checkout reproduction log, and a screenshot/log of the
  red-on-failure experiment (then reverted).
- `Android CI` is configured as a **required** status check on `android-port`
  branch protection (or the change to do so is filed if branch-protection edits
  need admin).
- R1 (runner label / orchestrator) resolved and reflected in `runs-on`.
- No secrets introduced; `permissions: contents: read`, `persist-credentials:
  false`, PR cache read-only confirmed in review.
- Reviewed and approved by a second engineer; documentation note added pointing
  future feature tickets at this gate as the place their unit tests will execute.

## 16. Citations & Assumption Audit

This is a CI/chore ticket. Most claims concern GitHub Actions, Gradle, and the
Android toolchain (framework refs), not the TestLogon backend API. Per Section 5
the ticket performs no HTTP I/O, so the OpenAPI/frontend sources are consulted only
to confirm that the "API is irrelevant here" claim is itself correct, and to
verify the few backend/web-app facts the spec mentions in passing.

1. **Claim:** "This ticket adds no application networking and contacts no HTTP
   endpoint" / Section 5 is N/A. **VERDICT: Verified.** The deliverable is a
   GitHub Actions workflow + Gradle config; no networking code is introduced. No
   AND-008-specific endpoint exists in the backend. **SOURCE:** OpenAPI index
   `reference/openapi.index.txt` (no CI/build-related path; endpoints are all
   product/admin APIs). Self-evident from ticket scope (AND-008 META: "CI: build +
   unit test on build server").

2. **Claim (Section 2 & 5):** the dev backend is reachable at
   `http://18.222.237.167:8000` and exposes OpenAPI at `/openapi.json`.
   **VERDICT: Unverified-assumption** (host literal). The frontend does not hardcode
   this host; it reads `VITE_API_BASE_URL` at runtime and prefixes relative paths.
   The IP/port comes from project context, not from any source file, so it cannot
   be confirmed against the repo. It is also immaterial to AND-008 (no network I/O).
   **SOURCE:** `src/api/client.ts` (lines ~7-13): `API_BASE_URL` derived from
   `import.meta.env.VITE_API_BASE_URL`; no literal host present.

3. **Claim (Section 5):** the web client uses a "cookie/CSRF session flow" that is
   irrelevant to this CI job. **VERDICT: Verified** (the CSRF flow exists; its
   irrelevance to AND-008 is correct). The web client sends requests with
   `credentials: "include"`, reads the CSRF token from the `ui_csrf` cookie, and
   sends it as the `X-CSRF-Token` header. None of this is exercised by a hermetic
   JVM unit-test/build job. **SOURCE:** `src/api/client.ts`: `credentials:
   "include"`, `getCookie("ui_csrf")`, `headers.set("X-CSRF-Token", csrf)`.

4. **Claim (Section 5):** the only "API" AND-008 consumes is the Gradle task
   interface `:app:assembleDebug` and `:app:testDebugUnitTest`. **VERDICT:
   Verified** (framework ref). `assembleDebug` and `testDebugUnitTest` are standard
   tasks contributed by the Android Gradle Plugin's application/unit-test variants.
   **SOURCE:** framework ref — AGP build/test task docs
   (https://developer.android.com/build/gradle-build-overview and
   https://developer.android.com/studio/test/command-line).

5. **Claim (Section 2):** toolchain pins Kotlin 2.0.21, AGP 8.7.3, Gradle 8.9
   (wrapper), JDK 17, compileSdk/targetSdk 35, minSdk 24, KSP for Hilt.
   **VERDICT: Unverified-assumption** (inherited from AND-002, not re-derivable from
   the API/frontend sources). These are an upstream-ticket contract, not facts in
   any authoritative source provided here; AGP 8.7.x requires JDK 17 and supports
   compileSdk 35, which is internally consistent. **SOURCE:** framework ref — AGP
   release/compatibility notes
   (https://developer.android.com/build/releases/gradle-plugin); cross-ticket
   reference to AND-002. Flagged so the implementer confirms against AND-002's spec.

6. **Claim (Section 4.1):** wrapper validation and Gradle setup use
   `gradle/actions/wrapper-validation@v4` and `gradle/actions/setup-gradle@v4`.
   **VERDICT: Verified** (framework ref). The standalone
   `gradle/wrapper-validation-action` was consolidated into the `gradle/actions`
   repo; `gradle/actions/wrapper-validation` and `gradle/actions/setup-gradle` are
   the current action paths, and `setup-gradle` provides the dependency-cache layer.
   **SOURCE:** framework ref — https://github.com/gradle/actions
   (setup-gradle / wrapper-validation READMEs).

7. **Claim (Section 4.1):** `cache-read-only: ${{ github.event_name != 'push' }}`
   makes PR runs read-only so fork PRs cannot poison the shared Gradle cache.
   **VERDICT: Verified** (framework ref). `setup-gradle` exposes `cache-read-only`,
   and restricting cache writes to trusted `push` events is the documented
   anti-poisoning pattern. **SOURCE:** framework ref — gradle/actions setup-gradle
   caching docs (https://github.com/gradle/actions/blob/main/docs/setup-gradle.md).

8. **Claim (Section 4.1 / FR-7):** `concurrency` with `cancel-in-progress: true`
   cancels superseded in-flight runs for the same ref. **VERDICT: Verified**
   (framework ref). **SOURCE:** framework ref — GitHub Actions concurrency docs
   (https://docs.github.com/actions/using-jobs/using-concurrency).

9. **Claim (Section 4.1 / FR-1):** `paths:` filters limit triggering to
   `android/**` and the workflow file. **VERDICT: Verified** (framework ref).
   `push`/`pull_request` support `paths` filtering. Caveat: `paths` interacts with
   required-status-check branch protection (a skipped required check can block
   merges); the implementer should pair `paths` with a path-skip "success shim" or
   use branch-protection's handling for skipped checks. **SOURCE:** framework ref —
   GitHub Actions `on.<event>.paths`
   (https://docs.github.com/actions/using-workflows/workflow-syntax-for-github-actions#onpushpull_requestpaths).

10. **Claim (Section 4.1):** self-hosted runner targeted via
    `runs-on: [self-hosted, andrioiddev]`. **VERDICT: Unverified-assumption.** The
    label string `andrioiddev` is copied verbatim from the backlog and may be a
    typo for `androiddev` (tracked as R1); the actual registered label cannot be
    confirmed from any provided source. **SOURCE:** ticket backlog
    `specs-src/AND-008.md` (scope line: "job on `andrioiddev`"); no source file
    confirms the runner label. Framework ref for syntax — GitHub Actions
    self-hosted `runs-on` labels
    (https://docs.github.com/actions/hosting-your-own-runners/managing-self-hosted-runners/using-self-hosted-runners-in-a-workflow).

11. **Claim (Section 4.2):** `org.gradle.configuration-cache=true`,
    `org.gradle.caching=true`, `org.gradle.parallel=true` are valid CI-determinism
    settings. **VERDICT: Verified** (framework ref), with one note: enabling the
    configuration cache while forcing `--no-daemon`/`org.gradle.daemon=false`
    reduces (but does not eliminate) the configuration-cache benefit, since the
    cache is reloaded from disk each invocation rather than reused from a warm
    daemon. Not an error; intentional per the "ephemeral runner" rationale in 4.2.
    **SOURCE:** framework ref — Gradle build environment / configuration-cache docs
    (https://docs.gradle.org/current/userguide/build_environment.html,
    https://docs.gradle.org/current/userguide/configuration_cache.html).

### Corrections made

- **Frontmatter:** `status: draft` -> `status: reviewed`; added
  `reviewed_on: 2026-06-06`.
- No factual corrections to the body were required: every concrete API/web-app
  reference in Sections 2 and 5 was confirmed against the sources (CSRF/cookie flow,
  configurable base URL, the "no networking" scope), and the framework claims
  (action paths, Gradle/AGP tasks, concurrency, caching, paths filter) check out
  against current official docs. Two pre-existing nuances were annotated rather than
  changed: (a) the `paths`-filter + required-check interaction (citation 9), and
  (b) configuration-cache vs `--no-daemon` effectiveness (citation 11). These are
  advisory notes, not contradictions of the spec.

### Open assumptions

- **Backend host literal** `http://18.222.237.167:8000` (citation 2): sourced from
  project context only; the frontend reads `VITE_API_BASE_URL`, so the IP cannot be
  verified from the repo. Immaterial to AND-008 (no network I/O), so left as-is.
- **Toolchain version pins** (citation 5): Kotlin/AGP/Gradle/SDK levels are an
  AND-002 contract, not present in the API/frontend sources; assumed correct and
  internally consistent. Confirm against the merged AND-002 before relying on them.
- **Runner label** `andrioiddev` vs `androiddev` (citation 10, R1): unverifiable
  from any source; must be confirmed against the actual registered self-hosted
  runner before merge.
- **Orchestrator is GitHub Actions** (Section 4.1, R1): assumed; if the build
  server runs Jenkins/GitLab CI the same step sequence must be ported. No source
  confirms the orchestrator.

## 17. Test Plan

Validation cases for the CI gate. Types: unit (Gradle/JVM test invoked by the gate),
contract/MockWebServer (N/A here — no HTTP), integration (workflow behavior on the
runner), Compose-UI / instrumented-e2e (N/A — no UI, no device), manual/review.
"Traces: AC-#" links to Section 14.

- **TC-AND-008-01 — Green on scaffold (happy path).** *Type:* integration.
  *Preconditions:* AND-002 merged; runner `andrioiddev` online; JDK 17 provisionable
  via `setup-java`. *Steps:* open a no-op PR against `android-port`; let the
  `Android CI` check run. *Expected:* check passes; log shows both `assembleDebug`
  and `testDebugUnitTest` executing in a single `./gradlew` invocation from
  `android/`; wrapper-validation step passes. *Traces: AC-1, AC-2.*

- **TC-AND-008-02 — Reproducible on fresh checkout.** *Type:* integration
  (clean-room). *Preconditions:* clean machine/container, JDK 17 on PATH,
  `ANDROID_HOME`/`ANDROID_SDK_ROOT` set, no prior Gradle home. *Steps:* `git clone`
  the repo, `cd android`, run `./gradlew assembleDebug testDebugUnitTest`. *Expected:*
  passes with no manual SDK component installation beyond `ANDROID_HOME`; no
  `local.properties` is present in the checkout (it is git-ignored). *Traces: AC-4.*

- **TC-AND-008-03 — Cache-independence (cold cache).** *Type:* integration.
  *Preconditions:* a previously-green pipeline; access to prune the runner Gradle
  home. *Steps:* delete `~/.gradle/caches` and `~/.gradle/wrapper` on the runner;
  re-run the workflow on `android-port`. *Expected:* run is still green (slower);
  proving the cache is an optimization, not a correctness dependency. *Traces: AC-7.*

- **TC-AND-008-04 — Red on real test failure + report artifact.** *Type:* unit
  (negative) + integration. *Preconditions:* green baseline. *Steps:* temporarily
  change `CiSanityTest` to `assertEquals(5, 2 + 2)`; push; observe the run; then
  revert. *Expected:* job goes red on a non-zero Gradle exit; the failing test
  appears in the uploaded `unit-test-reports` artifact (uploaded due to
  `if: always()`); after revert the job returns to green. *Traces: AC-5, AC-6.*

- **TC-AND-008-05 — Sanity test actually executes (non-vacuous gate).** *Type:*
  unit. *Preconditions:* green run. *Steps:* inspect `testDebugUnitTest` output and
  the uploaded HTML/XML report. *Expected:* reported executed-test count >= 1 (at
  least `CiSanityTest.arithmetic_holds`); an empty `src/test` source set must not be
  able to make the gate pass vacuously. *Traces: AC-2, AC-5.*

- **TC-AND-008-06 — Artifact upload on success and on failure.** *Type:*
  integration. *Preconditions:* one green run and one red run available (red from
  TC-04). *Steps:* check the Artifacts of both runs. *Expected:* `unit-test-reports`
  present on BOTH runs (`if: always()`); `app-debug-apk` present only on the
  successful run (`if: success()`), containing the debug APK; 7-day retention set.
  *Traces: AC-5.*

- **TC-AND-008-07 — Path filtering (under-trigger guard).** *Type:* integration.
  *Preconditions:* monorepo with `frontend/` and `android/`. *Steps:* open a PR that
  touches only `frontend/**`. *Expected:* the `Android CI` workflow does NOT run
  (paths filter scopes to `android/**` + the workflow file). Verify this does not
  block merge if `Android CI` is a required check (skipped-required-check handling /
  success-shim per citation 9). *Traces: AC-1.*

- **TC-AND-008-08 — Path filtering (over-trigger guard).** *Type:* integration.
  *Preconditions:* as above. *Steps:* open a PR that touches `android/**` (or the
  workflow file). *Expected:* the workflow DOES run. Confirms the filter does not
  silently drop legitimate Android changes (the missed-gate risk, R4). *Traces:
  AC-1, AC-2.*

- **TC-AND-008-09 — Concurrency cancellation.** *Type:* integration.
  *Preconditions:* a PR with an in-flight run. *Steps:* push a second commit to the
  same PR ref before the first run finishes. *Expected:* the older in-flight run is
  cancelled (`cancel-in-progress: true`, group keyed on ref); only the newest run
  proceeds. *Traces: AC-1.*

- **TC-AND-008-10 — Cache write-policy / PR cache-poisoning guard (security).**
  *Type:* integration (security). *Preconditions:* a PR run and a `push`-to-
  `android-port` run. *Steps:* inspect `setup-gradle` cache logs on each. *Expected:*
  PR run is cache **read-only** (`cache-read-only: true`, since
  `github.event_name != 'push'`); only the `push` run writes the shared Gradle
  cache. Confirms a fork PR cannot poison the cache. *Traces: AC-3.*

- **TC-AND-008-11 — Cache restore/save key correctness.** *Type:* integration.
  *Preconditions:* two consecutive `push` runs with no Gradle/catalog changes
  between them. *Steps:* compare cache restore on run 2 vs run 1. *Expected:* run 2
  restores the cache saved by run 1 (warm-cache hit, reduced download/wall time);
  changing a `*.gradle*` / `gradle-wrapper.properties` / `libs.versions.toml` file
  produces a new key with restore-key fallback to the nearest prior cache. *Traces:
  AC-3.*

- **TC-AND-008-12 — Least-privilege & credential hygiene (security).** *Type:*
  review + integration. *Preconditions:* workflow file + a completed run on the
  self-hosted runner. *Steps:* review `permissions:` and checkout config; on the
  runner workspace, check git config after the job. *Expected:* `permissions:
  contents: read` only (no write/publish); `persist-credentials: false` so no
  `GITHUB_TOKEN` remains in the persistent runner's local git config; no secrets,
  keystores, or backend credentials referenced. *Traces: AC-1.*

- **TC-AND-008-13 — Wrapper-integrity gate (security).** *Type:* integration
  (negative). *Preconditions:* green baseline. *Steps:* in a throwaway branch,
  tamper with `gradle/wrapper/gradle-wrapper.jar` (or point the wrapper at an
  unknown distribution) and run. *Expected:* `gradle/actions/wrapper-validation`
  fails the job before the build runs; restoring the genuine wrapper passes.
  *Traces: AC-2.*

- **TC-AND-008-14 — Timeout / no-auto-retry-on-failure (resilience).** *Type:*
  review + integration. *Preconditions:* workflow file. *Steps:* confirm
  `timeout-minutes: 30` is set and no step-level retry/`continue-on-error` wraps the
  build/test step. *Expected:* a hung job is capped at 30 min and fails; build/test
  failures are NOT auto-retried (a green-on-retry build would mask nondeterminism).
  No network I/O to the dev backend occurs during the job. *Traces: AC-2, AC-7.*

### Coverage matrix

| Acceptance criterion (Section 14) | Covered by |
|---|---|
| AC-1 (workflow triggers, scope, runner, concurrency, perms) | TC-01, TC-07, TC-08, TC-09, TC-12 |
| AC-2 (single `gradlew assembleDebug testDebugUnitTest`, JDK17, wrapper validated, tasks in log) | TC-01, TC-05, TC-08, TC-13, TC-14 |
| AC-3 (Gradle caches restored/saved, read-only on PRs, keyed on hashed files) | TC-10, TC-11 |
| AC-4 (reproducible on fresh checkout, no local.properties) | TC-02 |
| AC-5 (test reports always uploaded, APK on success, non-empty test count) | TC-04, TC-05, TC-06 |
| AC-6 (failing test -> red, visible in report, revert -> green) | TC-04 |
| AC-7 (cleared cache still green) | TC-03, TC-14 |

Accessibility note: no UI is delivered by AND-008, so no Compose-UI/TalkBack cases
apply (Section 9). The gate established here is what downstream accessibility/
semantics unit tests will execute under.
