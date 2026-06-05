---
id: AND-050
title: "CI: unit tests"
milestone: M1
epic: E07
priority: P0
size: M
status: draft
depends_on: [AND-008, AND-047]
blocks: []
---

# AND-050 — CI: unit tests

## 1. Overview & Goal

Wire the Android module's JVM unit tests into the project's continuous-integration
pipeline so that every change to the `android-port` branch (and every PR targeting it)
runs the full `test*UnitTest` suite, fails the build on any test failure, and publishes
machine- and human-readable test results as build artifacts. AND-008 already established
a CI job on the `andrioiddev` build server that runs `assembleDebug` + `testDebugUnitTest`
and caches Gradle. AND-050 elevates unit testing from "runs as a side effect of build"
to a **first-class, gating, reported** quality check: deterministic, fast (JVM-only — no
emulator), and visible. The deliverable is the CI configuration plus the Gradle wiring
that makes test outcomes authoritative for merge decisions.

This ticket does **not** write new feature tests (those live in their owning tickets, e.g.
AND-047 `AuthRepository contract tests`). It guarantees that whatever unit tests exist —
across `app`, `feature-*`, and `core-*` modules — are discovered, executed, aggregated, and
gate the pipeline.

Concretely, "done" means: a developer pushes a commit that breaks a `core-network` Moshi
adapter test; CI turns red within minutes; the failing test name, class, stack trace, and
stdout are one click away from the build summary; and the PR cannot be marked green.

## 2. Context & References

- **Repo / branch:** `spannella/testlogon`, Android app under `android/` (monorepo
  subfolder), branch `android-port`. CI definitions live under the repo root in
  `.github/workflows/` (GitHub Actions is the canonical runner for this monorepo; the
  `andrioiddev` build server from AND-008 is the self-hosted executor).
- **Module layering:** `app -> feature-* -> core-*` (`core-network`, `core-model`,
  `core-ui`, `core-data`, `core-testing`). Each module owns a `src/test/` JVM source set.
  `core-testing` provides shared fakes/fixtures (Turbine, fake API, dispatcher rules).
- **Stack relevant here:** Kotlin 2.0.21, Gradle 8.9 wrapper, AGP 8.7.3, JDK 17, KSP for
  Hilt. Unit tests use JUnit4 + kotlinx-coroutines-test + Turbine + MockK/Robolectric where
  needed. Namespace base `com.testlogon.android`.
- **Upstream deps:**
  - **AND-008** — created the CI job (`assembleDebug` + `testDebugUnitTest`, Gradle cache,
    reproducible fresh-checkout build). AND-050 extends that workflow.
  - **AND-047** — `AuthRepository contract tests`: the first substantial unit-test suite
    this pipeline must keep green; used as the representative integration target for
    verifying the reporting path end-to-end.
- **No backend interaction.** This is a build/chore ticket; the FastAPI dev host
  (`http://18.222.237.167:8000`) is irrelevant — unit tests must never hit the network.
- **References:** Gradle `Test` task and `test-report-aggregation` plugin docs; AGP
  `testDebugUnitTest` task; `dorny/test-reporter` and `mikepenz/action-junit-report`
  GitHub Actions for JUnit XML surfacing; `gradle/actions/setup-gradle` for caching.

## 3. Functional Requirements

FR-1. **Run on every change.** The unit-test job triggers on: `push` to `android-port`,
`pull_request` targeting `android-port`, and `workflow_dispatch` (manual). Path filter
limits triggers to changes under `android/**` and the workflow file itself.

FR-2. **Full-suite execution.** The job runs all JVM unit tests across every module via a
single aggregating Gradle invocation (`./gradlew testDebugUnitTest` from `android/`), so a
newly added module's tests are picked up automatically with no workflow edit.

FR-3. **Fail the build on test failure.** Any failing or errored test causes a non-zero
Gradle exit and a failed CI job. `--continue` is used so all modules run even after the
first failure, but the job still ends red (Gradle preserves the failure exit code).

FR-4. **Publish results.** JUnit XML and HTML reports from every module are collected and
uploaded as a build artifact (always, even on failure), and a check/summary annotates the
PR with pass/fail counts and per-test failure details inline in the diff.

FR-5. **Deterministic & isolated.** Tests run JVM-only (no emulator/device). No network,
no real clock, no real Android framework unless via Robolectric. Flaky/nondeterministic
tests are a build defect, not an accepted condition.

FR-6. **Reproducible on fresh checkout.** A clean clone + the workflow produces identical
pass/fail outcomes (inherits AND-008's reproducibility requirement). Gradle and KSP caches
are restored but must not change correctness.

FR-7. **Fast feedback.** Target wall-clock for the unit-test job < 8 minutes warm-cache on
the `andrioiddev` executor. Configuration cache + build cache + parallel module execution
enabled.

## 4. Technical Design

### 4.1 Workflow file

`.github/workflows/android-unit-tests.yml`:

```yaml
name: Android Unit Tests
on:
  push:
    branches: [android-port]
    paths: ["android/**", ".github/workflows/android-unit-tests.yml"]
  pull_request:
    branches: [android-port]
    paths: ["android/**", ".github/workflows/android-unit-tests.yml"]
  workflow_dispatch:

concurrency:
  group: unit-tests-${{ github.ref }}
  cancel-in-progress: true

jobs:
  unit-tests:
    runs-on: [self-hosted, andrioiddev]
    timeout-minutes: 25
    defaults:
      run:
        working-directory: android
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-java@v4
        with: { distribution: temurin, java-version: "17" }
      - uses: gradle/actions/setup-gradle@v4
        with:
          cache-read-only: ${{ github.ref != 'refs/heads/android-port' }}
      - name: Run unit tests
        run: ./gradlew testDebugUnitTest mergedTestReport --continue --stacktrace
      - name: Upload reports
        if: ${{ always() }}
        uses: actions/upload-artifact@v4
        with:
          name: unit-test-reports
          path: |
            android/**/build/test-results/testDebugUnitTest/*.xml
            android/build/reports/allTests/**
          if-no-files-found: error
          retention-days: 14
      - name: Publish JUnit report
        if: ${{ always() }}
        uses: mikepenz/action-junit-report@v5
        with:
          report_paths: "android/**/build/test-results/testDebugUnitTest/*.xml"
          fail_on_failure: true
          require_tests: true
          check_name: "Unit Tests"
```

`fail_on_failure: true` and `require_tests: true` provide a second gate: the check fails if
any test failed **or** if zero tests were found (guards against a broken filter silently
reporting green).

### 4.2 Gradle aggregation

Add the `test-report-aggregation` plugin to a small aggregation point so a single
`mergedTestReport` task produces one cross-module HTML report at
`android/build/reports/allTests/`. In `android/build.gradle.kts` (root):

```kotlin
plugins {
    id("test-report-aggregation")
}

dependencies {
    subprojects.forEach { testReportAggregation(project(it.path)) }
}

tasks.register<org.gradle.api.tasks.testing.TestReport>("mergedTestReport") {
    destinationDirectory.set(layout.buildDirectory.dir("reports/allTests"))
    testResults.from(
        subprojects.map { it.layout.buildDirectory.dir("test-results/testDebugUnitTest") }
    )
}
```

### 4.3 Shared test conventions

Centralize JVM test config in the existing convention plugin (created in scaffolding,
applied by every module) under `android/build-logic/`:

```kotlin
// AndroidUnitTestConventionPlugin.kt (applied as "testlogon.android.unittest")
class AndroidUnitTestConventionPlugin : Plugin<Project> {
    override fun apply(target: Project) = with(target) {
        extensions.configure<com.android.build.api.dsl.CommonExtension<*, *, *, *, *, *>> {
            testOptions.unitTests.isReturnDefaultValues = true
            testOptions.unitTests.isIncludeAndroidResources = true
        }
        tasks.withType<Test>().configureEach {
            useJUnit()
            testLogging {
                events("passed", "skipped", "failed")
                exceptionFormat = org.gradle.api.tasks.testing.logging.TestExceptionFormat.FULL
                showStandardStreams = false
            }
            maxParallelForks =
                (Runtime.getRuntime().availableProcessors() / 2).coerceAtLeast(1)
            systemProperty("robolectric.logging", "stdout")
        }
    }
}
```

`gradle.properties` (already present from AND-008) must include
`org.gradle.caching=true`, `org.gradle.parallel=true`,
`org.gradle.configuration-cache=true`, and an explicit JVM heap (`-Xmx4g`).

## 5. API Contract

**N/A — no application/HTTP API surface.** This ticket touches only CI configuration and
Gradle build logic. The relevant "contract" is the CI artifact/check interface defined in
§4.1: the JUnit XML schema at `**/build/test-results/testDebugUnitTest/*.xml`, the merged
HTML report, and the `Unit Tests` GitHub check. Backend API contracts and their tests are
owned by feature/test tickets (e.g. AND-047 for the auth repository).

## 6. Data & State Management

No runtime application state. The "data" managed by this ticket is build-time:

- **Test result XML** — per-module JUnit XML under
  `<module>/build/test-results/testDebugUnitTest/`. Consumed by the publish action and the
  merged report. Treated as authoritative output; never committed.
- **Merged HTML report** — `android/build/reports/allTests/index.html`, uploaded as the
  `unit-test-reports` artifact.
- **Caches** — Gradle build cache, configuration cache, and KSP outputs restored via
  `gradle/actions/setup-gradle`. Cache keying is by Gradle files + lockfiles; cache is
  **read-write on `android-port`** pushes and **read-only on PRs** (prevents PR runs from
  poisoning the shared cache). Cache state must be non-load-bearing for correctness (FR-6).
- **No persistence between runs** beyond caches; each job starts from a clean checkout.

## 7. Error Handling & Resilience

- **Test failure** → Gradle exits non-zero → job red (FR-3). `--continue` runs all modules
  so one failure doesn't mask others; the aggregated report shows every failure at once.
- **Zero tests discovered** (e.g. a misconfigured filter or removed source set) → treated
  as failure via `require_tests: true`. This prevents a green build with no coverage.
- **Compilation failure in test sources** → Gradle fails the `compile*UnitTestKotlin` task;
  job red with the compiler error in the log; artifact upload still runs (`if: always()`).
- **Infrastructure flakiness** (executor offline, cache restore error) → job
  `timeout-minutes: 25` bounds hangs; `concurrency.cancel-in-progress` reaps superseded
  runs. Cache restore failures degrade gracefully to a cold build (slower, still correct).
- **Flaky tests** — no automatic retry is configured at the CI level; a flaky test is a
  bug to fix in its owning ticket. (If a quarantine mechanism is later needed, it is added
  via a Gradle test tag filter, tracked separately — see §13.)
- **Artifact upload with no files** → `if-no-files-found: error` surfaces a broken report
  path immediately rather than silently producing an empty artifact.

## 8. Security & Privacy

- **No secrets required.** Unit tests are offline and use fakes; the workflow declares no
  `secrets.*` and tests must not read credentials, cookies, or the `ui_csrf` token from
  any real source. Code review rejects any unit test that opens a socket.
- **Least-privilege token.** Workflow sets `permissions: { contents: read, checks: write,
  pull-requests: write }` — only what the JUnit check publisher needs; no write to repo
  contents.
- **Self-hosted runner hygiene.** The `andrioiddev` executor runs untrusted PR code; PR
  triggers use `cache-read-only` and the restricted token. Forked-PR auto-run should be
  gated by a maintainer approval policy (org/runner setting) so untrusted code cannot abuse
  the self-hosted runner — noted as an operational control, not application code.
- **No PII.** Test logs and reports contain only test names and stack traces; fixtures use
  synthetic data (e.g. `user@example.com`), never real user emails.

## 9. Accessibility & i18n

**N/A for runtime UI** — this ticket ships no user-facing app surface. The only "UI" is the
GitHub PR check and report. To keep that usable: the check is named `Unit Tests` (clear,
stable), failure annotations attach to the exact failing test in the diff, and the merged
HTML report is structured/semantic (Gradle default) so it is navigable. App-level
accessibility/i18n is owned by feature tickets and is itself a candidate for future unit
coverage (e.g. string-resource presence tests), but no such requirement is in this scope.

## 10. Telemetry & Logging

- **Build logs:** `--stacktrace` and `testLogging { exceptionFormat = FULL }` ensure full
  stack traces on failure; `showStandardStreams = false` keeps logs readable (per-test
  stdout is captured in the XML/HTML reports instead).
- **CI summary:** the JUnit publish step writes total/passed/failed/skipped counts and
  duration to the GitHub Step Summary and as a PR check, giving a trend-visible signal.
- **Artifacts:** XML + HTML retained 14 days for post-mortem of intermittent failures.
- **No runtime analytics.** No app telemetry SDK is involved. Build-server-level metrics
  (queue time, job duration) are provided by the CI platform and out of scope here.
- **Optional:** enable Gradle Build Scan (`--scan`) gated behind a non-PR condition for
  deeper diagnostics; left as an opt-in to avoid publishing PR build data externally.

## 11. Testing Strategy

This ticket's "tests" are validations of the pipeline itself; it does not author feature
unit tests.

1. **Green path** — On a clean `android-port` checkout with all existing suites passing,
   the workflow runs, reports N>0 tests, uploads a non-empty artifact, and the check is
   green. Verified using AND-047's `AuthRepository` suite as the representative target.
2. **Red path (assertion failure)** — Introduce a deliberately failing assertion in a
   `core-network` test on a throwaway branch/PR; confirm: job exits non-zero, check is red,
   the PR diff is annotated at the failing test, and the artifact still uploads.
3. **Red path (compile failure)** — Break a test source's compilation; confirm job red with
   compiler error and artifact step still executes (`if: always()`).
4. **Empty-suite guard** — Temporarily filter out all tests
   (`-Dtest.single=__none__` style or removed source set) and confirm `require_tests: true`
   fails the job rather than reporting green.
5. **New-module discovery** — Add a trivial new `core-*` stub module with one test; confirm
   it runs and appears in the merged report with no workflow edit (validates FR-2).
6. **Reproducibility** — Run twice (cold cache, then warm cache); identical pass/fail set;
   warm run under the 8-minute target (FR-6, FR-7).
7. **Determinism scan** — Run the suite 3× consecutively; zero flaps required to accept.

Acceptance for each validation is a linked CI run URL showing the expected outcome.

## 12. Dependencies & Sequencing

- **Depends on AND-008** (`CI: build + unit test on build server`) — provides the
  `andrioiddev` executor, Gradle caching, and the baseline `testDebugUnitTest` invocation
  this ticket promotes to a gating, reported job. Must merge first.
- **Depends on AND-047** (`AuthRepository contract tests`) — supplies the first substantial,
  deterministic suite used to validate the green-path reporting end-to-end. AND-050 can be
  wired before AND-047 lands but cannot be *verified* meaningfully without a real suite;
  sequence AND-047 ahead of final acceptance.
- **Blocks:** nothing formally, but is a de-facto gate for all subsequent test tickets in
  epic E07 and for branch-protection enabling required checks (operational follow-up).
- **Sequencing note:** enabling `Unit Tests` as a *required* status check in branch
  protection is the final step, done only after green-path is confirmed, so the gate is
  never enabled against a broken pipeline.

## 13. Risks & Open Questions

- **R1 — Self-hosted runner contention.** A single `andrioiddev` executor may queue under
  load. Mitigation: `concurrency` cancels superseded runs; consider a second runner label
  if queue time becomes the bottleneck. *Open:* runner count/SLA for PR throughput.
- **R2 — Flaky tests erode trust.** No retry policy is intentional (forces fixes), but a
  genuinely flaky third-party interaction could block merges. *Open:* do we want a tagged
  `@Flaky` quarantine lane (`./gradlew test -PexcludeTags=flaky`) with a separate
  non-gating job? Deferred unless flakes appear.
- **R3 — Configuration cache incompatibility.** Some AGP/KSP task combinations can break
  the configuration cache. Mitigation: cache is correctness-neutral; if it errors, disable
  `--configuration-cache` for the job without affecting test outcomes.
- **R4 — Robolectric in unit tests** can be slow and JDK-version sensitive. Pinned to JDK
  17 + `isIncludeAndroidResources = true`; revisit if startup cost dominates runtime.
- **Open Q1:** Is GitHub Actions the agreed CI surface for the monorepo, or does
  `andrioiddev` run a different orchestrator (Jenkins/Buildkite)? Spec assumes Actions with
  a self-hosted runner per AND-008; adjust the YAML if the orchestrator differs (the Gradle
  wiring in §4.2/§4.3 is orchestrator-independent and remains valid).
- **Open Q2:** Coverage reporting (JaCoCo/Kover) is intentionally out of scope; confirm it
  belongs to a later E07 ticket rather than here.

## 14. Acceptance Criteria

AC-1. A push to `android-port` and a PR targeting it both trigger the `Android Unit Tests`
job automatically; manual `workflow_dispatch` also works. (FR-1)

AC-2. The job executes **all** module unit tests via a single Gradle invocation; adding a
new module's tests requires no workflow change. (FR-2)

AC-3. Any failing or errored unit test causes the job to fail and the `Unit Tests` check to
be red; all modules still run (`--continue`) so failures aren't masked. (FR-3)

AC-4. JUnit XML + merged HTML reports upload as the `unit-test-reports` artifact on every
run (including failures), and PR diffs are annotated with per-test failure details. (FR-4)

AC-5. A run with zero discovered tests fails (not greens) via `require_tests`. (FR-4/§7)

AC-6. Tests run JVM-only with no network access; the run is deterministic across 3
consecutive executions (zero flaps) and reproducible on a fresh checkout. (FR-5, FR-6)

AC-7. Warm-cache job wall-clock is under 8 minutes on `andrioiddev`. (FR-7)

AC-8. The source-ticket criterion is met: **CI runs and reports unit tests on every
change**, demonstrated via linked green-path and red-path CI run URLs.

## 15. Definition of Done

- `.github/workflows/android-unit-tests.yml`, the root `mergedTestReport`/aggregation
  wiring, and the `testlogon.android.unittest` convention plugin are merged to
  `android-port`.
- All §11 validations executed with linked CI run URLs (green path, assertion-failure red
  path, compile-failure red path, empty-suite guard, new-module discovery, reproducibility,
  determinism ×3).
- All §14 acceptance criteria verified.
- `Unit Tests` enabled as a **required** status check in branch protection for
  `android-port` (after green-path confirmed).
- Workflow uses least-privilege `permissions`, declares no secrets, and PR runs are
  cache-read-only.
- Code reviewed and approved; no test opens a network socket (verified in review).
- Documentation: a short `android/CONTRIBUTING` note (or README section) describes how to
  reproduce the CI unit-test run locally (`./gradlew testDebugUnitTest mergedTestReport`)
  and where to find reports.
