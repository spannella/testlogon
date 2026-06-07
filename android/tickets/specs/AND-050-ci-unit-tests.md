---
id: AND-050
title: "CI: unit tests"
milestone: M1
epic: E07
priority: P0
size: M
status: reviewed
reviewed_on: 2026-06-06
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
- **References:** Gradle `Test` and `TestReport` task docs (the built-in
  `test-report-aggregation` plugin is *not* used — it requires the JVM Test Suite Plugin and
  does not support Android plugins; see §4.2 correction); AGP `testDebugUnitTest` task;
  `dorny/test-reporter` and `mikepenz/action-junit-report` GitHub Actions for JUnit XML
  surfacing; `gradle/actions/setup-gradle` for caching.

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

Produce one cross-module HTML report at `android/build/reports/allTests/` via a single
`mergedTestReport` task. **Correction (review):** Gradle's built-in
`test-report-aggregation` plugin is **not** used here — per the Gradle docs it "takes no
action unless applied in concert with the JVM Test Suite Plugin" and "does not currently
work with the `com.android.application` plugin." Android library/app modules apply
`com.android.library`/`com.android.application`, not `java`/`jvm-test-suite`, and their
results land under `testDebugUnitTest` rather than a JVM test suite, so the plugin's
synthesized `testAggregateTestReport` task would aggregate nothing. We therefore aggregate
manually with a plain `TestReport` task that points at each module's
`test-results/testDebugUnitTest` directory (the `binary-results-dir`, which `TestReport`
consumes). In `android/build.gradle.kts` (root):

```kotlin
tasks.register<org.gradle.api.tasks.testing.TestReport>("mergedTestReport") {
    destinationDirectory.set(layout.buildDirectory.dir("reports/allTests"))
    // TestReport.testResults consumes the binary results dirs, not the XML dirs.
    testResults.from(
        subprojects.map {
            it.layout.buildDirectory.dir("test-results/testDebugUnitTest/binary")
        }
    )
    // Ensure all module unit tests have run before aggregating.
    mustRunAfter(subprojects.map { "${it.path}:testDebugUnitTest" })
}
```

Note: `TestReport.getTestResults()` expects the **binary** results directories
(`.../test-results/<task>/binary`), not the JUnit XML. The XML files (consumed separately
by the GitHub publish step in §4.1) live one level up at
`.../test-results/testDebugUnitTest/*.xml`.

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

## 16. Citations & Assumption Audit

This is a CI/build-chore ticket with **no application HTTP API surface** (confirmed by §5).
Accordingly, there are no OpenAPI endpoint or frontend-DTO claims to verify; the
authoritative `openapi.index.txt` / `openapi.pretty.json` and `reference/src/**` sources
yielded no relevant endpoints (the only matches for `unit`/`test`/`ci` in the OpenAPI index
are incidental substrings inside unrelated paths). The verifiable claims here are
**framework/tooling facts** (Gradle, AGP, GitHub Actions), checked against vendor docs and
labelled `framework ref`.

1. **Claim:** A single `./gradlew testDebugUnitTest` invocation runs JVM unit tests across
   all modules and auto-discovers new modules (FR-2, §4.1, §4.2).
   **VERDICT: Verified.** `testDebugUnitTest` is the standard AGP-generated unit-test task
   per module; invoking it at the root with no module path makes Gradle run the
   same-named task in every subproject that defines it.
   **SOURCE:** framework ref — AGP/Gradle test task model
   (https://developer.android.com/studio/test/command-line and
   https://docs.gradle.org/current/userguide/java_testing.html).

2. **Claim (ORIGINAL, WRONG):** Apply the `test-report-aggregation` plugin so a single
   `mergedTestReport` task produces one cross-module HTML report.
   **VERDICT: Corrected.** The Gradle `test-report-aggregation` plugin "takes no action
   unless applied in concert with the JVM Test Suite Plugin" and "does not currently work
   with the `com.android.application` plugin." Android modules apply
   `com.android.library`/`com.android.application` and produce `testDebugUnitTest` results,
   not a JVM test suite, so the plugin would aggregate nothing. §4.2 now drops the plugin
   and uses a plain `TestReport` task pointed at each module's binary results dir.
   **SOURCE:** framework ref —
   https://docs.gradle.org/current/userguide/test_report_aggregation_plugin.html.

3. **Claim (ADDED in correction):** `TestReport.testResults` must point at the **binary**
   results directory (`.../test-results/testDebugUnitTest/binary`), not the XML directory.
   **VERDICT: Verified.** `TestReport.getTestResults()` consumes `binary-results-dir`
   outputs (`TestReport`/`Test.binaryResultsDirectory`); the human XML lives one level up.
   **SOURCE:** framework ref —
   https://docs.gradle.org/current/javadoc/org/gradle/api/tasks/testing/TestReport.html and
   `Test.getBinaryResultsDirectory()`.

4. **Claim:** `mikepenz/action-junit-report@v5` accepts `report_paths`, `fail_on_failure`,
   `require_tests`, and `check_name`; `require_tests: true` fails the run when zero tests
   are found and `fail_on_failure: true` fails on any test failure (§4.1, FR-4, §7, AC-5).
   **VERDICT: Verified.** All four inputs exist; `require_tests` = "Fail if no tests are
   found", `fail_on_failure` = "Fail the build in case of a test failure". (Defaults are
   false, so the spec's explicit `true` values are required — confirmed.)
   **SOURCE:** framework ref — https://github.com/mikepenz/action-junit-report (action
   inputs/README).

5. **Claim:** `report_paths` glob
   `android/**/build/test-results/testDebugUnitTest/*.xml` locates the per-module JUnit XML
   (§4.1, §6).
   **VERDICT: Verified.** AGP writes JUnit XML to
   `<module>/build/test-results/testDebugUnitTest/*.xml`; the action's `report_paths` takes
   a glob (its own default is `**/junit-reports/TEST-*.xml`, so the override is necessary).
   **SOURCE:** framework ref — AGP test-results layout
   (https://developer.android.com/studio/test/command-line) +
   https://github.com/mikepenz/action-junit-report.

6. **Claim:** `cache-read-only: ${{ github.ref != 'refs/heads/android-port' }}` makes
   pushes to `android-port` write the cache while PRs read-only (§4.1, §6).
   **VERDICT: Verified.** `gradle/actions/setup-gradle` writes the cache only on the repo's
   default branch by default; the documented way to let another long-lived branch write is
   to override `cache-read-only`. Since `android-port` (not `main`) is the integration
   branch here, this override is the correct mechanism and yields the intended
   write-on-android-port / read-only-on-PR behavior.
   **SOURCE:** framework ref —
   https://github.com/gradle/actions/blob/main/docs/setup-gradle.md (caching section).

7. **Claim:** `actions/upload-artifact@v4` with `if: always()` and
   `if-no-files-found: error` uploads reports on success and failure and fails the step if
   the report path matched nothing (§4.1, §7).
   **VERDICT: Verified.** `if-no-files-found` supports `warn` | `error` | `ignore`;
   `if: always()` is standard GitHub Actions step conditioning.
   **SOURCE:** framework ref — https://github.com/actions/upload-artifact (inputs) +
   https://docs.github.com/actions/learn-github-actions/expressions (`always()`).

8. **Claim:** `--continue` runs all modules even after a failure yet the build still exits
   non-zero (FR-3, AC-3).
   **VERDICT: Verified.** Gradle `--continue` executes every task not dependent on the
   failed one and still reports a non-zero exit at the end.
   **SOURCE:** framework ref —
   https://docs.gradle.org/current/userguide/command_line_interface.html (`--continue`).

9. **Claim:** `testOptions.unitTests.isReturnDefaultValues` and
   `isIncludeAndroidResources` are valid AGP unit-test options (§4.3).
   **VERDICT: Verified.** Both are members of AGP's `TestOptions.UnitTestOptions`.
   **SOURCE:** framework ref —
   https://developer.android.com/reference/tools/gradle-api/current/com/android/build/api/dsl/UnitTestOptions
   and https://developer.android.com/training/testing/local-tests.

10. **Claim:** Robolectric requires `isIncludeAndroidResources = true` and is JDK-version
    sensitive (pinned JDK 17) (§4.3, R4).
    **VERDICT: Verified.** Robolectric's AGP guidance requires
    `includeAndroidResources = true`; JDK 17 is supported by current Robolectric.
    **SOURCE:** framework ref — http://robolectric.org/getting-started/.

11. **Claim:** "No backend interaction; unit tests must never hit the network; the FastAPI
    dev host `http://18.222.237.167:8000` is irrelevant" (§2, §8, FR-5).
    **VERDICT: Verified (scope claim).** Consistent with the ticket scope (CI chore) and
    §5's N/A API contract; nothing in the OpenAPI/frontend sources contradicts it.
    **SOURCE:** ticket scope (specs-src/AND-050.md) + spec §5.

12. **Claim:** Toolchain versions — Kotlin 2.0.21, Gradle 8.9, AGP 8.7.3, JDK 17, KSP for
    Hilt (§2).
    **VERDICT: Unverified-assumption.** These are inherited from scaffolding/AND-008 and
    are not checkable from the provided sources (no Android project, version catalog, or
    `gradle-wrapper.properties` is present in this plan repo). Mutually compatible per
    public compatibility matrices, but the exact pinned values cannot be confirmed here.
    **SOURCE:** inherited from AND-008 (not present in this repo) — see Open assumptions.

13. **Claim:** AND-008 already created a CI job running `assembleDebug` +
    `testDebugUnitTest` on a self-hosted `andrioiddev` runner with Gradle caching; GitHub
    Actions is the canonical runner (§1, §2, §12).
    **VERDICT: Unverified-assumption.** Cross-ticket dependency; AND-008's artifacts are
    not in the provided sources. Open Q1 in §13 already flags the orchestrator assumption.
    **SOURCE:** AND-008 (not provided) — see Open assumptions.

14. **Claim:** AND-047 supplies the representative `AuthRepository` unit suite used to
    validate the green path (§2, §11, §12).
    **VERDICT: Unverified-assumption.** AND-047 is a separate ticket not in the provided
    sources; its existence/shape can't be verified here (the *backend* auth contract it
    targets does exist in the OpenAPI index, but that does not confirm the AND-047 suite).
    **SOURCE:** AND-047 (not provided) — see Open assumptions.

15. **Claim:** `concurrency: { group: unit-tests-${{ github.ref }}, cancel-in-progress:
    true }` reaps superseded runs (§4.1, §7, R1).
    **VERDICT: Verified.** Standard GitHub Actions concurrency semantics; per-ref grouping
    cancels the older in-flight run on the same ref.
    **SOURCE:** framework ref —
    https://docs.github.com/actions/using-jobs/using-concurrency.

16. **Claim:** Least-privilege `permissions: { contents: read, checks: write,
    pull-requests: write }` is sufficient for the JUnit check publisher (§8).
    **VERDICT: Verified.** `mikepenz/action-junit-report` creates a check run (needs
    `checks: write`) and annotates PRs (`pull-requests: write`); it does not write repo
    contents.
    **SOURCE:** framework ref — https://github.com/mikepenz/action-junit-report (required
    permissions) + https://docs.github.com/actions/security-guides/automatic-token-authentication.

### Corrections made

- **§4.2 (Citation 2):** Removed the `plugins { id("test-report-aggregation") }` block and
  the `testReportAggregation(...)` dependency wiring. That plugin requires the JVM Test
  Suite Plugin and explicitly does not support Android plugins, so it would have aggregated
  nothing for `testDebugUnitTest` results. Replaced with a self-contained `TestReport` task.
- **§4.2 (Citation 3):** Corrected the aggregation source path — `TestReport.testResults`
  consumes the **binary** results dir (`.../test-results/testDebugUnitTest/binary`), not the
  XML dir. Added a `mustRunAfter(... :testDebugUnitTest)` ordering so the merged report is
  built after the tests run within the single §4.1 Gradle invocation.
- **§2 References:** Updated to state the `test-report-aggregation` plugin is intentionally
  not used and to reference the `TestReport` task instead, keeping §2 consistent with §4.2.

### Open assumptions

- **Toolchain pins (Citation 12):** Kotlin/Gradle/AGP/JDK/KSP versions are inherited from
  scaffolding and AND-008; no Android project files exist in this plan repo to confirm them.
  *Why unverifiable:* the authoritative sources are the backend OpenAPI and the web frontend
  reference, neither of which contains the Android build configuration.
- **AND-008 CI baseline (Citation 13):** existence/shape of the prior CI job, the
  `andrioiddev` self-hosted runner, and that GitHub Actions (not Jenkins/Buildkite) is the
  orchestrator. *Why unverifiable:* AND-008 is a separate ticket not provided; §13 Open Q1
  already records this and notes the §4.2/§4.3 Gradle wiring is orchestrator-independent.
- **AND-047 suite (Citation 14):** that AND-047 lands a deterministic `AuthRepository` unit
  suite usable as the green-path target. *Why unverifiable:* AND-047 is not in the provided
  sources; this spec can be wired before it but cannot be fully *verified* without it (§12
  sequencing note).
- **Default-branch identity:** the override in Citation 6 assumes `main`/`master` is the
  repo default while `android-port` is the long-lived integration branch. If `android-port`
  were itself the default branch, the `cache-read-only` expression would still be correct
  but redundant. *Why unverifiable:* repo branch settings are not in the provided sources.

## 17. Test Plan

These cases validate the **pipeline itself** (this ticket authors no feature unit tests).
Most are CI/infra validations executed on the self-hosted `andrioiddev` GitHub Actions
runner; the local-reproducibility case runs on a developer/JVM host. No Android device or
emulator is required for the JVM unit suite, so the headless `test35` emulator and the
physical Galaxy A15 are **not used** here — this ticket is JVM-only by design (FR-5); they
remain reserved for the instrumented/hardware tickets elsewhere in E07. Where a case asserts
Gradle behavior in isolation, it runs as a JVM-local check; where it asserts GitHub-check
surfacing, it runs as an integration test against a throwaway branch/PR.

- **TC-AND-050-01 — Triggers fire on push, PR, and manual dispatch**
  - Type: integration (CI)
  - Test target: `andrioiddev` self-hosted runner (GitHub Actions).
  - Preconditions: workflow `android-unit-tests.yml` merged; default-branch cache exists.
  - Steps: (a) push a no-op commit under `android/**` to `android-port`; (b) open a PR
    targeting `android-port` touching `android/**`; (c) trigger `workflow_dispatch` from the
    Actions UI; (d) push a commit touching only a path outside `android/**` and the workflow
    file.
  - Expected: the `Android Unit Tests` job runs for (a), (b), (c); (d) does **not** trigger
    it (path filter). Concurrency cancels a superseded earlier run on the same ref.
  - Traces: AC-1.

- **TC-AND-050-02 — Full-suite execution & new-module auto-discovery**
  - Type: integration (CI) + JVM-local sanity
  - Test target: `andrioiddev` runner; also reproducible JVM-local.
  - Preconditions: multi-module project with ≥2 modules owning unit tests.
  - Steps: confirm `./gradlew testDebugUnitTest` runs every module's tests; add a trivial
    new `core-sample` module with one passing test; re-run the workflow with **no** workflow
    edit.
  - Expected: all modules' tests execute under one invocation; the new module's test runs
    and appears in the merged `allTests` report; no `.yml` change needed.
  - Traces: AC-2.

- **TC-AND-050-03 — Failing test fails the job and the check (red path)**
  - Type: integration (CI)
  - Test target: `andrioiddev` runner.
  - Preconditions: green baseline.
  - Steps: on a throwaway branch/PR, add a deliberately failing assertion in a
    `core-network` test; run the workflow.
  - Expected: Gradle exits non-zero; job is red; `Unit Tests` check is red
    (`fail_on_failure: true`); other modules still ran (`--continue`) and their results are
    present; the PR diff is annotated at the failing test line.
  - Traces: AC-3, AC-4.

- **TC-AND-050-04 — Reports upload + PR annotation on success and failure**
  - Type: integration (CI)
  - Test target: `andrioiddev` runner.
  - Preconditions: TC-01 baseline plus the red-path branch from TC-03.
  - Steps: inspect the `unit-test-reports` artifact and the Step Summary on (a) a green run
    and (b) the TC-03 red run.
  - Expected: artifact contains per-module JUnit XML
    (`**/build/test-results/testDebugUnitTest/*.xml`) and the merged HTML
    (`build/reports/allTests/**`) on **both** runs (`if: always()`); Step Summary shows
    total/passed/failed/skipped counts; PR check annotations present.
  - Traces: AC-4.

- **TC-AND-050-05 — Compile failure in test sources fails red, artifact step still runs**
  - Type: integration (CI)
  - Test target: `andrioiddev` runner.
  - Preconditions: green baseline.
  - Steps: introduce a Kotlin compile error in a `src/test/` source; run the workflow.
  - Expected: `compile*UnitTestKotlin` fails; job red with the compiler error in the log;
    `upload-artifact` step still executes (`if: always()`); job stays red.
  - Traces: AC-3, AC-4.

- **TC-AND-050-06 — Empty-suite guard fails (does not green)**
  - Type: integration (CI)
  - Test target: `andrioiddev` runner.
  - Preconditions: green baseline.
  - Steps: temporarily make discovery find zero tests (e.g. a filter excluding all, or a
    removed test source set); run the workflow.
  - Expected: `mikepenz/action-junit-report` with `require_tests: true` fails the check even
    though no test technically "failed"; job is red — not a silent green.
  - Traces: AC-5.

- **TC-AND-050-07 — JVM-only, no network access (security/isolation)**
  - Type: unit / contract (offline enforcement)
  - Test target: JVM-local + `andrioiddev` runner.
  - Preconditions: suite present; ability to run with outbound network blocked (firewall/no
    egress on the runner step, or a `SecurityManager`/socket-deny test rule).
  - Steps: run `./gradlew testDebugUnitTest` with outbound network disabled; grep the suite
    for socket/`OkHttp` real-call usage in review.
  - Expected: suite passes with no network; any test attempting a real socket fails fast;
    code review rejects sockets in unit tests. No emulator/device involved.
  - Traces: AC-6 (security facet).

- **TC-AND-050-08 — Determinism: 3× consecutive runs, zero flaps**
  - Type: integration (CI)
  - Test target: `andrioiddev` runner.
  - Preconditions: green baseline.
  - Steps: run the workflow 3 times consecutively on the same commit (warm cache).
  - Expected: identical pass/fail set all 3 runs; zero flaky flaps (no retry policy
    configured, so a flap would show).
  - Traces: AC-6.

- **TC-AND-050-09 — Reproducibility on fresh checkout (cold vs warm cache)**
  - Type: integration (CI) + JVM-local
  - Test target: `andrioiddev` runner (cold cache via cache bust) and a clean local clone.
  - Preconditions: none beyond a clean clone.
  - Steps: run once cold (no cache), once warm; also run on a fresh local clone with
    `./gradlew testDebugUnitTest mergedTestReport`.
  - Expected: identical pass/fail outcome regardless of cache state (cache is
    correctness-neutral); local outcome matches CI.
  - Traces: AC-6.

- **TC-AND-050-10 — Warm-cache wall-clock under 8 minutes**
  - Type: integration (CI, performance)
  - Test target: `andrioiddev` runner.
  - Preconditions: warm Gradle/config/build cache present.
  - Steps: run the job and read the job duration from the Actions timing.
  - Expected: unit-test job wall-clock < 8 min warm-cache; within `timeout-minutes: 25`.
  - Traces: AC-7.

- **TC-AND-050-11 — Cache scoping: write on `android-port`, read-only on PR (security)**
  - Type: integration (CI, security)
  - Test target: `andrioiddev` runner.
  - Preconditions: setup-gradle caching enabled.
  - Steps: inspect setup-gradle logs on a push to `android-port` vs on a PR run.
  - Expected: push to `android-port` writes the cache; PR run is `cache-read-only` (the
    `github.ref != 'refs/heads/android-port'` expression evaluates true on PRs), so PR runs
    cannot poison the shared cache.
  - Traces: AC-6 (reproducibility/isolation), §8 security control.

- **TC-AND-050-12 — Least-privilege token & no secrets (security)**
  - Type: manual (config audit) + integration
  - Test target: workflow YAML + a live run.
  - Preconditions: workflow merged.
  - Steps: audit the workflow for `permissions:` (`contents: read`, `checks: write`,
    `pull-requests: write`) and absence of any `secrets.*`; confirm the publish step still
    posts the check with that token.
  - Expected: no `secrets.*` referenced; token cannot write repo contents; check
    publication succeeds with the restricted permissions; forked-PR auto-run gated by
    maintainer approval (runner/org policy).
  - Traces: AC-6 (security facet), §8.

- **TC-AND-050-13 — Merged report check is usable/accessible (a11y of the only "UI")**
  - Type: manual (accessibility review)
  - Test target: GitHub `Unit Tests` check + merged HTML report.
  - Preconditions: a completed run (green and red).
  - Steps: verify the check name is the stable `Unit Tests`; failure annotations attach to
    the exact failing test in the diff; open the merged `index.html` and confirm it is
    navigable/semantic (headings, links, no color-only signaling of pass/fail).
  - Expected: check is clearly named; annotations are precise; report is keyboard-navigable
    and not reliant on color alone to convey status.
  - Traces: AC-4 (reporting clarity), §9.

- **TC-AND-050-14 — Source-ticket criterion end-to-end (green + red URLs)**
  - Type: integration/e2e (CI)
  - Test target: `andrioiddev` runner.
  - Preconditions: TC-01..03 complete.
  - Steps: capture a linked green-path run URL and a linked red-path run URL demonstrating
    "CI runs and reports unit tests on every change."
  - Expected: both URLs exist and show the expected outcomes; once green-path is confirmed,
    `Unit Tests` is enabled as a **required** status check in branch protection.
  - Traces: AC-8.

### Coverage matrix

| Acceptance criterion | Covered by |
|---|---|
| AC-1 (triggers: push/PR/dispatch, path filter) | TC-AND-050-01 |
| AC-2 (single invocation runs all modules; new module auto-discovered) | TC-AND-050-02 |
| AC-3 (failing/errored test → job & check red; `--continue`) | TC-AND-050-03, TC-AND-050-05 |
| AC-4 (XML+HTML artifact always; PR annotations) | TC-AND-050-04, TC-AND-050-03, TC-AND-050-05, TC-AND-050-13 |
| AC-5 (zero discovered tests fails via `require_tests`) | TC-AND-050-06 |
| AC-6 (JVM-only, no network; deterministic ×3; reproducible) | TC-AND-050-07, TC-AND-050-08, TC-AND-050-09, TC-AND-050-11, TC-AND-050-12 |
| AC-7 (warm-cache < 8 min) | TC-AND-050-10 |
| AC-8 (source criterion; green+red URLs) | TC-AND-050-14 |
