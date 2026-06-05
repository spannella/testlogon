---
id: AND-005
title: Lint, format & static analysis
milestone: M1 (Auth Foundation)
epic: E01 (Project scaffolding & build tooling)
priority: P1
size: S
status: draft
depends_on: [AND-001]
blocks: [AND-006]
---

# AND-005 — Lint, format & static analysis

## 1. Overview & Goal

Establish the automated code-quality gate for the native Android port of TestLogon. This
ticket wires three complementary tools into the Gradle build so that every Kotlin source
file in `android/` is held to a single, machine-enforced standard:

- **Spotless** (driving **ktlint**) — deterministic *formatting*: import ordering, indentation,
  trailing whitespace, blank-line rules, and license headers. Spotless can both verify
  (`spotlessCheck`) and auto-fix (`spotlessApply`).
- **detekt** — *static analysis*: code smells, complexity, potential bugs, naming, and
  Compose-specific anti-patterns via the detekt-compose rule set.
- **Android Lint** is configured for baseline consistency (severity overrides) but is owned
  primarily by the per-module application/library plugins; this ticket only normalizes its
  config so CI (AND-006) can invoke it. Full Lint policy tuning is deferred to AND-006.

The deliverable is implementation-only build tooling: no application or feature code is
added. Success is a single command — `./gradlew spotlessCheck detekt` — running **clean**
against the existing scaffold (`:app`, `:core-*` from AND-001/AND-003 as they exist), with
the setup, conventions, and developer workflow documented in `android/README.md`.

**Success in one line:** a fresh clone of `android-port` runs `./gradlew spotlessCheck detekt`
green with zero violations, and a developer can auto-fix formatting with `./gradlew spotlessApply`.

This ticket is the precondition for AND-006 (CI), which will fail the pipeline on any
non-zero exit from these tasks. It depends on AND-001 (Gradle skeleton + `libs.versions.toml`
version catalog), where all plugin/library versions are pinned.

## 2. Context & References

**Repo / branch.** `spannella/testlogon`, Android app under `android/` (monorepo subfolder),
branch `android-port`. Canonical namespace base everywhere a package appears:
`com.testlogon.android`.

**Toolchain (from AND-001, authoritative).** Kotlin 2.0.21, Gradle 8.9 wrapper, AGP 8.7.3,
JDK 17, compileSdk/targetSdk 35, minSdk 24, KSP-based Hilt. All versions are declared in the
Gradle **version catalog** `android/gradle/libs.versions.toml`; this ticket adds entries there
rather than hard-coding versions in build scripts.

**Module layering (from AND-003).** `:app -> feature-* -> core-*` (`core-network`,
`core-model`, `core-ui`, `core-data`, `core-testing`). The quality plugins must apply uniformly
to every Kotlin module via a convention plugin or root-level subprojects configuration, so new
feature/core modules inherit the gate automatically.

**Web reference / backend.** Not consumed by this ticket. The FastAPI/DynamoDB backend
(`http://18.222.237.167:8000`) and the React reference app under `frontend/` are irrelevant to
formatting/static-analysis tooling and are listed only for cross-spec consistency.

**Tool versions (pin in catalog).** Spotless Gradle plugin `6.25.0`, ktlint engine `1.3.1`,
detekt `1.23.7` (with `detekt-formatting` and the `io.nlopez.compose.rules:detekt` Compose
rule set `0.4.16`). These are the latest stable lines compatible with Kotlin 2.0.21 / Gradle 8.9
as of this spec; exact pins live in `libs.versions.toml`.

## 3. Functional Requirements

FR-1. **Spotless integration.** Apply Spotless to every Kotlin module. Configure a `kotlin {}`
target (all `**/*.kt`, excluding generated and build dirs) using ktlint `1.3.1`, and a
`kotlinGradle {}` target for `*.gradle.kts` files.

FR-2. **License/format conventions.** Enforce ktlint's standard + experimental rule set with
explicit `.editorconfig`-driven overrides (see §6). No license header is mandated for v1 (the
repo carries a top-level license); Spotless `licenseHeader` is left unconfigured but documented
as the extension point.

FR-3. **Auto-fix task.** `./gradlew spotlessApply` rewrites all violations in place. This is the
documented developer pre-commit workflow.

FR-4. **Verify task.** `./gradlew spotlessCheck` fails the build (non-zero exit) on any
formatting deviation and prints the offending file:line plus a hint to run `spotlessApply`.

FR-5. **detekt integration.** Apply detekt to every Kotlin module with a single shared
config file `android/config/detekt/detekt.yml`. Include `detekt-formatting` and the Compose
rule set. `./gradlew detekt` aggregates across modules and fails on any issue above the
configured threshold.

FR-6. **detekt baseline (empty).** Generate and commit an **empty** baseline
`android/config/detekt/baseline.xml` so the mechanism exists and is documented, but the
scaffold must pass with **no** suppressed issues (acceptance requires a genuinely clean run,
not a baseline that hides debt).

FR-7. **Type resolution.** detekt runs with full type resolution (`detektMain`/per-variant
classpath tasks) enabled where rules require it, OR explicitly documents that the aggregate
`detekt` task runs without type resolution and which rules are consequently disabled. Default:
the lightweight `detekt` task (no type resolution) is the gate; the heavier `detektMain` is
available but not required by acceptance.

FR-8. **Uniform application.** Adding a new Kotlin module requires **zero** extra wiring to be
covered — achieved via a root `subprojects {}` block or, preferably, a `buildSrc`/convention
plugin `com.testlogon.android.quality`. Convention plugin is preferred for parity with the
AND-001 catalog approach; `subprojects {}` is the acceptable minimum.

FR-9. **Android Lint normalization.** Provide a shared `android/config/lint/lint.xml` and apply
`lint { baseline = ...; abortOnError = true }` defaults in the convention plugin. Tuning the
specific rule severities is explicitly deferred to AND-006; this ticket only ensures the config
file exists and is referenced so it does not block formatting/detekt.

FR-10. **Documentation.** `android/README.md` gains a "Code Quality" section documenting the
tools, the four commands, the config file locations, the pre-commit recommendation, and how to
regenerate the detekt baseline.

## 4. Technical Design

**Version catalog additions** (`android/gradle/libs.versions.toml`):

```toml
[versions]
spotless = "6.25.0"
ktlint   = "1.3.1"
detekt   = "1.23.7"
detektCompose = "0.4.16"

[plugins]
spotless = { id = "com.diffplug.spotless", version.ref = "spotless" }
detekt   = { id = "io.gitlab.arturbosch.detekt", version.ref = "detekt" }

[libraries]
detekt-formatting    = { module = "io.gitlab.arturbosch.detekt:detekt-formatting", version.ref = "detekt" }
detekt-compose-rules = { module = "io.nlopez.compose.rules:detekt", version.ref = "detektCompose" }
```

**Preferred: convention plugin.** Add `android/build-logic/` (an included build) or `buildSrc/`
with a precompiled script plugin:

```kotlin
// android/build-logic/convention/src/main/kotlin/com/testlogon/android/quality.gradle.kts
import com.diffplug.gradle.spotless.SpotlessExtension
import io.gitlab.arturbosch.detekt.Detekt
import io.gitlab.arturbosch.detekt.extensions.DetektExtension

plugins {
    id("com.diffplug.spotless")
    id("io.gitlab.arturbosch.detekt")
}

extensions.configure<SpotlessExtension> {
    kotlin {
        target("src/**/*.kt")
        targetExclude("**/build/**", "**/generated/**")
        ktlint(libs.versions.ktlint.get())
            .editorConfigOverride(
                mapOf("ktlint_standard_filename" to "disabled"),
            )
        trimTrailingWhitespace()
        endWithNewline()
    }
    kotlinGradle {
        target("*.gradle.kts")
        ktlint(libs.versions.ktlint.get())
    }
}

extensions.configure<DetektExtension> {
    config.setFrom(rootProject.file("config/detekt/detekt.yml"))
    baseline = rootProject.file("config/detekt/baseline.xml")
    parallel = true
    buildUponDefaultConfig = true
    autoCorrect = false
}

dependencies {
    add("detektPlugins", libs.detekt.formatting)
    add("detektPlugins", libs.detekt.compose.rules)
}

tasks.withType<Detekt>().configureEach {
    jvmTarget = "17"
    reports {
        html.required.set(true)
        sarif.required.set(true) // consumed by CI (AND-006)
        xml.required.set(false)
        txt.required.set(false)
    }
}
```

(`libs` is referenced inside build-logic via the standard
`the<org.gradle.accessors.dm.LibrariesForLibs>()` accessor; if `buildSrc` is chosen instead of
an included build, the catalog accessor is wired the same way.)

Each Kotlin module then adds a single line:

```kotlin
// android/app/build.gradle.kts (and every core-*/feature-* module)
plugins {
    id("com.testlogon.android.quality")
}
```

**Acceptable minimum (no convention plugin).** If build-logic is out of scope for the
timeframe, apply via the root script:

```kotlin
// android/build.gradle.kts
plugins {
    alias(libs.plugins.spotless) apply false
    alias(libs.plugins.detekt) apply false
}

subprojects {
    apply(plugin = "com.diffplug.spotless")
    apply(plugin = "io.gitlab.arturbosch.detekt")
    // identical spotless/detekt configuration as above
}
```

**Aggregate task.** Both approaches yield top-level `spotlessCheck`, `spotlessApply`, and
`detekt` lifecycle tasks that fan out across modules. The acceptance command
`./gradlew spotlessCheck detekt` invokes both.

**No application code.** This ticket touches only `*.gradle.kts`, `libs.versions.toml`,
`.editorconfig`, `config/detekt/*`, `config/lint/lint.xml`, and `README.md`. Any `.kt` changes
are limited to whatever reformatting `spotlessApply` produces on the existing scaffold so that
`spotlessCheck` passes.

## 5. API Contract

**N/A — no runtime API surface.** This is a pure build/chore ticket; it introduces no network
calls, endpoints, or serializable DTOs. The FastAPI cookie-based auth contract
(`POST /ui/session/start`, `/ui/mfa/*`, `/ui/session/finalize`, `GET /ui/me`, `X-CSRF-Token`)
is owned by the M1 networking tickets (AND-008 onward) and is unaffected here.

The only "contract" this ticket exposes is the **Gradle task interface** consumed by AND-006:

| Task | Inputs | Behavior | Exit |
| --- | --- | --- | --- |
| `spotlessCheck` | all `**/*.kt`, `*.gradle.kts` | verify formatting | non-zero on any deviation |
| `spotlessApply` | same | rewrite in place | zero (always, barring IO error) |
| `detekt` | all `**/*.kt` + `detekt.yml` + `baseline.xml` | static analysis | non-zero on any non-baselined issue |

Report artifacts (machine-consumable): detekt `build/reports/detekt/detekt.sarif` and
`detekt.html` per module; Spotless emits diffs to stdout. AND-006 uploads the SARIF.

## 6. Data & State Management

No runtime data, persistence, or Compose state. The "state" managed by this ticket is the set
of **configuration files** that define the rules and the build's expectations.

**`.editorconfig`** (repo `android/.editorconfig`) — the single source of truth shared by
ktlint (via Spotless), detekt-formatting, and IDEs:

```ini
root = true

[*.{kt,kts}]
charset = utf-8
indent_style = space
indent_size = 4
max_line_length = 120
insert_final_newline = true
ktlint_code_style = ktlint_official
ktlint_standard_import-ordering = enabled
ktlint_standard_no-wildcard-imports = enabled
ktlint_function_naming_ignore_when_annotated_with = Composable, Test
```

**`android/config/detekt/detekt.yml`** — `buildUponDefaultConfig: true`; key explicit settings:
`complexity.LongMethod.threshold: 60`, `complexity.TooManyFunctions` enabled,
`style.MagicNumber` enabled with `ignoreEnums/ignoreNumbers` defaults, `style.WildcardImport`
enabled, `formatting` ruleset active. Compose rules enabled:
`Compose:ComposableNaming`, `Compose:ParameterNaming`, `Compose:ModifierMissing`,
`Compose:MutableParams`, `Compose:UnstableCollections`. Naming aligned to the function-naming
override so `@Composable fun HomeScreen()` (PascalCase) does not trip `FunctionNaming`.

**`android/config/detekt/baseline.xml`** — committed but **empty** (`<SmellBaseline>` with no
`<ID>` entries). Regenerate via `./gradlew detektBaseline` only when accepting pre-existing
debt; the scaffold must not need it.

**`android/config/lint/lint.xml`** — placeholder severity map (referenced by convention
plugin); detailed policy deferred to AND-006.

## 7. Error Handling & Resilience

"Errors" here are build failures, which are the *intended* signal. Requirements:

- **Deterministic exit codes.** Any violation -> non-zero exit so CI (AND-006) can gate. Clean
  scaffold -> zero exit.
- **Actionable messages.** Spotless failure output must include the file, the diff, and the
  remediation hint (`Run './gradlew spotlessApply'`). detekt failures must include rule id,
  file:line, and the report path.
- **No flakiness.** Tasks must be deterministic and cacheable. Configure
  `parallel = true` for detekt and rely on Gradle's up-to-date checks; pin all versions via the
  catalog so results never drift between machines or the Ubuntu build server.
- **Offline-capable.** All plugins/deps resolve from the standard Gradle/Maven Central
  configuration established in AND-001; no tool downloads at task time beyond normal dependency
  resolution. Tasks must succeed with `--offline` after a warm cache.
- **Graceful interop with KSP/Hilt generated code.** `targetExclude`/detekt `excludes` must
  cover `**/build/**` and generated KSP output so generated Hilt/Moshi code never trips the gate.

## 8. Security & Privacy

Minimal surface. No user data, credentials, network, or PII is involved. Considerations:

- **Supply chain.** Spotless, ktlint, detekt, and the Compose rule set are added as build-time
  plugins/dependencies. Versions are pinned in `libs.versions.toml` (no dynamic `+` versions) to
  prevent silent upgrades. Where AND-001 has established dependency verification
  (`gradle/verification-metadata.xml`), the new artifacts' checksums are added.
- **detekt as a guardrail.** The detekt config keeps potential-bug rules
  (`potential-bugs` ruleset, e.g. `ExplicitGarbageCollectionCall`, `UnsafeCast`) enabled so the
  static analyzer also catches a class of security-adjacent smells in later feature code.
- **No secrets in config.** Config files contain no tokens; nothing in this ticket reads the
  backend, cookie jar, or `ui_csrf` handling.

## 9. Accessibility & i18n

**N/A for runtime UI** — this ticket produces no user-facing screens or strings, so there is
nothing to localize or make accessible at runtime.

Tooling note: the detekt Compose rule set indirectly supports later accessibility work by
flagging Compose anti-patterns (e.g. `ModifierMissing`), which downstream UI tickets (AND-0xx
feature tickets) leverage when adding `contentDescription`/semantics. No `strings.xml` or
locale handling is introduced here.

## 10. Telemetry & Logging

No runtime telemetry (no app code). Build-time observability only:

- **Report artifacts.** detekt emits HTML (human) and SARIF (machine) reports per module under
  `build/reports/detekt/`. SARIF is the integration point for AND-006, which uploads it to the
  CI code-scanning surface and annotates PRs.
- **Console output.** Spotless and detekt log violation counts and the report path on failure.
- **Build scans (optional).** If Gradle build scans are enabled in AND-001, the quality tasks
  appear in the scan timeline; no extra wiring required.

## 11. Testing Strategy

This ticket has no unit-testable production code; "tests" are reproducible verifications of the
gate itself.

1. **Clean-run verification (acceptance).** On a fresh checkout of `android-port`,
   `./gradlew spotlessCheck detekt` exits 0 with no violations across all existing modules.

2. **Positive-detection verification.** Temporarily introduce a deliberate violation
   (e.g. a wildcard import `import com.testlogon.android.*` and an over-long method) in a scratch
   file; confirm `spotlessCheck` and `detekt` each fail with non-zero exit and a clear message;
   revert. This proves the gate is not a no-op. Document the procedure in the PR description.

3. **Auto-fix verification.** Run a misformatted file through `./gradlew spotlessApply`; confirm
   it is rewritten and a subsequent `spotlessCheck` passes.

4. **New-module coverage.** Add a throwaway empty `:core-scratch` module containing one `.kt`
   file with a violation; confirm it is caught **without** editing the convention plugin
   (proves uniform application per FR-8); remove the module.

5. **Offline/determinism.** With a warm cache, `./gradlew spotlessCheck detekt --offline` passes;
   running twice yields identical results (cache/up-to-date behavior).

6. **Build-server parity.** The same command passes on the Ubuntu build server (JDK 17,
   SDK 35) exactly as locally.

No instrumentation tests, no Robolectric, no `core-testing` consumption — those belong to
feature tickets.

## 12. Dependencies & Sequencing

**Depends on:** AND-001 (Gradle skeleton, wrapper 8.9, AGP 8.7.3, `libs.versions.toml`,
dependency-resolution/Maven Central setup, optional verification-metadata). The convention-plugin
variant also relies on the `build-logic`/`buildSrc` location established or permitted by AND-001.

**Soft-orders-with:** AND-003 (core module structure) — if core modules already exist, they are
covered by the gate immediately; if AND-005 lands first, the convention plugin/`subprojects` block
ensures AND-003's new modules inherit the gate with no extra work. AND-005 does **not** hard-block
on AND-003.

**Blocks:** AND-006 (CI pipeline), which invokes `./gradlew spotlessCheck detekt` as a required
gate and consumes the SARIF reports. AND-006 also owns final Android Lint policy tuning that this
ticket only stubs.

**Sequencing within ticket:** (1) add catalog entries; (2) add config files
(`.editorconfig`, `detekt.yml`, empty `baseline.xml`, `lint.xml`); (3) add convention
plugin / `subprojects` wiring; (4) `spotlessApply` to normalize the existing scaffold;
(5) confirm `spotlessCheck detekt` green; (6) document in README.

## 13. Risks & Open Questions

- **R1 — Tool/Kotlin compatibility.** ktlint 1.3.1 / detekt 1.23.7 must parse Kotlin 2.0.21
  sources. *Mitigation:* these are the stable lines validated against K2; if a parser issue
  arises, fall back to the latest patch and record the pin in the catalog.
- **R2 — detekt-compose-rules detekt-version coupling.** The Compose rule set is tied to a
  detekt minor line. *Mitigation:* pin `detektCompose = 0.4.16` against detekt 1.23.x; bump both
  together.
- **R3 — Convention plugin vs. `subprojects` scope.** Standing up `build-logic` may exceed the
  S sizing if AND-001 did not provision it. *Open question:* does AND-001 already include a
  `build-logic` included build? If not, ship the `subprojects {}` variant for this ticket and
  file a follow-up to migrate. **Recommended default:** `subprojects {}` unless build-logic
  exists.
- **R4 — Baseline temptation.** Risk that a non-empty baseline is committed to make the build
  pass over real debt. *Mitigation:* FR-6 mandates an empty baseline; reviewer rejects any
  populated baseline in this PR.
- **R5 — Function-naming vs. Compose.** Default detekt `FunctionNaming` flags `@Composable`
  PascalCase functions. *Mitigation:* `.editorconfig` and detekt config exclude
  `@Composable`/`@Test` from naming rules (see §6); verified once a Composable exists.
- **Open question:** Should a Git pre-commit hook (e.g. via a Gradle task or a committed
  `.git/hooks` installer) be added now, or left to developer discretion? *Default:* document the
  `spotlessApply` workflow in README; do **not** auto-install hooks in this ticket.

## 14. Acceptance Criteria

AC-1. `./gradlew spotlessCheck detekt` runs **clean** (exit 0, no violations) on a fresh
`android-port` checkout, across `:app` and all existing `:core-*`/`:feature-*` modules. *(Primary
acceptance from the backlog.)*

AC-2. Gradle tasks `spotlessCheck`, `spotlessApply`, and `detekt` all exist at the root and fan
out across every Kotlin module.

AC-3. All tool versions (Spotless, ktlint, detekt, detekt-compose-rules) are declared in
`android/gradle/libs.versions.toml`; no version is hard-coded in a build script.

AC-4. Shared config files exist and are referenced: `android/.editorconfig`,
`android/config/detekt/detekt.yml`, `android/config/detekt/baseline.xml` (empty),
`android/config/lint/lint.xml`.

AC-5. The quality gate applies uniformly via a convention plugin
(`com.testlogon.android.quality`) or a root `subprojects {}` block; a newly added Kotlin module
is covered with no per-module configuration beyond applying the plugin (or zero, for
`subprojects`).

AC-6. Introducing a deliberate formatting error makes `spotlessCheck` fail with a non-zero exit
and an actionable message; introducing a deliberate code smell makes `detekt` fail likewise.
(Demonstrated in the PR; reverted before merge.)

AC-7. `./gradlew spotlessApply` auto-corrects formatting and a subsequent `spotlessCheck` passes.

AC-8. detekt produces SARIF + HTML reports under `build/reports/detekt/` for CI consumption.

AC-9. `android/README.md` documents the four commands, config locations, the recommended
`spotlessApply` pre-commit workflow, and how to regenerate the detekt baseline.

AC-10. The same `./gradlew spotlessCheck detekt` passes on the Ubuntu build server (JDK 17,
SDK 35) identically to local.

## 15. Definition of Done

- All Acceptance Criteria (AC-1 … AC-10) met and demonstrated.
- Catalog entries, config files, and convention-plugin/`subprojects` wiring committed on
  `android-port`; only `*.gradle.kts`, `*.toml`, config files, `README.md`, and
  `spotlessApply`-driven reformatting of existing `.kt` files are touched (no functional app
  code).
- detekt `baseline.xml` is present and **empty** (no suppressed issues).
- `./gradlew spotlessCheck detekt` green locally and on the Ubuntu build server; reproducible
  with `--offline` on a warm cache.
- The positive-detection check (AC-6) was performed and evidenced in the PR description, then
  reverted.
- `android/README.md` "Code Quality" section reviewed for accuracy.
- PR reviewed and approved; no populated detekt baseline introduced; all new artifact versions
  pinned (and added to `verification-metadata.xml` if AND-001 enabled dependency verification).
- Hand-off note to AND-006 confirms the task names and SARIF report paths the CI pipeline will
  consume.
