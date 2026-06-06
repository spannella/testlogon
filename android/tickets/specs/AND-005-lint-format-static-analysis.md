---
id: AND-005
title: Lint, format & static analysis
milestone: M1 (Auth Foundation)
epic: E01 (Project scaffolding & build tooling)
priority: P1
size: S
status: reviewed
reviewed_on: 2026-06-06
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
detekt `1.23.8` (with `detekt-formatting` and the `io.nlopez.compose.rules:detekt` Compose
rule set `0.4.16`). **[Corrected]** The original draft pinned detekt `1.23.7`, but per the
detekt compatibility table 1.23.7 is built against Kotlin **2.0.10**; the first 1.23.x patch
that compiles/parses Kotlin **2.0.21** sources is detekt **1.23.8** — so the pin must be
`1.23.8` to match the AND-001 Kotlin 2.0.21 toolchain. The Compose rule set `0.4.16` targets
the detekt 1.23.x line (compatible with 1.23.8). Note: Spotless `6.25.0` (Jan 2024) ships a
default ktlint of `1.1.1`; pinning the ktlint engine to `1.3.1` relies on Spotless's
`ktlint("1.3.1")` version-override API and is treated as an *unverified compatibility
assumption* (see §16) — if the 6.25.0 adapter cannot drive the 1.3.1 engine, bump Spotless to
the latest 6.x/7.x line that bundles a ktlint ≥ 1.3.1 adapter. Exact pins live in
`libs.versions.toml`.

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
detekt   = "1.23.8"   # corrected from 1.23.7: 1.23.8 is the 1.23.x patch built for Kotlin 2.0.21
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

- **R1 — Tool/Kotlin compatibility.** ktlint 1.3.1 / detekt 1.23.8 must parse Kotlin 2.0.21
  sources. *Correction during review:* the draft's detekt `1.23.7` is built against Kotlin
  2.0.10, not 2.0.21 — pin **1.23.8** (the 1.23.x patch aligned to Kotlin 2.0.21 per the detekt
  compatibility table). *Residual risk (Spotless↔ktlint):* Spotless 6.25.0 defaults to ktlint
  1.1.1; driving the 1.3.1 engine via `ktlint("1.3.1")` is unverified. *Mitigation:* if a parser
  or adapter issue arises, bump to the latest compatible patch (Spotless 6.x/7.x and/or detekt
  1.23.x) and record the pin in the catalog.
- **R2 — detekt-compose-rules detekt-version coupling.** The Compose rule set is tied to a
  detekt minor line. *Mitigation:* pin `detektCompose = 0.4.16` against detekt 1.23.x (compatible
  with 1.23.8); bump both together.
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

## 16. Citations & Assumption Audit

This is a build/chore ticket with **no runtime API surface**, so most claims are about tool
versions and framework wiring rather than backend endpoints. Each key technical claim below is
listed with a VERDICT and an exact SOURCE pointer.

1. **Claim:** detekt `1.23.7` is "compatible with Kotlin 2.0.21 / validated against K2."
   **VERDICT: Corrected → detekt `1.23.8`.**
   **Source:** framework ref — detekt compatibility table, https://detekt.dev/docs/introduction/compatibility/
   (1.23.7 ↔ Kotlin 2.0.10; 1.23.8 ↔ Kotlin 2.0.21). AND-001 toolchain is Kotlin 2.0.21 (§2),
   so the pin must be 1.23.8.

2. **Claim:** Spotless Gradle plugin `6.25.0` can drive ktlint engine `1.3.1` via `ktlint("1.3.1")`.
   **VERDICT: Unverified-assumption.**
   **Source:** framework ref — Spotless changelog, https://github.com/diffplug/spotless/blob/main/plugin-gradle/CHANGES.md
   (6.25.0 dated 2024-01-23, default ktlint 1.1.1; no explicit 1.3.1 adapter entry at/before 6.25.0).
   The `ktlint(version)` override API exists, but adapter↔engine compatibility for 1.3.1 on the
   6.25.0 adapter is not confirmed by the changelog. Fallback documented in §2/§13-R1.

3. **Claim:** Compose rule set artifact `io.nlopez.compose.rules:detekt:0.4.16` exists and targets
   the detekt 1.23.x line. **VERDICT: Verified (existence) / Verified-by-line (compat).**
   **Source:** framework ref — Maven Central, https://central.sonatype.com/artifact/io.nlopez.compose.rules/detekt
   (0.4.16 published; 0.4.x series tracks detekt 1.23.x, compatible with the corrected 1.23.8 pin).

4. **Claim (§5/§8):** The backend auth contract this ticket defers to uses cookie-based sessions
   plus a CSRF token from the `ui_csrf` cookie sent as the `X-CSRF-Token` request header.
   **VERDICT: Verified.**
   **Source:** frontend `src/api/client.ts` — `credentials: "include"`, `getCookie("ui_csrf")`,
   `headers.set("X-CSRF-Token", csrf)`.

5. **Claim (§5):** Endpoints `POST /ui/session/start`, `POST /ui/session/finalize`, `GET /ui/me`,
   and the `/ui/mfa/*` family exist and are owned by later networking tickets.
   **VERDICT: Verified.**
   **Source:** OpenAPI index — `POST /ui/session/start` (op=ui_session_start, req=UiSessionStartReq,
   resp=200:UiSessionStartResp), `POST /ui/session/finalize` (req=UiSessionFinalizeReq),
   `GET /ui/me` (op=ui_me_ui_me_get), and `POST /ui/mfa/{totp,sms,email,recovery}/*`. These are
   out of scope for AND-005 (correctly marked N/A in §5).

6. **Claim (§2):** AND-001 toolchain — Kotlin 2.0.21, Gradle 8.9, AGP 8.7.3, JDK 17,
   compileSdk/targetSdk 35, minSdk 24, KSP-based Hilt; versions in `libs.versions.toml`.
   **VERDICT: Unverified-assumption** (cross-spec dependency on AND-001; no AND-001 source in the
   provided reference set to confirm). Treated as authoritative per the ticket but flagged.

7. **Claim (§4):** detekt `jvmTarget = "17"`, SARIF/HTML reports under `build/reports/detekt/`,
   `buildUponDefaultConfig`, `baseline`, `parallel`, and the `detektPlugins` dependency
   configuration are valid detekt-Gradle-plugin API. **VERDICT: Verified (framework API).**
   **Source:** framework ref — detekt Gradle plugin docs, https://detekt.dev/docs/gettingstarted/gradle/.

8. **Claim (§4/§6):** Spotless `SpotlessExtension` with `kotlin { ktlint(...).editorConfigOverride(...) }`,
   `kotlinGradle {}`, `trimTrailingWhitespace()`, `endWithNewline()` are valid Spotless API.
   **VERDICT: Verified (framework API).**
   **Source:** framework ref — Spotless gradle README, https://github.com/diffplug/spotless/blob/main/plugin-gradle/README.md.

9. **Claim (§6):** `.editorconfig` ktlint properties (`ktlint_code_style = ktlint_official`,
   `ktlint_standard_*`, `ktlint_function_naming_ignore_when_annotated_with`) are honored by the
   ktlint 1.x engine. **VERDICT: Verified (framework behavior).**
   **Source:** framework ref — ktlint .editorconfig docs, https://pinterest.github.io/ktlint/latest/rules/configuration-ktlint/.

### Corrections made

- **§2, §4 (toml), §13-R1, §13-R2:** detekt pin changed `1.23.7` → `1.23.8` because 1.23.7 is
  built against Kotlin 2.0.10 while AND-001 uses Kotlin 2.0.21; 1.23.8 is the matching 1.23.x
  patch (detekt compatibility table). The "validated against K2 for 2.0.21" wording was corrected
  accordingly.
- **§2, §13-R1:** Added an explicit note that Spotless 6.25.0's default ktlint is 1.1.1 and that
  driving ktlint 1.3.1 via the `ktlint("1.3.1")` override is an unverified compatibility
  assumption with a documented fallback (bump Spotless).
- No correction needed for §5/§8: the cookie + `X-CSRF-Token`/`ui_csrf` auth contract and the
  cited endpoint paths/methods are accurate against the OpenAPI index and `src/api/client.ts`.

### Open assumptions

- **Spotless 6.25.0 ↔ ktlint 1.3.1 engine compatibility** — not confirmable from the Spotless
  changelog (no explicit 1.3.1 adapter entry at/before 6.25.0); must be validated empirically by
  running `spotlessCheck`/`spotlessApply` (see TC-AND-005-08). Why unverifiable: adapter↔engine
  support matrices are not published per-version in the consulted changelog.
- **AND-001 contents** (Gradle/AGP/Kotlin/JDK/SDK pins, presence of a `build-logic` included
  build, dependency-verification metadata) — no AND-001 source was in the provided reference set;
  taken as authoritative per the ticket but flagged. Drives the convention-plugin-vs-`subprojects`
  open question in §13-R3.
- **Exact ruleset names** in the detekt default config (e.g. `Compose:UnstableCollections`,
  `complexity.LongMethod.threshold`) follow detekt/compose-rules conventions but the precise
  available rule IDs depend on the resolved `0.4.16`/`1.23.8` artifacts; verify when the build is
  first assembled.

## 17. Test Plan

"Tests" here are reproducible verifications of the quality gate itself (no production code to unit
test). Each case traces to a §14 Acceptance Criterion. All commands run from `android/`.

**TC-AND-005-01 — Clean-run acceptance.**
Type: integration. Preconditions: fresh `android-port` checkout; AND-001 scaffold present; warm
or cold Gradle cache. Steps: run `./gradlew spotlessCheck detekt`. Expected: exit 0; no
violations reported across `:app` and all existing `:core-*`/`:feature-*` modules. Traces: AC-1.

**TC-AND-005-02 — Task existence & fan-out.**
Type: integration. Preconditions: scaffold wired. Steps: `./gradlew tasks --all | grep -E
'spotlessCheck|spotlessApply|detekt'`; then `./gradlew spotlessCheck --dry-run`. Expected: root
`spotlessCheck`, `spotlessApply`, `detekt` tasks exist; dry-run shows per-module subtasks for
every Kotlin module. Traces: AC-2.

**TC-AND-005-03 — Versions sourced only from the catalog.**
Type: unit (config assertion). Preconditions: repo checked out. Steps: inspect
`libs.versions.toml` for `spotless`, `ktlint`, `detekt` (=`1.23.8`), `detektCompose`; grep all
`*.gradle.kts` for hard-coded version strings of these tools. Expected: all four declared in the
catalog; **zero** hard-coded versions in build scripts; detekt pinned at `1.23.8` (not `1.23.7`).
Traces: AC-3.

**TC-AND-005-04 — Config files present & referenced.**
Type: unit (config assertion). Preconditions: repo checked out. Steps: assert existence of
`android/.editorconfig`, `android/config/detekt/detekt.yml`, `android/config/detekt/baseline.xml`,
`android/config/lint/lint.xml`; confirm the convention plugin / `subprojects` block references
`config/detekt/detekt.yml` and the baseline. Expected: all four files exist and are wired.
Traces: AC-4.

**TC-AND-005-05 — Empty baseline (no hidden debt).**
Type: unit (config assertion). Preconditions: repo checked out. Steps: open
`config/detekt/baseline.xml`. Expected: a `<SmellBaseline>` with **no** `<ID>` entries; clean
run from TC-01 confirms acceptance does not rely on suppression. Traces: AC-1, AC-4.

**TC-AND-005-06 — Uniform application to a new module (zero extra wiring).**
Type: integration. Preconditions: gate wired via convention plugin or `subprojects {}`. Steps:
add a throwaway `:core-scratch` module with one `.kt` file containing a wildcard import and an
over-long method, applying only `id("com.testlogon.android.quality")` (or nothing, for
`subprojects`); run `./gradlew spotlessCheck detekt`; remove the module. Expected: violations are
caught **without** editing the convention plugin. Traces: AC-5.

**TC-AND-005-07 — Positive detection: formatting + smell both fail.**
Type: integration (negative). Preconditions: clean scaffold. Steps: introduce a deliberate
formatting deviation (bad indentation / missing final newline) and a deliberate code smell
(wildcard import + over-long method) in a scratch file; run `./gradlew spotlessCheck` then
`./gradlew detekt`; revert. Expected: each task exits non-zero; Spotless message names the
file and hints `spotlessApply`; detekt message includes rule id + file:line + report path.
Traces: AC-6.

**TC-AND-005-08 — Auto-fix round-trip (incl. ktlint 1.3.1 engine resolves).**
Type: integration. Preconditions: a misformatted `.kt` file. Steps: run `./gradlew spotlessApply`;
re-run `./gradlew spotlessCheck`. Expected: file is rewritten; subsequent `spotlessCheck` passes;
the run also empirically confirms Spotless 6.25.0 successfully resolves and drives the pinned
ktlint `1.3.1` engine (resolves Open-assumption #1). If resolution fails, escalate per §13-R1
fallback. Traces: AC-7.

**TC-AND-005-09 — Report artifacts produced.**
Type: integration. Preconditions: gate wired. Steps: run `./gradlew detekt`; inspect
`build/reports/detekt/`. Expected: `detekt.sarif` and `detekt.html` exist per module; XML/TXT
disabled per §4 config. Traces: AC-8.

**TC-AND-005-10 — Composable naming does not trip FunctionNaming.**
Type: integration (regression for §13-R5). Preconditions: gate wired. Steps: add a scratch
`@Composable fun HomeScreen()` (PascalCase) and a `@Test fun does_X()`; run `./gradlew detekt`;
remove. Expected: no `FunctionNaming` violation, due to the
`ignore_when_annotated_with = Composable, Test` overrides in `.editorconfig`/detekt config.
Traces: AC-1, AC-6.

**TC-AND-005-11 — Offline & deterministic.**
Type: integration. Preconditions: warm Gradle cache from a prior run. Steps: run
`./gradlew spotlessCheck detekt --offline` twice. Expected: both runs pass with identical
results; second run shows UP-TO-DATE/cached tasks; no network fetch at task time. Traces: AC-1, AC-10.

**TC-AND-005-12 — Generated code excluded.**
Type: integration (security/robustness). Preconditions: KSP/Hilt/Moshi generated output present
under `**/build/**`. Steps: run `./gradlew :app:kspDebugKotlin` (or assemble) then
`./gradlew spotlessCheck detekt`. Expected: no violations originate from `**/build/**` or
`**/generated/**`; the gate runs clean despite generated sources (confirms `targetExclude`/detekt
`excludes`). Traces: AC-1.

**TC-AND-005-13 — Supply-chain pins (no dynamic versions).**
Type: unit (security). Preconditions: repo checked out. Steps: grep `libs.versions.toml` and
build scripts for `+` / `latest.release` / range notation on the four tools; if AND-001 enabled
`gradle/verification-metadata.xml`, confirm the new artifacts' checksums are present. Expected:
no dynamic versions; verification metadata covers the added artifacts (or N/A if AND-001 did not
enable it). Traces: AC-3.

**TC-AND-005-14 — Build-server parity.**
Type: instrumented/e2e (CI host). Preconditions: Ubuntu build server, JDK 17, SDK 35, same
catalog. Steps: run `./gradlew spotlessCheck detekt` on the server. Expected: identical pass
result to local; hands off task names + SARIF paths to AND-006. Traces: AC-10.

**TC-AND-005-15 — README "Code Quality" documentation.**
Type: manual. Preconditions: PR open. Steps: review `android/README.md`. Expected: documents the
four commands (`spotlessCheck`, `spotlessApply`, `detekt`, baseline regen), config-file
locations, the `spotlessApply` pre-commit recommendation, and how to regenerate the baseline.
Traces: AC-9.

### Coverage matrix

| AC | Covered by |
| --- | --- |
| AC-1  | TC-01, TC-05, TC-10, TC-11, TC-12 |
| AC-2  | TC-02 |
| AC-3  | TC-03, TC-13 |
| AC-4  | TC-04, TC-05 |
| AC-5  | TC-06 |
| AC-6  | TC-07, TC-10 |
| AC-7  | TC-08 |
| AC-8  | TC-09 |
| AC-9  | TC-15 |
| AC-10 | TC-11, TC-14 |
