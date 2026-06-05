---
id: AND-111
title: i18n plumbing + string structure
milestone: M2
epic: E16
priority: P1
size: S
status: draft
depends_on: [AND-003]
blocks: []
---

# AND-111 — i18n plumbing + string structure

## 1. Overview & Goal

This ticket establishes the **internationalization (i18n) foundation** for the native Android
port of TestLogon: the conventions, file structure, plural/format handling, and the automated
**lint gate that forbids hardcoded user-facing strings**. It is a Chore — it ships *plumbing
and policy*, not features. No new screen, ViewModel, or endpoint is introduced.

Concretely, AND-111 delivers four things:

1. **String resource conventions** — a documented naming scheme, ownership model (which module
   owns which strings), and the directory/file layout for `strings.xml` across `:core-ui` and
   `feature-*` modules under the `com.testlogon.android` namespace.
2. **Plurals and runtime formatting** — `<plurals>` resources for count-bearing copy, positional
   format arguments (`%1$s`), a small Compose-friendly accessor surface, and rules for locale-aware
   number/date formatting via `java.text`/`android.icu`.
3. **Hardcoded-string lint** — Android Lint's `HardcodedText`, `SetTextI18n`,
   `StringFormatInvalid`, `StringFormatCount`, `PluralsCandidate`, and `MissingTranslation`-class
   checks promoted to **error** severity with a committed baseline, so CI (AND-008/AND-050)
   fails on any new hardcoded literal.
4. **Baseline externalization** — every user-visible literal that exists in the codebase at the
   time this ticket lands is moved into `strings.xml`, leaving the lint run green.

**Pseudo-locale verification** (`en-XA` / `ar-XB`) is wired so that expansion and
bidi/RTL issues are visible at dev time, but the only shipping locale at this milestone is the
default (`values/`, English). Adding additional translated locales is explicitly out of scope.

**Success in one line:** `./gradlew :app:lintDebug` runs clean with `HardcodedText` and the
companion i18n checks at `error` severity, every baseline literal lives in a resource file, and
a developer who hardcodes a new UI string sees the build fail locally and in CI.

## 2. Context & References

**Repo / branch.** `spannella/testlogon`; Android app under `android/` (monorepo subfolder),
branch `android-port`. Canonical namespace / `applicationId` base everywhere a package appears:
`com.testlogon.android`. Per-module Android resource packages are derived from each module's
`namespace` (e.g. `com.testlogon.core.ui`, `com.testlogon.feature.auth`); generated `R` classes
are therefore module-scoped.

**Toolchain (authoritative).** Kotlin 2.0.21, AGP 8.7.3, Gradle 8.9 wrapper, JDK 17,
compileSdk/targetSdk 35, minSdk 24, Jetpack Compose + Material 3. AGP 8.7 emits per-module
non-transitive `R` classes (`android.nonTransitiveRClass=true`, the AGP 8 default), which makes
string ownership a hard architectural constraint, not a style preference (see §4).

**Related tickets.**
- **AND-003** (Core module structure) — *blocks this ticket.* Provides the `:core-ui` /
  `core-*` / `feature-*` module graph and the `build-logic` convention plugins where Lint and
  resource configuration are centralized. AND-111 adds a `values/strings.xml` to `:core-ui` and
  configures Lint via the existing convention plugins rather than per-module duplication.
- **AND-005** (Lint, format & static analysis) — establishes Spotless/detekt and *normalizes*
  Android Lint config so it can be invoked. AND-111 is the ticket that actually **tightens
  Lint's i18n rules to `error`** and commits the lint baseline. The two are complementary:
  AND-005 owns formatting/static-analysis policy; AND-111 owns i18n policy.
- **AND-008 / AND-050** (CI) — run `lint` in the pipeline; this ticket's severities make i18n
  violations CI-blocking. AND-111 does not modify CI YAML; it only changes Gradle config that CI
  already invokes.
- **AND-019** (Material 3 theme) and **AND-020/AND-021** (core composables) — early consumers of
  the conventions established here; their literals are part of the baseline externalization.

**Web reference / backend.** The FastAPI/DynamoDB backend (`http://18.222.237.167:8000`) and the
React app under `frontend/` are **not consumed** by this ticket. Server-supplied text (e.g. error
`detail` strings) is *display passthrough* and is not subject to client-side string-resource
rules; client-authored copy that *wraps* server data (labels, retry buttons, "Try again") is.
The frontend's i18n approach (if any) is non-authoritative here.

## 3. Functional Requirements

- **FR-1.** Every user-visible, client-authored string in the codebase at merge time is declared
  in a `res/values/strings.xml` resource and referenced via `stringResource(...)` (Compose) or a
  resource id (non-Compose), with **zero** string literals passed to Compose `Text(...)`,
  content descriptions, or `Toast`/notification builders.
- **FR-2.** A documented **naming convention** exists (key grammar, casing, prefixes) and is
  applied to all new and migrated keys (see §4).
- **FR-3.** All **count-dependent** copy uses `<plurals>` with the correct CLDR quantity keys;
  no manual `"if (n == 1) ... else ..."` string selection in Kotlin.
- **FR-4.** All **interpolated** copy uses positional format args (`%1$s`, `%2$d`) — never string
  concatenation — and is resolved through `Context.getString(id, args...)` /
  `pluralStringResource` / `stringResource(id, args...)`.
- **FR-5.** Android **Lint** flags hardcoded UI text as an **error**: `HardcodedText`,
  `SetTextI18n`, `StringFormatMatches`/`StringFormatInvalid`/`StringFormatCount`,
  `PluralsCandidate`, and `ImpliedQuantity` are `error`; a committed `lint-baseline.xml` captures
  only pre-existing third-party/unavoidable cases (target: empty for first-party code).
- **FR-6.** **Pseudo-localization** is enabled for the `debug` build type
  (`isPseudoLocalesEnabled = true`) so testers can switch device language to *English (XA)* and
  *Accented English (XB)* to surface truncation and concatenation defects.
- **FR-7.** `resConfigs`/`androidResources.localeFilters` is documented so that, today, only the
  default locale ships, while the structure permits adding `values-<lang>` folders later with no
  code change.
- **FR-8.** A short `android/docs/i18n.md` (or a section in `android/README.md`) documents the
  conventions, the lint gate, and the "add a string" / "add a plural" developer workflow.

## 4. Technical Design

**String ownership & layout.** Because of non-transitive `R` classes, a module can only reference
its own `R.string.*`. Therefore:

- **Shared / cross-feature** copy (generic actions, state messages: *Retry*, *Loading…*,
  *You're offline*, *Cancel*, *OK*) lives in **`:core-ui`** at
  `android/core-ui/src/main/res/values/strings.xml` and is exposed through typed accessors so
  features do not depend on `core-ui`'s `R` directly.
- **Feature-specific** copy lives in that feature module's own `res/values/strings.xml`
  (e.g. `android/feature-auth/src/main/res/values/strings.xml`).
- The **`:app`** module owns only app-global text (`app_name`, notification channel names).

**Key naming grammar.** `snake_case`, structured as
`<area>_<screen_or_component>_<role>[_<qualifier>]`:

```
app_name
core_action_retry
core_action_cancel
core_state_offline_title
core_state_offline_body
auth_login_title
auth_login_username_label
auth_login_username_error_required
auth_mfa_totp_code_hint
auth_session_active_count            <!-- plurals -->
```

Roles use a closed vocabulary: `title`, `body`, `label`, `hint`, `cta`/`action`, `error`,
`a11y` (content descriptions), `placeholder`. This keeps keys greppable and lint-able.

**Compose accessor surface (in `:core-ui`).** Thin, testable wrappers so feature code reads
intent, not raw `R` ids, and so shared strings cross the module boundary:

```kotlin
package com.testlogon.core.ui.i18n

import androidx.annotation.PluralsRes
import androidx.annotation.StringRes
import androidx.compose.runtime.Composable
import androidx.compose.runtime.ReadOnlyComposable
import androidx.compose.ui.platform.LocalContext

/** Compose-side resolver; delegates to platform stringResource but lives in core-ui
 *  so shared keys (R.string from core-ui) are reachable by all features. */
@Composable
@ReadOnlyComposable
fun text(@StringRes id: Int, vararg formatArgs: Any): String =
    LocalContext.current.resources.getString(id, *formatArgs)

@Composable
@ReadOnlyComposable
fun quantityText(@PluralsRes id: Int, count: Int, vararg formatArgs: Any): String =
    LocalContext.current.resources.getQuantityString(id, count, *formatArgs)

/** Non-Compose call sites (ViewModels must NOT format user copy; this is for
 *  Services / notification builders that legitimately need a Context). */
object Strings {
    fun get(ctx: android.content.Context, @StringRes id: Int, vararg args: Any): String =
        ctx.getString(id, *args)
}
```

> ViewModels expose `StateFlow<UiState>` and must **not** resolve strings (no `Context` in
> ViewModels). UiState carries either `@StringRes` ids + args, or a small sealed
> `UiText` type; resolution happens in the composable. AND-111 introduces the optional `UiText`
> helper so later feature tickets have a sanctioned pattern:

```kotlin
package com.testlogon.core.ui.i18n

import androidx.annotation.StringRes

sealed interface UiText {
    data class Res(@StringRes val id: Int, val args: List<Any> = emptyList()) : UiText
    data class Raw(val value: String) : UiText   // server passthrough only (e.g. error detail)
}

@androidx.compose.runtime.Composable
fun UiText.asString(): String = when (this) {
    is UiText.Res -> text(id, *args.toTypedArray())
    is UiText.Raw -> value
}
```

**Plurals.** Defined with CLDR quantity keys. English only needs `one`/`other`, but `zero`,
`two`, `few`, `many` are documented as reserved for future locales:

```xml
<plurals name="auth_session_active_count">
    <item quantity="one">%1$d active session</item>
    <item quantity="other">%1$d active sessions</item>
</plurals>
```

**Formatting rules.** Numbers, dates, and relative times are formatted with locale-aware
platform APIs (`android.icu.text.NumberFormat`, `DateTimeFormatter.ofLocalizedDateTime`,
`android.text.format.DateUtils.getRelativeTimeSpanString`) — never `String.format("%d", …)`
without an explicit `Locale`, and never hand-built strings. Where a number is embedded in copy,
it is passed as a `%1$d`/`%1$s` argument so the resource controls placement.

**Lint configuration (via `build-logic` convention plugin from AND-003).** Centralized so every
module inherits it:

```kotlin
// build-logic: AndroidLibraryConventionPlugin / AndroidApplicationConventionPlugin
android {
    lint {
        warningsAsErrors = false            // selective, not blanket
        abortOnError = true
        checkDependencies = true
        baseline = file("lint-baseline.xml")
        disable += "MissingTranslation"     // single-locale milestone; re-enabled when locales land (AND-112+)
        // i18n checks promoted explicitly:
        error += setOf(
            "HardcodedText", "SetTextI18n", "StringFormatInvalid",
            "StringFormatCount", "StringFormatMatches", "PluralsCandidate",
            "ImpliedQuantity",
        )
    }
}
android.buildFeatures // (unchanged)
android.buildTypes { getByName("debug") { isPseudoLocalesEnabled = true } }
```

**Baseline migration.** A grep-assisted sweep replaces literal strings in all existing Compose
`Text`, `contentDescription`, `placeholder`/`label` parameters, `Toast`, and notification copy
with resource references; `./gradlew :app:lintDebug` is run iteratively until clean.

## 5. API Contract

**N/A.** This ticket introduces no network calls and consumes no backend endpoint. The only
interaction with server data is *display passthrough* of FastAPI error `detail` text (mapped in
AND-015), which is rendered via `UiText.Raw` and is intentionally exempt from string-resource
rules. The auth/session endpoints (`/ui/session/start`, `/ui/me`, etc.) are owned by AND-027 and
later tickets.

## 6. Data & State Management

No persistence (Room/DataStore) is added. Relevant "state" is two-fold:

- **Resource resolution state.** Strings are resolved at the composable layer against the current
  `Configuration`/`Locale`. The contract for the rest of the app is: **UiState carries
  `@StringRes` ids / `UiText`, not resolved `String`s** (except server passthrough). This keeps
  ViewModels locale-agnostic and configuration-change-safe — on locale change, Compose
  recomposition re-resolves text automatically because `LocalConfiguration` updates.
- **App locale (forward-looking).** When per-app language selection lands later, it will use
  `AppCompatDelegate.setApplicationLocales(...)` / the AndroidX `AppLocalesMetadataHolderService`
  with `android:localeConfig`. AND-111 reserves the `res/xml/locales_config.xml` slot and
  documents it but ships only the default locale; the actual picker UI is out of scope (future
  ticket in E16). DataStore keys for a stored language preference are **not** created here.

## 7. Error Handling & Resilience

i18n-specific failure modes and their handling:

- **Missing format argument / arity mismatch** — caught at build time by `StringFormatCount` /
  `StringFormatMatches` (now `error`); a malformed `%1$s` template fails the build, not the user.
- **Missing plural quantity** — `ImpliedQuantity` flags a plural used with a number whose
  required quantity item is absent.
- **Runtime missing resource** — `Resources.NotFoundException` is a programming error, not a
  recoverable condition; it is allowed to crash in debug and is covered by tests (§11) rather than
  try/catch. No silent fallback to empty string.
- **Resilience interaction.** The offline/stale and retry copy used by AND-021's state
  composables (*"You're offline"*, *"Try again"*) is externalized here so the resilience UI
  (~20s timeouts, bounded GET retry, stale banners defined elsewhere) renders localizable,
  testable text. This ticket does not implement networking resilience; it only guarantees the
  strings that resilience UI needs exist and are typed.

## 8. Security & Privacy

- **No PII in resources.** `strings.xml` contains only static, non-sensitive copy. Reviewers must
  ensure no tokens, URLs containing credentials, or environment secrets are externalized as
  strings (the dev base URL belongs to BuildConfig/flavors per AND-006, not `strings.xml`).
- **No interpolation of secrets.** Format args must never carry passwords, session/CSRF cookies,
  `ui_csrf` values, or MFA codes into log-visible string assembly.
- **Server passthrough sanitation.** `UiText.Raw` (error `detail`) is rendered as text only and
  never interpreted as HTML/markup, avoiding injection via server-controlled copy.
- This ticket does not touch the cookie jar, CSRF header, or `/ui/session/refresh` flow.

## 9. Accessibility & i18n

This *is* the i18n ticket; accessibility is first-class:

- **Content descriptions** for all non-decorative icons/images use `core_*_a11y_*` /
  `*_a11y_*` keys; decorative elements pass `contentDescription = null` explicitly (also enforced
  by lint). No `contentDescription = "Profile"` literals.
- **Pseudo-locale (`en-XA`/`ar-XB`)** testing surfaces text expansion (≈30%+) and right-to-left
  mirroring defects before real translations exist. Layouts use `start`/`end` (not `left`/`right`)
  and `RtlSpacing`-safe paddings.
- **No truncation of meaning.** Copy that may grow under translation is allowed to wrap; fixed-width
  text containers are flagged in review.
- **TalkBack** reads resolved strings; because copy is resourced, screen-reader output is
  localizable. Plurals ensure grammatically correct spoken counts.
- **Sentence vs. title case** is locale-managed via resources, not `String.uppercase()` in code.

## 10. Telemetry & Logging

No analytics events are added. Logging guidance only:

- **Never log resolved user-facing copy** as a proxy for events; log stable string **keys/ids**
  (`R.string` entry name) if a label must be referenced in a log.
- Auth-area logging (AND-052) is redacted; this ticket adds no new log sites. A lint/CI note
  documents that `Log.*`/`println` of user copy is discouraged.
- A build-time signal (lint result count) is the only "telemetry": CI surfaces the i18n lint
  status as part of the existing `lint` report artifact (AND-008/AND-050).

## 11. Testing Strategy

- **Static gate (primary).** `./gradlew :app:lintDebug` (and `:core-ui:lint`,
  `:feature-*:lint` via `checkDependencies=true`) must report **zero** `HardcodedText` /
  `SetTextI18n` / `StringFormat*` / plural errors. A deliberately-added hardcoded `Text("hi")` in a
  scratch branch must fail the build — verified once manually and documented.
- **Resource integrity unit tests** (`:core-ui`, JVM): a test asserts that every `<plurals>` has
  at least `one` and `other`; that no `strings.xml` key duplicates across the file; and that
  format-arg counts in templates are internally consistent.
- **Robolectric/instrumented spot checks:** `context.getString(R.string.auth_login_title)` and
  `getQuantityString(R.plurals.auth_session_active_count, 1/2, n)` return expected English copy and
  correct singular/plural selection.
- **Pseudo-locale smoke (manual, documented):** run a debug build, switch device language to
  *English (XA)*, confirm screens show bracketed/accented expanded text with no clipped or
  concatenated strings; capture in the i18n doc.
- **CI:** existing unit/instrumented jobs (AND-050/AND-051) run the above; no new CI file changes.

## 12. Dependencies & Sequencing

- **Depends on AND-003** (core module structure + `build-logic` convention plugins): required so
  the lint config and the `:core-ui` `strings.xml`/accessors have a home. Hard dependency.
- **Complements AND-005** (lint/Spotless/detekt baseline): AND-005 should land first so the lint
  invocation is normalized; AND-111 then promotes the i18n checks to `error`. If AND-005 has not
  landed, AND-111 must add the minimal `lint {}` block itself.
- **Soft-precedes feature UI tickets** (AND-019, AND-020, AND-021, AND-030, AND-039, …): those
  tickets should consume the conventions and `UiText` pattern. AND-111 does not *block* them in
  the tracker (it has no `blocks`), but reviewers should reject new hardcoded strings in PRs that
  merge after this ticket — the lint gate enforces this automatically.
- **Forward link:** translated-locale enablement and a per-app language picker (E16, future
  ticket, provisionally AND-112+) consume the `locales_config.xml` slot and re-enable
  `MissingTranslation`.

## 13. Risks & Open Questions

- **R1 — Large baseline churn.** If many literals already exist when this lands, the migration PR
  is wide and merge-conflict-prone. *Mitigation:* land early in M2, before the bulk of feature UI;
  do the sweep per module to keep diffs reviewable.
- **R2 — Non-transitive R friction.** Features cannot see `core-ui`'s `R.string`; teams may be
  tempted to duplicate shared strings. *Mitigation:* the `text()`/`UiText` accessors in `:core-ui`
  are the sanctioned cross-module path; document and code-review for it.
- **R3 — Lint baseline masking regressions.** A non-empty `lint-baseline.xml` can hide new
  violations if misused. *Mitigation:* target an empty baseline for first-party code; review any
  baseline additions.
- **R4 — ViewModel string resolution leakage.** Devs may inject `Context`/`@ApplicationContext`
  into ViewModels to format copy. *Mitigation:* the `UiText` pattern + review guidance; optionally
  a detekt rule (owned by AND-005) flagging `Context.getString` outside UI/Service layers.
- **OQ1.** Do we adopt the `UiText` sealed type now or defer to feature tickets? *Recommendation:*
  introduce it here (low cost) so feature tickets have one pattern.
- **OQ2.** Keep `MissingTranslation` disabled until real locales exist (single-locale milestone) —
  confirm with product that no second locale ships in M2. *Assumed: yes, English only.*

## 14. Acceptance Criteria

- **AC-1.** `./gradlew :app:lintDebug` completes with `abortOnError=true` and **zero**
  `HardcodedText`, `SetTextI18n`, `StringFormatInvalid`, `StringFormatCount`,
  `StringFormatMatches`, `PluralsCandidate`, and `ImpliedQuantity` violations across `:app`,
  `:core-ui`, and any existing `feature-*` modules (`checkDependencies=true`).
- **AC-2.** Every user-facing, client-authored literal present at merge time is externalized to a
  `res/values/strings.xml`; a repo grep for `Text("…literal…")` and hardcoded `contentDescription`
  in first-party `src/main` returns none (server-passthrough `UiText.Raw` excepted).
- **AC-3.** At least one `<plurals>` resource (e.g. `auth_session_active_count`) exists and a test
  proves correct `one`/`other` selection for counts 1 and 2.
- **AC-4.** Naming conventions, the lint gate, and the "add a string / add a plural / a11y
  description" workflow are documented in `android/docs/i18n.md` (or `android/README.md`).
- **AC-5.** `debug` builds have `isPseudoLocalesEnabled = true`; switching the device to *English
  (XA)* renders expanded/accented copy with no clipped or concatenated UI on smoke-tested screens.
- **AC-6.** Inserting a hardcoded `Text("test")` causes `lintDebug` to fail (demonstrated once,
  reverted) — the gate is proven, not just configured.
- **AC-7.** `core-ui` exposes `text(...)`, `quantityText(...)`, and the `UiText` type; feature code
  references shared strings only through these, never another module's `R`.

## 15. Definition of Done

- All Acceptance Criteria (AC-1…AC-7) pass.
- Lint i18n severities and `isPseudoLocalesEnabled` are configured in the **shared `build-logic`
  convention plugins** (from AND-003), not duplicated per module; a committed `lint-baseline.xml`
  (empty for first-party code) is present.
- `:core-ui` contains the `strings.xml`, `plurals`, and `com.testlogon.core.ui.i18n` accessors
  (`text`, `quantityText`, `Strings`, `UiText`, `asString`), with KDoc.
- Resource-integrity and Robolectric/instrumented tests (§11) pass in CI (AND-050/AND-051) with no
  CI YAML changes required.
- Documentation (`android/docs/i18n.md`) merged and linked from `android/README.md`.
- Branch `android-port`; PR reviewed; `./gradlew spotlessCheck detekt :app:lintDebug` green;
  no new hardcoded strings; namespace `com.testlogon.android` (and `com.testlogon.core.ui`)
  respected throughout.
