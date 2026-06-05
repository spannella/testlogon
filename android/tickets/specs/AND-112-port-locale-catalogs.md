---
id: AND-112
title: Port locale catalogs
milestone: M2
epic: E16
priority: P2
size: M
status: draft
depends_on: [AND-111]
blocks: [AND-113]
---

# AND-112 — Port locale catalogs

## 1. Overview & Goal

The web reference app (`frontend/`) ships its user-facing copy as i18next JSON
catalogs under `frontend/src/i18n/locales/<lang>/<namespace>.json`. The native
Android port must present the same copy, translated into the same set of locales,
using Android's resource-qualifier mechanism so that the platform performs locale
resolution and runtime fallback for us.

This ticket is a **chore**: it converts the existing i18next locale catalogs into
Android string resources (`res/values/`, `res/values-<lang>/`, optionally
`res/values-<lang>-r<REGION>/`) and establishes a repeatable, scripted conversion
path so future copy changes on the web side can be re-imported without hand
editing. It does **not** introduce runtime locale-switching UI or server-driven
locale preference — that behaviour is owned by **AND-113 (Server-locale sync)**.

Goal, stated testably: at least two locales (the default plus one translated
locale, e.g. `en` and `es`) load correctly at runtime, every key present in the
default catalog resolves to a string, and any key missing from a translated
catalog falls back to the default-locale value with no crash and no empty string.

## 2. Context & References

- **Depends on AND-111** (`i18n-plumbing-string-structure`): defines the string
  resource conventions, plural/`plurals` structure, format-argument style
  (positional `%1$s` / `%1$d`), namespace-to-resource-name mapping, and enables
  the hardcoded-string Lint check. AND-112 consumes those conventions; it must not
  redefine them.
- **Blocks AND-113** (`server-locale-sync`): AND-113 reads the server/user locale
  preference and applies it via `AppCompatDelegate.setApplicationLocales` /
  per-app language. AND-113 requires the catalogs ported here to exist.
- Web source of truth: `frontend/src/i18n/locales/` (i18next JSON). Namespaces map
  to one Android string file each (see §4). Shared types in
  `frontend/src/api/types.ts` are not relevant to copy.
- Stack: Kotlin 2.0.21, Compose + Material 3, AGP 8.7.3, minSdk 24, compileSdk 35,
  JDK 17, Gradle 8.9. Strings live in `core-ui` (see §4 module placement).
- Android per-app language / `LocaleConfig` requires `androidx.appcompat` 1.7+ and
  AGP `androidResources.generateLocaleConfig`. minSdk 24 is supported via the
  AppCompat backport.

## 3. Functional Requirements

FR-1. Every key in the **default** i18next catalog (`locales/en/*.json`) has a
corresponding Android string resource in `res/values/`. No web key is dropped.

FR-2. At least one fully-translated locale (target: `es`) is ported into
`res/values-es/`. Where the web ships additional locales, each is ported into the
correctly qualified directory using BCP-47 → Android-qualifier mapping (e.g.
`pt-BR` → `values-pt-rBR`, `zh-Hans` → `values-b+zh+Hans`).

FR-3. A key missing from a translated catalog resolves at runtime to the
default-locale value (Android resource fallback), never to an empty string or the
raw key name.

FR-4. i18next interpolation placeholders (`{{name}}`, `{{count}}`) are converted
to Android positional format args (`%1$s`, `%2$d`) per AND-111 conventions, and
the argument order is preserved consistently across all locales of the same key.

FR-5. i18next plural forms (`key_one` / `key_other`, and language-specific forms
such as Polish `_few`/`_many`) are converted to Android `<plurals>` with the
correct `quantity` items for each locale's CLDR plural rules.

FR-6. The conversion is performed by a **checked-in, idempotent script** so the
import can be re-run when web copy changes; running it twice on unchanged input
produces no diff.

FR-7. A `locales_config.xml` enumerates the supported locales so the OS (Android
13+) and AppCompat backport (minSdk 24) expose the per-app language list.

FR-8. The build fails (Lint or a unit test) if a non-default locale contains a key
that does **not** exist in the default catalog (orphan key) — these are stale and
must be removed at the source.

## 4. Technical Design

**Module placement.** All catalogs land in `core-ui` so every `feature-*` module
can resolve them transitively:

```
core-ui/src/main/res/
  values/strings.xml            # default (en) — base catalog
  values/plurals.xml
  values-es/strings.xml
  values-es/plurals.xml
  values-pt-rBR/strings.xml
  ...
  xml/locales_config.xml
```

**Namespace → file mapping.** i18next namespaces become resource-name prefixes,
not separate files (Android merges all `values*/strings.xml`). A web key
`auth:login.submit` becomes `auth_login_submit`. The prefix scheme is defined in
AND-111; AND-112 applies it deterministically.

**Conversion tool.** A Gradle task wrapping a Kotlin/JVM converter (preferred over
an ad-hoc shell script so it is testable and cross-platform on the Windows dev
box):

```kotlin
// build-logic/convert-locales/src/main/kotlin/LocaleConverter.kt
package com.testlogon.android.buildlogic.locales

data class WebCatalog(
    val locale: String,                 // BCP-47, e.g. "pt-BR"
    val entries: Map<String, JsonValue> // flattened "ns:dotted.path" -> value
)

object LocaleConverter {
    /** Flatten nested i18next JSON into "ns:dotted.key" -> value. */
    fun flatten(namespace: String, json: JsonObject): Map<String, JsonValue>

    /** Map a web key to an Android resource name (snake_case, sanitized). */
    fun resourceName(webKey: String): String

    /** Convert {{var}} -> %1$s and group _one/_other into plurals. */
    fun toAndroidStrings(catalog: WebCatalog): AndroidResourceSet

    /** BCP-47 -> Android values-* qualifier. */
    fun qualifierDir(locale: String): String   // "pt-BR" -> "values-pt-rBR"
}
```

```kotlin
// build.gradle.kts (core-ui)
tasks.register<ConvertLocalesTask>("convertLocales") {
    webLocalesDir.set(rootProject.file("frontend/src/i18n/locales"))
    outputResDir.set(layout.projectDirectory.dir("src/main/res"))
    defaultLocale.set("en")
}
```

The task is **not** wired into the default `assemble` graph (generated resources
are committed so reviewers can diff copy); it is run on demand and its output is
verified clean by CI (`git diff --exit-code` after `convertLocales`).

**Escaping.** The converter applies Android string escaping: `'` → `\'`, `"` →
`\"`, leading/trailing whitespace wrapped in `"..."`, `@`/`?` at index 0 escaped,
`&`/`<`/`>` XML-escaped, and literal `%` → `%%` when no format args are present.

**Runtime access.** Compose reads via `stringResource(R.string.auth_login_submit)`
and `pluralStringResource(R.plurals.items_count, n, n)`. No custom i18n runtime is
introduced — the platform resolver is the engine. A thin helper exists only for
non-Composable contexts:

```kotlin
// core-ui/src/main/kotlin/com/testlogon/android/core/ui/text/Strings.kt
package com.testlogon.android.core.ui.text

fun Context.str(@StringRes id: Int, vararg args: Any): String = getString(id, *args)
```

`locales_config.xml` is referenced from the manifest:

```xml
<application android:localeConfig="@xml/locales_config">
```

## 5. API Contract

N/A for this ticket. No network calls are made: locale catalogs are bundled
compile-time resources. Server-driven locale preference and any `/ui/me`
`locale` field consumption are owned by **AND-113 (Server-locale sync)**, which
depends on this ticket. The dev backend (`http://18.222.237.167:8000`), CSRF/cookie
auth, and timeout/retry policy are therefore out of scope here.

## 6. Data & State Management

No runtime mutable state, no Room, no DataStore writes in this ticket. The only
"data" is the static resource set merged by AGP at build time. Resolution order is
the platform default:

1. Active app locale (resolved by `AppCompatDelegate` / OS per-app language).
2. Region-stripped language match (`values-pt-rBR` → `values-pt`).
3. `values/` default (the ported `en` catalog) — guarantees FR-3.

The supported-locale set is data-driven by `locales_config.xml`; the converter is
the single producer of all `values-*` directories. Reading the user's stored
locale preference from DataStore is explicitly deferred to AND-113.

## 7. Error Handling & Resilience

- **Missing key in a translated locale:** handled structurally by Android fallback
  (FR-3); no code path. Verified by test (§11).
- **Orphan key (present in translation, absent in default):** the converter rejects
  it and a unit test/Lint check fails the build (FR-8), preventing silent dead copy.
- **Malformed format spec:** AGP's `XmlValidate`/Lint `StringFormatInvalid` and
  `StringFormatMatches` catch mismatched arg counts/types across locales; treated
  as build-breaking.
- **Converter crash on bad JSON:** the Gradle task fails fast with the offending
  file path and key; no partial resource directory is written (write to a temp dir,
  then atomic-replace).
- No runtime resilience concerns (no I/O, no async). There is no offline/stale
  state because nothing is fetched.

## 8. Security & Privacy

Minimal surface. Catalogs are static UI copy containing no secrets, PII, or
credentials. Review must confirm no API keys, internal hostnames, or debug copy
leak from the web catalogs into shipped resources (the converter logs any value
matching a host/secret heuristic for manual review). No new permissions, no
network, no cookie/CSRF interaction. String resources are world-readable inside the
APK as normal — acceptable for translated UI text.

## 9. Accessibility & i18n

This ticket **is** the i18n foundation, so the bar is high:

- All ported strings are real resources, satisfying the AND-111 hardcoded-string
  Lint gate so screen readers (TalkBack) announce translated copy.
- Plurals use `<plurals>`/`pluralStringResource`, never string concatenation, so
  grammatical number is correct per locale (FR-5).
- Positional format args (`%1$s`) allow translators to reorder substitutions for
  languages with different word order (FR-4).
- `locales_config.xml` enables the system per-app language picker (Android 13+) and
  the AppCompat backport for minSdk 24.
- RTL: any RTL locale ported (e.g. Arabic) requires `android:supportsRtl="true"`
  (set in AND-003 baseline); converter does not flip strings, layout mirroring is a
  layout concern, not a copy concern.
- Contrast/font scaling unaffected by this ticket.

## 10. Telemetry & Logging

No runtime telemetry is added. Build-time logging only: the `convertLocales` task
emits a per-locale summary (locale, key count, plural count, skipped/orphan keys)
to the Gradle console and a `build/reports/locales/coverage.txt` artifact listing,
per non-default locale, the count and names of keys falling back to default. This
coverage report is the artifact reviewers use to judge translation completeness.
Actual usage analytics for locale selection belong to AND-113.

## 11. Testing Strategy

**Unit (converter, `core-testing` + JVM):**

```kotlin
class LocaleConverterTest {
    @Test fun flattens_nested_i18next_keys()
    @Test fun maps_interpolation_to_positional_args()      // {{name}} -> %1$s
    @Test fun groups_one_other_into_plurals()
    @Test fun maps_bcp47_to_android_qualifier()            // pt-BR -> values-pt-rBR
    @Test fun escapes_apostrophes_and_percent()
    @Test fun rejects_orphan_key_absent_from_default()     // FR-8
    @Test fun idempotent_on_unchanged_input()              // FR-6
}
```

**Instrumented / Robolectric (resource resolution):**

```kotlin
@Config(qualifiers = "es")
@Test fun spanish_resolves_translated_value() {
    assertThat(context.getString(R.string.auth_login_submit))
        .isEqualTo("Iniciar sesión")
}

@Config(qualifiers = "es")
@Test fun missing_es_key_falls_back_to_default() {        // FR-3
    // key only present in values/strings.xml
    assertThat(context.getString(R.string.some_en_only_key))
        .isEqualTo(context.createConfigurationContext(
            Configuration().apply { setLocale(Locale.ENGLISH) })
            .getString(R.string.some_en_only_key))
}
```

**Parity test:** assert the set of resource names generated for each non-default
locale is a subset of the default set, and that the default set equals the union of
all flattened web keys (no drops, no orphans).

**CI gate:** run `./gradlew convertLocales` then `git diff --exit-code
core-ui/src/main/res` — committed output must match regeneration (FR-6).

**Lint:** `StringFormatInvalid`, `StringFormatMatches`, `PluralsCandidate`,
`MissingTranslation` configured (MissingTranslation may be informational, since
fallback is intentional — documented in `lint.xml`).

## 12. Dependencies & Sequencing

- **Hard dependency: AND-111** — conventions, prefix scheme, plurals/format style,
  and the hardcoded-string Lint must exist first; this ticket applies them.
- **Transitively: AND-003** (project/Gradle baseline, `supportsRtl`, AppCompat
  dependency) via AND-111.
- **Blocks: AND-113** — server-locale sync consumes these catalogs and the
  `locales_config.xml` produced here.
- Internal sequencing: (a) implement converter + tests, (b) run against
  `frontend/src/i18n/locales`, (c) commit generated `values-*`, (d) add
  `locales_config.xml` + manifest reference, (e) wire CI diff gate.
- No backend or feature-module work is required; integrates cleanly with `core-ui`.

## 13. Risks & Open Questions

- **R1 — Which locales does the web actually ship?** The acceptance bar is "≥2
  locales"; the full target set depends on `frontend/src/i18n/locales` contents at
  port time. Resolution: port `en` + every directory present; flag incomplete
  translations in the coverage report rather than blocking.
- **R2 — Language-specific plural rules.** i18next and Android both follow CLDR,
  but the converter must emit only the `quantity` forms a given locale legally uses
  (e.g. no `_one` for Japanese). Mitigation: drive plural categories from
  `android.icu.text.PluralRules` for the target locale.
- **R3 — Key collisions after snake_case sanitization** (e.g. `login.Submit` vs
  `login_submit`). Mitigation: converter detects collisions and fails.
- **R4 — Region vs language qualifiers** for fallback correctness (`values-pt-rBR`
  will not fall back to `values-pt` unless `values-pt` exists; it falls to
  `values/`). Open question for AND-113: do we want intermediate language-only
  catalogs? Documented, not blocking here.
- **R5 — ICU `<` / format edge cases** in web copy; covered by escaping tests but
  may surface untested patterns — coverage report surfaces anomalies.

## 14. Acceptance Criteria

AC-1. (Source acceptance) At least two locales load at runtime; a Robolectric test
proves `en` and `es` each resolve their own translated values.

AC-2. (Source acceptance) A key missing from the `es` catalog falls back to the
default `en` value — proven by `missing_es_key_falls_back_to_default`; no empty
string, no key name, no crash.

AC-3. The default `values/strings.xml` (+ `plurals.xml`) contains a resource for
every flattened key in `frontend/src/i18n/locales/en/*.json` (parity test passes).

AC-4. i18next `{{var}}` placeholders appear as positional `%n$s`/`%n$d` and all
plurals are `<plurals>` with locale-correct `quantity` items.

AC-5. Running `./gradlew convertLocales` on unchanged source produces no git diff
(idempotency / CI gate green).

AC-6. An orphan key in a non-default locale fails the build.

AC-7. `locales_config.xml` exists, is referenced from the manifest, and lists every
ported locale; the system per-app language picker shows them.

## 15. Definition of Done

- Converter (`LocaleConverter` + `ConvertLocalesTask`) implemented in `build-logic`,
  unit-tested, idempotent, cross-platform (runs on the Windows dev environment).
- Generated `values/`, `values-<lang>/` (≥1 non-default), `plurals.xml`, and
  `xml/locales_config.xml` committed under `core-ui` with package base
  `com.testlogon.android`.
- Manifest references `@xml/locales_config`; AppCompat per-app language enabled.
- All §11 unit, Robolectric, parity, and idempotency tests pass; relevant Lint
  checks (`StringFormat*`, `PluralsCandidate`) green; coverage report generated.
- CI `git diff --exit-code` gate added and passing.
- No hardcoded user-facing strings remain in `core-ui` (AND-111 Lint clean).
- PR reviewed; coverage report attached showing per-locale key counts and
  fallbacks; merged to `android-port`.
- AND-113 unblocked (catalogs + `locales_config.xml` available for consumption).
