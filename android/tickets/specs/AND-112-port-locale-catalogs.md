---
id: AND-112
title: Port locale catalogs
milestone: M2
epic: E16
priority: P2
size: M
status: reviewed
reviewed_on: 2026-06-06
depends_on: [AND-111]
blocks: [AND-113]
---

# AND-112 — Port locale catalogs

## 1. Overview & Goal

The web reference app ships its user-facing copy as i18next JSON
catalogs under `src/i18n/locales/<lang>.json` (one flat file per locale —
verified: `en.json`, `es.json`, `fr.json`; there are **no** per-namespace
subdirectories, and keys are already flat dot-delimited strings such as
`"common.save"` and `"auth.login"`, not nested objects). The native
Android port must present the same copy, translated into the same set of locales,
using Android's resource-qualifier mechanism so that the platform performs locale
resolution and runtime fallback for us.

> Path note: the reference web source root in this repo is `src/` (reference app),
> not `frontend/src/`. Other sections in this spec say `frontend/src/i18n/locales`;
> the verified path is `src/i18n/locales` (see §16). The structure — not the
> top-level prefix — is what matters for the converter.

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

The web ships exactly three locales (verified, all LTR): `en` (fallback),
`es`, `fr`. The `pt-BR` / `zh-Hans` / Arabic examples used elsewhere in this spec
are illustrative of the BCP-47→qualifier mapping rules only; none of those locales
are present in the source today (see R1, resolved, and §16).

## 2. Context & References

- **Depends on AND-111** (`i18n-plumbing-string-structure`): defines the string
  resource conventions, plural/`plurals` structure, format-argument style
  (positional `%1$s` / `%1$d`), namespace-to-resource-name mapping, and enables
  the hardcoded-string Lint check. AND-112 consumes those conventions; it must not
  redefine them.
- **Blocks AND-113** (`server-locale-sync`): AND-113 reads the server/user locale
  preference and applies it via `AppCompatDelegate.setApplicationLocales` /
  per-app language. AND-113 requires the catalogs ported here to exist.
- Web source of truth: `src/i18n/locales/<lang>.json` (i18next JSON; verified
  path is `src/i18n/locales`, not `frontend/src/...`). The web app uses a **single**
  i18next namespace (`ns: ["translation"]`, `defaultNS: "translation"` — verified in
  `src/i18n/index.ts`), so there are no per-namespace files to map. Keys are flat
  dotted strings (`common.save`, `feed.comments_one`); the leading segment
  (`common`, `auth`, `feed`, …) is a key prefix, **not** an i18next colon-namespace.
  Shared DTOs in `src/api/types.ts` are not relevant to copy.
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

**Key → resource-name mapping.** The web app uses a single i18next namespace
(`translation`), so there are no namespaces to fold into separate files (and Android
merges all `values*/strings.xml` regardless). Each flat dotted key becomes one
resource name by replacing `.` with `_`: the verified key `auth.login` becomes
`auth_login`, and `feed.comments_one` / `feed.comments_other` group into the
`<plurals name="feed_comments">` resource. (Earlier drafts showed an
`auth:login.submit` colon-namespaced key — no such colon form or `login.submit` key
exists in the source; corrected here, see §16.) The prefix scheme is defined in
AND-111; AND-112 applies it deterministically.

**Conversion tool.** A Gradle task wrapping a Kotlin/JVM converter (preferred over
an ad-hoc shell script so it is testable and cross-platform on the Windows dev
box):

```kotlin
// build-logic/convert-locales/src/main/kotlin/LocaleConverter.kt
package com.testlogon.android.buildlogic.locales

data class WebCatalog(
    val locale: String,                 // BCP-47, e.g. "en", "es", "fr"
    val entries: Map<String, JsonValue> // flat "dotted.key" -> value (source is
                                        // already flat; flatten() stays defensive)
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

**Runtime access.** Compose reads via `stringResource(R.string.auth_login)`
and `pluralStringResource(R.plurals.feed_comments, n, n)` (verified resource names
derived from `auth.login` and `feed.comments_*`). No custom i18n runtime is
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

N/A for **this** ticket. No network calls are made by AND-112: locale catalogs are
bundled compile-time Android resources, mirroring how the web app itself bundles its
catalogs statically (`resources: { en, es, fr }` in `src/i18n/index.ts`, verified).

Correction to a prior draft claim: there is **no `locale` field on `/ui/me`**. The
web app persists/reads the user locale preference through a dedicated i18n API, not
`/ui/me`. Those endpoints (verified in the OpenAPI index and `src/api/endpoints/i18n.ts`)
are owned by **AND-113 (Server-locale sync)**, not AND-112:

- `GET  /ui/i18n/locales` — list available locales (public, no auth).
- `GET  /ui/i18n/translations/{locale}` — server-side translation bundle (public).
- `GET  /ui/i18n/locale` — read the authenticated user's saved locale.
- `PUT  /ui/i18n/locale` — save the user's locale (`{ locale }` body; web client
  treats this as **best-effort**, swallowing failures, because the preference is also
  kept in `localStorage["i18nextLng"]` — see `LanguageSwitcher.tsx`).

(The `/v1/kyc/i18n/*` endpoints are a separate KYC-specific i18n surface and are not
in scope for either ticket.) The dev backend (`http://18.222.237.167:8000`),
CSRF/cookie auth, and timeout/retry policy are therefore out of scope for AND-112.

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
    // Verified source: es.json "auth.login" = "Iniciar Sesión" -> R.string.auth_login
    assertThat(context.getString(R.string.auth_login))
        .isEqualTo("Iniciar Sesión")
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

- **R1 — Which locales does the web actually ship? (RESOLVED).** Verified: exactly
  three, all LTR — `en` (fallback), `es`, `fr` (`src/i18n/index.ts` `SUPPORTED_LOCALES`
  and `src/i18n/locales/{en,es,fr}.json`). Port `en` → `values/`, `es` → `values-es/`,
  `fr` → `values-fr/`. No region/script qualifiers are needed today. Keep the
  converter generic (port every file present) so new web locales import automatically;
  flag incomplete translations in the coverage report rather than blocking.
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

## 16. Citations & Assumption Audit

Each key technical claim, its verdict, and an exact source pointer. "OpenAPI"
refers to `reference/openapi.index.txt` (line cited) and
`reference/openapi.pretty.json`; frontend paths are under `reference/src/`.

1. **Locale catalogs live at `src/i18n/locales/<lang>.json` (one flat file per
   locale), not `<lang>/<namespace>.json` nested dirs.** VERDICT: Corrected.
   SOURCE: directory listing `src/i18n/locales/` → only `en.json`, `es.json`,
   `fr.json`; `src/i18n/index.ts` imports them directly.
2. **The source path is `src/i18n/locales`, not `frontend/src/i18n/locales`.**
   VERDICT: Corrected (prefix). SOURCE: `src/i18n/locales/` exists; no `frontend/`
   root present in the reference checkout. (Top-level prefix is environment-relative;
   structure is authoritative.)
3. **Keys are flat dot-delimited strings (`common.save`, `auth.login`,
   `feed.comments_one`), already flattened — not nested JSON objects.** VERDICT:
   Corrected. SOURCE: `src/i18n/locales/en.json` (e.g. lines 2, 69, 110).
4. **The web app uses a single i18next namespace `translation`; there is no
   colon-namespace and no `auth:login.submit` / `login.submit` key.** VERDICT:
   Corrected. SOURCE: `src/i18n/index.ts` (`ns: ["translation"]`,
   `defaultNS: "translation"`); no such key in any locale file.
5. **Exactly three locales are shipped — `en`, `es`, `fr`, all LTR; `en` is the
   fallback.** VERDICT: Corrected/Resolved (was R1 open question). SOURCE:
   `src/i18n/index.ts` `SUPPORTED_LOCALES` and `fallbackLng: "en"`;
   `src/i18n/locales/{en,es,fr}.json`.
6. **`pt-BR` / `zh-Hans` / Arabic are NOT in the source.** VERDICT:
   Unverified-assumption → reclassified as illustrative-only. SOURCE: same as #5
   (only en/es/fr present). The BCP-47→qualifier mapping rules they demonstrate are
   still correct framework behavior (see #13).
7. **i18next `{{var}}` interpolation placeholders exist and must map to positional
   args (FR-4).** VERDICT: Verified. SOURCE: `en.json` `messages.unlock`
   ("Unlock for {{price}}", line 90), `messages.scheduled` ("{{date}}", line 91),
   `errors.rateLimited` ("{{seconds}}", line 116).
8. **i18next plural forms (`_one`/`_other`) exist and must map to `<plurals>`
   (FR-5).** VERDICT: Verified. SOURCE: `en.json` `feed.comments_one`/`_other`
   (lines 110-111); same pair in `es.json` and `fr.json` (lines 110-111 each). No
   `_few`/`_many`/`_zero` forms appear in the shipped locales (those rules remain
   relevant only if such locales are later added — R2).
9. **Apostrophes appear in copy and require Android escaping (`'` → `\'`).**
   VERDICT: Verified. SOURCE: `en.json` `auth.noAccount` "Don't have an account?"
   (line 78); `fr.json` `profile.displayName` "Nom d'affichage" (line 121).
10. **es resolves `auth.login` to "Iniciar Sesión" (capital S).** VERDICT:
    Corrected (prior draft used `auth_login_submit`="Iniciar sesión", lowercase, wrong
    key). SOURCE: `es.json` line 69 (`"auth.login": "Iniciar Sesión"`).
11. **There is NO `locale` field on `/ui/me`.** VERDICT: Corrected. SOURCE:
    OpenAPI `GET /ui/me` (`openapi.index.txt:1638`, op `ui_me_ui_me_get`); user locale
    is exposed via the separate `/ui/i18n/locale` endpoint instead. (The only `locale`
    string in `types.ts` near `/ui/me` shapes is `SeoMetadata.locale`, line 10138 —
    unrelated SEO/OpenGraph field.)
12. **A dedicated server i18n API exists (owned by AND-113, not AND-112).**
    VERDICT: Verified. SOURCE: `GET /ui/i18n/locales` (`openapi.index.txt:1517`),
    `GET /ui/i18n/translations/{locale}` (`:1518`), `GET /ui/i18n/locale` (`:1515`),
    `PUT /ui/i18n/locale` (`:1516`); frontend `src/api/endpoints/i18n.ts`
    (`getLocales`, `getTranslations`, `getUserLocale`, `saveUserLocale`). The web
    `PUT` is best-effort and also persists to `localStorage["i18nextLng"]`
    (`src/components/shared/LanguageSwitcher.tsx`, lines 22-37).
13. **Android per-app language / `localeConfig` / `LocaleConfig`, resource-qualifier
    fallback, `pluralStringResource`, and BCP-47→`values-*` mapping
    (`pt-BR`→`values-pt-rBR`, `zh-Hans`→`values-b+zh+Hans`).** VERDICT:
    Unverified-assumption (framework ref — not checkable against this repo). SOURCE
    (framework ref): developer.android.com/guide/topics/resources/app-languages and
    .../resources/providing-resources#AlternativeResources (qualifier syntax and
    resolution). Marked as framework behavior, treated as authoritative for Android.
14. **`AppCompatDelegate.setApplicationLocales` backports per-app language to
    minSdk 24 via AppCompat 1.7+ (deferred to AND-113).** VERDICT:
    Unverified-assumption (framework ref). SOURCE (framework ref):
    developer.android.com/reference/androidx/appcompat/app/AppCompatDelegate.
15. **Lint checks `StringFormatInvalid`/`StringFormatMatches`/`PluralsCandidate`/
    `MissingTranslation` exist and behave as described.** VERDICT:
    Unverified-assumption (framework ref). SOURCE (framework ref): Android Lint
    checks catalog (googlesamples.github.io/android-custom-lint-rules / Studio Lint
    docs). Behavior assumed; not validated in this repo.

### Corrections made

- §1/§2/§4: catalog layout corrected from nested `<lang>/<namespace>.json` to flat
  `src/i18n/locales/<lang>.json`; clarified single `translation` namespace and that
  keys are already flat dotted strings.
- §1/§2/§4 source path corrected from `frontend/src/i18n/locales` to
  `src/i18n/locales` (prefix note added; structure is what matters).
- §4 key-mapping example corrected: removed the non-existent colon key
  `auth:login.submit`; replaced with verified `auth.login` → `auth_login` and
  `feed.comments_*` → `<plurals name="feed_comments">`.
- §4 runtime-access example resource names corrected to `R.string.auth_login` /
  `R.plurals.feed_comments`.
- §5 corrected: removed the false "`/ui/me` `locale` field" claim; documented the
  real `/ui/i18n/*` API and its AND-113 ownership; noted best-effort `PUT`.
- §11 Robolectric example corrected to `R.string.auth_login` == "Iniciar Sesión".
- §1/§13-R1: locale set resolved to the verified en/es/fr (all LTR); pt-BR/zh-Hans/
  Arabic relabeled as illustrative mapping examples only.

### Open assumptions

- All Android-framework behaviors (resource-qualifier fallback semantics, per-app
  `LocaleConfig`/`localeConfig`, `pluralStringResource`, `AppCompatDelegate`
  backport, the named Lint checks, ICU `android.icu.text.PluralRules`) are
  **framework refs** that cannot be verified against this repo; they rely on the
  cited Android documentation and are taken as authoritative (claims #13-#15).
- The build toolchain versions (Kotlin 2.0.21, AGP 8.7.3, Gradle 8.9, JDK 17,
  minSdk 24/compileSdk 35) and the `core-ui`/`build-logic` module layout come from
  AND-111/AND-003; not independently verifiable here. Assumed correct per those
  upstream tickets.
- The orphan-key (FR-8) and idempotency (FR-6) behaviors describe **to-be-built**
  converter logic, not existing source; verified only as design intent.
- Whether any future locale will need `_few`/`_many`/`_zero` plural categories is
  unknown today (none of en/es/fr do); R2 remains a forward-looking design note.

## 17. Test Plan

Test targets: **JVM** = JVM unit/Robolectric (local, no device); **emu** = headless
emulator AVD `test35` (x86_64, API 35); **device** = physical Samsung Galaxy A15 5G
(SM-A156U, API 34, arm64-v8a). This ticket is a build-time chore with no hardware,
camera, biometrics, push, WebRTC, or telephony surface, so most cases run on JVM;
emulator/device cases exist only to validate real on-device resource resolution,
the system per-app language picker, and ABI/API-level parity.

- **TC-AND-112-01** — Type: unit (JVM). Target: `LocaleConverter.flatten` /
  `resourceName`. Preconditions: load `en.json` fixture. Steps: run converter on the
  three real locale files; collect generated resource names. Expected: `auth.login`
  → `auth_login`, `common.save` → `common_save`, `messages.unlock` →
  `messages_unlock`; no colon handling needed; flatten is a no-op on already-flat
  keys. Traces: AC-3, AC-4.
- **TC-AND-112-02** — Type: unit (JVM). Target: interpolation mapping. Preconditions:
  keys `messages.unlock` ("...{{price}}"), `errors.rateLimited` ("...{{seconds}}...").
  Steps: convert. Expected: single-arg strings become `%1$s`; arg order preserved
  identically across en/es/fr for the same key. Traces: AC-4.
- **TC-AND-112-03** — Type: unit (JVM). Target: plural grouping. Preconditions:
  `feed.comments_one` / `feed.comments_other`. Steps: convert en, es, fr. Expected:
  one `<plurals name="feed_comments">` per locale with `quantity="one"` and
  `quantity="other"` items, each containing `%1$d`/`%1$s` for `{{count}}`; no leftover
  flat `feed_comments_one` string. Traces: AC-4.
- **TC-AND-112-04** — Type: unit (JVM). Target: escaping. Preconditions: en
  `auth.noAccount` "Don't have an account?", fr `profile.displayName`
  "Nom d'affichage". Steps: convert. Expected: apostrophes emitted as `\'`; output is
  valid Android XML; round-trips back to the original literal text. Traces: AC-4.
- **TC-AND-112-05** — Type: unit (JVM). Target: BCP-47→qualifier mapping
  (`qualifierDir`). Preconditions: synthetic inputs (en/es/fr present today plus the
  illustrative pt-BR/zh-Hans). Steps: call `qualifierDir`. Expected: `en`→`values`,
  `es`→`values-es`, `fr`→`values-fr`, `pt-BR`→`values-pt-rBR`,
  `zh-Hans`→`values-b+zh+Hans`. Traces: AC-7.
- **TC-AND-112-06** — Type: unit (JVM). Target: parity/orphan check (FR-8).
  Preconditions: default set from `en.json`; inject a key present in `es.json` but
  absent from `en.json`. Steps: run parity validator. Expected: build-breaking error
  naming the orphan locale+key; happy case (no orphan) passes and confirms every
  non-default locale's key set ⊆ default set, and default set == union of all web
  keys. Traces: AC-3, AC-6.
- **TC-AND-112-07** — Type: unit (JVM). Target: idempotency (FR-6).
  Preconditions: committed `values-*` output. Steps: run `convertLocales` twice on
  unchanged input; diff outputs. Expected: byte-identical output, zero diff
  (stable key ordering, stable XML formatting). Traces: AC-5.
- **TC-AND-112-08** — Type: integration / CI gate. Target: `./gradlew convertLocales`
  then `git diff --exit-code core-ui/src/main/res`. Preconditions: clean tree, real
  `src/i18n/locales` as input. Steps: regenerate, check exit code. Expected: exit 0
  (committed resources match regeneration). Traces: AC-5.
- **TC-AND-112-09** — Type: Robolectric (JVM). Target: translated-value resolution.
  Preconditions: generated resources on classpath, `@Config(qualifiers="es")`. Steps:
  `context.getString(R.string.auth_login)`. Expected: "Iniciar Sesión" (es) and
  "Log In" under default; `@Config(qualifiers="fr")` yields "Se Connecter" (verified
  fr.json value). Traces: AC-1.
- **TC-AND-112-10** — Type: Robolectric (JVM). Target: fallback (FR-3).
  Preconditions: a key present only in `values/strings.xml`, `@Config(qualifiers="es")`.
  Steps: resolve that key under the es config. Expected: returns the default `en`
  value — not an empty string, not the resource name, no exception/crash. Traces:
  AC-2.
- **TC-AND-112-11** — Type: instrumented (emu `test35`, API 35). Target: real
  on-device resource resolution + plural quantity selection. Preconditions: app
  installed; app locale set to `es` via `AppCompatDelegate.setApplicationLocales`.
  Steps: resolve `R.string.common_save` and
  `pluralStringResource(R.plurals.feed_comments, 1)` / `(…, 5)`. Expected: es strings
  shown; n=1 → "1 comentario", n=5 → "5 comentarios" (correct CLDR `one`/`other`).
  Traces: AC-1, AC-4.
- **TC-AND-112-12** — Type: instrumented/e2e (**device** — physical SM-A156U, API 34).
  Target: system per-app language picker + ABI/API-level parity. Rationale: MUST run
  on the physical device — validates the OS per-app language UI surfaced by
  `@xml/locales_config` on real Android 14, and confirms resources resolve correctly
  on arm64-v8a/API 34 (vs the x86_64/API 35 emulator). Preconditions: app installed
  on device; `android:localeConfig="@xml/locales_config"` set. Steps: open Settings →
  Apps → (app) → Language; verify the list shows English, Español, Français; select
  Español; relaunch app. Expected: picker lists exactly the three ported locales with
  native names; after selection the UI renders es copy; no missing-resource crash on
  arm64/API 34. Traces: AC-1, AC-7.
- **TC-AND-112-13** — Type: manual (offline / flaky-dev-host). Target: confirm
  AND-112 has zero network dependency. Preconditions: device/emulator in airplane mode,
  dev backend unreachable. Steps: cold-launch the app and switch locales locally.
  Expected: all ported copy resolves from bundled resources with no network call,
  no spinner, no error — locale rendering is fully offline (server `/ui/i18n/*` sync
  is AND-113's concern, must not be exercised here). Traces: AC-1, AC-2.
- **TC-AND-112-14** — Type: Compose-UI + accessibility (emu `test35`). Target:
  TalkBack/semantics announce translated copy. Preconditions: a screen using
  `stringResource(R.string.auth_login)`; app locale `es`; accessibility test harness
  (Espresso/Compose semantics + accessibility checks). Steps: render the screen,
  read the semantics/contentDescription text node, run the Compose accessibility
  checks. Expected: announced text is the es resource ("Iniciar Sesión"), proving no
  hardcoded string leaked the AND-111 Lint gate; no accessibility violations
  (labeled, focusable). Traces: AC-1.

### Coverage matrix

| AC   | Covered by |
|------|------------|
| AC-1 | TC-09, TC-11, TC-12, TC-13, TC-14 |
| AC-2 | TC-10, TC-13 |
| AC-3 | TC-01, TC-06 |
| AC-4 | TC-01, TC-02, TC-03, TC-04, TC-11 |
| AC-5 | TC-07, TC-08 |
| AC-6 | TC-06 |
| AC-7 | TC-05, TC-12 |
