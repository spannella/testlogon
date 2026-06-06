---
id: AND-019
title: Material 3 theme
milestone: M1
epic: E03
priority: P0
size: M
status: reviewed
reviewed_on: 2026-06-06
depends_on: [AND-003]
blocks: [AND-020, AND-021, AND-022, AND-023]
---

# AND-019 — Material 3 theme

## 1. Overview & Goal

Establish the single, canonical Material 3 design system for the TestLogon native
Android app inside the `core-ui` library module. This ticket delivers the
`TestLogonTheme` composable and its three pillars — a light/dark `ColorScheme`
with Android 12+ dynamic color support, a `Typography` scale, and a `Shapes`
definition — plus the supporting infrastructure (status-bar/edge-to-edge handling,
Compose previews, and a UI test) needed to prove the theme is applied app-wide.

Every feature module (`feature-auth`, `feature-mfa`, `feature-home`, and all
later screens) consumes this theme by wrapping its content in `TestLogonTheme {}`.
No feature is permitted to define its own `ColorScheme`, `Typography`, or raw
hard-coded colors; this ticket is the authoritative source. Success means a
designer or engineer can toggle the device into dark mode and observe the entire
app — including system bars — re-theme correctly, verified both by `@Preview`
rendering and an instrumented UI test that asserts theme color tokens resolve to
the expected light vs. dark values.

The goal is explicitly limited to the theme primitives and their wiring. Reusable
component composables (buttons, text fields, scaffolds, loading/empty/error
states) are out of scope and owned by downstream `core-ui` component tickets
(AND-020+). This ticket guarantees those components have a correct theming
foundation to build on.

## 2. Context & References

- **Module:** `core-ui` (Android library, namespace `com.testlogon.android.core.ui`),
  created by AND-003. This ticket adds the theme package; it does not create the
  module.
- **Dependency:** AND-003 (Core module structure) must be complete so `core-ui`
  exists, compiles, and is consumable by `app`.
- **Stack:** Kotlin 2.0.21, Jetpack Compose with the Compose BOM, Material 3
  (`androidx.compose.material3`), `compileSdk`/`targetSdk` 35, `minSdk` 24, JDK 17,
  AGP 8.7.3, Gradle 8.9.
- **Dynamic color** requires Android 12 (API 31+); on API 24–30 the app falls
  back to the static brand `ColorScheme`. `Build.VERSION.SDK_INT` gating is
  mandatory because `minSdk` is 24.
- **Edge-to-edge:** `targetSdk` 35 forces edge-to-edge by default; theme must
  cooperate via `enableEdgeToEdge()` (called by the single Activity, AND owned by
  the app shell ticket) and transparent system bars driven by theme darkness.
- **Web reference:** `frontend/` uses its own design tokens (shadcn/ui + Tailwind
  HSL variables); there is no requirement for pixel parity. Brand colors below are
  seed values for the static scheme and may be refined by design later without
  changing this contract. Note (verified): the web app actually persists a
  three-way theme **mode** (`"light" | "dark" | "system"`) plus accent color,
  font scale, density, and high-contrast server-side via `GET/PATCH/PUT/DELETE
  /ui/theme` (`ThemeConfigResponse` → `ThemeConfig`), and applies the `system`
  case reactively through `matchMedia("(prefers-color-scheme: dark)")` (see
  `src/components/ThemeProvider.tsx`). This Android ticket deliberately implements
  only the OS-following case (`isSystemInDarkTheme()`); mirroring the persisted
  `/ui/theme` `mode` preference is a separate future ticket (see §6, §13).
- **Downstream consumers (blocks):** AND-020+ core-ui components, `feature-*`
  screens, and the single-Activity app shell all depend on `TestLogonTheme`.

## 3. Functional Requirements

1. **FR-1 Theme entry point.** Provide `TestLogonTheme(darkTheme, dynamicColor,
   content)` in `core-ui`. It resolves a `ColorScheme`, applies `Typography` and
   `Shapes`, and emits `MaterialTheme`.
2. **FR-2 Light & dark schemes.** Define complete static `lightColorScheme()` and
   `darkColorScheme()` instances using the brand seed palette. All Material 3
   roles (`primary`, `onPrimary`, `primaryContainer`, `secondary`, `tertiary`,
   `error`, `background`, `surface`, `surfaceVariant`, `outline`, etc.) must be
   populated; no role may be left at library default unless intentional.
3. **FR-3 Dynamic color.** When `dynamicColor == true` and `SDK_INT >= 31`, use
   `dynamicLightColorScheme(context)` / `dynamicDarkColorScheme(context)`.
   Otherwise use the static schemes. `dynamicColor` defaults to `true`.
4. **FR-4 Dark mode source of truth.** `darkTheme` defaults to
   `isSystemInDarkTheme()` so the app follows the OS setting, but callers may
   override (used by previews and tests).
5. **FR-5 Typography.** Define a `Typography` covering all Material 3 type roles
   (`displayLarge` … `labelSmall`) with explicit `fontFamily`, `fontWeight`,
   `fontSize`, `lineHeight`, `letterSpacing`. Use the platform default font
   family (no bundled custom font in this ticket) so there are no licensing/asset
   tasks.
6. **FR-6 Shapes.** Define `Shapes` with `extraSmall`=4.dp, `small`=8.dp,
   `medium`=12.dp, `large`=16.dp, `extraLarge`=28.dp rounded corners.
7. **FR-7 System bars.** Drive status-bar/navigation-bar icon appearance from the
   effective `darkTheme` value so light/dark icons contrast correctly under
   edge-to-edge.
8. **FR-8 App-wide application.** The theme is the only theme; consuming code
   wraps top-level content once. No feature defines its own scheme.
9. **FR-9 Previews.** Provide `@Preview` composables demonstrating light and dark
   rendering of representative themed elements.
10. **FR-10 Verification.** A connected/Robolectric UI test asserts color tokens
    differ between light and dark and match expected static values.

## 4. Technical Design

### Package layout (in `core-ui`)

```
core-ui/src/main/java/com/testlogon/android/core/ui/theme/
  Color.kt        // brand color constants + light/dark ColorScheme definitions
  Type.kt         // Typography
  Shape.kt        // Shapes
  Theme.kt        // TestLogonTheme composable + system-bar handling
```

### Theme.kt

```kotlin
package com.testlogon.android.core.ui.theme

@Composable
fun TestLogonTheme(
    darkTheme: Boolean = isSystemInDarkTheme(),
    // Dynamic color is available on Android 12+
    dynamicColor: Boolean = true,
    content: @Composable () -> Unit,
) {
    val context = LocalContext.current
    val colorScheme: ColorScheme = when {
        dynamicColor && Build.VERSION.SDK_INT >= Build.VERSION_CODES.S ->
            if (darkTheme) dynamicDarkColorScheme(context)
            else dynamicLightColorScheme(context)
        darkTheme -> DarkColors
        else -> LightColors
    }

    ApplySystemBarAppearance(darkTheme = darkTheme)

    MaterialTheme(
        colorScheme = colorScheme,
        typography = TestLogonTypography,
        shapes = TestLogonShapes,
        content = content,
    )
}
```

### System bars (edge-to-edge cooperative)

Window insets and `enableEdgeToEdge()` are called by the single Activity (app
shell ticket). This ticket only adjusts the *icon* appearance to match theme
darkness, using a non-deprecated path that works on API 24+:

```kotlin
@Composable
private fun ApplySystemBarAppearance(darkTheme: Boolean) {
    val view = LocalView.current
    if (!view.isInEditMode) {
        SideEffect {
            val window = (view.context as Activity).window
            WindowCompat.getInsetsController(window, view).apply {
                isAppearanceLightStatusBars = !darkTheme
                isAppearanceLightNavigationBars = !darkTheme
            }
        }
    }
}
```

`isInEditMode` guards previews (no host Activity). The cast to `Activity` is safe
in app context; tests that host the theme outside an Activity must use the preview
override path (`view.isInEditMode` or a `ComponentActivity` test host).

### Color.kt (static schemes)

```kotlin
// Brand seed palette
val BrandPrimary       = Color(0xFF2962FF)
val BrandSecondary     = Color(0xFF455A64)
val BrandTertiary      = Color(0xFF00897B)
val BrandError         = Color(0xFFB3261E)

internal val LightColors: ColorScheme = lightColorScheme(
    primary = BrandPrimary,
    onPrimary = Color.White,
    primaryContainer = Color(0xFFD8E2FF),
    onPrimaryContainer = Color(0xFF001A41),
    secondary = BrandSecondary,
    tertiary = BrandTertiary,
    error = BrandError,
    background = Color(0xFFFDFBFF),
    onBackground = Color(0xFF1A1C1E),
    surface = Color(0xFFFDFBFF),
    onSurface = Color(0xFF1A1C1E),
    surfaceVariant = Color(0xFFE1E2EC),
    outline = Color(0xFF74777F),
)

internal val DarkColors: ColorScheme = darkColorScheme(
    primary = Color(0xFFADC6FF),
    onPrimary = Color(0xFF002E69),
    primaryContainer = Color(0xFF004494),
    onPrimaryContainer = Color(0xFFD8E2FF),
    secondary = Color(0xFFB9C8D6),
    tertiary = Color(0xFF4DB6AC),
    error = Color(0xFFF2B8B5),
    background = Color(0xFF1A1C1E),
    onBackground = Color(0xFFE2E2E6),
    surface = Color(0xFF1A1C1E),
    onSurface = Color(0xFFE2E2E6),
    surfaceVariant = Color(0xFF43474E),
    outline = Color(0xFF8E9199),
)
```

The two schemes deliberately use distinct `primary`/`background`/`surface` values
so the UI test (FR-10) can assert measurable divergence.

### Type.kt / Shape.kt

```kotlin
internal val TestLogonTypography: Typography = Typography(
    titleLarge = TextStyle(
        fontFamily = FontFamily.Default, fontWeight = FontWeight.SemiBold,
        fontSize = 22.sp, lineHeight = 28.sp, letterSpacing = 0.sp,
    ),
    bodyLarge = TextStyle(
        fontFamily = FontFamily.Default, fontWeight = FontWeight.Normal,
        fontSize = 16.sp, lineHeight = 24.sp, letterSpacing = 0.5.sp,
    ),
    labelLarge = TextStyle(
        fontFamily = FontFamily.Default, fontWeight = FontWeight.Medium,
        fontSize = 14.sp, lineHeight = 20.sp, letterSpacing = 0.1.sp,
    ),
    // ...remaining roles (display*, headline*, title*, body*, label*) defined explicitly
)

internal val TestLogonShapes: Shapes = Shapes(
    extraSmall = RoundedCornerShape(4.dp),
    small = RoundedCornerShape(8.dp),
    medium = RoundedCornerShape(12.dp),
    large = RoundedCornerShape(16.dp),
    extraLarge = RoundedCornerShape(28.dp),
)
```

### Gradle wiring (`core-ui/build.gradle.kts`)

```kotlin
android {
    namespace = "com.testlogon.android.core.ui"
    buildFeatures { compose = true }
}
dependencies {
    val composeBom = platform(libs.androidx.compose.bom)
    implementation(composeBom); androidTestImplementation(composeBom)
    api(libs.androidx.compose.material3)
    api(libs.androidx.compose.ui)
    debugImplementation(libs.androidx.compose.ui.tooling)
    implementation(libs.androidx.compose.ui.tooling.preview)
    implementation(libs.androidx.core.ktx)            // WindowCompat
    androidTestImplementation(libs.androidx.compose.ui.test.junit4)
    androidTestImplementation(libs.androidx.test.ext.junit)
}
```

Material 3 and core Compose APIs are exposed via `api(...)` so feature modules
inherit them transitively through `core-ui`.

## 5. API Contract

Not applicable. AND-019 is a pure UI/design-system ticket inside `core-ui` and
makes no network calls. There is no FastAPI endpoint, request, or response shape
associated with it. Networking contracts (session, MFA, error mapping) are owned
by the `core-network` tickets AND-009 through AND-016 and consumed by feature
tickets, none of which this ticket touches.

The "contract" this ticket exposes is the public Kotlin surface in
`com.testlogon.android.core.ui.theme`: the single public composable
`TestLogonTheme(darkTheme, dynamicColor, content)`. Color/type/shape definitions
are `internal` and not part of the public API; consumers read tokens at runtime
via `MaterialTheme.colorScheme`, `MaterialTheme.typography`,
`MaterialTheme.shapes`.

## 6. Data & State Management

No persistent or networked data is introduced. The theme has exactly two inputs:

- **`darkTheme: Boolean`** — defaults to `isSystemInDarkTheme()`, a Compose-level
  read of the OS night-mode `Configuration`. The app does not store a per-user
  light/dark override in this ticket; an in-app theme preference is explicitly out
  of scope and, if desired later, is a separate ticket that would pass an override
  into `darkTheme`. (Verified: the web reference persists this as `ThemeConfig.mode`
  = `"light" | "dark" | "system"` via `/ui/theme`; a future Android override ticket
  should mirror that field rather than invent a new contract, and would likely back
  the override with DataStore and/or the `/ui/theme` endpoint.)
- **`dynamicColor: Boolean`** — compile-time default `true`, gated at runtime by
  `Build.VERSION.SDK_INT`.

State flows through Compose's `CompositionLocal` mechanism: `MaterialTheme`
installs `LocalColorScheme`, `LocalTypography`, and `LocalShapes`. No
`StateFlow`, ViewModel, Room, or DataStore is involved. Theme recomposition on OS
night-mode change is handled automatically by `isSystemInDarkTheme()` reacting to
`Configuration` changes; no manual subscription is required.

## 7. Error Handling & Resilience

There are no failure modes from I/O, parsing, or network in this ticket. The
relevant resilience concerns are correctness/compatibility:

- **API-level gating.** `dynamicDarkColorScheme`/`dynamicLightColorScheme` exist
  only on API 31+. The `when` branch is guarded by
  `Build.VERSION.SDK_INT >= Build.VERSION_CODES.S`; on API 24–30 the static
  schemes are always used. Lint `NewApi` must pass clean.
- **Missing Activity context.** `ApplySystemBarAppearance` casts
  `view.context` to `Activity`. Inside `@Preview` (`view.isInEditMode == true`)
  the side effect is skipped to avoid a `ClassCastException`. Tests host the
  composable in a real `ComponentActivity` (via `createComposeRule()`'s default
  activity) so the cast succeeds.
- **Incomplete schemes.** All Material 3 color roles are populated explicitly to
  avoid surprising library-default colors (e.g., grey containers) leaking into
  themed components.

## 8. Security & Privacy

No security-sensitive surface. The theme handles no credentials, cookies, CSRF
tokens, PII, or network traffic. It reads only public, non-sensitive system
state: the OS night-mode flag and (on API 31+) the user's dynamic-color palette
seeded from their wallpaper. Dynamic color reads only the derived tonal palette
exposed by the platform `DynamicColors` API — never the wallpaper image itself —
so no image data or media permission is accessed. No new Android permissions are
declared. No logging of any user data occurs (see Section 10).

## 9. Accessibility & i18n

- **Contrast.** Static light/dark schemes are chosen so `onX`/`X` role pairs meet
  WCAG AA contrast (≥4.5:1 for body text). This is validated visually via dark/
  light previews and should be spot-checked with a contrast tool; downstream
  component tickets carry the per-component contrast assertions.
- **Dynamic type.** Typography uses `sp` units so it scales with the system font
  size setting. No fixed `dp` text sizes are used. `lineHeight` is set per role to
  preserve legibility at large scale factors.
- **System bar contrast.** `isAppearanceLightStatusBars`/`...NavigationBars` are
  driven by `darkTheme` so bar icons remain visible against the themed background
  under edge-to-edge.
- **i18n.** The theme contains no user-facing strings; there is nothing to
  localize. Layout direction (RTL) is unaffected because shapes are symmetric
  rounded corners. No hard-coded strings are introduced.

## 10. Telemetry & Logging

No telemetry or analytics events are emitted by the theme; emitting events on
theme resolution would be noise. No `Log` / `Timber` calls are added — the theme
runs on every recomposition and must stay silent and allocation-light. If a
future debugging need arises, a single `debug`-build-only log of the resolved
scheme branch (dynamic vs. static, light vs. dark) at first composition may be
added, but it is not part of this ticket's deliverable. App-level crash/analytics
infrastructure is owned by separate observability tickets.

## 11. Testing Strategy

### Compose previews (FR-9) — manual/visual

```kotlin
@Preview(name = "Light", uiMode = Configuration.UI_MODE_NIGHT_NO)
@Preview(name = "Dark", uiMode = Configuration.UI_MODE_NIGHT_YES)
@Composable
private fun ThemePreview() {
    TestLogonTheme(dynamicColor = false) {
        Surface(color = MaterialTheme.colorScheme.background) {
            Column(Modifier.padding(16.dp)) {
                Text("TestLogon", style = MaterialTheme.typography.titleLarge)
                Text("Body sample", style = MaterialTheme.typography.bodyLarge)
                Button(onClick = {}) { Text("Primary") }
            }
        }
    }
}
```

`dynamicColor = false` forces the static brand palette so previews are
deterministic across machines.

### Instrumented / Robolectric UI test (FR-10)

Using `createComposeRule()` (Robolectric-capable, runs on CI without a device):

```kotlin
@RunWith(AndroidJUnit4::class)
class TestLogonThemeTest {
    @get:Rule val rule = createComposeRule()

    private fun capturePrimary(dark: Boolean): Color {
        var captured = Color.Unspecified
        rule.setContent {
            TestLogonTheme(darkTheme = dark, dynamicColor = false) {
                captured = MaterialTheme.colorScheme.primary
            }
        }
        return captured
    }

    @Test fun light_primary_matches_brand() {
        assertEquals(BrandPrimary, capturePrimary(dark = false))
    }

    @Test fun dark_primary_differs_from_light() {
        assertNotEquals(capturePrimary(dark = false), capturePrimary(dark = true))
    }

    @Test fun dark_background_is_dark_scheme_value() {
        var bg = Color.Unspecified
        rule.setContent {
            TestLogonTheme(darkTheme = true, dynamicColor = false) {
                bg = MaterialTheme.colorScheme.background
            }
        }
        assertEquals(Color(0xFF1A1C1E), bg)
    }
}
```

This satisfies "dark mode verified via preview + UI test." Tests pin
`dynamicColor = false` so assertions are independent of the test device's
wallpaper palette. Typography and shapes are smoke-checked by asserting
`MaterialTheme.typography.titleLarge.fontSize == 22.sp` and
`MaterialTheme.shapes.medium == RoundedCornerShape(12.dp)` in a third test.

### CI

Tests run under the existing CI build (AND-008) via the standard
`testDebugUnitTest` (Robolectric) task; no device farm needed.

## 12. Dependencies & Sequencing

- **Depends on AND-003** (Core module structure): `core-ui` must exist with its
  namespace and build file and be consumable by `app`. This is a hard
  prerequisite — there is nowhere to put the theme otherwise.
- **Indirectly relies on AND-001/AND-002** for the Compose BOM, version catalog
  (`libs.versions.toml`), and Compose compiler plugin being configured; if the
  Compose plugin is not yet enabled in `core-ui`, this ticket includes enabling
  `buildFeatures { compose = true }` and the Kotlin Compose plugin for that
  module.
- **Blocks** all UI work: the core-ui component library tickets (AND-020+), every
  `feature-*` screen, and the single-Activity app shell, since they wrap content
  in `TestLogonTheme`. Land this early in M1's UI epic (E03).
- No backend, no flavor (AND-006), and no networking dependency.

## 13. Risks & Open Questions

- **Brand palette is provisional.** The seed colors above are engineering
  placeholders. Risk: design later supplies official tokens. Mitigation: colors
  are centralized in `Color.kt`; swapping values is a one-file change and the UI
  test's expected constants update alongside. *Open question: are official brand
  hex values available before M1 close?*
- **Dynamic color vs. brand identity.** With `dynamicColor = true` default, Android
  12+ devices show wallpaper-derived colors, not brand colors. *Open question:
  should TestLogon prefer brand consistency (default `false`) or system harmony
  (default `true`)?* Spec defaults to `true` per the scope's "dynamic color"
  requirement; flip the default if product disagrees.
- **In-app theme override.** No user-facing light/dark toggle is delivered. If
  product wants one, it is a follow-up ticket adding a preference fed into
  `darkTheme`. To stay contract-compatible with the web client, that ticket should
  mirror the existing backend `ThemeConfig.mode` (`"light" | "dark" | "system"`)
  exposed by `GET/PATCH/PUT/DELETE /ui/theme`, rather than a bespoke local-only
  enum. (The web app also persists accent color, font scale, density, and
  high-contrast via the same endpoint; those are out of scope for the Android M3
  theme ticket and would be further follow-ups.)
- **Activity cast assumption.** `ApplySystemBarAppearance` assumes the host
  context is an `Activity`. Safe for the single-Activity architecture but would
  break if the theme were ever hosted in a non-Activity context (e.g., a custom
  `Dialog` without window). Acceptable given current architecture.

## 14. Acceptance Criteria

1. `TestLogonTheme(darkTheme, dynamicColor, content)` exists in
   `com.testlogon.android.core.ui.theme` and is the single public theme entry
   point. (FR-1)
2. Complete static `lightColorScheme()` and `darkColorScheme()` are defined with
   all Material 3 roles populated; `Typography` covers all roles; `Shapes` uses
   the specified corner radii. (FR-2, FR-5, FR-6)
3. Dynamic color is used only when `dynamicColor == true` and `SDK_INT >= 31`;
   otherwise static schemes are used. Lint `NewApi` passes. (FR-3)
4. `darkTheme` defaults to `isSystemInDarkTheme()` and is overridable. (FR-4)
5. System-bar icon appearance follows `darkTheme`. (FR-7)
6. Light and dark `@Preview` composables render correctly in Android Studio.
   (FR-9)
7. The UI test asserts: light `primary == BrandPrimary`, dark `primary !=` light
   `primary`, dark `background == 0xFF1A1C1E`, and that typography/shape tokens
   match the spec. All tests pass under `testDebugUnitTest` on CI. (FR-10)
8. `core-ui` compiles and is consumed by at least the app shell / a sample
   `TestLogonTheme {}` wrapper without any feature module redefining a
   `ColorScheme`. (FR-8)

## 15. Definition of Done

- All Section 14 acceptance criteria met and demonstrably true.
- Code merged to branch `android-port` under
  `android/core-ui/src/main/java/com/testlogon/android/core/ui/theme/`.
- `:core-ui:assembleDebug`, `:core-ui:lintDebug`, and `:core-ui:testDebugUnitTest`
  all green locally and on CI (AND-008).
- No hard-coded colors, type sizes, or shapes outside the `theme` package; no
  Material 2 (`androidx.compose.material`) imports introduced.
- Material 3 and Compose UI exposed via `api(...)` so feature modules inherit them
  through `core-ui`.
- Light/dark previews verified visually; dark mode UI test verified passing.
- No new permissions, no telemetry, no user-facing strings added.
- Brief KDoc on `TestLogonTheme` documenting the `darkTheme`/`dynamicColor`
  parameters and the API-31 dynamic-color gate.

## 16. Citations & Assumption Audit

This is a pure `core-ui` design-system ticket: it makes **no** network calls, so
most claims are framework references (Android/Compose docs) rather than backend
contract claims. Backend/frontend sources were still checked for the spec's claims
about the web reference's theming behavior, since the spec asserts things about it.

1. **Claim:** "AND-019 makes no network calls; there is no FastAPI endpoint,
   request, or response shape associated with it" (§5).
   **VERDICT:** Verified. The ticket's deliverables (`TestLogonTheme`, color/type/
   shape definitions) are UI-only. There is no theming-related endpoint *consumed
   by this ticket*. (Backend theming endpoints exist but are not in this ticket's
   scope — see claim 2.)
   **SOURCE:** Ticket scope `specs-src/AND-019.md`; absence of any endpoint call
   in the deliverable design (§4).

2. **Claim (added in review):** "The web reference persists a three-way theme
   `mode` plus accent/font/density/high-contrast server-side" (§2, §6, §13).
   **VERDICT:** Verified.
   **SOURCE:** OpenAPI `GET /ui/theme`, `PATCH /ui/theme`, `PUT /ui/theme`,
   `DELETE /ui/theme` (all `resp=200:ThemeConfigResponse`); schema
   `components.schemas.ThemeConfigResponse` / `ThemeConfig`;
   `src/api/endpoints/themeCustomization.ts: getThemeCustomization / patchThemeCustomization / resetThemeCustomization`;
   `src/api/types.ts: ThemeConfig` (fields `mode`, `accent_color`,
   `custom_accent_hex`, `font_scale`, `density`, `preset`, `high_contrast`) and
   `ThemeMode = "light" | "dark" | "system"`.

3. **Claim (added in review):** "The web app applies the `system` theme case
   reactively via `matchMedia('(prefers-color-scheme: dark)')`."
   **VERDICT:** Verified.
   **SOURCE:** `src/components/ThemeProvider.tsx` (the dark/light `useEffect`
   toggles the `dark` class on `<html>` and, for `theme === "system"`, subscribes
   to `window.matchMedia("(prefers-color-scheme: dark)")`). The Android analogue
   is `isSystemInDarkTheme()` (framework ref).

4. **Claim:** "Web app has an Appearance settings screen offering System / Light /
   Dark."
   **VERDICT:** Verified.
   **SOURCE:** `src/pages/settings/Appearance.tsx` (`THEMES` array with values
   `system | light | dark`, `setTheme` from `uiStore`).

5. **Claim:** "`/ui/theme` requires a UI session and CSRF for non-GET cookie
   requests."
   **VERDICT:** Verified (as the web client's documented behavior).
   **SOURCE:** `src/api/endpoints/themeCustomization.ts` header comment
   ("Backend: /ui/theme (require_ui_session; CSRF for non-GET cookie requests)").
   Not exercised by this Android ticket; relevant only to the future override
   ticket noted in §6/§13.

6. **Claim:** "Dynamic color requires Android 12 (API 31, `Build.VERSION_CODES.S`);
   `dynamicLightColorScheme(context)` / `dynamicDarkColorScheme(context)` are used
   only when `SDK_INT >= 31`, else static schemes; `minSdk` 24 makes the gate
   mandatory" (§2, §3 FR-3, §7).
   **VERDICT:** Verified (framework ref).
   **SOURCE:** framework ref — Android Material 3 Compose dynamic color API
   (`androidx.compose.material3.dynamicLightColorScheme` /
   `dynamicDarkColorScheme`, available API 31+):
   https://developer.android.com/develop/ui/compose/designsystems/material3#dynamic .

7. **Claim:** "`darkTheme` defaults to `isSystemInDarkTheme()` and recomposes on OS
   night-mode change without manual subscription" (§3 FR-4, §6).
   **VERDICT:** Verified (framework ref).
   **SOURCE:** framework ref — `androidx.compose.foundation.isSystemInDarkTheme`:
   https://developer.android.com/reference/kotlin/androidx/compose/foundation/package-summary#isSystemInDarkTheme() .

8. **Claim:** "System-bar icon appearance is driven via
   `WindowCompat.getInsetsController(window, view)` setting
   `isAppearanceLightStatusBars` / `isAppearanceLightNavigationBars`; this path is
   non-deprecated and works API 24+" (§4, §3 FR-7).
   **VERDICT:** Verified (framework ref).
   **SOURCE:** framework ref — `androidx.core.view.WindowCompat` /
   `WindowInsetsControllerCompat`:
   https://developer.android.com/reference/androidx/core/view/WindowInsetsControllerCompat .

9. **Claim:** "`targetSdk` 35 forces edge-to-edge by default; the Activity calls
   `enableEdgeToEdge()`" (§2).
   **VERDICT:** Verified (framework ref). `enableEdgeToEdge()` ownership is
   correctly placed in the app-shell Activity, not this ticket.
   **SOURCE:** framework ref — Android 15 edge-to-edge enforcement and
   `enableEdgeToEdge`:
   https://developer.android.com/develop/ui/views/layout/edge-to-edge .

10. **Claim:** "M3 `Shapes` roles are `extraSmall`/`small`/`medium`/`large`/
    `extraLarge`; the spec sets 4/8/12/16/28 dp" (§3 FR-6, §4).
    **VERDICT:** Verified (framework ref). The role *names* are the real M3 shape
    roles; the dp values are an intentional project choice (and happen to match the
    M3 default scale).
    **SOURCE:** framework ref — `androidx.compose.material3.Shapes`:
    https://developer.android.com/reference/kotlin/androidx/compose/material3/Shapes .

11. **Claim:** "`MaterialTheme` installs the resolved scheme/typography/shapes via
    composition locals readable as `MaterialTheme.colorScheme/.typography/.shapes`"
    (§5, §6).
    **VERDICT:** Verified (framework ref).
    **SOURCE:** framework ref — `androidx.compose.material3.MaterialTheme`:
    https://developer.android.com/reference/kotlin/androidx/compose/material3/MaterialTheme .

12. **Claim:** "`createComposeRule()` is Robolectric-capable and runs under
    `testDebugUnitTest` without a device; default test host is a
    `ComponentActivity`, so the `Activity` cast in `ApplySystemBarAppearance`
    succeeds" (§7, §11).
    **VERDICT:** Verified (framework ref).
    **SOURCE:** framework ref — Compose testing (`createComposeRule`) and
    Robolectric support for Compose:
    https://developer.android.com/develop/ui/compose/testing .

13. **Claim:** "Brand seed hex values (`BrandPrimary 0xFF2962FF`, etc.) and the
    full light/dark role assignments are the design contract" (§4).
    **VERDICT:** Unverified-assumption (explicitly flagged provisional in §13).
    **SOURCE:** none authoritative — these are engineering placeholders; no design
    token source exists in the reference repo for the native app, and the web app
    uses unrelated shadcn HSL tokens.

14. **Claim:** "Typography uses `FontFamily.Default` (platform font), `sp` units
    scale with system font size; no bundled font" (§3 FR-5, §9).
    **VERDICT:** Verified (framework ref) for the API behavior; the specific per-
    role sizes are a project choice.
    **SOURCE:** framework ref — `androidx.compose.material3.Typography` and
    `sp` scaling: https://developer.android.com/develop/ui/compose/text/fonts .

15. **Claim:** "Dynamic color reads only the derived tonal palette, never the
    wallpaper image; no media permission required" (§8).
    **VERDICT:** Verified (framework ref).
    **SOURCE:** framework ref — Dynamic color is derived by the platform from the
    user's wallpaper and exposed only as a `ColorScheme`; no app permission is
    involved: https://developer.android.com/develop/ui/compose/designsystems/material3#dynamic .

### Corrections made

No hard factual errors (wrong endpoint path/method/field) were found — the spec's
"no network contract" stance is accurate for this ticket's scope. The review made
**accuracy/completeness corrections** to the spec's characterization of the web
reference:

- **§2 Web reference:** expanded from "uses its own design tokens" to also state
  (verified) that the web app persists a three-way theme `mode` + accent/font/
  density/high-contrast server-side via `/ui/theme` and applies `system` reactively
  via `matchMedia`. Previously the spec implied the web side had nothing
  comparable, which understated the existing contract.
- **§6 Data & State Management:** the "out of scope, future ticket" note now names
  the concrete backend contract (`ThemeConfig.mode` via `/ui/theme`) a future
  override ticket should mirror, instead of leaving the storage mechanism vague.
- **§13 Risks:** the in-app theme override risk now points the follow-up ticket at
  the existing `ThemeConfig.mode` enum (`"light" | "dark" | "system"`) for
  contract compatibility with the web client.

These are additive clarifications; no existing design decision, code sample, or
acceptance criterion was changed.

### Open assumptions

- **Brand palette (all hex values in §4):** unverifiable — no authoritative design
  token source for the native app exists in the reference repo; the web app's HSL
  tokens are unrelated. Flagged provisional in §13; UI-test expected constants must
  move with any design update (claim 13).
- **Per-role typography sizes/weights and shape dp values:** project choices, not
  derived from an authoritative source. The role *names* and scaling behavior are
  framework-verified (claims 10, 14); the exact numbers are assumptions.
- **`/ui/theme` auth/CSRF specifics for a future Android override:** the web client
  comment states `require_ui_session` + CSRF on non-GET (claim 5); the exact
  Android header/cookie handling is owned by the `core-network` tickets and is an
  assumption for any future override ticket, not validated here.

## 17. Test Plan

All cases trace to the Acceptance Criteria in §14 (AC-1 … AC-8). Because this is a
non-networked UI ticket, "contract/MockWebServer" cases are N/A; the contract under
test is the Kotlin/Compose theme surface. Tests pin `dynamicColor = false` unless a
case explicitly targets the dynamic-color branch so results are deterministic across
machines/wallpapers.

- **TC-AND-019-01 — Public theme entry point exists & emits MaterialTheme**
  Type: unit (compile/source) / Compose-UI.
  Preconditions: `core-ui` builds; AND-003 complete.
  Steps: Reference `TestLogonTheme(darkTheme, dynamicColor, content)` from a test in
  `com.testlogon.android.core.ui.theme`; set content that reads
  `MaterialTheme.colorScheme`.
  Expected: Symbol resolves as the single public composable; content composes and a
  non-null `ColorScheme` is provided.
  Traces: AC-1.

- **TC-AND-019-02 — Light primary equals BrandPrimary (static scheme)**
  Type: instrumented/Robolectric (`createComposeRule`).
  Preconditions: dynamic color disabled.
  Steps: `setContent { TestLogonTheme(darkTheme = false, dynamicColor = false) { capture = MaterialTheme.colorScheme.primary } }`.
  Expected: `captured == BrandPrimary` (0xFF2962FF).
  Traces: AC-2, AC-7.

- **TC-AND-019-03 — Dark primary differs from light primary**
  Type: instrumented/Robolectric.
  Preconditions: dynamic color disabled.
  Steps: Capture `primary` for `darkTheme = false` and `darkTheme = true`.
  Expected: The two values are not equal (measurable light/dark divergence).
  Traces: AC-7.

- **TC-AND-019-04 — Dark background is the dark-scheme value**
  Type: instrumented/Robolectric.
  Preconditions: dynamic color disabled.
  Steps: Capture `MaterialTheme.colorScheme.background` with `darkTheme = true`.
  Expected: `background == Color(0xFF1A1C1E)`.
  Traces: AC-7.

- **TC-AND-019-05 — All Material 3 color roles populated (no library defaults)**
  Type: unit/instrumented.
  Preconditions: dynamic color disabled.
  Steps: For both `LightColors` and `DarkColors`, assert the roles named in FR-2
  (`primary`, `onPrimary`, `primaryContainer`, `onPrimaryContainer`, `secondary`,
  `tertiary`, `error`, `background`, `onBackground`, `surface`, `onSurface`,
  `surfaceVariant`, `outline`) are `!= Color.Unspecified` and match the §4 constants.
  Expected: Every asserted role is explicitly set to the spec value.
  Traces: AC-2.

- **TC-AND-019-06 — Typography & shape tokens match spec**
  Type: unit/instrumented.
  Preconditions: none beyond theme available.
  Steps: Assert `MaterialTheme.typography.titleLarge.fontSize == 22.sp`,
  `bodyLarge.fontSize == 16.sp`, and `MaterialTheme.shapes.medium ==
  RoundedCornerShape(12.dp)` (plus extraSmall=4, small=8, large=16, extraLarge=28).
  Expected: All token assertions pass.
  Traces: AC-2, AC-7.

- **TC-AND-019-07 — `darkTheme` defaults to `isSystemInDarkTheme()` and is overridable**
  Type: instrumented/Robolectric (configuration override).
  Preconditions: ability to set `uiMode` night yes/no in the test config.
  Steps: (a) Host `TestLogonTheme(dynamicColor = false) { ... }` under a NIGHT_YES
  configuration and capture a scheme value; under NIGHT_NO capture again. (b)
  Separately call with explicit `darkTheme = true`/`false` to confirm the override
  wins regardless of system config.
  Expected: With no override, resolved scheme follows the system night mode; with an
  explicit `darkTheme`, the override is honored.
  Traces: AC-4.

- **TC-AND-019-08 — Dynamic color used only when enabled AND SDK_INT >= 31**
  Type: instrumented/Robolectric with `@Config(sdk = ...)`.
  Preconditions: Robolectric able to set SDK level.
  Steps: (a) `@Config(sdk = 34)` with `dynamicColor = true`: assert
  `primary == BrandPrimary` (static, because gate requires 31+ — verifies fallback
  on sub-31 *and* that 34 still resolves dynamic only when available; use sdk=30 for
  a strict pre-31 fallback assertion). (b) `@Config(sdk = 30)`, `dynamicColor = true`:
  assert static `BrandPrimary` is used (fallback). (c) `dynamicColor = false` on any
  SDK: assert static `BrandPrimary`.
  Expected: Static brand scheme used whenever `dynamicColor == false` OR `SDK_INT < 31`.
  Traces: AC-3.

- **TC-AND-019-09 — Lint NewApi passes (no unguarded API-31 call)**
  Type: integration (static analysis / CI gate).
  Preconditions: `:core-ui:lintDebug` configured.
  Steps: Run `:core-ui:lintDebug`.
  Expected: No `NewApi` errors for `dynamicLightColorScheme`/`dynamicDarkColorScheme`
  (they are guarded by `Build.VERSION.SDK_INT >= Build.VERSION_CODES.S`).
  Traces: AC-3.

- **TC-AND-019-10 — System-bar icon appearance follows darkTheme**
  Type: instrumented (real `ComponentActivity` host).
  Preconditions: theme hosted in an Activity (createComposeRule default).
  Steps: Render `TestLogonTheme(darkTheme = false)` then `darkTheme = true`; read
  `WindowCompat.getInsetsController(window, view).isAppearanceLightStatusBars` /
  `isAppearanceLightNavigationBars` after the `SideEffect` settles.
  Expected: Light theme → light status/nav bars `true`; dark theme → `false`.
  Traces: AC-5.

- **TC-AND-019-11 — Preview path is Activity-cast safe (offline/no-host resilience)**
  Type: Compose-UI / unit.
  Preconditions: simulate `view.isInEditMode == true` (preview) or host without an
  Activity window.
  Steps: Compose `TestLogonTheme` where `ApplySystemBarAppearance` runs in edit mode.
  Expected: No `ClassCastException`; the system-bar `SideEffect` is skipped and the
  theme still resolves a scheme. (This is the analogue of the "flaky host / no real
  Activity" path for a non-networked ticket.)
  Traces: AC-1, AC-6.

- **TC-AND-019-12 — Light & dark previews render**
  Type: manual (Android Studio) + Compose-UI screenshot (optional).
  Preconditions: `ThemePreview` with NIGHT_NO and NIGHT_YES `@Preview` annotations,
  `dynamicColor = false`.
  Steps: Open the preview pane; render both variants; optionally capture screenshots
  in CI.
  Expected: Light preview shows light background/brand primary; dark preview shows
  dark background; text and Button render with themed colors.
  Traces: AC-6.

- **TC-AND-019-13 — App-wide application; no feature redefines a ColorScheme**
  Type: integration (build/architecture check).
  Preconditions: a sample/app-shell consumer wraps content in `TestLogonTheme {}`.
  Steps: (a) Build the app-shell consumer using only `TestLogonTheme`. (b) Static
  check (lint rule, Konsist, or CI grep) asserting no `lightColorScheme(`/
  `darkColorScheme(`/`MaterialTheme(colorScheme = ` usage outside the
  `core.ui.theme` package, and no `androidx.compose.material` (M2) imports.
  Expected: Consumer compiles reading tokens via `MaterialTheme.*`; no feature-level
  scheme/M2 import is found.
  Traces: AC-8.

- **TC-AND-019-14 — Accessibility: contrast & dynamic type**
  Type: manual + Compose-UI.
  Preconditions: light/dark previews; ability to set system font scale.
  Steps: (a) Spot-check key `onX`/`X` pairs (onPrimary/primary, onBackground/
  background, onSurface/surface) with a contrast tool for ≥4.5:1 on body text.
  (b) Set system font size to largest and re-render a typography sample; confirm `sp`
  text scales and `lineHeight` keeps text legible (no clipping/overlap). (c) Confirm
  status/nav bar icons remain visible against themed background under edge-to-edge.
  Expected: Body text pairs meet WCAG AA; text scales with system font size; bar
  icons contrast correctly.
  Traces: AC-2, AC-5, AC-6.

### Coverage matrix

| Acceptance Criterion (§14) | Covered by |
| --- | --- |
| AC-1 — `TestLogonTheme` is the single public entry point | TC-01, TC-11 |
| AC-2 — complete light/dark schemes, full typography, specified shapes | TC-02, TC-05, TC-06, TC-14 |
| AC-3 — dynamic color only when enabled & SDK≥31; Lint NewApi passes | TC-08, TC-09 |
| AC-4 — `darkTheme` defaults to `isSystemInDarkTheme()` & overridable | TC-07 |
| AC-5 — system-bar icon appearance follows `darkTheme` | TC-10, TC-14 |
| AC-6 — light & dark `@Preview` render | TC-11, TC-12, TC-14 |
| AC-7 — UI test: light primary=Brand, dark≠light, dark bg=0xFF1A1C1E, type/shape tokens | TC-02, TC-03, TC-04, TC-06 |
| AC-8 — `core-ui` consumed app-wide; no feature redefines a `ColorScheme` | TC-13 |
