---
id: AND-019
title: Material 3 theme
milestone: M1
epic: E03
priority: P0
size: M
status: draft
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
- **Web reference:** `frontend/` uses its own design tokens; there is no
  requirement for pixel parity. Brand colors below are seed values for the static
  scheme and may be refined by design later without changing this contract.
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
  light/dark override in this ticket; an in-app theme preference (DataStore-backed)
  is explicitly out of scope and, if desired later, is a separate ticket that
  would pass an override into `darkTheme`.
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
  product wants one, it is a follow-up ticket adding a DataStore preference fed
  into `darkTheme`.
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
