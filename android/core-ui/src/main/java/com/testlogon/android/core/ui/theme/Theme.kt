package com.testlogon.android.core.ui.theme

import android.app.Activity
import android.os.Build
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.material3.ColorScheme
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.dynamicDarkColorScheme
import androidx.compose.material3.dynamicLightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.runtime.SideEffect
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.luminance
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalView
import androidx.core.view.WindowCompat

/**
 * Canonical Material 3 theme for the TestLogon app. This is the single, authoritative theme;
 * no feature module may define its own [ColorScheme], [androidx.compose.material3.Typography],
 * or [androidx.compose.material3.Shapes].
 *
 * @param darkTheme defaults to [isSystemInDarkTheme] so the app follows the OS setting; callers
 *   (previews, tests) may override.
 * @param dynamicColor when `true` (default) AND running on Android 12+ (API 31+), uses the
 *   wallpaper-derived dynamic palette; otherwise falls back to the static brand scheme.
 * @param accentSeed optional accent color the user picked (density + accent theming feature). When
 *   non-null AND [dynamicColor] is not in effect, it recolors the scheme's primary/secondary tones so
 *   the whole app re-accents live. Null (default) or dynamic-color-on keeps the current look.
 * @param density the app UI density, provided as [LocalAppUiDensity] for high-traffic surfaces.
 * @param content the themed content.
 */
@Composable
fun TestLogonTheme(
    darkTheme: Boolean = isSystemInDarkTheme(),
    dynamicColor: Boolean = true,
    accentSeed: Color? = null,
    density: AppUiDensity = AppUiDensity.COMFORTABLE,
    content: @Composable () -> Unit,
) {
    val context = LocalContext.current
    val useDynamic = dynamicColor && Build.VERSION.SDK_INT >= Build.VERSION_CODES.S
    val baseScheme: ColorScheme = when {
        useDynamic ->
            if (darkTheme) dynamicDarkColorScheme(context) else dynamicLightColorScheme(context)
        darkTheme -> DarkColors
        else -> LightColors
    }
    // Apply the chosen accent only when NOT using the wallpaper-derived dynamic palette (dynamic
    // color already owns the accent in that mode). Accent recolors the primary/secondary channels.
    val colorScheme: ColorScheme =
        if (!useDynamic && accentSeed != null) baseScheme.withAccent(accentSeed) else baseScheme

    ApplySystemBarAppearance(darkTheme = darkTheme)

    CompositionLocalProvider(LocalAppUiDensity provides density) {
        MaterialTheme(
            colorScheme = colorScheme,
            typography = TestLogonTypography,
            shapes = TestLogonShapes,
            content = content,
        )
    }
}

/**
 * Recolor the primary/secondary channels of [this] scheme from a single [seed] accent. Container /
 * on-container tones are lightened/darkened from the seed and the on-color is chosen for contrast, so
 * an arbitrary preset stays legible in both light and dark schemes.
 */
private fun ColorScheme.withAccent(seed: Color): ColorScheme {
    val onSeed = if (seed.luminance() > 0.5f) Color.Black else Color.White
    val container = seed.copy(alpha = 1f).blendTowards(surface, 0.72f)
    val onContainer = if (container.luminance() > 0.5f) Color.Black else Color.White
    return copy(
        primary = seed,
        onPrimary = onSeed,
        primaryContainer = container,
        onPrimaryContainer = onContainer,
        secondary = seed.blendTowards(secondary, 0.35f),
        onSecondary = onSeed,
        tertiary = seed,
    )
}

/** Linear blend of [this] toward [other] by [fraction] (0 = this, 1 = other). */
private fun Color.blendTowards(other: Color, fraction: Float): Color {
    val f = fraction.coerceIn(0f, 1f)
    return Color(
        red = red + (other.red - red) * f,
        green = green + (other.green - green) * f,
        blue = blue + (other.blue - blue) * f,
        alpha = 1f,
    )
}

/** Drives status/navigation bar icon appearance from the effective [darkTheme]. */
@Composable
private fun ApplySystemBarAppearance(darkTheme: Boolean) {
    val view = LocalView.current
    if (!view.isInEditMode) {
        SideEffect {
            val window = (view.context as? Activity)?.window ?: return@SideEffect
            WindowCompat.getInsetsController(window, view).apply {
                isAppearanceLightStatusBars = !darkTheme
                isAppearanceLightNavigationBars = !darkTheme
            }
        }
    }
}
