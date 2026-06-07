package com.testlogon.android.core.ui.theme

import android.app.Activity
import android.os.Build
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.material3.ColorScheme
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.dynamicDarkColorScheme
import androidx.compose.material3.dynamicLightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.SideEffect
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
 * @param content the themed content.
 */
@Composable
fun TestLogonTheme(
    darkTheme: Boolean = isSystemInDarkTheme(),
    dynamicColor: Boolean = true,
    content: @Composable () -> Unit,
) {
    val context = LocalContext.current
    val colorScheme: ColorScheme = when {
        dynamicColor && Build.VERSION.SDK_INT >= Build.VERSION_CODES.S ->
            if (darkTheme) dynamicDarkColorScheme(context) else dynamicLightColorScheme(context)
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
