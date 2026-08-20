package com.testlogon.android.ui.theme

import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Color
import com.testlogon.android.core.ui.theme.AppUiDensity
import com.testlogon.android.core.ui.theme.TestLogonTheme as CoreTestLogonTheme

/**
 * Thin app-module wrapper that delegates to the canonical design-system theme in `core-ui`
 * ([com.testlogon.android.core.ui.theme.TestLogonTheme], AND-019). Kept so any app-module call
 * sites referencing the local name keep compiling; prefer importing the core-ui theme directly.
 */
@Composable
fun TestLogonTheme(
    accentSeed: Color? = null,
    density: AppUiDensity = AppUiDensity.COMFORTABLE,
    content: @Composable () -> Unit,
) {
    CoreTestLogonTheme(accentSeed = accentSeed, density = density, content = content)
}
