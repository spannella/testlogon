package com.testlogon.android.ui.theme

import androidx.compose.runtime.Composable
import com.testlogon.android.core.ui.theme.TestLogonTheme as CoreTestLogonTheme

/**
 * Thin app-module wrapper that delegates to the canonical design-system theme in `core-ui`
 * ([com.testlogon.android.core.ui.theme.TestLogonTheme], AND-019). Kept so any app-module call
 * sites referencing the local name keep compiling; prefer importing the core-ui theme directly.
 */
@Composable
fun TestLogonTheme(content: @Composable () -> Unit) {
    CoreTestLogonTheme(content = content)
}
