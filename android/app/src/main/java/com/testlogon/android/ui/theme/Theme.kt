package com.testlogon.android.ui.theme

import androidx.compose.material3.MaterialTheme
import androidx.compose.runtime.Composable

/**
 * App-level Material 3 theme wrapper.
 *
 * Kept self-contained in the app module for the foundation. A richer shared design system
 * lives in `core-ui` (see [com.testlogon.android.core.ui]); this stub simply applies the
 * default Material 3 color scheme/typography so the Compose host renders correctly.
 */
@Composable
fun TestLogonTheme(content: @Composable () -> Unit) {
    MaterialTheme(content = content)
}
