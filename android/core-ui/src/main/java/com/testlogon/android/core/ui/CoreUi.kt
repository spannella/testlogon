package com.testlogon.android.core.ui

import androidx.compose.material3.MaterialTheme
import androidx.compose.runtime.Composable

/**
 * Placeholder marker for the core-ui module.
 *
 * The shared design system (color, typography, spacing, reusable components) lands in AND-019.
 * This object only keeps the module non-empty and compilable.
 */
object CoreUi

/**
 * Shared Material 3 theme stub for the app.
 *
 * Expanded into the full TestLogon design system in AND-019. For now it simply applies the
 * default Material 3 theme so consumers have a single themable entry point.
 */
@Composable
fun TestLogonTheme(content: @Composable () -> Unit) {
    MaterialTheme(content = content)
}
