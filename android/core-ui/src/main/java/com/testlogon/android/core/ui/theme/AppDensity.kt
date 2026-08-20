package com.testlogon.android.core.ui.theme

import androidx.compose.runtime.compositionLocalOf

/**
 * App-wide UI density knob (density + accent theming feature). COMPACT tightens the padding / row
 * height of a few high-traffic list & card surfaces; the default is COMFORTABLE (spacing unchanged).
 *
 * Provided once at the app root ([TestLogonTheme]) so any composable can read it; only a handful of
 * high-traffic surfaces honor it deliberately — this is a global knob, not a full restyle.
 */
enum class AppUiDensity { COMFORTABLE, COMPACT }

/** True when the current density is COMPACT. */
val AppUiDensity.isCompact: Boolean get() = this == AppUiDensity.COMPACT

/**
 * CompositionLocal carrying the current [AppUiDensity]. Defaults to COMFORTABLE so any composable
 * read outside an explicit provider (previews, isolated tests) behaves exactly as before.
 */
val LocalAppUiDensity = compositionLocalOf { AppUiDensity.COMFORTABLE }
