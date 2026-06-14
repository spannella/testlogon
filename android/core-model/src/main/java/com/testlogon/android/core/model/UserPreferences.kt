package com.testlogon.android.core.model

/**
 * AND-078 — domain model for server-synced UI preferences, mirroring the backend
 * `PreferencesPatchReq` / `UiPreferences` contract (web `src/api/endpoints/preferences.ts`).
 *
 * The GET endpoint returns only explicitly-set keys; absent keys fall back to these defaults.
 */
enum class ThemeModePref { SYSTEM, LIGHT, DARK }

enum class AccentColor { BLUE, PURPLE, GREEN, ORANGE, PINK, RED, TEAL, CUSTOM }

enum class FontSizePref { SMALL, DEFAULT, LARGE, XLARGE }

enum class Density { COMPACT, COMFORTABLE, SPACIOUS }

/**
 * Fully-resolved UI preferences with sensible defaults for any key the server omits.
 */
data class UserPreferences(
    val theme: ThemeModePref = ThemeModePref.SYSTEM,
    val sidebarCollapsed: Boolean = false,
    val accentColor: AccentColor = AccentColor.BLUE,
    val customAccentHex: String? = null,
    val fontSize: FontSizePref = FontSizePref.DEFAULT,
    val density: Density = Density.COMFORTABLE,
    val highContrast: Boolean = false,
)

/**
 * Partial update. A null field means "leave unchanged" and is omitted from the request body.
 */
data class PreferencesPatch(
    val theme: ThemeModePref? = null,
    val sidebarCollapsed: Boolean? = null,
    val accentColor: AccentColor? = null,
    val customAccentHex: String? = null,
    val fontSize: FontSizePref? = null,
    val density: Density? = null,
    val highContrast: Boolean? = null,
)
