package com.testlogon.android.data.preferences

import com.testlogon.android.core.model.AccentColor
import com.testlogon.android.core.model.Density
import com.testlogon.android.core.model.FontSizePref
import com.testlogon.android.core.model.PreferencesPatch
import com.testlogon.android.core.model.ThemeModePref
import com.testlogon.android.core.model.UserPreferences

/**
 * AND-078 — pure DTO <-> domain mappers for UI preferences. Lenient read (unknown server tokens
 * fall back to defaults), strict write (`enum.name.lowercase()` is the exact wire token).
 */
internal fun PreferencesEnvelopeDto.toDomain(): UserPreferences =
    (preferences ?: PreferencesDto()).toDomain()

internal fun PreferencesDto.toDomain(): UserPreferences = UserPreferences(
    theme = theme.toThemeModeOrDefault(),
    sidebarCollapsed = sidebarCollapsed ?: false,
    accentColor = accentColor.toAccentColorOrDefault(),
    customAccentHex = customAccentHex,
    fontSize = fontSize.toFontSizeOrDefault(),
    density = density.toDensityOrDefault(),
    highContrast = highContrast ?: false,
)

internal fun PreferencesPatch.toRequestDto(): UpdatePreferencesRequestDto =
    UpdatePreferencesRequestDto(
        theme = theme?.name?.lowercase(),
        sidebarCollapsed = sidebarCollapsed,
        accentColor = accentColor?.name?.lowercase(),
        customAccentHex = customAccentHex,
        fontSize = fontSize?.name?.lowercase(),
        density = density?.name?.lowercase(),
        highContrast = highContrast,
    )

/** Merge a patch onto a base, for optimistic local application. */
internal fun UserPreferences.applyPatch(patch: PreferencesPatch): UserPreferences = copy(
    theme = patch.theme ?: theme,
    sidebarCollapsed = patch.sidebarCollapsed ?: sidebarCollapsed,
    accentColor = patch.accentColor ?: accentColor,
    customAccentHex = patch.customAccentHex ?: customAccentHex,
    fontSize = patch.fontSize ?: fontSize,
    density = patch.density ?: density,
    highContrast = patch.highContrast ?: highContrast,
)

private fun String?.toThemeModeOrDefault(): ThemeModePref = when (this?.lowercase()) {
    "light" -> ThemeModePref.LIGHT
    "dark" -> ThemeModePref.DARK
    else -> ThemeModePref.SYSTEM
}

private fun String?.toAccentColorOrDefault(): AccentColor = when (this?.lowercase()) {
    "purple" -> AccentColor.PURPLE
    "green" -> AccentColor.GREEN
    "orange" -> AccentColor.ORANGE
    "pink" -> AccentColor.PINK
    "red" -> AccentColor.RED
    "teal" -> AccentColor.TEAL
    "custom" -> AccentColor.CUSTOM
    else -> AccentColor.BLUE
}

private fun String?.toFontSizeOrDefault(): FontSizePref = when (this?.lowercase()) {
    "small" -> FontSizePref.SMALL
    "large" -> FontSizePref.LARGE
    "xlarge" -> FontSizePref.XLARGE
    else -> FontSizePref.DEFAULT
}

private fun String?.toDensityOrDefault(): Density = when (this?.lowercase()) {
    "compact" -> Density.COMPACT
    "spacious" -> Density.SPACIOUS
    else -> Density.COMFORTABLE
}
