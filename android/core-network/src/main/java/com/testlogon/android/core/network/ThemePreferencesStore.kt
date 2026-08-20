package com.testlogon.android.core.network

import android.content.Context
import android.content.SharedPreferences
import dagger.hilt.android.qualifiers.ApplicationContext
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import javax.inject.Inject
import javax.inject.Singleton

/**
 * AND-081 — device-local appearance preference (theme mode + dynamic-color flag + accent + density).
 *
 * Backed by [SharedPreferences] (like [SettingsStore]) so the value is available synchronously at
 * app startup with no flash, and exposed as a [StateFlow] so a write from the Appearance / Trading-
 * preferences screen re-themes the whole app immediately. Theme is intentionally device-local
 * (offline-instant), not synced to the unreliable dev backend.
 *
 * Kept in core-network (not a feature module) because the app shell / MainActivity must read it,
 * and the app module must not depend on a feature for its theme bootstrap. This module has no Compose
 * dependency, so the accent is stored as an ARGB [Long] seed that the app/core-ui boundary converts
 * to a Compose Color; density is a plain enum the app maps onto a CompositionLocal.
 */
enum class AppThemeMode { SYSTEM, LIGHT, DARK }

/**
 * Accent presets for the app's primary color. [seedArgb] is the 0xAARRGGBB seed the theme derives
 * its primary/secondary tones from. [DEFAULT] reproduces the current brand blue so an untouched
 * install looks identical.
 */
enum class AppAccent(val seedArgb: Long) {
    DEFAULT(0xFF2962FFL), // current BrandPrimary (blue) — keep as the default
    VIOLET(0xFF7C4DFFL),
    TEAL(0xFF00897BL),
    AMBER(0xFFF9A825L),
    ROSE(0xFFE91E63L),
    GREEN(0xFF2E7D32L);

    companion object {
        val Default = DEFAULT
    }
}

/** UI density. COMFORTABLE is the default (unchanged spacing); COMPACT tightens key list surfaces. */
enum class AppDensity { COMFORTABLE, COMPACT }

data class AppearancePreferences(
    val mode: AppThemeMode = AppThemeMode.SYSTEM,
    val dynamicColor: Boolean = true,
    val accent: AppAccent = AppAccent.DEFAULT,
    val density: AppDensity = AppDensity.COMFORTABLE,
)

@Singleton
class ThemePreferencesStore @Inject constructor(
    @ApplicationContext context: Context,
) {
    private val prefs: SharedPreferences =
        context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)

    private val _preferences = MutableStateFlow(readFrom(prefs::getString, prefs::getBoolean))

    /** Hot stream of the current appearance preference. Re-emits on every write. */
    val preferences: StateFlow<AppearancePreferences> = _preferences.asStateFlow()

    fun setMode(mode: AppThemeMode) {
        prefs.edit().putString(KEY_MODE, mode.name).apply()
        _preferences.value = _preferences.value.copy(mode = mode)
    }

    fun setDynamicColor(enabled: Boolean) {
        prefs.edit().putBoolean(KEY_DYNAMIC, enabled).apply()
        _preferences.value = _preferences.value.copy(dynamicColor = enabled)
    }

    fun setAccent(accent: AppAccent) {
        prefs.edit().putString(KEY_ACCENT, accent.name).apply()
        _preferences.value = _preferences.value.copy(accent = accent)
    }

    fun setDensity(density: AppDensity) {
        prefs.edit().putString(KEY_DENSITY, density.name).apply()
        _preferences.value = _preferences.value.copy(density = density)
    }

    companion object {
        const val PREFS_NAME = "tl_appearance_prefs"
        const val KEY_MODE = "theme_mode"
        const val KEY_DYNAMIC = "dynamic_color"
        const val KEY_ACCENT = "accent"
        const val KEY_DENSITY = "density"

        /**
         * Pure decode of the four persisted values into [AppearancePreferences]. Extracted from
         * [SharedPreferences] so it is unit-testable without an Android [Context]: callers pass a
         * string- and boolean-getter (both defaulting when the key is absent / malformed).
         */
        fun readFrom(
            getString: (String, String?) -> String?,
            getBoolean: (String, Boolean) -> Boolean,
        ): AppearancePreferences {
            val mode = getString(KEY_MODE, null)
                ?.let { runCatching { AppThemeMode.valueOf(it) }.getOrNull() }
                ?: AppThemeMode.SYSTEM
            val dynamic = getBoolean(KEY_DYNAMIC, true)
            val accent = getString(KEY_ACCENT, null)
                ?.let { runCatching { AppAccent.valueOf(it) }.getOrNull() }
                ?: AppAccent.DEFAULT
            val density = getString(KEY_DENSITY, null)
                ?.let { runCatching { AppDensity.valueOf(it) }.getOrNull() }
                ?: AppDensity.COMFORTABLE
            return AppearancePreferences(
                mode = mode,
                dynamicColor = dynamic,
                accent = accent,
                density = density,
            )
        }
    }
}
