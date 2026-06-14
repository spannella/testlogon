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
 * AND-081 — device-local appearance preference (theme mode + dynamic-color flag).
 *
 * Backed by [SharedPreferences] (like [SettingsStore]) so the value is available synchronously at
 * app startup with no flash, and exposed as a [StateFlow] so a write from the Appearance screen
 * re-themes the whole app immediately. Theme is intentionally device-local (offline-instant), not
 * synced to the unreliable dev backend — a roaming follow-up could map it onto
 * `PreferencesPatchReq.theme`.
 *
 * Kept in core-network (not a feature module) because the app shell / MainActivity must read it,
 * and the app module must not depend on a feature for its theme bootstrap.
 */
enum class AppThemeMode { SYSTEM, LIGHT, DARK }

data class AppearancePreferences(
    val mode: AppThemeMode = AppThemeMode.SYSTEM,
    val dynamicColor: Boolean = true,
)

@Singleton
class ThemePreferencesStore @Inject constructor(
    @ApplicationContext context: Context,
) {
    private val prefs: SharedPreferences =
        context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)

    private val _preferences = MutableStateFlow(read())

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

    private fun read(): AppearancePreferences {
        val mode = prefs.getString(KEY_MODE, null)
            ?.let { runCatching { AppThemeMode.valueOf(it) }.getOrNull() }
            ?: AppThemeMode.SYSTEM
        val dynamic = prefs.getBoolean(KEY_DYNAMIC, true)
        return AppearancePreferences(mode = mode, dynamicColor = dynamic)
    }

    private companion object {
        const val PREFS_NAME = "tl_appearance_prefs"
        const val KEY_MODE = "theme_mode"
        const val KEY_DYNAMIC = "dynamic_color"
    }
}
