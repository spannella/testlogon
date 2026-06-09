package com.testlogon.android.feature.settings.appearance

import android.os.Build
import androidx.lifecycle.ViewModel
import com.testlogon.android.core.network.AppThemeMode
import com.testlogon.android.core.network.AppearancePreferences
import com.testlogon.android.core.network.ThemePreferencesStore
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.StateFlow
import javax.inject.Inject

/**
 * AND-081 — reads/mutates the device-local appearance preference. Writes go straight to the
 * SharedPreferences-backed [ThemePreferencesStore], whose [StateFlow] both this screen and the app
 * shell observe — so a change re-themes the whole app immediately with no restart.
 */
@HiltViewModel
class AppearanceSettingsViewModel @Inject constructor(
    private val store: ThemePreferencesStore,
) : ViewModel() {

    val uiState: StateFlow<AppearancePreferences> = store.preferences

    /** Dynamic color (Material You) is Android 12+ only; hidden/forced-off below. */
    val dynamicColorSupported: Boolean = Build.VERSION.SDK_INT >= Build.VERSION_CODES.S

    fun onModeSelected(mode: AppThemeMode) = store.setMode(mode)

    fun onDynamicColorChanged(enabled: Boolean) = store.setDynamicColor(enabled)
}
