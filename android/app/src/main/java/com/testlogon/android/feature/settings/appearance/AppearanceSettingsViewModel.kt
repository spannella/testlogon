package com.testlogon.android.feature.settings.appearance

import android.os.Build
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.network.AppThemeMode
import com.testlogon.android.core.network.AppearancePreferences
import com.testlogon.android.core.network.ThemePreferencesStore
import com.testlogon.android.feature.onboarding.OnboardingStore
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.launch
import javax.inject.Inject

/**
 * AND-081 — reads/mutates the device-local appearance preference. Writes go straight to the
 * SharedPreferences-backed [ThemePreferencesStore], whose [StateFlow] both this screen and the app
 * shell observe — so a change re-themes the whole app immediately with no restart.
 */
@HiltViewModel
class AppearanceSettingsViewModel @Inject constructor(
    private val store: ThemePreferencesStore,
    private val onboardingStore: OnboardingStore,
) : ViewModel() {

    val uiState: StateFlow<AppearancePreferences> = store.preferences

    /** Dynamic color (Material You) is Android 12+ only; hidden/forced-off below. */
    val dynamicColorSupported: Boolean = Build.VERSION.SDK_INT >= Build.VERSION_CODES.S

    fun onModeSelected(mode: AppThemeMode) = store.setMode(mode)

    fun onDynamicColorChanged(enabled: Boolean) = store.setDynamicColor(enabled)

    /**
     * Replay the trading/investing product tour: clears the whole onboarding seen-set so the first-run
     * welcome tour and every per-surface intro callout show again.
     */
    fun onReplayProductTour() {
        viewModelScope.launch { onboardingStore.resetAll() }
    }
}
