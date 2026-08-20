package com.testlogon.android.feature.settings.trading

import com.testlogon.android.core.network.AppAccent
import com.testlogon.android.core.network.AppDensity
import com.testlogon.android.core.network.AppThemeMode
import com.testlogon.android.core.network.ThemePreferencesStore
import org.junit.Assert.assertEquals
import org.junit.Test

/**
 * Density + accent theming: pure-JVM coverage of [ThemePreferencesStore.readFrom], the accent/density/
 * mode/dynamic decode. Uses fake string/boolean getters so no Android Context is needed. Lives in the
 * app test source set (the core-network unit-test source set has a pre-existing AGP friend-paths compile
 * break unrelated to this change; the app source set is the one the required gate compiles + runs).
 */
class ThemePreferencesStoreTest {

    private fun getter(vararg pairs: Pair<String, String>): (String, String?) -> String? {
        val map = pairs.toMap()
        return { key, default -> map[key] ?: default }
    }

    @Test
    fun defaults_whenNothingPersisted() {
        val prefs = ThemePreferencesStore.readFrom(
            getString = { _, default -> default },
            getBoolean = { _, default -> default },
        )
        assertEquals(AppThemeMode.SYSTEM, prefs.mode)
        assertEquals(true, prefs.dynamicColor)
        assertEquals(AppAccent.DEFAULT, prefs.accent)
        assertEquals(AppDensity.COMFORTABLE, prefs.density)
    }

    @Test
    fun readsPersistedAccentAndDensity() {
        val prefs = ThemePreferencesStore.readFrom(
            getString = getter(
                ThemePreferencesStore.KEY_MODE to AppThemeMode.DARK.name,
                ThemePreferencesStore.KEY_ACCENT to AppAccent.TEAL.name,
                ThemePreferencesStore.KEY_DENSITY to AppDensity.COMPACT.name,
            ),
            getBoolean = { _, _ -> false },
        )
        assertEquals(AppThemeMode.DARK, prefs.mode)
        assertEquals(false, prefs.dynamicColor)
        assertEquals(AppAccent.TEAL, prefs.accent)
        assertEquals(AppDensity.COMPACT, prefs.density)
    }

    @Test
    fun malformedValues_fallBackToDefaults() {
        val prefs = ThemePreferencesStore.readFrom(
            getString = getter(
                ThemePreferencesStore.KEY_ACCENT to "NOT_AN_ACCENT",
                ThemePreferencesStore.KEY_DENSITY to "NOT_A_DENSITY",
                ThemePreferencesStore.KEY_MODE to "garbage",
            ),
            getBoolean = { _, default -> default },
        )
        assertEquals(AppThemeMode.SYSTEM, prefs.mode)
        assertEquals(AppAccent.DEFAULT, prefs.accent)
        assertEquals(AppDensity.COMFORTABLE, prefs.density)
    }

    @Test
    fun defaultAccentSeedMatchesCurrentBrandBlue() {
        // Guards the promise that an untouched install renders the existing brand accent.
        assertEquals(0xFF2962FFL, AppAccent.DEFAULT.seedArgb)
    }
}
