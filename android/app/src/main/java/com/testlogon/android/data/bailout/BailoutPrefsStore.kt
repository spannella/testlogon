package com.testlogon.android.data.bailout

import android.content.Context
import android.content.SharedPreferences
import dagger.hilt.android.qualifiers.ApplicationContext
import javax.inject.Inject
import javax.inject.Singleton

/**
 * Device-local fallback for the AUTO-BAILOUT preference.
 *
 * The authoritative store is the server (`GET/PUT me/prefs/bailout`), but that endpoint is not built
 * yet, so the settings surface degrades to this SharedPreferences-backed local copy (labelled "saved on
 * this device" in the UI). When the backend lands, the server read wins and this simply mirrors the
 * last chosen value so the toggle is never blank. Amounts in basis points (10_000 == 100%).
 */
@Singleton
class BailoutPrefsStore @Inject constructor(
    @ApplicationContext context: Context,
) {
    private val prefs: SharedPreferences =
        context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)

    fun read(): BailoutPrefs = BailoutPrefs(
        autoEnabled = prefs.getBoolean(KEY_AUTO_ENABLED, false),
        defaultMaxShareBps = prefs.getInt(KEY_MAX_SHARE_BPS, DEFAULT_MAX_SHARE_BPS),
    )

    fun write(prefsValue: BailoutPrefs) {
        prefs.edit()
            .putBoolean(KEY_AUTO_ENABLED, prefsValue.autoEnabled)
            .putInt(KEY_MAX_SHARE_BPS, prefsValue.defaultMaxShareBps)
            .apply()
    }

    companion object {
        const val DEFAULT_MAX_SHARE_BPS = 2_000 // 20%
        private const val PREFS_NAME = "tl_bailout_prefs"
        private const val KEY_AUTO_ENABLED = "auto_enabled"
        private const val KEY_MAX_SHARE_BPS = "default_max_share_bps"
    }
}
