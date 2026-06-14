package com.testlogon.android.core.network

import android.content.Context
import android.content.SharedPreferences
import dagger.hilt.android.qualifiers.ApplicationContext
import javax.inject.Inject
import javax.inject.Singleton

/**
 * Synchronous, SharedPreferences-backed store for the runtime backend base URL.
 *
 * Kept deliberately synchronous (plain [SharedPreferences], not DataStore) so it can be read
 * cheaply from inside an OkHttp interceptor on the dispatcher thread without blocking on a flow.
 *
 * Default points at the unreliable plaintext dev host.
 */
@Singleton
class SettingsStore @Inject constructor(
    @ApplicationContext context: Context,
) {
    private val prefs: SharedPreferences =
        context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)

    /** Current base URL (always normalized to end with '/'). */
    var baseUrl: String
        get() = prefs.getString(KEY_BASE_URL, null) ?: DEFAULT_BASE_URL
        set(value) {
            prefs.edit().putString(KEY_BASE_URL, normalize(value)).apply()
        }

    /** Restore the compile-time default base URL. */
    fun resetBaseUrl() {
        prefs.edit().remove(KEY_BASE_URL).apply()
    }

    companion object {
        /**
         * Compile-time default base URL (AND-006). Sourced from [BuildConfig.API_BASE_URL] and
         * normalized to end with '/' so the flaky plaintext dev host is never hard-coded in source.
         * dev/staging/prod selection is a runtime concern (this store), not a build flavor.
         */
        val DEFAULT_BASE_URL: String = normalize(BuildConfig.API_BASE_URL)

        private const val PREFS_NAME = "tl_settings"
        private const val KEY_BASE_URL = "base_url"

        /** Retrofit requires the base URL to end with '/'. Idempotent. */
        fun normalize(raw: String): String = if (raw.endsWith("/")) raw else "$raw/"
    }
}
