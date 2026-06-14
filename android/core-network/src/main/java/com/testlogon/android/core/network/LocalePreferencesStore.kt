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
 * AND-113/AND-114 — device-local persistence for the in-app language override.
 *
 * Backed by [SharedPreferences] (mirroring [ThemePreferencesStore]) so the value is readable
 * synchronously at startup with no flash, and exposed as a [StateFlow] so a write re-resolves the
 * effective locale and re-applies it app-wide with no restart. Kept in core-network (not a feature
 * module) so the app shell / MainActivity can read it for its launch-time locale bootstrap without
 * depending on a feature module.
 *
 * State:
 *  - [LocalePrefsState.tag]     persisted BCP-47 tag, or null when following the device/system default.
 *  - [LocalePrefsState.override] true once the user explicitly picked a locale this install (so the
 *    server value does not clobber an explicit choice — AND-113 reconciliation).
 *  - [LocalePrefsState.pendingSync] a local change not yet written to the server (AND-113 FR-6 queue).
 */
data class LocalePrefsState(
    val tag: String? = null,
    val override: Boolean = false,
    val pendingSync: Boolean = false,
)

@Singleton
class LocalePreferencesStore @Inject constructor(
    @ApplicationContext context: Context,
) {
    private val prefs: SharedPreferences =
        context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)

    private val _state = MutableStateFlow(read())

    /** Hot stream of the persisted locale state. Re-emits on every write. */
    val state: StateFlow<LocalePrefsState> = _state.asStateFlow()

    /** Current snapshot (synchronous, for startup bootstrap). */
    fun current(): LocalePrefsState = _state.value

    /**
     * Persists an explicit user choice: a non-null [tag] marks an in-app override; null clears the
     * override and follows the system default. [pendingSync] marks it for a server write retry.
     */
    fun setUserChoice(tag: String?, pendingSync: Boolean) {
        prefs.edit()
            .apply {
                if (tag.isNullOrBlank()) remove(KEY_TAG) else putString(KEY_TAG, tag)
                putBoolean(KEY_OVERRIDE, !tag.isNullOrBlank())
                putBoolean(KEY_PENDING, pendingSync)
            }
            .apply()
        _state.value = LocalePrefsState(
            tag = tag?.takeIf { it.isNotBlank() },
            override = !tag.isNullOrBlank(),
            pendingSync = pendingSync,
        )
    }

    /** Adopts a server-provided locale as the cached value WITHOUT setting the override flag. */
    fun setServerValue(tag: String?) {
        prefs.edit()
            .apply {
                if (tag.isNullOrBlank()) remove(KEY_TAG) else putString(KEY_TAG, tag)
                putBoolean(KEY_OVERRIDE, false)
                putBoolean(KEY_PENDING, false)
            }
            .apply()
        _state.value = LocalePrefsState(
            tag = tag?.takeIf { it.isNotBlank() },
            override = false,
            pendingSync = false,
        )
    }

    /** Clears the pending-server-sync flag after a successful write. */
    fun clearPendingSync() {
        prefs.edit().putBoolean(KEY_PENDING, false).apply()
        _state.value = _state.value.copy(pendingSync = false)
    }

    /** Clears the session override so a server value can win again. */
    fun clearOverride() {
        prefs.edit().putBoolean(KEY_OVERRIDE, false).apply()
        _state.value = _state.value.copy(override = false)
    }

    private fun read(): LocalePrefsState = LocalePrefsState(
        tag = prefs.getString(KEY_TAG, null)?.takeIf { it.isNotBlank() },
        override = prefs.getBoolean(KEY_OVERRIDE, false),
        pendingSync = prefs.getBoolean(KEY_PENDING, false),
    )

    private companion object {
        const val PREFS_NAME = "tl_locale_prefs"
        const val KEY_TAG = "locale_tag"
        const val KEY_OVERRIDE = "locale_override"
        const val KEY_PENDING = "locale_pending_sync"
    }
}
