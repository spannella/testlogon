package com.testlogon.android.feature.paper

import android.content.Context
import androidx.datastore.preferences.core.booleanPreferencesKey
import androidx.datastore.preferences.core.edit
import androidx.datastore.preferences.core.emptyPreferences
import androidx.datastore.preferences.preferencesDataStore
import dagger.hilt.android.qualifiers.ApplicationContext
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.catch
import kotlinx.coroutines.flow.map
import java.io.IOException
import javax.inject.Inject
import javax.inject.Singleton

private val Context.paperModeDataStore by preferencesDataStore(name = "paper_mode")

/**
 * Tiny durable flag shared by the real trade ticket and the standalone Paper screen so both agree on
 * whether the user is in PAPER (simulated) mode. Backed by its own one-key DataStore; every read is
 * failure-safe (a store error degrades to `false` = real trading, never throws). Exposed as a [Flow] so
 * the ticket header switch and any future surface observe the same source of truth. Injectable directly
 * (@Inject constructor + @Singleton) — no Hilt module needed.
 */
@Singleton
class PaperModeStore @Inject constructor(
    @ApplicationContext context: Context,
) {
    private val dataStore = context.paperModeDataStore

    /** Emits the current paper-mode flag (defaults to false when unset or on any store error). */
    val paperMode: Flow<Boolean> = dataStore.data
        .catch { e -> if (e is IOException) emit(emptyPreferences()) else throw e }
        .map { it[KEY] ?: false }

    /** Persist the paper-mode flag (no-op on a store error). */
    suspend fun setPaperMode(enabled: Boolean) {
        runCatching { dataStore.edit { it[KEY] = enabled } }
    }

    private companion object {
        val KEY = booleanPreferencesKey("paper_mode_enabled")
    }
}
