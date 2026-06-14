package com.testlogon.android.data.earnings

import android.content.Context
import androidx.datastore.preferences.core.edit
import androidx.datastore.preferences.core.emptyPreferences
import androidx.datastore.preferences.core.stringPreferencesKey
import androidx.datastore.preferences.preferencesDataStore
import dagger.hilt.android.qualifiers.ApplicationContext
import kotlinx.coroutines.flow.catch
import kotlinx.coroutines.flow.first
import java.io.IOException
import javax.inject.Inject
import javax.inject.Singleton

private val Context.earningsPrefsDataStore by preferencesDataStore(name = "earnings_prefs")

/**
 * AND-252 — persists the selected dashboard range across process death (DataStore Preferences).
 * Only the range key (a small enum token) is stored — never any monetary value (§8/§10).
 */
interface EarningsPrefs {
    suspend fun selectedRange(): EarningsRange
    suspend fun setSelectedRange(range: EarningsRange)
}

@Singleton
class DataStoreEarningsPrefs @Inject constructor(
    @ApplicationContext context: Context,
) : EarningsPrefs {

    private val dataStore = context.earningsPrefsDataStore

    override suspend fun selectedRange(): EarningsRange {
        val prefs = dataStore.data
            .catch { e -> if (e is IOException) emit(emptyPreferences()) else throw e }
            .first()
        return EarningsRange.fromKey(prefs[KEY_RANGE])
    }

    override suspend fun setSelectedRange(range: EarningsRange) {
        dataStore.edit { it[KEY_RANGE] = range.apiKey }
    }

    private companion object {
        val KEY_RANGE = stringPreferencesKey("earnings_range")
    }
}
