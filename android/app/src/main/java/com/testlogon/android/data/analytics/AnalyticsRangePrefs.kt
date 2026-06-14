package com.testlogon.android.data.analytics

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

private val Context.analyticsRangePrefsDataStore by preferencesDataStore(name = "analytics_range_prefs")

/**
 * AND-399 - persists the last-selected dashboard range across re-entry / process death (FR-8). Only a
 * small enum token is stored - never any metric value (spec sections 8 / 10).
 */
interface AnalyticsRangePrefs {
    suspend fun selectedRange(): AnalyticsDashboardRange
    suspend fun setSelectedRange(range: AnalyticsDashboardRange)
}

@Singleton
class DataStoreAnalyticsRangePrefs @Inject constructor(
    @ApplicationContext context: Context,
) : AnalyticsRangePrefs {

    private val dataStore = context.analyticsRangePrefsDataStore

    override suspend fun selectedRange(): AnalyticsDashboardRange {
        val prefs = dataStore.data
            .catch { e -> if (e is IOException) emit(emptyPreferences()) else throw e }
            .first()
        return AnalyticsDashboardRange.fromKey(prefs[KEY_RANGE])
    }

    override suspend fun setSelectedRange(range: AnalyticsDashboardRange) {
        dataStore.edit { it[KEY_RANGE] = range.apiKey }
    }

    private companion object {
        val KEY_RANGE = stringPreferencesKey("analytics_range")
    }
}
