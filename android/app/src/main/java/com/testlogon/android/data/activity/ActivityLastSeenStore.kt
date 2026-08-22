package com.testlogon.android.data.activity

import android.content.Context
import androidx.datastore.preferences.core.edit
import androidx.datastore.preferences.core.emptyPreferences
import androidx.datastore.preferences.core.longPreferencesKey
import androidx.datastore.preferences.preferencesDataStore
import dagger.hilt.android.qualifiers.ApplicationContext
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.catch
import kotlinx.coroutines.flow.map
import java.io.IOException
import javax.inject.Inject
import javax.inject.Singleton

private val Context.activityLastSeenDataStore by preferencesDataStore(name = "activity_center_last_seen")

/**
 * Persists the Activity Center "last seen" high-water mark (epoch millis of the newest event the user
 * has acknowledged) so unread markers survive re-entry / process death. Only a single Long is stored -
 * never any event payload. Reads degrade to 0 (everything unread) on an IO error.
 */
@Singleton
class ActivityLastSeenStore @Inject constructor(
    @ApplicationContext context: Context,
) {
    private val dataStore = context.activityLastSeenDataStore

    /** Hot stream of the persisted last-seen millis (0 when never set). */
    val lastSeen: Flow<Long> = dataStore.data
        .catch { e -> if (e is IOException) emit(emptyPreferences()) else throw e }
        .map { it[KEY_LAST_SEEN] ?: 0L }

    /** Advance the mark to [ts] (never moves it backwards). */
    suspend fun setLastSeen(ts: Long) {
        dataStore.edit { prefs ->
            val current = prefs[KEY_LAST_SEEN] ?: 0L
            if (ts > current) prefs[KEY_LAST_SEEN] = ts
        }
    }

    private companion object {
        val KEY_LAST_SEEN = longPreferencesKey("activity_last_seen_ms")
    }
}
