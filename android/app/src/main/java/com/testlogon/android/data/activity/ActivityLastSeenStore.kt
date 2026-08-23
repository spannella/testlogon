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
/**
 * Contract for the Activity Center last-seen high-water mark. Extracted as an interface so the
 * ViewModel can be unit-tested against an in-memory fake; [ActivityLastSeenStoreImpl] is the real
 * DataStore-backed implementation.
 */
interface ActivityLastSeenStore {
    /** Hot stream of the persisted last-seen millis (0 when never set). */
    val lastSeen: Flow<Long>

    /** Advance the mark to [ts] (never moves it backwards). */
    suspend fun setLastSeen(ts: Long)
}

@Singleton
class ActivityLastSeenStoreImpl @Inject constructor(
    @ApplicationContext context: Context,
) : ActivityLastSeenStore {
    private val dataStore = context.activityLastSeenDataStore

    /** Hot stream of the persisted last-seen millis (0 when never set). */
    override val lastSeen: Flow<Long> = dataStore.data
        .catch { e -> if (e is IOException) emit(emptyPreferences()) else throw e }
        .map { it[KEY_LAST_SEEN] ?: 0L }

    /** Advance the mark to [ts] (never moves it backwards). */
    override suspend fun setLastSeen(ts: Long) {
        dataStore.edit { prefs ->
            val current = prefs[KEY_LAST_SEEN] ?: 0L
            if (ts > current) prefs[KEY_LAST_SEEN] = ts
        }
    }

    private companion object {
        val KEY_LAST_SEEN = longPreferencesKey("activity_last_seen_ms")
    }
}

/** Binds the Activity last-seen store contract to its DataStore-backed implementation. */
@dagger.Module
@dagger.hilt.InstallIn(dagger.hilt.components.SingletonComponent::class)
abstract class ActivityLastSeenStoreModule {
    @dagger.Binds
    @Singleton
    abstract fun bindActivityLastSeenStore(impl: ActivityLastSeenStoreImpl): ActivityLastSeenStore
}
