package com.testlogon.android.data.analytics

import android.content.Context
import androidx.datastore.preferences.core.edit
import androidx.datastore.preferences.core.emptyPreferences
import androidx.datastore.preferences.core.longPreferencesKey
import androidx.datastore.preferences.core.stringPreferencesKey
import androidx.datastore.preferences.preferencesDataStore
import dagger.hilt.android.qualifiers.ApplicationContext
import kotlinx.coroutines.flow.catch
import kotlinx.coroutines.flow.first
import java.io.IOException
import javax.inject.Inject
import javax.inject.Singleton

private val Context.abandonDataStore by preferencesDataStore(name = "cart_abandonment")

/** The durable background mark used for BACKGROUND_TIMEOUT / PROCESS_KILLED recovery. */
data class BackgroundMark(val atEpochMs: Long, val hash: String)

/**
 * AND-216 — durable de-dupe + process-kill recovery marker.
 *
 * Persists the minimal scalar state for exactly-once (`lastEmittedHash`) and kill recovery
 * (`backgroundMark`). Interface seam so the use case / tracker inject an in-memory fake on the JVM (no
 * DataStore I/O in unit tests). All reads/writes are wrapped so a store failure degrades to "no marker"
 * (prefer one possible duplicate over a lost signal — section 7) and never throws.
 *
 * Contains no PII (only a one-way hash, timestamps, ids); app-private storage; excluded from backup via
 * the manifest data-extraction rules.
 */
interface AbandonmentMarkerStore {
    suspend fun lastEmittedHash(): String?
    suspend fun recordEmitted(hash: String, episodeId: String)
    suspend fun markBackgrounded(atEpochMs: Long, hash: String)
    suspend fun backgroundMark(): BackgroundMark?
    suspend fun clearBackgroundMark()
    suspend fun reset()
}

@Singleton
class DataStoreAbandonmentMarkerStore @Inject constructor(
    @ApplicationContext context: Context,
) : AbandonmentMarkerStore {

    private val dataStore = context.abandonDataStore

    private object Keys {
        val LAST_HASH = stringPreferencesKey("cart_abandon_last_hash")
        val BG_HASH = stringPreferencesKey("cart_abandon_bg_hash")
        val BG_AT = longPreferencesKey("cart_abandon_bg_at")
        val EPISODE = stringPreferencesKey("cart_abandon_episode_id")
    }

    private suspend fun read() = dataStore.data
        .catch { e -> if (e is IOException) emit(emptyPreferences()) else throw e }
        .first()

    override suspend fun lastEmittedHash(): String? =
        runCatching { read()[Keys.LAST_HASH] }.getOrNull()

    override suspend fun recordEmitted(hash: String, episodeId: String) {
        runCatching {
            dataStore.edit {
                it[Keys.LAST_HASH] = hash
                it[Keys.EPISODE] = episodeId
            }
        }
    }

    override suspend fun markBackgrounded(atEpochMs: Long, hash: String) {
        runCatching {
            dataStore.edit {
                it[Keys.BG_AT] = atEpochMs
                it[Keys.BG_HASH] = hash
            }
        }
    }

    override suspend fun backgroundMark(): BackgroundMark? = runCatching {
        val prefs = read()
        val at = prefs[Keys.BG_AT] ?: return null
        val hash = prefs[Keys.BG_HASH] ?: return null
        BackgroundMark(atEpochMs = at, hash = hash)
    }.getOrNull()

    override suspend fun clearBackgroundMark() {
        runCatching {
            dataStore.edit {
                it.remove(Keys.BG_AT)
                it.remove(Keys.BG_HASH)
            }
        }
    }

    override suspend fun reset() {
        runCatching {
            dataStore.edit {
                it.remove(Keys.LAST_HASH)
                it.remove(Keys.BG_AT)
                it.remove(Keys.BG_HASH)
                it.remove(Keys.EPISODE)
            }
        }
    }
}
