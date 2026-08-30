package com.testlogon.android.data.messaging.mute

import android.content.Context
import androidx.datastore.preferences.core.edit
import androidx.datastore.preferences.core.emptyPreferences
import androidx.datastore.preferences.core.longPreferencesKey
import androidx.datastore.preferences.preferencesDataStore
import dagger.hilt.android.qualifiers.ApplicationContext
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.catch
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.map
import java.io.IOException
import javax.inject.Inject
import javax.inject.Singleton

private val Context.conversationMuteDataStore by preferencesDataStore(name = "conversation_mute")

/**
 * FE-140 — a small, durable client-side cache of per-conversation `muted_until` (epoch SECONDS),
 * keyed by conversation id. This is the ONE mute source that is readable from the notification
 * presentation path (which may run after a process restart, with no ViewModel alive), and it also
 * feeds the conversation-list / thread mute indicators.
 *
 * It is a client-side MIRROR of the server's authoritative `muted_until`, refreshed whenever
 * conversations are fetched ([syncFromList]) and updated the moment the user mutes/unmutes
 * ([setMuted]). It is intentionally advisory: an unknown conversation reads back as 0 (not muted),
 * so the notification path fails OPEN (posts as today) when state is unknown.
 *
 * Interface seam so JVM tests can inject an in-memory fake (no DataStore I/O off-device).
 */
interface ConversationMuteStore {
    /** `muted_until` epoch seconds for [conversationId]; 0 when unknown / not muted. */
    suspend fun mutedUntil(conversationId: String): Long

    /** Reactive `muted_until` for one conversation (emits 0 when unknown / cleared). */
    fun observeMutedUntil(conversationId: String): Flow<Long>

    /** Whole mute map (conversationId -> mutedUntil). Used by the list screen. */
    fun observeAll(): Flow<Map<String, Long>>

    /** Record a single conversation's mute state (0 clears it). */
    suspend fun setMuted(conversationId: String, mutedUntil: Long)

    /**
     * Reconcile from an authoritative fetch: upserts every (id -> mutedUntil) pair. Entries not in
     * [pairs] are left untouched (a partial page must not wipe others). A 0 in [pairs] clears that id.
     */
    suspend fun syncFromList(pairs: List<Pair<String, Long>>)

    suspend fun clear()
}

@Singleton
class DataStoreConversationMuteStore @Inject constructor(
    @ApplicationContext context: Context,
) : ConversationMuteStore {

    private val dataStore = context.conversationMuteDataStore

    private fun key(conversationId: String) = longPreferencesKey("mute_$conversationId")

    override suspend fun mutedUntil(conversationId: String): Long =
        dataStore.data
            .catch { e -> if (e is IOException) emit(emptyPreferences()) else throw e }
            .first()[key(conversationId)] ?: 0L

    override fun observeMutedUntil(conversationId: String): Flow<Long> =
        dataStore.data
            .catch { e -> if (e is IOException) emit(emptyPreferences()) else throw e }
            .map { it[key(conversationId)] ?: 0L }

    override fun observeAll(): Flow<Map<String, Long>> =
        dataStore.data
            .catch { e -> if (e is IOException) emit(emptyPreferences()) else throw e }
            .map { prefs ->
                prefs.asMap().entries
                    .filter { it.key.name.startsWith("mute_") && it.value is Long }
                    .associate { it.key.name.removePrefix("mute_") to (it.value as Long) }
            }

    override suspend fun setMuted(conversationId: String, mutedUntil: Long) {
        dataStore.edit { prefs ->
            if (mutedUntil > 0L) prefs[key(conversationId)] = mutedUntil
            else prefs.remove(key(conversationId))
        }
    }

    override suspend fun syncFromList(pairs: List<Pair<String, Long>>) {
        if (pairs.isEmpty()) return
        dataStore.edit { prefs ->
            for ((id, until) in pairs) {
                if (until > 0L) prefs[key(id)] = until else prefs.remove(key(id))
            }
        }
    }

    override suspend fun clear() {
        dataStore.edit { it.clear() }
    }
}
