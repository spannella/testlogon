package com.testlogon.android.feature.boost.data

import android.content.Context
import androidx.datastore.preferences.core.edit
import androidx.datastore.preferences.core.emptyPreferences
import androidx.datastore.preferences.core.stringPreferencesKey
import androidx.datastore.preferences.preferencesDataStore
import com.squareup.moshi.Moshi
import com.squareup.moshi.Types
import com.testlogon.android.core.model.ads.BoostStatus
import com.testlogon.android.core.model.ads.ContentBoost
import dagger.Binds
import dagger.Module
import dagger.hilt.InstallIn
import dagger.hilt.android.qualifiers.ApplicationContext
import dagger.hilt.components.SingletonComponent
import kotlinx.coroutines.flow.catch
import kotlinx.coroutines.flow.first
import java.io.IOException
import javax.inject.Inject
import javax.inject.Singleton

private val Context.boostStatusDataStore by preferencesDataStore(name = "boost_status_cache")

/**
 * AND-364 - tiny per-post boost-status cache.
 *
 * DELIBERATE PERSISTENCE DIVERGENCE (functionally equivalent to FR-9's Room ask): a per-post last-known
 * boost is far too small to justify a Room schema bump + v8 -> v9 migration + the Pixel smoke that a DB
 * change pulls in. Instead this is a DataStore-Preferences-backed JSON map (postId -> serialized boost),
 * mirroring the AND-353 SelectedOrgStore / AND-317 HostSessionPrefs pattern. NO Room change, NO migration,
 * NO new dependency. The persistence is functionally equivalent (a durable, process-death-surviving
 * last-known status the ViewModel reads on load to decide Form vs. Status).
 *
 * SERIALIZATION (app-unit-test friendly): each boost is stored as a PLAIN Map<String, Any?> of primitive
 * fields serialized via the injected [Moshi]'s built-in Map adapter, NOT as a Kotlin data class. The
 * app-test classpath has no moshi-kotlin reflective/codegen adapter, so a default Moshi cannot serialize a
 * data class - the primitive-map form round-trips with a default Moshi too. Reads are tolerant: a
 * malformed / partial entry yields null rather than throwing.
 */
interface BoostStatusCache {

    /** Persists the last-known [boost] for [postId] (overwrites any prior entry). */
    suspend fun put(postId: String, boost: ContentBoost)

    /** The last-known boost for [postId], or null when none is cached / the entry is unreadable. */
    suspend fun get(postId: String): ContentBoost?
}

@Singleton
class DataStoreBoostStatusCache @Inject constructor(
    @ApplicationContext context: Context,
    private val moshi: Moshi,
) : BoostStatusCache {

    private val dataStore = context.boostStatusDataStore

    // Map<String postId, Map<String field, Any value>> - the whole cache is one JSON blob under one key.
    private val mapType = Types.newParameterizedType(
        Map::class.java,
        String::class.java,
        Types.newParameterizedType(Map::class.java, String::class.java, Any::class.java),
    )
    private val adapter = moshi.adapter<Map<String, Map<String, Any?>>>(mapType)

    override suspend fun put(postId: String, boost: ContentBoost) {
        val current = readAll().toMutableMap()
        current[postId] = boost.toEntry()
        val json = adapter.toJson(current)
        dataStore.edit { it[Keys.CACHE] = json }
    }

    override suspend fun get(postId: String): ContentBoost? =
        readAll()[postId]?.let(::entryToBoost)

    private suspend fun readAll(): Map<String, Map<String, Any?>> {
        val json = dataStore.data
            .catch { e -> if (e is IOException) emit(emptyPreferences()) else throw e }
            .first()[Keys.CACHE]
            ?: return emptyMap()
        return try {
            adapter.fromJson(json) ?: emptyMap()
        } catch (_: Exception) {
            // Tolerant: a corrupt / schema-drifted blob is treated as an empty cache, never throws.
            emptyMap()
        }
    }

    /** Serializes a boost to a primitive map. Numbers are stored as Double (JSON's native number form). */
    private fun ContentBoost.toEntry(): Map<String, Any?> = buildMap {
        put("boost_id", boostId)
        put("status", status)
        put("budget_cents", budgetCents.toDouble())
        spentCents?.let { put("spent_cents", it.toDouble()) }
        remainingCents?.let { put("remaining_cents", it.toDouble()) }
        durationSeconds?.let { put("duration_seconds", it.toDouble()) }
        endsAt?.let { put("ends_at", it.toDouble()) }
    }

    /** Rebuilds a [ContentBoost] from a primitive map; returns null when required keys are missing. */
    private fun entryToBoost(entry: Map<String, Any?>): ContentBoost? {
        val boostId = entry["boost_id"] as? String ?: return null
        val status = entry["status"] as? String ?: return null
        val budget = entry.long("budget_cents") ?: return null
        return ContentBoost(
            boostId = boostId,
            status = status,
            statusEnum = BoostStatus.from(status),
            budgetCents = budget,
            spentCents = entry.long("spent_cents"),
            remainingCents = entry.long("remaining_cents"),
            durationSeconds = entry.long("duration_seconds"),
            endsAt = entry.long("ends_at"),
        )
    }

    /** Reads a numeric field back as a Long (JSON decodes numbers as Double; tolerate Int / Long too). */
    private fun Map<String, Any?>.long(key: String): Long? = when (val v = this[key]) {
        is Number -> v.toLong()
        is String -> v.toLongOrNull()
        else -> null
    }

    private object Keys {
        val CACHE = stringPreferencesKey("boost_status_cache_json")
    }
}

/** AND-364 - binds the [BoostStatusCache] seam to its DataStore-backed impl. */
@Module
@InstallIn(SingletonComponent::class)
abstract class BoostStatusCacheModule {
    @Binds
    @Singleton
    abstract fun bindBoostStatusCache(impl: DataStoreBoostStatusCache): BoostStatusCache
}
