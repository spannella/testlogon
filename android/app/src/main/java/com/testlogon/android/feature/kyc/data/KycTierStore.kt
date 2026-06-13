package com.testlogon.android.feature.kyc.data

import android.content.Context
import androidx.datastore.preferences.core.edit
import androidx.datastore.preferences.core.emptyPreferences
import androidx.datastore.preferences.core.stringPreferencesKey
import androidx.datastore.preferences.preferencesDataStore
import com.squareup.moshi.Moshi
import com.testlogon.android.feature.kyc.model.TierStatus
import dagger.hilt.android.qualifiers.ApplicationContext
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.catch
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.map
import java.io.IOException
import javax.inject.Inject
import javax.inject.Singleton

private val Context.kycTierDataStore by preferencesDataStore(name = "kyc_tier_prefs")

/**
 * AND-320 — persists the last [TierStatus] snapshot so the screen can render an instant (offline-friendly)
 * cached view before / during a refresh. Mirrors the DataStore-preferences pattern of
 * [com.testlogon.android.feature.broadcast.host.DataStoreHostSessionPrefs] (AND-317). NO new dependency
 * (DataStore is already used), NO Room.
 *
 * The snapshot is serialized to a single JSON string via the injected shared [Moshi] (a feature-local
 * [TierStatusSnapshotDto] kept verbatim so the Instant fields round-trip as epoch seconds — Moshi has no
 * built-in Instant adapter, so we never persist Instant directly).
 */
interface KycTierStore {

    /** Emits the cached snapshot (null when none persisted / on read error). */
    fun observe(): Flow<TierStatus?>

    /** Reads the cached snapshot once (null when none / on read error). */
    suspend fun read(): TierStatus?

    /** Replaces the cached snapshot. */
    suspend fun write(status: TierStatus)

    /** Clears the cached snapshot. */
    suspend fun clear()
}

@Singleton
class DataStoreKycTierStore @Inject constructor(
    @ApplicationContext context: Context,
    moshi: Moshi,
) : KycTierStore {

    private val dataStore = context.kycTierDataStore
    private val adapter = moshi.adapter(TierStatusSnapshotDto::class.java)

    override fun observe(): Flow<TierStatus?> = dataStore.data
        .catch { e -> if (e is IOException) emit(emptyPreferences()) else throw e }
        .map { prefs -> prefs[Keys.SNAPSHOT]?.let(::decode) }

    override suspend fun read(): TierStatus? = observe().first()

    override suspend fun write(status: TierStatus) {
        val json = adapter.toJson(TierStatusSnapshotDto.from(status))
        dataStore.edit { it[Keys.SNAPSHOT] = json }
    }

    override suspend fun clear() {
        dataStore.edit { it.remove(Keys.SNAPSHOT) }
    }

    /** Decodes the persisted JSON; malformed/legacy payloads degrade to null rather than throwing. */
    private fun decode(json: String): TierStatus? =
        runCatching { adapter.fromJson(json)?.toDomain() }.getOrNull()

    private object Keys {
        val SNAPSHOT = stringPreferencesKey("tier_status_snapshot")
    }
}
