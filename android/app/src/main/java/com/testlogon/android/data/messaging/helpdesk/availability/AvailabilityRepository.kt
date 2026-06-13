package com.testlogon.android.data.messaging.helpdesk.availability

import androidx.datastore.core.DataStore
import androidx.datastore.preferences.core.Preferences
import androidx.datastore.preferences.core.edit
import androidx.datastore.preferences.core.emptyPreferences
import androidx.datastore.preferences.core.stringPreferencesKey
import com.testlogon.android.core.model.helpdesk.Availability
import com.testlogon.android.core.model.helpdesk.heartbeatStatus
import com.testlogon.android.data.auth.AppScope
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.catch
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.flow.stateIn
import java.io.IOException
import javax.inject.Inject
import javax.inject.Singleton

/**
 * AND-379 — single source of truth for agent availability.
 *
 * Both the availability toggle UI and the presence heartbeat read [availability]; there is no path
 * where the UI shows Online while heartbeats send "away" (FR-7 / AC-4). Persisted in DataStore so the
 * value survives process death and is correct before the first UI composition (the StateFlow is hot,
 * `SharingStarted.Eagerly`, seeded from DataStore). Default is [Availability.AWAY] (fail-safe — agents
 * must opt in to receiving claims, FR-1 / AC-3).
 */
interface AvailabilityRepository {

    /** Hot, durable availability. Defaults to AWAY when no value is persisted. */
    val availability: StateFlow<Availability>

    /** Persist [value] then fire an immediate out-of-band heartbeat carrying the new status. */
    suspend fun set(value: Availability)

    /** Synchronous-ish current value, used by the claim gate and the periodic heartbeat. */
    suspend fun current(): Availability
}

/**
 * AND-379 — narrow heartbeat-push seam owned by AND-145's heartbeat write side. Kept separate from the
 * full presence repository so [AvailabilityRepositoryImpl] depends only on the push capability,
 * avoiding a hard reference cycle with the heartbeat scheduler (see AvailabilityModule + the
 * `dagger.Lazy` indirection on the scheduler's availability read).
 */
interface PresenceHeartbeatPush {
    /** Fire one immediate heartbeat carrying [status]. Non-fatal: failures are swallowed. */
    suspend fun sendHeartbeatNow(status: String)
}

@Singleton
class AvailabilityRepositoryImpl @Inject constructor(
    @AvailabilityPrefs private val dataStore: DataStore<Preferences>,
    private val heartbeatPush: PresenceHeartbeatPush,
    @AppScope private val scope: CoroutineScope,
) : AvailabilityRepository {

    override val availability: StateFlow<Availability> =
        dataStore.data
            .catch { e -> if (e is IOException) emit(emptyPreferences()) else throw e }
            .map { it.readAvailability() }
            .stateIn(scope, SharingStarted.Eagerly, Availability.AWAY)

    override suspend fun set(value: Availability) {
        // DataStore commit is authoritative; the immediate heartbeat is best-effort (FR-3 / §7).
        dataStore.edit { it[KEY] = value.name }
        heartbeatPush.sendHeartbeatNow(value.heartbeatStatus())
    }

    override suspend fun current(): Availability =
        dataStore.data
            .catch { e -> if (e is IOException) emit(emptyPreferences()) else throw e }
            .first()
            .readAvailability()

    private fun Preferences.readAvailability(): Availability =
        this[KEY]?.let { name -> runCatching { Availability.valueOf(name) }.getOrNull() }
            ?: Availability.AWAY

    private companion object {
        val KEY = stringPreferencesKey("agent_availability")
    }
}
