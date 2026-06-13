package com.testlogon.android.feature.broadcast.host

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

private val Context.hostSessionDataStore by preferencesDataStore(name = "host_session_prefs")

/**
 * AND-317 — persists the single active host session id + last client phase across process death, so the
 * host VM can seed a restore on cold start. Mirrors the DataStore-preferences pattern of
 * [com.testlogon.android.feature.call.fsm.DataStoreCallSnapshotStore] /
 * [com.testlogon.android.data.earnings.DataStoreEarningsPrefs]. NO new dependency, NO Room.
 */
interface HostSessionPrefs {

    /** The active session id (null if none persisted). */
    suspend fun activeSessionId(): String?

    /** The last persisted client phase (null if none). */
    suspend fun lastStatus(): HostSessionStatus?

    /** Writes both keys (clears the id when [sessionId] is null). */
    suspend fun write(sessionId: String?, status: HostSessionStatus)

    /** Clears all persisted host-session state. */
    suspend fun clear()
}

@Singleton
class DataStoreHostSessionPrefs @Inject constructor(
    @ApplicationContext context: Context,
) : HostSessionPrefs {

    private val dataStore = context.hostSessionDataStore

    override suspend fun activeSessionId(): String? = read()[Keys.SESSION_ID]

    override suspend fun lastStatus(): HostSessionStatus? =
        read()[Keys.LAST_STATUS]?.let { token ->
            HostSessionStatus.entries.firstOrNull { it.name == token }
        }

    override suspend fun write(sessionId: String?, status: HostSessionStatus) {
        dataStore.edit { prefs ->
            if (sessionId != null) prefs[Keys.SESSION_ID] = sessionId else prefs.remove(Keys.SESSION_ID)
            prefs[Keys.LAST_STATUS] = status.name
        }
    }

    override suspend fun clear() {
        dataStore.edit { it.clear() }
    }

    private suspend fun read() = dataStore.data
        .catch { e -> if (e is IOException) emit(emptyPreferences()) else throw e }
        .first()

    private object Keys {
        val SESSION_ID = stringPreferencesKey("active_session_id")
        val LAST_STATUS = stringPreferencesKey("last_status")
    }
}
