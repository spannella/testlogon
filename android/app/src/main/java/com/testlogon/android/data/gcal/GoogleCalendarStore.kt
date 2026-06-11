package com.testlogon.android.data.gcal

import android.content.Context
import androidx.datastore.preferences.core.booleanPreferencesKey
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

private val Context.gcalDataStore by preferencesDataStore(name = "integrations_prefs")

/** A persisted projection of the last-known connection (for instant render + process-death survival). */
data class CachedConnection(
    val connectionActive: Boolean,
    val accountEmail: String?,
)

/** The in-flight OAuth state/nonce captured at connect/start, validated on a deep-link return. */
data class PendingOauth(
    val state: String,
    val nonce: String,
)

/**
 * AND-273 — DataStore store ("integrations_prefs") for the Google Calendar integration.
 *
 * Persists (1) a small projection of the connection (active flag + account email — captured from the
 * connect callback, since status omits it) for instant render after process death, and (2) the in-flight
 * OAuth `state`/`nonce` so a returning custom-scheme deep link can be validated. The account email is
 * PII; it lives only in app-private DataStore and must never reach logs/telemetry (AND-273 §8/§10).
 */
interface GoogleCalendarStore {
    suspend fun cachedConnection(): CachedConnection?
    suspend fun saveConnection(active: Boolean, accountEmail: String?)
    suspend fun clearConnection()

    suspend fun savePendingOauth(state: String, nonce: String)
    suspend fun pendingOauth(): PendingOauth?
    suspend fun clearPendingOauth()
}

@Singleton
class DataStoreGoogleCalendarStore @Inject constructor(
    @ApplicationContext context: Context,
) : GoogleCalendarStore {

    private val dataStore = context.gcalDataStore

    private object Keys {
        val CONNECTION_ACTIVE = booleanPreferencesKey("gcal_connection_active")
        val ACCOUNT_EMAIL = stringPreferencesKey("gcal_account_email")
        val OAUTH_STATE = stringPreferencesKey("gcal_oauth_state")
        val OAUTH_NONCE = stringPreferencesKey("gcal_oauth_nonce")
    }

    private suspend fun read() = dataStore.data
        .catch { e -> if (e is IOException) emit(emptyPreferences()) else throw e }
        .first()

    override suspend fun cachedConnection(): CachedConnection? {
        val prefs = read()
        if (!prefs.contains(Keys.CONNECTION_ACTIVE)) return null
        return CachedConnection(
            connectionActive = prefs[Keys.CONNECTION_ACTIVE] ?: false,
            accountEmail = prefs[Keys.ACCOUNT_EMAIL],
        )
    }

    override suspend fun saveConnection(active: Boolean, accountEmail: String?) {
        dataStore.edit {
            it[Keys.CONNECTION_ACTIVE] = active
            if (accountEmail != null) it[Keys.ACCOUNT_EMAIL] = accountEmail
        }
    }

    override suspend fun clearConnection() {
        dataStore.edit {
            it[Keys.CONNECTION_ACTIVE] = false
            it.remove(Keys.ACCOUNT_EMAIL)
        }
    }

    override suspend fun savePendingOauth(state: String, nonce: String) {
        dataStore.edit {
            it[Keys.OAUTH_STATE] = state
            it[Keys.OAUTH_NONCE] = nonce
        }
    }

    override suspend fun pendingOauth(): PendingOauth? {
        val prefs = read()
        val state = prefs[Keys.OAUTH_STATE] ?: return null
        val nonce = prefs[Keys.OAUTH_NONCE] ?: return null
        return PendingOauth(state, nonce)
    }

    override suspend fun clearPendingOauth() {
        dataStore.edit {
            it.remove(Keys.OAUTH_STATE)
            it.remove(Keys.OAUTH_NONCE)
        }
    }
}
