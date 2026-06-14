package com.testlogon.android.data.auth

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

private val Context.ssoStateDataStore by preferencesDataStore(name = "sso_state")

/** Pending SSO launch state, persisted so a redirect after process death can still be correlated. */
data class PendingSso(
    val state: String,
    val expiresAtEpochMs: Long,
)

/**
 * AND-063 — DataStore-backed store for the in-flight SSO `state` token. The `state` is a local-only
 * defense-in-depth correlation guard (the backend `/saml/login` does NOT accept/echo it); the
 * authoritative session check remains `GET /ui/me`. Single in-flight attempt; TTL-bounded (10 min).
 */
interface SsoStateStore {
    suspend fun save(state: String, ttlMillis: Long = DEFAULT_TTL_MS)

    /** Returns the pending state if present AND not expired; null otherwise. */
    suspend fun peek(): PendingSso?

    suspend fun clear()

    companion object {
        const val DEFAULT_TTL_MS = 10 * 60 * 1000L
    }
}

@Singleton
class DataStoreSsoStateStore @Inject constructor(
    @ApplicationContext context: Context,
) : SsoStateStore {

    private val dataStore = context.ssoStateDataStore

    private object Keys {
        val STATE = stringPreferencesKey("pending_state")
        val EXPIRES_AT = longPreferencesKey("expires_at")
    }

    override suspend fun save(state: String, ttlMillis: Long) {
        dataStore.edit {
            it[Keys.STATE] = state
            it[Keys.EXPIRES_AT] = System.currentTimeMillis() + ttlMillis
        }
    }

    override suspend fun peek(): PendingSso? {
        val prefs = dataStore.data
            .catch { e -> if (e is IOException) emit(emptyPreferences()) else throw e }
            .first()
        val state = prefs[Keys.STATE] ?: return null
        val expiresAt = prefs[Keys.EXPIRES_AT] ?: 0L
        if (System.currentTimeMillis() > expiresAt) return null
        return PendingSso(state = state, expiresAtEpochMs = expiresAt)
    }

    override suspend fun clear() {
        dataStore.edit {
            it.remove(Keys.STATE)
            it.remove(Keys.EXPIRES_AT)
        }
    }
}
