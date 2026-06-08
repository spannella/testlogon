package com.testlogon.android.data.auth

import android.content.Context
import androidx.datastore.preferences.core.booleanPreferencesKey
import androidx.datastore.preferences.core.edit
import androidx.datastore.preferences.core.emptyPreferences
import androidx.datastore.preferences.core.stringPreferencesKey
import androidx.datastore.preferences.preferencesDataStore
import com.testlogon.android.auth.AuthStateProvider
import dagger.hilt.android.qualifiers.ApplicationContext
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.catch
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.flow.stateIn
import java.io.IOException
import javax.inject.Inject
import javax.inject.Singleton

private val Context.authDataStore by preferencesDataStore(name = "auth_state")

/**
 * Durable, observable projection of "who is logged in" (AND-029).
 *
 * The TestLogon session is cookie-based; this store is the fast, persisted mirror of that session
 * so navigation gating, logout, and cold start can react without a network round-trip. It backs the
 * navigation-layer [AuthStateProvider] seam (replacing the temporary always-false default).
 *
 * Only `authenticated` + `user_sub` are persisted (PII-minimization); the richer [User]
 * (`session_id`, `ip`) stays in memory in the repository's cache and is dropped on process death.
 */
interface AuthStateStore : AuthStateProvider {
    /** Opaque `user_sub` of the current principal, or null when unauthenticated. */
    val userSub: StateFlow<String?>

    suspend fun setAuthenticated(userSub: String)
    suspend fun clear()
}

@Singleton
class DataStoreAuthStateStore @Inject constructor(
    @ApplicationContext context: Context,
    @AppScope private val scope: CoroutineScope,
) : AuthStateStore {

    private val dataStore = context.authDataStore

    private object Keys {
        val AUTHENTICATED = booleanPreferencesKey("authenticated")
        val USER_SUB = stringPreferencesKey("user_sub")
    }

    private val state: StateFlow<Pair<Boolean, String?>> =
        dataStore.data
            .catch { e -> if (e is IOException) emit(emptyPreferences()) else throw e }
            .map { prefs ->
                val sub = prefs[Keys.USER_SUB]
                val authed = prefs[Keys.AUTHENTICATED] == true && !sub.isNullOrBlank()
                authed to sub?.takeIf { authed }
            }
            .stateIn(scope, SharingStarted.Eagerly, false to null)

    override val isAuthenticated: StateFlow<Boolean> =
        state.map { it.first }.stateIn(scope, SharingStarted.Eagerly, false)

    override val userSub: StateFlow<String?> =
        state.map { it.second }.stateIn(scope, SharingStarted.Eagerly, null)

    override suspend fun setAuthenticated(userSub: String) {
        dataStore.edit {
            it[Keys.AUTHENTICATED] = true
            it[Keys.USER_SUB] = userSub
        }
    }

    override suspend fun clear() {
        dataStore.edit {
            it[Keys.AUTHENTICATED] = false
            it.remove(Keys.USER_SUB)
        }
    }
}
