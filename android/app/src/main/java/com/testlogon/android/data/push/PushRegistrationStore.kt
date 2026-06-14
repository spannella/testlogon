package com.testlogon.android.data.push

import android.content.Context
import androidx.datastore.preferences.core.edit
import androidx.datastore.preferences.core.emptyPreferences
import androidx.datastore.preferences.core.intPreferencesKey
import androidx.datastore.preferences.core.stringPreferencesKey
import androidx.datastore.preferences.preferencesDataStore
import dagger.hilt.android.qualifiers.ApplicationContext
import kotlinx.coroutines.flow.catch
import kotlinx.coroutines.flow.first
import java.io.IOException
import javax.inject.Inject
import javax.inject.Singleton

private val Context.pushDataStore by preferencesDataStore(name = "push_registration")

/**
 * AND-106/109 — durable local push-registration state, separate from the auth store.
 *
 * Holds the last server-confirmed registration tuple `(userSub, token, contractVersion)` used for
 * client-side idempotency (FR-3: do not re-POST when nothing changed), the server-assigned
 * `device_id` needed for `POST /ui/push/revoke` at logout (AND-109), and a `pendingToken` cached
 * when a token rotates while logged out (FR-2/FR-3 of AND-109).
 *
 * Interface seam so repository tests inject an in-memory fake (no DataStore I/O on the JVM).
 */
interface PushRegistrationStore {
    suspend fun lastRegistered(): RegisteredTuple?
    suspend fun setLastRegistered(tuple: RegisteredTuple)
    suspend fun deviceId(): String?
    suspend fun setDeviceId(deviceId: String?)
    suspend fun pendingToken(): String?
    suspend fun cachePendingToken(token: String?)
    suspend fun clear()
}

/** Idempotency tuple — re-registration is skipped when the current tuple equals the stored one. */
data class RegisteredTuple(
    val userSub: String,
    val token: String,
    val contractVersion: Int,
)

/**
 * Bumped whenever [PushRegisterRequest] changes shape, forcing re-registration across app upgrades.
 */
const val PUSH_CONTRACT_VERSION = 1

@Singleton
class DataStorePushRegistrationStore @Inject constructor(
    @ApplicationContext context: Context,
) : PushRegistrationStore {

    private val dataStore = context.pushDataStore

    private object Keys {
        val USER_SUB = stringPreferencesKey("last_user_sub")
        val TOKEN = stringPreferencesKey("last_token")
        val CONTRACT_VERSION = intPreferencesKey("last_contract_version")
        val DEVICE_ID = stringPreferencesKey("server_device_id")
        val PENDING_TOKEN = stringPreferencesKey("pending_token")
    }

    private suspend fun read() = dataStore.data
        .catch { e -> if (e is IOException) emit(emptyPreferences()) else throw e }
        .first()

    override suspend fun lastRegistered(): RegisteredTuple? {
        val prefs = read()
        val sub = prefs[Keys.USER_SUB] ?: return null
        val token = prefs[Keys.TOKEN] ?: return null
        val version = prefs[Keys.CONTRACT_VERSION] ?: return null
        return RegisteredTuple(sub, token, version)
    }

    override suspend fun setLastRegistered(tuple: RegisteredTuple) {
        dataStore.edit {
            it[Keys.USER_SUB] = tuple.userSub
            it[Keys.TOKEN] = tuple.token
            it[Keys.CONTRACT_VERSION] = tuple.contractVersion
        }
    }

    override suspend fun deviceId(): String? = read()[Keys.DEVICE_ID]

    override suspend fun setDeviceId(deviceId: String?) {
        dataStore.edit {
            if (deviceId.isNullOrBlank()) it.remove(Keys.DEVICE_ID) else it[Keys.DEVICE_ID] = deviceId
        }
    }

    override suspend fun pendingToken(): String? = read()[Keys.PENDING_TOKEN]

    override suspend fun cachePendingToken(token: String?) {
        dataStore.edit {
            if (token.isNullOrBlank()) it.remove(Keys.PENDING_TOKEN) else it[Keys.PENDING_TOKEN] = token
        }
    }

    override suspend fun clear() {
        dataStore.edit {
            it.remove(Keys.USER_SUB)
            it.remove(Keys.TOKEN)
            it.remove(Keys.CONTRACT_VERSION)
            it.remove(Keys.DEVICE_ID)
            it.remove(Keys.PENDING_TOKEN)
        }
    }
}
