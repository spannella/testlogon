package com.testlogon.android.data.privacy

import android.content.Context
import androidx.datastore.preferences.core.Preferences
import androidx.datastore.preferences.core.booleanPreferencesKey
import androidx.datastore.preferences.core.edit
import androidx.datastore.preferences.core.emptyPreferences
import androidx.datastore.preferences.core.intPreferencesKey
import androidx.datastore.preferences.core.longPreferencesKey
import androidx.datastore.preferences.core.stringPreferencesKey
import androidx.datastore.preferences.preferencesDataStore
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

private val Context.accountDeletionStatusDataStore by
    preferencesDataStore(name = "privacy_deletion_status")

/**
 * AND-386 - best-effort, last-known deletion status mirror (spec §6).
 *
 * Persists ONLY the non-secret pending-request descriptor so the Privacy row + the deletion screen can show
 * a stale value while offline (FR-6). DataStore writes are best-effort; a read failure falls back to null
 * (-> the caller shows Loading -> fetch). The user's password is NEVER written here (spec §8 / AC-8) - this
 * store only knows the public pending descriptor (request id is intentionally NOT logged anywhere, only
 * persisted locally for the cancel CTA target).
 */
interface AccountDeletionStatusStore {

    /** Returns the last-known status, or null if nothing has ever been cached / a read fails. */
    suspend fun load(): DeletionStatus?

    /** Mirrors the latest authoritative status (best-effort). */
    suspend fun save(status: DeletionStatus)

    /** Wipes the mirror on sign-out (PII hygiene). */
    suspend fun clear()
}

@Singleton
class DataStoreAccountDeletionStatusStore @Inject constructor(
    @ApplicationContext context: Context,
) : AccountDeletionStatusStore {

    private val dataStore = context.accountDeletionStatusDataStore

    override suspend fun load(): DeletionStatus? {
        val prefs = readPrefs()
        // The marker distinguishes "never cached" from "cached Active".
        when (prefs[KEY_MARKER]) {
            MARKER_ACTIVE -> return DeletionStatus.Active
            MARKER_PENDING -> {
                val id = prefs[KEY_REQUEST_ID] ?: return DeletionStatus.Active
                return DeletionStatus.Pending(
                    requestId = id,
                    createdAtEpochMs = prefs[KEY_CREATED_AT] ?: 0L,
                    scheduledForEpochMs = if (prefs[KEY_HAS_SCHEDULED] == true) prefs[KEY_SCHEDULED_FOR] else null,
                    graceDaysRemaining = if (prefs[KEY_HAS_GRACE] == true) prefs[KEY_GRACE_DAYS] else null,
                    canCancel = prefs[KEY_CAN_CANCEL] ?: false,
                )
            }
            else -> return null
        }
    }

    override suspend fun save(status: DeletionStatus) {
        runCatching {
            dataStore.edit { p ->
                when (status) {
                    is DeletionStatus.Active -> {
                        p[KEY_MARKER] = MARKER_ACTIVE
                        p.remove(KEY_REQUEST_ID)
                        p.remove(KEY_CREATED_AT)
                        p.remove(KEY_HAS_SCHEDULED)
                        p.remove(KEY_SCHEDULED_FOR)
                        p.remove(KEY_HAS_GRACE)
                        p.remove(KEY_GRACE_DAYS)
                        p.remove(KEY_CAN_CANCEL)
                    }
                    is DeletionStatus.Pending -> {
                        p[KEY_MARKER] = MARKER_PENDING
                        p[KEY_REQUEST_ID] = status.requestId
                        p[KEY_CREATED_AT] = status.createdAtEpochMs
                        val sched = status.scheduledForEpochMs
                        p[KEY_HAS_SCHEDULED] = sched != null
                        p[KEY_SCHEDULED_FOR] = sched ?: 0L
                        val grace = status.graceDaysRemaining
                        p[KEY_HAS_GRACE] = grace != null
                        p[KEY_GRACE_DAYS] = grace ?: 0
                        p[KEY_CAN_CANCEL] = status.canCancel
                    }
                }
            }
        }
    }

    override suspend fun clear() {
        runCatching { dataStore.edit { it.clear() } }
    }

    private suspend fun readPrefs(): Preferences = dataStore.data
        .catch { e -> if (e is IOException) emit(emptyPreferences()) else throw e }
        .first()

    private companion object {
        const val MARKER_ACTIVE = "active"
        const val MARKER_PENDING = "pending"

        val KEY_MARKER = stringPreferencesKey("deletion/marker")
        val KEY_REQUEST_ID = stringPreferencesKey("deletion/request_id")
        val KEY_CREATED_AT = longPreferencesKey("deletion/created_at")
        val KEY_HAS_SCHEDULED = booleanPreferencesKey("deletion/has_scheduled")
        val KEY_SCHEDULED_FOR = longPreferencesKey("deletion/scheduled_for")
        val KEY_HAS_GRACE = booleanPreferencesKey("deletion/has_grace")
        val KEY_GRACE_DAYS = intPreferencesKey("deletion/grace_days")
        val KEY_CAN_CANCEL = booleanPreferencesKey("deletion/can_cancel")
    }
}

/** AND-386 - binds the DataStore-backed last-known deletion status mirror. */
@Module
@InstallIn(SingletonComponent::class)
abstract class AccountDeletionStoreModule {
    @Binds
    @Singleton
    abstract fun bindAccountDeletionStatusStore(
        impl: DataStoreAccountDeletionStatusStore,
    ): AccountDeletionStatusStore
}
