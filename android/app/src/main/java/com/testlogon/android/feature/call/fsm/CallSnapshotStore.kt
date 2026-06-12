package com.testlogon.android.feature.call.fsm

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

private val Context.callSnapshotDataStore by preferencesDataStore(name = "call_fsm_snapshot")

/**
 * AND-305 — persistence of the single in-progress [CallSnapshot] so a NON-TERMINAL call rehydrates on a
 * cold start (process death mid-call). [save] is called on each non-terminal transition; [clear] on Ended /
 * logout. Mirrors the DataStore-preferences pattern of [com.testlogon.android.data.payments.PaymentIntentStore].
 */
interface CallSnapshotStore {
    suspend fun save(snapshot: CallSnapshot)
    suspend fun load(): CallSnapshot?
    suspend fun clear()
}

@Singleton
class DataStoreCallSnapshotStore @Inject constructor(
    @ApplicationContext context: Context,
) : CallSnapshotStore {

    private val dataStore = context.callSnapshotDataStore

    private object Keys {
        val SNAPSHOT = stringPreferencesKey("snapshot")
    }

    override suspend fun save(snapshot: CallSnapshot) {
        dataStore.edit { it[Keys.SNAPSHOT] = CallSnapshotCodec.encode(snapshot) }
    }

    override suspend fun load(): CallSnapshot? {
        val prefs = dataStore.data
            .catch { e -> if (e is IOException) emit(emptyPreferences()) else throw e }
            .first()
        return CallSnapshotCodec.decode(prefs[Keys.SNAPSHOT])
    }

    override suspend fun clear() {
        dataStore.edit { it.remove(Keys.SNAPSHOT) }
    }
}
