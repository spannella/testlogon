package com.testlogon.android.feature.onboarding

import android.content.Context
import androidx.datastore.preferences.core.edit
import androidx.datastore.preferences.core.emptyPreferences
import androidx.datastore.preferences.core.stringSetPreferencesKey
import androidx.datastore.preferences.preferencesDataStore
import dagger.hilt.android.qualifiers.ApplicationContext
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.catch
import kotlinx.coroutines.flow.map
import java.io.IOException
import javax.inject.Inject
import javax.inject.Singleton

private val Context.onboardingDataStore by preferencesDataStore(name = "onboarding")

/**
 * Durable "already-seen" set for the trading/investing onboarding (welcome tour + per-surface intros),
 * persisted as one string-set in DataStore. Mirrors the failure-safe pattern of
 * [com.testlogon.android.feature.paper.PaperAccountStore]: a store error degrades to "nothing seen" /
 * a no-op write, never throws. Interface seam so ViewModels can inject an in-memory fake on the JVM.
 *
 * The set only ever grows via [markSeen] (monotonic show-once); [resetAll] is the single un-set path,
 * used by the Settings "Product tour" replay control.
 */
interface OnboardingStore {
    /** A live stream of the seen-set (emits the current set immediately, then on every change). */
    fun seenIds(): Flow<Set<String>>

    /** Record [id] as seen (idempotent). A subsequent [seenIds] contains it. */
    suspend fun markSeen(id: String)

    /** Clear every recorded id so all tours/intros show again. */
    suspend fun resetAll()
}

@Singleton
class DataStoreOnboardingStore @Inject constructor(
    @ApplicationContext context: Context,
) : OnboardingStore {

    private val dataStore = context.onboardingDataStore

    override fun seenIds(): Flow<Set<String>> = dataStore.data
        .catch { e -> if (e is IOException) emit(emptyPreferences()) else throw e }
        .map { prefs -> prefs[Keys.SEEN].orEmpty() }

    override suspend fun markSeen(id: String) {
        runCatching {
            dataStore.edit { prefs ->
                prefs[Keys.SEEN] = OnboardingModel.markSeen(id, prefs[Keys.SEEN].orEmpty())
            }
        }
    }

    override suspend fun resetAll() {
        runCatching { dataStore.edit { it.remove(Keys.SEEN) } }
    }

    private object Keys {
        val SEEN = stringSetPreferencesKey("onboarding_seen_ids")
    }
}
