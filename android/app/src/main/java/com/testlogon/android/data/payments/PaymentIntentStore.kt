package com.testlogon.android.data.payments

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

private val Context.paymentIntentDataStore by preferencesDataStore(name = "payment_in_flight_intent")

/**
 * AND-231 — the single in-flight redirect payment, persisted the moment a Custom Tab is launched so a
 * cold-start / process-death return can still correlate. [intentId] is an app-local correlation token
 * (seeded from `checkout_session_id`/`order_id`), [state] an optional opaque CSRF/replay guard.
 */
data class InFlightPayment(
    val intentId: String,
    val provider: String,
    val state: String?,
    val originRoute: String?,
    val createdAtEpochMs: Long,
)

/**
 * AND-231 — store for the in-flight intent + a small consumed-set for exactly-once return handling
 * (FR-8). Single in-flight at a time; launching a new one overwrites the prior and clears its consumed
 * marker. A returned intent older than [TTL_MS] classifies as Stale (§6).
 */
interface PaymentIntentStore {
    suspend fun put(payment: InFlightPayment)
    suspend fun get(): InFlightPayment?
    suspend fun clear()

    /** Marks [intentId] consumed; returns false if it was already consumed (idempotency, FR-8). */
    suspend fun markConsumed(intentId: String): Boolean

    companion object {
        const val TTL_MS = 15 * 60 * 1000L
    }
}

@Singleton
class DataStorePaymentIntentStore @Inject constructor(
    @ApplicationContext context: Context,
) : PaymentIntentStore {

    private val dataStore = context.paymentIntentDataStore

    private object Keys {
        val INTENT_ID = stringPreferencesKey("intent_id")
        val PROVIDER = stringPreferencesKey("provider")
        val STATE = stringPreferencesKey("state")
        val ORIGIN = stringPreferencesKey("origin_route")
        val CREATED_AT = longPreferencesKey("created_at")
        val CONSUMED = stringPreferencesKey("consumed_ids")
    }

    override suspend fun put(payment: InFlightPayment) {
        dataStore.edit {
            it[Keys.INTENT_ID] = payment.intentId
            it[Keys.PROVIDER] = payment.provider
            payment.state?.let { s -> it[Keys.STATE] = s } ?: it.remove(Keys.STATE)
            payment.originRoute?.let { r -> it[Keys.ORIGIN] = r } ?: it.remove(Keys.ORIGIN)
            it[Keys.CREATED_AT] = payment.createdAtEpochMs
            // Launching a new intent clears the prior intent's consumed marker for re-correlation.
            val consumed = it[Keys.CONSUMED].orEmpty().splitIds().filterNot { id -> id == payment.intentId }
            it[Keys.CONSUMED] = consumed.joinIds()
        }
    }

    override suspend fun get(): InFlightPayment? {
        val prefs = readPrefs()
        val intentId = prefs[Keys.INTENT_ID] ?: return null
        return InFlightPayment(
            intentId = intentId,
            provider = prefs[Keys.PROVIDER].orEmpty(),
            state = prefs[Keys.STATE],
            originRoute = prefs[Keys.ORIGIN],
            createdAtEpochMs = prefs[Keys.CREATED_AT] ?: 0L,
        )
    }

    override suspend fun clear() {
        dataStore.edit {
            it.remove(Keys.INTENT_ID)
            it.remove(Keys.PROVIDER)
            it.remove(Keys.STATE)
            it.remove(Keys.ORIGIN)
            it.remove(Keys.CREATED_AT)
        }
    }

    override suspend fun markConsumed(intentId: String): Boolean {
        var firstTime = false
        dataStore.edit {
            val current = it[Keys.CONSUMED].orEmpty().splitIds()
            if (current.contains(intentId)) {
                firstTime = false
            } else {
                firstTime = true
                // Bounded LRU: keep the last MAX_CONSUMED ids.
                val updated = (current + intentId).takeLast(MAX_CONSUMED)
                it[Keys.CONSUMED] = updated.joinIds()
            }
        }
        return firstTime
    }

    private suspend fun readPrefs() = dataStore.data
        .catch { e -> if (e is IOException) emit(emptyPreferences()) else throw e }
        .first()

    private fun String.splitIds(): List<String> = split(',').filter { it.isNotBlank() }
    private fun List<String>.joinIds(): String = joinToString(",")

    companion object {
        private const val MAX_CONSUMED = 20
    }
}
