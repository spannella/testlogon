package com.testlogon.android.data.exchange.alerts

import android.content.Context
import androidx.datastore.preferences.core.edit
import androidx.datastore.preferences.core.emptyPreferences
import androidx.datastore.preferences.core.stringPreferencesKey
import androidx.datastore.preferences.preferencesDataStore
import com.squareup.moshi.JsonClass
import com.squareup.moshi.Moshi
import com.squareup.moshi.Types
import com.squareup.moshi.adapter
import dagger.hilt.android.qualifiers.ApplicationContext
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.catch
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.map
import java.io.IOException
import javax.inject.Inject
import javax.inject.Singleton

private val Context.priceAlertsDataStore by preferencesDataStore(name = "price_alerts")

/**
 * Durable CRUD store for user-authored [PriceAlert]s (persisted as Moshi JSON in DataStore, mirroring
 * the derived-trading-alerts store). Interface seam so the evaluator/VM can inject an in-memory fake on
 * the JVM. Every read/write is failure-safe (a store error degrades to "no data" / no-op, never throws).
 */
interface PriceAlertsStore {
    /** The persisted alerts as a reactive stream (newest-created first). */
    fun alerts(): Flow<List<PriceAlert>>

    /** A one-shot snapshot for the evaluator hot path (no Flow collection). */
    suspend fun snapshot(): List<PriceAlert>

    /** Insert or replace an alert by [PriceAlert.id]. */
    suspend fun upsert(alert: PriceAlert)

    /** Replace the whole set (used by the evaluator to persist post-fire updates in one write). */
    suspend fun replaceAll(alerts: List<PriceAlert>)

    suspend fun delete(id: String)

    /** Re-arm a triggered alert: armed = true, triggeredTs = null (no-op if the id is unknown). */
    suspend fun rearm(id: String)
}

@Singleton
class DataStorePriceAlertsStore @Inject constructor(
    @ApplicationContext context: Context,
    moshi: Moshi,
) : PriceAlertsStore {

    private val dataStore = context.priceAlertsDataStore

    @OptIn(ExperimentalStdlibApi::class)
    private val listAdapter =
        moshi.adapter<List<PriceAlertJson>>(
            Types.newParameterizedType(List::class.java, PriceAlertJson::class.java),
        )

    override fun alerts(): Flow<List<PriceAlert>> = dataStore.data
        .catch { e -> if (e is IOException) emit(emptyPreferences()) else throw e }
        .map { prefs -> decode(prefs[Keys.ALERTS]) }

    override suspend fun snapshot(): List<PriceAlert> = runCatching {
        val prefs = dataStore.data
            .catch { e -> if (e is IOException) emit(emptyPreferences()) else throw e }
            .first()
        decode(prefs[Keys.ALERTS])
    }.getOrDefault(emptyList())

    override suspend fun upsert(alert: PriceAlert) {
        runCatching {
            dataStore.edit { prefs ->
                val existing = decode(prefs[Keys.ALERTS]).filterNot { it.id == alert.id }
                // Newest-created first.
                prefs[Keys.ALERTS] = encode((listOf(alert) + existing).take(MAX_RETAINED))
            }
        }
    }

    override suspend fun replaceAll(alerts: List<PriceAlert>) {
        runCatching { dataStore.edit { it[Keys.ALERTS] = encode(alerts.take(MAX_RETAINED)) } }
    }

    override suspend fun delete(id: String) {
        runCatching {
            dataStore.edit { prefs ->
                prefs[Keys.ALERTS] = encode(decode(prefs[Keys.ALERTS]).filterNot { it.id == id })
            }
        }
    }

    override suspend fun rearm(id: String) {
        runCatching {
            dataStore.edit { prefs ->
                val updated = decode(prefs[Keys.ALERTS]).map {
                    if (it.id == id) it.copy(armed = true, triggeredTs = null) else it
                }
                prefs[Keys.ALERTS] = encode(updated)
            }
        }
    }

    private fun decode(json: String?): List<PriceAlert> = runCatching {
        json?.let { listAdapter.fromJson(it) }?.map { it.toDomain() }
    }.getOrNull().orEmpty()

    private fun encode(alerts: List<PriceAlert>): String =
        listAdapter.toJson(alerts.map { it.toJson() })

    private object Keys {
        val ALERTS = stringPreferencesKey("price_alerts_json")
    }

    private companion object {
        const val MAX_RETAINED = 200
    }
}

// ---- JSON wire model (KSP codegen adapter; unit-test-safe with a plain Moshi.Builder) ----

@JsonClass(generateAdapter = true)
internal data class PriceAlertJson(
    val id: String,
    val symbolId: Int,
    val direction: String,
    val priceTicks: Long,
    val note: String? = null,
    val createdTs: Long = 0L,
    val triggeredTs: Long? = null,
    val armed: Boolean = true,
)

internal fun PriceAlertJson.toDomain() = PriceAlert(
    id = id,
    symbolId = symbolId,
    direction = runCatching { PriceAlertDirection.valueOf(direction) }
        .getOrDefault(PriceAlertDirection.ABOVE),
    priceTicks = priceTicks,
    note = note,
    createdTs = createdTs,
    triggeredTs = triggeredTs,
    armed = armed,
)

internal fun PriceAlert.toJson() = PriceAlertJson(
    id = id,
    symbolId = symbolId,
    direction = direction.name,
    priceTicks = priceTicks,
    note = note,
    createdTs = createdTs,
    triggeredTs = triggeredTs,
    armed = armed,
)
