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

private val Context.tradingAlertsDataStore by preferencesDataStore(name = "trading_alerts")

/**
 * Durable store for the derived trading alerts: the detector's [TradingAlertsMarker] (last-seen
 * high-water marks) plus the rolling list of recent [TradingAlert]s and their read state.
 *
 * Interface seam so the poller/usecase can inject an in-memory fake on the JVM (no DataStore I/O in
 * unit tests). All reads/writes are failure-safe (a store error degrades to "no data" / no-op and
 * never throws). Only scalar event metadata is persisted — no PII, no credentials.
 */
interface TradingAlertsStore {
    /** The persisted last-seen marker (default = un-seeded so the first poll seeds instead of firing). */
    suspend fun marker(): TradingAlertsMarker
    suspend fun setMarker(marker: TradingAlertsMarker)

    /** The rolling recent-alerts list (newest first) as a reactive stream for the UI. */
    fun alerts(): Flow<List<TradingAlert>>
    /** Reactive unread count derived from [alerts]. */
    fun unreadCount(): Flow<Int>

    /** Prepend [newAlerts] (already de-duped by the detector) and cap the retained history. */
    suspend fun addAlerts(newAlerts: List<TradingAlert>)
    suspend fun markAllRead()
    suspend fun markRead(id: String)
    suspend fun clear()
}

@Singleton
class DataStoreTradingAlertsStore @Inject constructor(
    @ApplicationContext context: Context,
    moshi: Moshi,
) : TradingAlertsStore {

    private val dataStore = context.tradingAlertsDataStore

    @OptIn(ExperimentalStdlibApi::class)
    private val markerAdapter = moshi.adapter<MarkerJson>()

    @OptIn(ExperimentalStdlibApi::class)
    private val listAdapter =
        moshi.adapter<List<AlertJson>>(Types.newParameterizedType(List::class.java, AlertJson::class.java))

    private suspend fun read() = dataStore.data
        .catch { e -> if (e is IOException) emit(emptyPreferences()) else throw e }
        .first()

    override suspend fun marker(): TradingAlertsMarker = runCatching {
        read()[Keys.MARKER]?.let { markerAdapter.fromJson(it) }?.toDomain()
    }.getOrNull() ?: TradingAlertsMarker()

    override suspend fun setMarker(marker: TradingAlertsMarker) {
        runCatching { dataStore.edit { it[Keys.MARKER] = markerAdapter.toJson(marker.toJson()) } }
    }

    override fun alerts(): Flow<List<TradingAlert>> = dataStore.data
        .catch { e -> if (e is IOException) emit(emptyPreferences()) else throw e }
        .map { prefs -> decode(prefs[Keys.ALERTS]) }

    override fun unreadCount(): Flow<Int> = alerts().map { list -> list.count { !it.read } }

    override suspend fun addAlerts(newAlerts: List<TradingAlert>) {
        if (newAlerts.isEmpty()) return
        runCatching {
            dataStore.edit { prefs ->
                val existing = decode(prefs[Keys.ALERTS])
                val existingIds = existing.mapTo(HashSet()) { it.id }
                // Newest first; drop any incoming that already exist (double de-dupe on top of the detector).
                val merged = (newAlerts.filter { it.id !in existingIds }.reversed() + existing).take(MAX_RETAINED)
                prefs[Keys.ALERTS] = encode(merged)
            }
        }
    }

    override suspend fun markAllRead() {
        runCatching {
            dataStore.edit { prefs ->
                val updated = decode(prefs[Keys.ALERTS]).map { if (it.read) it else it.copy(read = true) }
                prefs[Keys.ALERTS] = encode(updated)
            }
        }
    }

    override suspend fun markRead(id: String) {
        runCatching {
            dataStore.edit { prefs ->
                val updated = decode(prefs[Keys.ALERTS]).map { if (it.id == id) it.copy(read = true) else it }
                prefs[Keys.ALERTS] = encode(updated)
            }
        }
    }

    override suspend fun clear() {
        runCatching { dataStore.edit { it.remove(Keys.ALERTS) } }
    }

    private fun decode(json: String?): List<TradingAlert> = runCatching {
        json?.let { listAdapter.fromJson(it) }?.map { it.toDomain() }
    }.getOrNull().orEmpty()

    private fun encode(alerts: List<TradingAlert>): String =
        listAdapter.toJson(alerts.map { it.toJson() })

    private object Keys {
        val MARKER = stringPreferencesKey("marker_json")
        val ALERTS = stringPreferencesKey("alerts_json")
    }

    private companion object {
        const val MAX_RETAINED = 100
    }
}

// ---- JSON wire models (kept separate from the domain types so persistence is explicit + stable) ----

@JsonClass(generateAdapter = true)
internal data class MarkerJson(
    val seeded: Boolean = false,
    val lastFillTsNs: Long = 0L,
    val lastLiquidationTsNs: Long = 0L,
    val lastFundingTsNs: Long = 0L,
    val marginDistressLevel: Int = 0,
    val marginLiquidating: Boolean = false,
    val pmResolutionCount: Int = 0,
)

internal fun MarkerJson.toDomain() = TradingAlertsMarker(
    seeded, lastFillTsNs, lastLiquidationTsNs, lastFundingTsNs,
    marginDistressLevel, marginLiquidating, pmResolutionCount,
)

internal fun TradingAlertsMarker.toJson() = MarkerJson(
    seeded, lastFillTsNs, lastLiquidationTsNs, lastFundingTsNs,
    marginDistressLevel, marginLiquidating, pmResolutionCount,
)

@JsonClass(generateAdapter = true)
internal data class AlertJson(
    val id: String,
    val kind: String,
    val title: String,
    val body: String,
    val eventTsNs: Long = 0L,
    val createdAtMs: Long = 0L,
    val read: Boolean = false,
)

internal fun AlertJson.toDomain() = TradingAlert(
    id = id,
    kind = runCatching { TradingAlertKind.valueOf(kind) }.getOrDefault(TradingAlertKind.FILL),
    title = title,
    body = body,
    eventTsNs = eventTsNs,
    createdAtMs = createdAtMs,
    read = read,
)

internal fun TradingAlert.toJson() = AlertJson(
    id = id,
    kind = kind.name,
    title = title,
    body = body,
    eventTsNs = eventTsNs,
    createdAtMs = createdAtMs,
    read = read,
)
