package com.testlogon.android.feature.markets.trade

import android.content.Context
import androidx.datastore.preferences.core.edit
import androidx.datastore.preferences.core.emptyPreferences
import androidx.datastore.preferences.core.stringPreferencesKey
import androidx.datastore.preferences.preferencesDataStore
import com.squareup.moshi.JsonClass
import com.squareup.moshi.Moshi
import com.squareup.moshi.adapter
import com.testlogon.android.data.exchange.OrderSide
import dagger.hilt.android.qualifiers.ApplicationContext
import kotlinx.coroutines.flow.catch
import kotlinx.coroutines.flow.first
import java.io.IOException
import javax.inject.Inject
import javax.inject.Singleton

private val Context.algoOrdersDataStore by preferencesDataStore(name = "algo_orders")

/**
 * Durable snapshot store for the client-side algo orders ([AlgoOrder]) — persisted as one Moshi JSON blob
 * (a list) in DataStore, mirroring [com.testlogon.android.feature.paper.PaperAccountStore]. The whole list
 * is serialized on every save (cheap for the handful of algos a user runs). Interface seam so the manager
 * can inject an in-memory fake on the JVM. Every read/write is failure-safe (a store error degrades to
 * "no data" / no-op, never throws).
 */
interface AlgoOrderStore {
    suspend fun load(): List<AlgoOrder>
    suspend fun save(algos: List<AlgoOrder>)
    suspend fun clear()
}

@Singleton
class DataStoreAlgoOrderStore @Inject constructor(
    @ApplicationContext context: Context,
    moshi: Moshi,
) : AlgoOrderStore {

    private val dataStore = context.algoOrdersDataStore

    @OptIn(ExperimentalStdlibApi::class)
    private val adapter = moshi.adapter<AlgoOrdersJson>()

    override suspend fun load(): List<AlgoOrder> = runCatching {
        val prefs = dataStore.data
            .catch { e -> if (e is IOException) emit(emptyPreferences()) else throw e }
            .first()
        prefs[Keys.ALGOS]?.let { adapter.fromJson(it) }?.algos?.map { it.toDomain() }.orEmpty()
    }.getOrDefault(emptyList())

    override suspend fun save(algos: List<AlgoOrder>) {
        runCatching {
            dataStore.edit { it[Keys.ALGOS] = adapter.toJson(AlgoOrdersJson(algos.map { a -> a.toJson() })) }
        }
    }

    override suspend fun clear() {
        runCatching { dataStore.edit { it.remove(Keys.ALGOS) } }
    }

    private object Keys {
        val ALGOS = stringPreferencesKey("algo_orders_json")
    }
}

// ---- JSON wire model (KSP codegen adapters; unit-test-safe with a plain Moshi.Builder) ----

@JsonClass(generateAdapter = true)
internal data class AlgoOrdersJson(val algos: List<AlgoOrderJson> = emptyList())

@JsonClass(generateAdapter = true)
internal data class AlgoOrderJson(
    val id: String,
    val kind: String,
    val symbolId: Int,
    val symbolLabel: String,
    val side: String,
    val totalQty: Long,
    val limitPrice: Long? = null,
    val paperMode: Boolean = false,
    val slices: Int = 0,
    val durationMs: Long = 0L,
    val sliceIntervalMs: Long = 0L,
    val visibleQty: Long = 0L,
    val childrenDone: Int = 0,
    val childrenTotal: Int = 0,
    val placedQty: Long = 0L,
    val status: String = "RUNNING",
    val createdTsMs: Long = 0L,
    val nextFireAtMs: Long? = null,
    val message: String? = null,
)

private fun sideOf(s: String): OrderSide =
    runCatching { OrderSide.valueOf(s) }.getOrDefault(OrderSide.BUY)

internal fun AlgoOrderJson.toDomain() = AlgoOrder(
    id = id,
    kind = runCatching { AlgoKind.valueOf(kind) }.getOrDefault(AlgoKind.TWAP),
    symbolId = symbolId,
    symbolLabel = symbolLabel,
    side = sideOf(side),
    totalQty = totalQty,
    limitPrice = limitPrice,
    paperMode = paperMode,
    slices = slices,
    durationMs = durationMs,
    sliceIntervalMs = sliceIntervalMs,
    visibleQty = visibleQty,
    childrenDone = childrenDone,
    childrenTotal = childrenTotal,
    placedQty = placedQty,
    status = runCatching { AlgoStatus.valueOf(status) }.getOrDefault(AlgoStatus.RUNNING),
    createdTsMs = createdTsMs,
    nextFireAtMs = nextFireAtMs,
    message = message,
)

internal fun AlgoOrder.toJson() = AlgoOrderJson(
    id = id,
    kind = kind.name,
    symbolId = symbolId,
    symbolLabel = symbolLabel,
    side = side.name,
    totalQty = totalQty,
    limitPrice = limitPrice,
    paperMode = paperMode,
    slices = slices,
    durationMs = durationMs,
    sliceIntervalMs = sliceIntervalMs,
    visibleQty = visibleQty,
    childrenDone = childrenDone,
    childrenTotal = childrenTotal,
    placedQty = placedQty,
    status = status.name,
    createdTsMs = createdTsMs,
    nextFireAtMs = nextFireAtMs,
    message = message,
)
