package com.testlogon.android.feature.paper

import android.content.Context
import androidx.datastore.preferences.core.edit
import androidx.datastore.preferences.core.emptyPreferences
import androidx.datastore.preferences.core.stringPreferencesKey
import androidx.datastore.preferences.preferencesDataStore
import com.squareup.moshi.JsonClass
import com.squareup.moshi.Moshi
import com.squareup.moshi.adapter
import com.testlogon.android.data.exchange.OrderSide
import com.testlogon.android.feature.paper.PaperEngine.PaperAccount
import com.testlogon.android.feature.paper.PaperEngine.PaperFill
import com.testlogon.android.feature.paper.PaperEngine.PaperOrder
import com.testlogon.android.feature.paper.PaperEngine.PaperOrderStatus
import com.testlogon.android.feature.paper.PaperEngine.PaperOrderType
import com.testlogon.android.feature.paper.PaperEngine.PaperPosition
import dagger.hilt.android.qualifiers.ApplicationContext
import kotlinx.coroutines.flow.catch
import kotlinx.coroutines.flow.first
import java.io.IOException
import javax.inject.Inject
import javax.inject.Singleton

private val Context.paperTradingDataStore by preferencesDataStore(name = "paper_trading")

/**
 * Durable snapshot store for the client-side paper-trading [PaperAccount] (persisted as one Moshi JSON
 * blob in DataStore). The account is a self-contained value graph, so the whole thing is serialized/
 * deserialized on every save/load — cheap for a single account. Interface seam so the VM can inject an
 * in-memory fake on the JVM. Every read/write is failure-safe (a store error degrades to "no data" /
 * no-op, never throws).
 */
interface PaperAccountStore {
    /** Load the persisted account, or null when nothing has been saved yet. */
    suspend fun load(): PaperAccount?

    /** Persist the whole account snapshot (overwrites the prior save). */
    suspend fun save(account: PaperAccount)

    /** Drop the persisted account entirely (a subsequent [load] returns null). */
    suspend fun clear()
}

@Singleton
class DataStorePaperAccountStore @Inject constructor(
    @ApplicationContext context: Context,
    moshi: Moshi,
) : PaperAccountStore {

    private val dataStore = context.paperTradingDataStore

    @OptIn(ExperimentalStdlibApi::class)
    private val adapter = moshi.adapter<PaperAccountJson>()

    override suspend fun load(): PaperAccount? = runCatching {
        val prefs = dataStore.data
            .catch { e -> if (e is IOException) emit(emptyPreferences()) else throw e }
            .first()
        prefs[Keys.ACCOUNT]?.let { adapter.fromJson(it) }?.toDomain()
    }.getOrNull()

    override suspend fun save(account: PaperAccount) {
        runCatching { dataStore.edit { it[Keys.ACCOUNT] = adapter.toJson(account.toJson()) } }
    }

    override suspend fun clear() {
        runCatching { dataStore.edit { it.remove(Keys.ACCOUNT) } }
    }

    private object Keys {
        val ACCOUNT = stringPreferencesKey("paper_account_json")
    }
}

// ---- JSON wire model (KSP codegen adapters; unit-test-safe with a plain Moshi.Builder) ----

@JsonClass(generateAdapter = true)
internal data class PaperAccountJson(
    val cash: Long,
    val positions: List<PaperPositionJson> = emptyList(),
    val orders: List<PaperOrderJson> = emptyList(),
    val fills: List<PaperFillJson> = emptyList(),
    val realizedPnl: Long = 0L,
    val startingCash: Long,
)

@JsonClass(generateAdapter = true)
internal data class PaperPositionJson(
    val symbolId: Int,
    val qty: Long,
    val avgEntry: Long,
)

@JsonClass(generateAdapter = true)
internal data class PaperOrderJson(
    val id: String,
    val symbolId: Int,
    val side: String,
    val type: String,
    val qty: Long,
    val limitPrice: Long? = null,
    val status: String,
    val createdTsMs: Long = 0L,
)

@JsonClass(generateAdapter = true)
internal data class PaperFillJson(
    val orderId: String,
    val symbolId: Int,
    val side: String,
    val price: Long,
    val qty: Long,
    val tsMs: Long = 0L,
)

private fun sideOf(s: String): OrderSide =
    runCatching { OrderSide.valueOf(s) }.getOrDefault(OrderSide.BUY)

internal fun PaperAccountJson.toDomain() = PaperAccount(
    cash = cash,
    positions = positions.associate { it.symbolId to PaperPosition(it.qty, it.avgEntry) },
    orders = orders.map { o ->
        PaperOrder(
            id = o.id,
            symbolId = o.symbolId,
            side = sideOf(o.side),
            type = runCatching { PaperOrderType.valueOf(o.type) }.getOrDefault(PaperOrderType.MARKET),
            qty = o.qty,
            limitPrice = o.limitPrice,
            status = runCatching { PaperOrderStatus.valueOf(o.status) }
                .getOrDefault(PaperOrderStatus.WORKING),
            createdTsMs = o.createdTsMs,
        )
    },
    fills = fills.map { f ->
        PaperFill(
            orderId = f.orderId,
            symbolId = f.symbolId,
            side = sideOf(f.side),
            price = f.price,
            qty = f.qty,
            tsMs = f.tsMs,
        )
    },
    realizedPnl = realizedPnl,
    startingCash = startingCash,
)

internal fun PaperAccount.toJson() = PaperAccountJson(
    cash = cash,
    positions = positions.map { (symbolId, p) -> PaperPositionJson(symbolId, p.qty, p.avgEntry) },
    orders = orders.map { o ->
        PaperOrderJson(
            id = o.id,
            symbolId = o.symbolId,
            side = o.side.name,
            type = o.type.name,
            qty = o.qty,
            limitPrice = o.limitPrice,
            status = o.status.name,
            createdTsMs = o.createdTsMs,
        )
    },
    fills = fills.map { f ->
        PaperFillJson(
            orderId = f.orderId,
            symbolId = f.symbolId,
            side = f.side.name,
            price = f.price,
            qty = f.qty,
            tsMs = f.tsMs,
        )
    },
    realizedPnl = realizedPnl,
    startingCash = startingCash,
)
