package com.testlogon.android.feature.blotter

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import javax.inject.Inject
import kotlin.math.abs
import kotlin.random.Random

/** Immutable UI state for the Trading Blotter. Fills + positions are derived from [orders]. */
data class BlotterUiState(
    val tab: BlotterTab = BlotterTab.ORDERS,
    val orders: List<BlotterOrder> = emptyList(),
    val sortColumn: BlotterSortColumn = BlotterSortColumn.SYM,
    val sortDir: BlotterSortDir = BlotterSortDir.ASC,
) {
    /** Orders that have at least one execution (the Fills tab). */
    val fills: List<BlotterOrder> get() = orders.filter { it.cumQty > 0.0 }

    /** Per-symbol aggregated net positions (the Positions tab). */
    val positions: List<BlotterPosition>
        get() {
            val marks = orders.associate { it.sym to it.px } // reference mark per symbol (last wins)
            return orders
                .filter { it.cumQty > 0.0 }
                .groupBy { it.sym }
                .map { (sym, rows) ->
                    var net = 0.0
                    var costNotional = 0.0
                    for (o in rows) {
                        val signed = if (o.side == BlotterSide.BUY) o.cumQty else -o.cumQty
                        net += signed
                        costNotional += signed * o.avgPx
                    }
                    val avgCost = if (abs(net) > 1e-9) abs(costNotional / net) else 0.0
                    val mark = marks[sym] ?: avgCost
                    val uPnl = (mark - avgCost) * net
                    BlotterPosition(sym = sym, net = net, avgCost = avgCost, mark = mark, uPnl = uPnl)
                }
                .sortedBy { it.sym }
        }
}

/**
 * Trading Blotter presentation.
 *
 * Seeds ~400 sample orders across BTC-USD / ETH-USD / SOL-USD / PMKT-2028 with realistic reference
 * prices, partial fills and mixed statuses, then runs a 1-second ticker that drifts a few prices and
 * occasionally advances a working order (so the surface feels live). No backend — this mirrors the
 * web trading blotter for parity and is deterministic-ish sample data.
 */
@HiltViewModel
class TradingBlotterViewModel @Inject constructor() : ViewModel() {

    private val rng = Random(0xB107)

    private val _uiState = MutableStateFlow(BlotterUiState(orders = seedOrders()))
    val uiState: StateFlow<BlotterUiState> = _uiState.asStateFlow()

    init {
        applySort(BlotterSortColumn.SYM, toggle = false)
        startTicker()
    }

    fun onTabSelected(tab: BlotterTab) {
        _uiState.update { it.copy(tab = tab) }
    }

    /** Tap a header column: re-sort ascending, or toggle direction if already the active column. */
    fun onSortColumn(column: BlotterSortColumn) = applySort(column, toggle = true)

    private fun applySort(column: BlotterSortColumn, toggle: Boolean) {
        _uiState.update { s ->
            val dir = when {
                !toggle -> BlotterSortDir.ASC
                s.sortColumn != column -> BlotterSortDir.ASC
                s.sortDir == BlotterSortDir.ASC -> BlotterSortDir.DESC
                else -> BlotterSortDir.ASC
            }
            s.copy(sortColumn = column, sortDir = dir, orders = sortOrders(s.orders, column, dir))
        }
    }

    private fun sortOrders(
        orders: List<BlotterOrder>,
        column: BlotterSortColumn,
        dir: BlotterSortDir,
    ): List<BlotterOrder> {
        val cmp: Comparator<BlotterOrder> = when (column) {
            BlotterSortColumn.SYM -> compareBy { it.sym }
            BlotterSortColumn.SIDE -> compareBy { it.side.code }
            BlotterSortColumn.PX -> compareBy { it.px }
            BlotterSortColumn.QTY -> compareBy { it.qty }
            BlotterSortColumn.CUM -> compareBy { it.cumQty }
            BlotterSortColumn.AVG_PX -> compareBy { it.avgPx }
            BlotterSortColumn.STATUS -> compareBy { it.status.ordinal }
        }
        val tie = cmp.thenBy { it.clord }
        return if (dir == BlotterSortDir.ASC) orders.sortedWith(tie) else orders.sortedWith(tie).reversed()
    }

    private fun startTicker() {
        viewModelScope.launch {
            while (true) {
                delay(1_000L)
                _uiState.update { s ->
                    if (s.orders.isEmpty()) return@update s
                    val mutated = s.orders.toMutableList()
                    // Drift a handful of rows + occasionally advance a working order.
                    repeat(6) {
                        val idx = rng.nextInt(mutated.size)
                        val o = mutated[idx]
                        val driftPct = (rng.nextDouble() - 0.5) * 0.004 // +/- 0.2%
                        val newPx = roundPx(o.px * (1.0 + driftPct), o.sym)
                        var updated = o.copy(px = newPx)
                        val working = o.status == BlotterStatus.LIVE || o.status == BlotterStatus.PARTIAL
                        if (working && rng.nextInt(100) < 25) {
                            updated = advanceFill(updated, newPx)
                        }
                        mutated[idx] = updated
                    }
                    s.copy(orders = sortOrders(mutated, s.sortColumn, s.sortDir))
                }
            }
        }
    }

    /** Advance a working order by a random partial (may complete it). */
    private fun advanceFill(o: BlotterOrder, mark: Double): BlotterOrder {
        val remaining = o.qty - o.cumQty
        if (remaining <= 0.0) return o
        val step = minOf(remaining, remaining * rng.nextDouble(0.2, 1.0))
        val newCum = (o.cumQty + step).coerceAtMost(o.qty)
        val fillPx = mark
        val newAvg = if (newCum > 0.0) (o.avgPx * o.cumQty + fillPx * (newCum - o.cumQty)) / newCum else 0.0
        val leaves = o.qty - newCum
        val status = if (leaves <= 1e-9) BlotterStatus.FILLED else BlotterStatus.PARTIAL
        return o.copy(cumQty = newCum, avgPx = roundPx(newAvg, o.sym), leaves = leaves, status = status)
    }

    private fun seedOrders(): List<BlotterOrder> {
        val out = ArrayList<BlotterOrder>(SEED_COUNT)
        for (i in 0 until SEED_COUNT) {
            val ref = REF_SYMBOLS[rng.nextInt(REF_SYMBOLS.size)]
            val sym = ref.first
            val refPx = ref.second
            val side = if (rng.nextBoolean()) BlotterSide.BUY else BlotterSide.SELL
            val px = roundPx(refPx * (1.0 + (rng.nextDouble() - 0.5) * 0.02), sym)
            val qty = roundQty(sym)
            // Choose a status distribution, then a consistent cumQty for it.
            val roll = rng.nextInt(100)
            val status = when {
                roll < 30 -> BlotterStatus.LIVE
                roll < 55 -> BlotterStatus.PARTIAL
                roll < 85 -> BlotterStatus.FILLED
                else -> BlotterStatus.CANCELLED
            }
            val cumQty = when (status) {
                BlotterStatus.LIVE -> 0.0
                BlotterStatus.PARTIAL -> roundQ(qty * rng.nextDouble(0.1, 0.9), sym)
                BlotterStatus.FILLED -> qty
                BlotterStatus.CANCELLED -> roundQ(qty * rng.nextDouble(0.0, 0.5), sym)
            }
            val avgPx = if (cumQty > 0.0) roundPx(px * (1.0 + (rng.nextDouble() - 0.5) * 0.001), sym) else 0.0
            val leaves = if (status == BlotterStatus.CANCELLED) 0.0 else (qty - cumQty)
            val tif = BlotterTif.entries[rng.nextInt(BlotterTif.entries.size)]
            out += BlotterOrder(
                clord = "C%05d".format(100000 + i),
                sym = sym,
                side = side,
                px = px,
                qty = qty,
                cumQty = cumQty,
                leaves = leaves,
                avgPx = avgPx,
                status = status,
                tif = tif,
            )
        }
        return out
    }

    private fun roundQty(sym: String): Double {
        return when (sym) {
            "PMKT-2028" -> rng.nextInt(50, 5000).toDouble()
            "SOL-USD" -> roundQ(rng.nextDouble(1.0, 400.0), sym)
            else -> roundQ(rng.nextDouble(0.05, 8.0), sym)
        }
    }

    private fun roundQ(q: Double, sym: String): Double =
        if (sym == "PMKT-2028") kotlin.math.round(q) else kotlin.math.round(q * 1000) / 1000.0

    private fun roundPx(px: Double, sym: String): Double =
        if (sym == "PMKT-2028") kotlin.math.round(px * 10000) / 10000.0
        else kotlin.math.round(px * 100) / 100.0

    private companion object {
        const val SEED_COUNT = 400
        val REF_SYMBOLS = listOf(
            "BTC-USD" to 64000.0,
            "ETH-USD" to 3400.0,
            "SOL-USD" to 145.0,
            "PMKT-2028" to 0.62,
        )
    }
}
