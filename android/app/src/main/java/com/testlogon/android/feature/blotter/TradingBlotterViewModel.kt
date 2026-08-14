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

/**
 * One display row of the Orders/Fills list. Grouping turns a flat list into a mix of collapsible
 * [Group] headers and [Item] rows so the LazyColumn can render both without branching on nulls.
 */
sealed interface BlotterRow {
    /** A collapsible group header: the group [value], its child [count], and whether it is expanded. */
    data class Group(val value: String, val count: Int, val expanded: Boolean) : BlotterRow

    /** A single order row belonging to the (optionally collapsed) group above it. */
    data class Item(val order: BlotterOrder) : BlotterRow
}

/**
 * Immutable UI state for the Trading Blotter. [orders] is the source of truth (kept sorted so the
 * ticker mutates a stable, ordered list). Fills + positions are derived from it; the filtered,
 * grouped, display-ready rows are computed lazily below so composables stay simple and the ticker's
 * updates always flow through.
 */
data class BlotterUiState(
    val tab: BlotterTab = BlotterTab.ORDERS,
    val orders: List<BlotterOrder> = emptyList(),
    val sortColumn: BlotterSortColumn = BlotterSortColumn.SYM,
    val sortDir: BlotterSortDir = BlotterSortDir.ASC,
    val hiddenColumns: Set<BlotterColumn> = defaultHiddenColumns(),
    val columnOrder: List<BlotterColumn> = BlotterColumn.entries.toList(),
    val columnWidths: Map<BlotterColumn, Float> = emptyMap(),
    val filters: BlotterFilters = BlotterFilters(),
    val groupBy: BlotterGroupKey? = null,
    val collapsedGroups: Set<String> = emptySet(),
    val expandedRows: Set<String> = emptySet(),
) {
    /**
     * The Row weight to lay a column out with: the user's persisted per-column width override when
     * present, otherwise the column descriptor's default [BlotterColumn.weight]. Header AND cells
     * both route through this so they stay pixel-aligned when a column is resized.
     */
    fun effectiveWeight(col: BlotterColumn): Float = columnWidths[col] ?: col.weight
    /** Orders that have at least one execution (the Fills tab). */
    val fills: List<BlotterOrder> get() = orders.filter { it.cumQty > 0.0 }

    /** The Orders/Fills columns currently shown (descriptor order, minus hidden). */
    val visibleColumns: List<BlotterColumn>
        get() = columnOrder.filter { it !in hiddenColumns }

    /** Filtered + grouped display rows for the Orders tab. */
    val ordersRows: List<BlotterRow> get() = buildRows(applyFilters(orders))

    /** Filtered + grouped display rows for the Fills tab. */
    val fillsRows: List<BlotterRow> get() = buildRows(applyFilters(fills))

    /** Distinct symbols present in the seed (drives the filter chip list). */
    val allSymbols: List<String> get() = orders.map { it.sym }.distinct().sorted()

    private fun applyFilters(src: List<BlotterOrder>): List<BlotterOrder> {
        val f = filters
        if (!f.isActive) return src
        val needle = f.search.trim().lowercase()
        return src.filter { o ->
            (needle.isEmpty() ||
                o.sym.lowercase().contains(needle) ||
                o.side.code.lowercase().contains(needle) ||
                o.status.label.lowercase().contains(needle) ||
                o.clord.lowercase().contains(needle)) &&
                (f.symbols.isEmpty() || o.sym in f.symbols) &&
                (f.sides.isEmpty() || o.side in f.sides) &&
                (f.statuses.isEmpty() || o.status in f.statuses) &&
                (f.tifs.isEmpty() || o.tif in f.tifs) &&
                (f.pxMin == null || o.px >= f.pxMin) &&
                (f.pxMax == null || o.px <= f.pxMax) &&
                (f.qtyMin == null || o.qty >= f.qtyMin) &&
                (f.qtyMax == null || o.qty <= f.qtyMax)
        }
    }

    private fun groupValue(o: BlotterOrder, key: BlotterGroupKey): String = when (key) {
        BlotterGroupKey.SYMBOL -> o.sym
        BlotterGroupKey.SIDE -> o.side.code
        BlotterGroupKey.STATUS -> o.status.label
    }

    /** Flatten a filtered order list into display rows, applying grouping/collapse if active. */
    private fun buildRows(rows: List<BlotterOrder>): List<BlotterRow> {
        val key = groupBy ?: return rows.map { BlotterRow.Item(it) }
        // Preserve current sort order of the first-seen group value.
        val grouped = LinkedHashMap<String, MutableList<BlotterOrder>>()
        for (o in rows) grouped.getOrPut(groupValue(o, key)) { mutableListOf() }.add(o)
        val out = ArrayList<BlotterRow>(rows.size + grouped.size)
        for ((value, children) in grouped) {
            val expanded = value !in collapsedGroups
            out += BlotterRow.Group(value = value, count = children.size, expanded = expanded)
            if (expanded) children.forEach { out += BlotterRow.Item(it) }
        }
        return out
    }

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

    companion object {
        /** Columns hidden by default (the wider/secondary ones) — the visible subset matches legacy. */
        fun defaultHiddenColumns(): Set<BlotterColumn> =
            BlotterColumn.entries.filter { !it.defaultVisible }.toSet()
    }
}

/**
 * Trading Blotter presentation.
 *
 * Seeds ~400 sample orders across BTC-USD / ETH-USD / SOL-USD / PMKT-2028 with realistic reference
 * prices, partial fills and mixed statuses, then runs a 1-second ticker that drifts a few prices and
 * occasionally advances a working order (so the surface feels live). No backend — this mirrors the
 * web trading blotter for parity and is deterministic-ish sample data.
 *
 * Layout facets (sort, grouping, hidden columns, filters/search) are restored from
 * [BlotterLayoutStore] on init and persisted whenever any of them changes.
 */
@HiltViewModel
class TradingBlotterViewModel @Inject constructor(
    private val layoutStore: BlotterLayoutStore,
) : ViewModel() {

    private val rng = Random(0xB107)

    private val _uiState = MutableStateFlow(BlotterUiState(orders = seedOrders()))
    val uiState: StateFlow<BlotterUiState> = _uiState.asStateFlow()

    init {
        restoreLayout()
        startTicker()
    }

    /** Merge the persisted layout over defaults and re-sort the seed to match. Never throws. */
    private fun restoreLayout() {
        val saved = layoutStore.load()
        _uiState.update { s ->
            s.copy(
                sortColumn = saved.sortColumn,
                sortDir = saved.sortDir,
                groupBy = saved.groupBy,
                hiddenColumns = saved.hiddenColumns,
                columnOrder = normalizeColumnOrder(saved.columnOrder),
                columnWidths = saved.columnWidths,
                filters = saved.filters,
                orders = sortOrders(s.orders, saved.sortColumn, saved.sortDir),
            )
        }
    }

    private fun persist(s: BlotterUiState) {
        layoutStore.save(
            BlotterLayout(
                sortColumn = s.sortColumn,
                sortDir = s.sortDir,
                groupBy = s.groupBy,
                hiddenColumns = s.hiddenColumns,
                columnOrder = s.columnOrder,
                columnWidths = s.columnWidths,
                filters = s.filters,
            ),
        )
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
        persist(_uiState.value)
    }

    // ---- Column chooser ----------------------------------------------------

    fun onToggleColumn(column: BlotterColumn) {
        _uiState.update { s ->
            val hidden = s.hiddenColumns.toMutableSet()
            if (column in hidden) hidden.remove(column) else hidden.add(column)
            // Never allow every column to be hidden — keep at least the symbol column.
            if (hidden.size >= BlotterColumn.entries.size) hidden.remove(BlotterColumn.SYM)
            s.copy(hiddenColumns = hidden)
        }
        persist(_uiState.value)
    }

    /**
     * Reorder the FULL column list by moving the column at [from] to index [to]. The move operates
     * over the complete columnOrder (not just the visible subset) so hidden columns keep a stable
     * relative position, then normalizes to guarantee completeness and persists.
     */
    fun onReorderColumn(from: Int, to: Int) {
        _uiState.update { s ->
            val order = s.columnOrder.toMutableList()
            if (from !in order.indices || to !in order.indices || from == to) return@update s
            val moved = order.removeAt(from)
            order.add(to, moved)
            s.copy(columnOrder = normalizeColumnOrder(order))
        }
        persist(_uiState.value)
    }

    // ---- Column resize -----------------------------------------------------

    /** Sane clamp for a per-column weight override so a column can never collapse or dominate. */
    private val minColWeight = 0.4f
    private val maxColWeight = 5.0f

    /**
     * Resize [col] by [deltaWeight] (added to its current effective weight), clamped to a sane
     * range, then persist. The override starts from the column's current effective weight so the
     * first drag continues smoothly from whatever the column is showing (default or prior override).
     */
    fun onResizeColumn(col: BlotterColumn, deltaWeight: Float) {
        _uiState.update { s ->
            val current = s.columnWidths[col] ?: col.weight
            val next = (current + deltaWeight).coerceIn(minColWeight, maxColWeight)
            s.copy(columnWidths = s.columnWidths + (col to next))
        }
        persist(_uiState.value)
    }

    /** Clear all per-column width overrides (columns snap back to their descriptor weights). */
    fun onResetColumnWidths() {
        _uiState.update { it.copy(columnWidths = emptyMap()) }
        persist(_uiState.value)
    }

    // ---- Filters + search --------------------------------------------------

    fun onSearchChanged(query: String) {
        _uiState.update { it.copy(filters = it.filters.copy(search = query)) }
        persist(_uiState.value)
    }

    fun onSetFilters(filters: BlotterFilters) {
        _uiState.update { it.copy(filters = filters) }
        persist(_uiState.value)
    }

    fun onClearFilters() {
        _uiState.update { it.copy(filters = BlotterFilters()) }
        persist(_uiState.value)
    }

    // ---- Grouping ----------------------------------------------------------

    fun onSetGroupBy(key: BlotterGroupKey?) {
        _uiState.update { it.copy(groupBy = key, collapsedGroups = emptySet()) }
        persist(_uiState.value)
    }

    fun onToggleGroupCollapsed(value: String) {
        _uiState.update { s ->
            val c = s.collapsedGroups.toMutableSet()
            if (value in c) c.remove(value) else c.add(value)
            s.copy(collapsedGroups = c)
        }
        // Collapse state is transient view detail; intentionally not persisted.
    }

    // ---- Row master-detail -------------------------------------------------

    /** Toggle the inline detail panel for a row (keyed by clord). */
    fun onToggleRowExpanded(clord: String) {
        _uiState.update { s ->
            val e = s.expandedRows.toMutableSet()
            if (clord in e) e.remove(clord) else e.add(clord)
            s.copy(expandedRows = e)
        }
        // Row-expand state is transient view detail; intentionally not persisted.
    }

    // ---- Order actions -----------------------------------------------------

    /**
     * Cancel a working (LIVE/PARTIAL) order in place: mutate the stored source-of-truth order to
     * status=CANCELLED, leaves=0.0 (mock; no backend). FILLED / already-CANCELLED rows are ignored.
     * The row is NOT re-sorted (so it does not jump) and layout is NOT persisted (cancellation is
     * order data, not layout). Derived fills/positions recompute automatically; the 1s ticker never
     * resurrects it (it only advances working rows, and advanceFill early-returns on terminal state).
     */
    fun onCancelOrder(clord: String) {
        _uiState.update { s ->
            s.copy(
                orders = s.orders.map { o ->
                    if (o.clord == clord && o.status.isWorking()) {
                        o.copy(status = BlotterStatus.CANCELLED, leaves = 0.0)
                    } else {
                        o
                    }
                },
            )
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
            BlotterSortColumn.LEAVES -> compareBy { it.leaves }
            BlotterSortColumn.AVG_PX -> compareBy { it.avgPx }
            BlotterSortColumn.TIF -> compareBy { it.tif.ordinal }
            BlotterSortColumn.STATUS -> compareBy { it.status.ordinal }
            BlotterSortColumn.CLORD -> compareBy { it.clord }
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
                        val working = o.status.isWorking()
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
        // Never advance a terminal row (CANCELLED/FILLED): keep leaves as-is and status unchanged.
        if (!o.status.isWorking()) return o
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


/** Whether an order is still working (open) and therefore cancelable / tickable. */
private fun BlotterStatus.isWorking(): Boolean =
    this == BlotterStatus.LIVE || this == BlotterStatus.PARTIAL
