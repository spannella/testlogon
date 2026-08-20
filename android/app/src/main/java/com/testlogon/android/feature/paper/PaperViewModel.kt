package com.testlogon.android.feature.paper

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.exchange.ExchangeRepository
import com.testlogon.android.data.exchange.Instrument
import com.testlogon.android.data.exchange.OrderSide
import com.testlogon.android.feature.paper.PaperEngine.PaperAccount
import com.testlogon.android.feature.paper.PaperEngine.PaperOrder
import com.testlogon.android.feature.paper.PaperEngine.PaperOrderStatus
import com.testlogon.android.feature.paper.PaperEngine.PaperOrderType
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import javax.inject.Inject

/**
 * Drives the self-contained Paper Trading screen. The pure [PaperEngine.PaperAccount] is the single
 * source of truth; the VM loads/persists it via [PaperAccountStore], loads the instrument catalogue for
 * the symbol picker, and polls the market-data feed for a live mark price. Each poll feeds the mark into
 * [PaperEngine.onTick] so resting LIMIT orders fill as the (simulated) market moves, then re-projects +
 * persists. NOTHING here touches the real order/matching stack — it is a client-side simulation.
 */
@HiltViewModel
class PaperViewModel @Inject constructor(
    private val exchange: ExchangeRepository,
    private val store: PaperAccountStore,
) : ViewModel() {

    private val _uiState = MutableStateFlow(PaperUiState())
    val uiState: StateFlow<PaperUiState> = _uiState.asStateFlow()

    /** The authoritative simulated account; the UI state is always a projection of this + live marks. */
    private var account: PaperAccount = PaperEngine.newAccount(STARTING_CASH)
    private var instruments: List<Instrument> = emptyList()

    /** Latest known mark per symbol, so equity/unrealized use every position's price, not just the open one. */
    private val marks = HashMap<Int, Long>()

    init {
        bootstrap()
    }

    private fun bootstrap() {
        viewModelScope.launch {
            account = store.load() ?: PaperEngine.newAccount(STARTING_CASH).also { store.save(it) }
            val symbolsResult = exchange.symbols()
            instruments = (symbolsResult as? ApiResult.Success)?.data ?: FALLBACK
            val selected = _uiState.value.selectedSymbolId
                ?: instruments.firstOrNull()?.symbolId
            _uiState.update {
                it.copy(loading = false, symbols = instruments, selectedSymbolId = selected)
            }
            project()
            pollMarks()
        }
    }

    /** Continuously refresh the selected symbol's mark and feed it into onTick while the VM is alive. */
    private fun pollMarks() {
        viewModelScope.launch {
            while (isActive) {
                val symbolId = _uiState.value.selectedSymbolId
                if (symbolId != null) {
                    val mark = fetchMark(symbolId)
                    if (mark != null) {
                        marks[symbolId] = mark
                        // Feed the live price into the engine so limit orders fill as the market moves.
                        val before = account
                        account = PaperEngine.onTick(account, symbolId, mark)
                        _uiState.update { it.copy(markPrice = mark) }
                        if (account !== before) persist()
                        project()
                    }
                }
                delay(POLL_MS)
            }
        }
    }

    /** Best available live price for [symbolId]: last trade, else order-book mid. Null when unavailable. */
    private suspend fun fetchMark(symbolId: Int): Long? {
        val last = (exchange.trades(symbolId) as? ApiResult.Success)?.data?.firstOrNull()?.price
        if (last != null) return last
        val book = (exchange.orderBook(symbolId) as? ApiResult.Success)?.data
        return book?.mid?.let { Math.round(it) }
    }

    fun onSelectSymbol(symbolId: Int) {
        if (symbolId == _uiState.value.selectedSymbolId) return
        _uiState.update { it.copy(selectedSymbolId = symbolId, markPrice = marks[symbolId]) }
        // Kick an immediate mark fetch so the readout + preview update without waiting a full poll.
        viewModelScope.launch {
            val mark = fetchMark(symbolId)
            if (mark != null) {
                marks[symbolId] = mark
                account = PaperEngine.onTick(account, symbolId, mark)
                _uiState.update { it.copy(markPrice = mark) }
                persist()
                project()
            }
        }
    }

    // ---- ticket editing ----

    fun onSideChange(side: OrderSide) = _uiState.update { it.copy(ticket = it.ticket.copy(side = side)) }
    fun onTypeChange(type: PaperOrderType) = _uiState.update { it.copy(ticket = it.ticket.copy(type = type)) }
    fun onQtyChange(v: String) = _uiState.update { it.copy(ticket = it.ticket.copy(qtyInput = v.filter { c -> c.isDigit() })) }
    fun onLimitPriceChange(v: String) =
        _uiState.update { it.copy(ticket = it.ticket.copy(limitPriceInput = v.filter { c -> c.isDigit() })) }

    /** Submit the staged ticket. MARKET fills at the live mark; LIMIT rests (or fills if marketable). */
    fun onSubmit() {
        val state = _uiState.value
        val ticket = state.ticket
        val symbolId = state.selectedSymbolId ?: return
        val qty = ticket.qty ?: run { toast("Enter a quantity"); return }
        val mark = state.markPrice ?: run { toast("No live price yet — try again"); return }
        if (ticket.type == PaperOrderType.LIMIT && ticket.limitPrice == null) {
            toast("Enter a limit price"); return
        }
        val order = PaperOrder(
            id = "po-" + System.currentTimeMillis() + "-" + (account.orders.size + 1),
            symbolId = symbolId,
            side = ticket.side,
            type = ticket.type,
            qty = qty,
            limitPrice = if (ticket.type == PaperOrderType.LIMIT) ticket.limitPrice else null,
            createdTsMs = System.currentTimeMillis(),
        )
        account = PaperEngine.placeOrder(account, order, mark)
        val filled = account.fills.lastOrNull()?.orderId == order.id
        toast(if (filled) "Order filled" else "Limit order working")
        _uiState.update { it.copy(ticket = ticket.copy(qtyInput = "", limitPriceInput = "")) }
        persist()
        project()
    }

    fun onCancelOrder(orderId: String) {
        account = PaperEngine.cancelOrder(account, orderId)
        toast("Order cancelled")
        persist()
        project()
    }

    /** Reset to a fresh account (confirmed in the UI) and re-persist. */
    fun onReset() {
        account = PaperEngine.newAccount(STARTING_CASH)
        marks.clear()
        toast("Paper account reset")
        persist()
        project()
        // Re-seed a mark for the current symbol on the next poll tick.
    }

    fun consumeToast() = _uiState.update { it.copy(toast = null) }

    private fun toast(msg: String) = _uiState.update { it.copy(toast = msg) }

    private fun persist() {
        val snapshot = account
        viewModelScope.launch { store.save(snapshot) }
    }

    /** Project the authoritative account + live marks into the render-ready [PaperUiState]. */
    private fun project() {
        val names = instruments.associate { it.symbolId to it.symbol }
        fun name(id: Int) = names[id] ?: FALLBACK.firstOrNull { it.symbolId == id }?.symbol ?: "#$id"

        val positionRows = account.positions.entries
            .sortedBy { it.key }
            .map { (symbolId, pos) ->
                val mark = marks[symbolId]
                val upl = if (mark != null) PaperEngine.positionMtm(pos, mark) else 0L
                PaperPositionRow(
                    symbolId = symbolId,
                    symbol = name(symbolId),
                    qty = pos.qty,
                    avgEntry = pos.avgEntry,
                    mark = mark,
                    unrealized = upl,
                )
            }

        val workingRows = account.orders
            .filter { it.status == PaperOrderStatus.WORKING }
            .map { PaperOrderRow(it.id, name(it.symbolId), it.side, it.qty, it.limitPrice) }

        val fillRows = account.fills
            .asReversed()
            .map { PaperFillRow(name(it.symbolId), it.side, it.price, it.qty, it.tsMs) }

        _uiState.update { s ->
            s.copy(
                symbols = instruments,
                startingCash = account.startingCash,
                cash = account.cash,
                equity = PaperEngine.equity(account, marks),
                realizedPnl = account.realizedPnl,
                unrealizedPnl = PaperEngine.unrealized(account, marks),
                positions = positionRows,
                workingOrders = workingRows,
                fills = fillRows,
            )
        }
    }

    private companion object {
        const val STARTING_CASH = 100_000L
        const val POLL_MS = 2_000L
        val FALLBACK = listOf(
            Instrument("BTCUSDC", 1, 1, 1, 100_000, false),
            Instrument("ETHUSDC", 2, 1, 1, 3_000, false),
            Instrument("SOLUSDC", 3, 1, 1, 150, false),
        )
    }
}
