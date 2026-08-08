package com.testlogon.android.feature.markets.trade

import androidx.lifecycle.SavedStateHandle
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.exchange.OrderSide
import com.testlogon.android.data.exchange.TradingRepository
import com.testlogon.android.navigation.SymbolDetailDest
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
 * Drives the order ticket + this-session working orders for one symbol. Places limit orders via
 * [TradingRepository], tracks the resulting working orders locally (no server list), and refreshes
 * the margin account (wallet/margin/position) after each fill-changing action.
 */
@HiltViewModel
class TradingViewModel @Inject constructor(
    private val repository: TradingRepository,
    savedStateHandle: SavedStateHandle,
) : ViewModel() {

    private val symbolId: Int = savedStateHandle.get<Int>(SymbolDetailDest.ARG_SYMBOL_ID) ?: 0

    private val _uiState = MutableStateFlow(TradingUiState())
    val uiState: StateFlow<TradingUiState> = _uiState.asStateFlow()

    private var seq = 0

    init {
        refreshAccount()
        pollAccount()
    }

    /** Keep the wallet / margin / position fresh while the VM is alive. */
    private fun pollAccount() {
        viewModelScope.launch {
            while (isActive) {
                delay(5_000L)
                refreshAccount()
                drainExecEvents()
            }
        }
    }

    fun setSide(side: OrderSide) = _uiState.update { it.copy(side = side) }
    fun setPrice(text: String) = _uiState.update { it.copy(priceText = text.filter { c -> c.isDigit() }.take(12)) }
    fun setQty(text: String) = _uiState.update { it.copy(qtyText = text.filter { c -> c.isDigit() }.take(9)) }
    fun setDeposit(text: String) = _uiState.update { it.copy(depositText = text.filter { c -> c.isDigit() }.take(12)) }
    fun setStop(text: String) = _uiState.update { it.copy(stopText = digits(text, 12)) }
    fun setBid(text: String) = _uiState.update { it.copy(bidText = digits(text, 12)) }
    fun setAsk(text: String) = _uiState.update { it.copy(askText = digits(text, 12)) }
    fun setChildPrice(text: String) = _uiState.update { it.copy(childPriceText = digits(text, 12)) }
    fun setChildQty(text: String) = _uiState.update { it.copy(childQtyText = digits(text, 9)) }
    fun setOrderType(t: OrderType) = _uiState.update { it.copy(orderType = t, amendingClordid = null, message = null) }
    fun setTif(t: String) = _uiState.update { it.copy(tif = t) }
    fun togglePostOnly() = _uiState.update { it.copy(postOnly = !it.postOnly) }
    fun toggleHidden() = _uiState.update { it.copy(hidden = !it.hidden) }
    fun toggleAon() = _uiState.update { it.copy(aon = !it.aon) }
    fun toggleAdvanced() = _uiState.update { it.copy(advancedOpen = !it.advancedOpen) }
    fun setDisplayQty(text: String) = _uiState.update { it.copy(displayText = digits(text, 9)) }
    fun setMinQty(text: String) = _uiState.update { it.copy(minQtyText = digits(text, 9)) }
    fun setExpiryMin(text: String) = _uiState.update { it.copy(expiryMinText = digits(text, 6)) }

    /** Route the ticket's primary action to the right engine endpoint for the selected order type. */
    fun submit() {
        when (_uiState.value.orderType) {
            OrderType.LIMIT -> place()
            OrderType.MARKET -> place()
            OrderType.STOP -> submitAlgo("stop_market")
            OrderType.STOP_LIMIT -> submitAlgo("stop_limit")
            OrderType.TAKE_PROFIT -> submitAlgo("take_profit")
            OrderType.QUOTE -> submitQuote()
            OrderType.OTO -> submitOto()
        }
    }

    private fun digits(t: String, max: Int) = t.filter { it.isDigit() }.take(max)

    /**
     * Deposit collateral into the margin account (`POST /me/margin_deposit`). Fresh accounts start at
     * zero balance and a fill on an unfunded account opens NO position, so funding is a precondition
     * for trading. Also flips the engine into margin mode.
     */
    fun deposit() {
        val amount = _uiState.value.depositText.toLongOrNull() ?: return
        if (amount <= 0) return
        _uiState.update { it.copy(depositing = true, message = null) }
        viewModelScope.launch {
            when (val r = repository.deposit(amount)) {
                is ApiResult.Success -> {
                    val ack = r.data
                    _uiState.update {
                        it.copy(
                            depositing = false,
                            depositText = if (ack.accepted) "" else it.depositText,
                            message = if (ack.accepted) "Deposited · balance ${ack.newBalance}" else (ack.message ?: "Deposit rejected"),
                            messageIsError = !ack.accepted,
                        )
                    }
                    if (ack.accepted) refreshAccount()
                }
                is ApiResult.Failure -> _uiState.update { it.copy(depositing = false, message = r.error.message, messageIsError = true) }
                is ApiResult.NetworkError -> _uiState.update { it.copy(depositing = false, message = "Network error", messageIsError = true) }
            }
        }
    }

    /** Prefill the price (click-to-trade from the book/chart). */
    fun prefillPrice(price: Long, side: OrderSide? = null) = _uiState.update {
        it.copy(priceText = price.toString(), side = side ?: it.side)
    }

    fun refreshAccount() {
        viewModelScope.launch {
            when (val r = repository.marginAccount()) {
                is ApiResult.Success -> _uiState.update { it.copy(account = r.data) }
                else -> Unit
            }
        }
    }

    /** Drain async exec events (fills that landed after placement + algo/OTO triggers) into the ticket. */
    private fun drainExecEvents() {
        viewModelScope.launch {
            val r = repository.execEvents()
            if (r is ApiResult.Success && !r.data.isEmpty) {
                val ev = r.data
                _uiState.update { st ->
                    st.copy(
                        sessionFills = ev.fills + st.sessionFills,
                        message = when {
                            ev.triggeredCount > 0 -> "Algo triggered (${ev.triggeredCount})"
                            ev.otoTriggeredCount > 0 -> "OTO child triggered (${ev.otoTriggeredCount})"
                            ev.fills.isNotEmpty() -> "Filled ${ev.fills.sumOf { f -> f.qty }} (async)"
                            else -> st.message
                        },
                        messageIsError = false,
                    )
                }
                refreshAccount()
            }
        }
    }

    fun place() {
        val s = _uiState.value
        val isMarket = s.orderType == OrderType.MARKET
        val qty = s.qtyLong ?: return
        val price = if (isMarket) 0L else (s.priceLong ?: return)
        if (qty <= 0 || (!isMarket && price <= 0)) return
        s.amendingClordid?.let { amend(it, price, qty, s.side); return }
        // clordid: <=20 chars, unique per placement.
        val clordid = "t${System.currentTimeMillis()}${seq++ % 100}"
        val tif = if (isMarket) null else s.tif.takeIf { it != "GTC" }
        val expiryNs = if (!isMarket && s.tif == "GTD") s.expiryMinLong?.let { (System.currentTimeMillis() + it * 60_000L) * 1_000_000L } else null
        _uiState.update { it.copy(placing = true, message = null) }
        viewModelScope.launch {
            when (val r = repository.placeOrder(
                symbolId, s.side, price, qty, clordid,
                market = if (isMarket) true else null,
                tif = tif,
                postOnly = s.postOnly.takeIf { it },
                hidden = s.hidden.takeIf { it },
                aon = s.aon.takeIf { it },
                displayQty = s.displayQtyLong?.takeIf { v -> v > 0 },
                minQty = s.minQtyLong?.takeIf { v -> v > 0 },
                expiryNs = expiryNs,
            )) {
                is ApiResult.Success -> {
                    val ack = r.data
                    if (ack.accepted) {
                        val filled = ack.fills.sumOf { f -> f.qty }
                        val wo = WorkingOrder(ack.clordid, s.side, price, qty - filled, ack.orderId)
                        _uiState.update { st ->
                            st.copy(
                                placing = false,
                                message = "Placed #${ack.orderId ?: "?"}" + if (filled > 0) " · filled $filled" else "",
                                messageIsError = false,
                                qtyText = "",
                                workingOrders = if (qty - filled > 0) st.workingOrders + wo else st.workingOrders,
                                sessionFills = ack.fills + st.sessionFills,
                            )
                        }
                        refreshAccount()
                    } else {
                        _uiState.update { it.copy(placing = false, message = ack.message ?: "Order rejected", messageIsError = true) }
                    }
                }
                is ApiResult.Failure -> _uiState.update { it.copy(placing = false, message = r.error.message, messageIsError = true) }
                is ApiResult.NetworkError -> _uiState.update { it.copy(placing = false, message = "Network error", messageIsError = true) }
            }
        }
    }

    fun cancel(clordid: String) {
        viewModelScope.launch {
            when (val r = repository.cancelOrder(clordid)) {
                is ApiResult.Success -> if (r.data.accepted) {
                    _uiState.update { st ->
                        st.copy(
                            workingOrders = st.workingOrders.filterNot { it.clordid == clordid },
                            message = "Cancelled ${r.data.cancelledQty}",
                            messageIsError = false,
                        )
                    }
                    refreshAccount()
                }
                is ApiResult.Failure -> _uiState.update { it.copy(message = r.error.message, messageIsError = true) }
                is ApiResult.NetworkError -> _uiState.update { it.copy(message = "Network error", messageIsError = true) }
            }
        }
    }

    /** Load a working order into the ticket in amend-mode. */
    fun startAmend(order: WorkingOrder) = _uiState.update {
        it.copy(
            side = order.side,
            priceText = order.price.toString(),
            qtyText = order.qty.toString(),
            amendingClordid = order.clordid,
            message = null,
        )
    }

    /** Leave amend-mode without changing the order. */
    fun cancelAmend() = _uiState.update { it.copy(amendingClordid = null, message = null) }

    /**
     * Flatten the current net position with an opposing marketable-limit order priced ~5% through the
     * market (from [lastPrice]) so it crosses and fills. Long -> Sell, Short -> Buy, qty = |pos_qty|.
     * With one net position per account this is also "close all".
     */
    fun closePosition(lastPrice: Long) {
        val pos = _uiState.value.account?.position ?: return
        if (pos.qty == 0L || lastPrice <= 0) return
        val side = if (pos.qty > 0) OrderSide.SELL else OrderSide.BUY
        val qty = kotlin.math.abs(pos.qty)
        val clordid = "c${System.currentTimeMillis()}${seq++ % 100}"
        // Close with a real MARKET order (walks the book). STP guard: a market close would be killed if
        // it crossed our OWN resting orders on the opposite side -> cancel those first.
        val colliding = _uiState.value.workingOrders.filter { it.side != side }
        _uiState.update { it.copy(placing = true, message = null) }
        viewModelScope.launch {
            colliding.forEach { wo -> repository.cancelOrder(wo.clordid) }
            if (colliding.isNotEmpty()) {
                _uiState.update { st -> st.copy(workingOrders = st.workingOrders.filterNot { c -> colliding.any { it.clordid == c.clordid } }) }
            }
            when (val r = repository.placeOrder(symbolId, side, 0L, qty, clordid, market = true)) {
                is ApiResult.Success -> {
                    val ack = r.data
                    _uiState.update {
                        it.copy(
                            placing = false,
                            message = if (ack.accepted) "Closing position (${if (side == OrderSide.SELL) "sold" else "bought"} $qty)" else (ack.message ?: "Close rejected"),
                            messageIsError = !ack.accepted,
                        )
                    }
                    refreshAccount()
                }
                is ApiResult.Failure -> _uiState.update { it.copy(placing = false, message = r.error.message, messageIsError = true) }
                is ApiResult.NetworkError -> _uiState.update { it.copy(placing = false, message = "Network error", messageIsError = true) }
            }
        }
    }

    /** Cancel ALL resting orders (server-side) via bulk_cancel. Clears quote/OTO legs we can't track. */
    fun cancelAll() {
        _uiState.update { it.copy(message = null) }
        viewModelScope.launch {
            when (val r = repository.cancelAll()) {
                is ApiResult.Success -> {
                    _uiState.update { it.copy(workingOrders = emptyList(), message = "Cancelled all (${r.data.cancelledCount})", messageIsError = false) }
                    refreshAccount()
                }
                is ApiResult.Failure -> _uiState.update { it.copy(message = r.error.message, messageIsError = true) }
                is ApiResult.NetworkError -> _uiState.update { it.copy(message = "Network error", messageIsError = true) }
            }
        }
    }

    /** Stop / stop-limit / take-profit conditional order. Uses stopText as the trigger, priceText as limit. */
    private fun submitAlgo(algoType: String) {
        val s = _uiState.value
        val stop = s.stopLong ?: return
        val qty = s.qtyLong ?: return
        if (stop <= 0 || qty <= 0) return
        val limit = if (algoType == "stop_market") null else s.priceLong
        _uiState.update { it.copy(placing = true, message = null) }
        viewModelScope.launch {
            when (val r = repository.placeAlgo(algoType, symbolId, s.side, qty, stop, limit)) {
                is ApiResult.Success -> {
                    val ack = r.data
                    _uiState.update {
                        it.copy(
                            placing = false,
                            message = if (ack.accepted) "Algo #${ack.algoId ?: "?"} armed (${s.orderType.label})" else (ack.message ?: "Algo rejected"),
                            messageIsError = !ack.accepted,
                        )
                    }
                    if (ack.accepted) refreshAccount()
                }
                is ApiResult.Failure -> _uiState.update { it.copy(placing = false, message = r.error.message, messageIsError = true) }
                is ApiResult.NetworkError -> _uiState.update { it.copy(placing = false, message = "Network error", messageIsError = true) }
            }
        }
    }

    /** Two-sided maker quote (one qty applied to both bid and ask). */
    private fun submitQuote() {
        val s = _uiState.value
        val bid = s.bidLong ?: return
        val ask = s.askLong ?: return
        val qty = s.qtyLong ?: return
        if (bid <= 0 || ask <= 0 || qty <= 0) return
        _uiState.update { it.copy(placing = true, message = null) }
        viewModelScope.launch {
            when (val r = repository.placeQuote(symbolId, bid, ask, qty, qty)) {
                is ApiResult.Success -> {
                    val ack = r.data
                    val filled = ack.fills.sumOf { f -> f.qty }
                    _uiState.update {
                        it.copy(
                            placing = false,
                            message = if (ack.accepted) "Quote live · bid #${ack.bidOrderId ?: 0} / ask #${ack.askOrderId ?: 0}" + if (filled > 0) " · filled $filled" else "" else (ack.message ?: "Quote rejected"),
                            messageIsError = !ack.accepted,
                            sessionFills = ack.fills + it.sessionFills,
                        )
                    }
                    if (ack.accepted) refreshAccount()
                }
                is ApiResult.Failure -> _uiState.update { it.copy(placing = false, message = r.error.message, messageIsError = true) }
                is ApiResult.NetworkError -> _uiState.update { it.copy(placing = false, message = "Network error", messageIsError = true) }
            }
        }
    }

    /** One-triggers-other: parent uses the Buy/Sell selector + price/qty; child is the opposite side. */
    private fun submitOto() {
        val s = _uiState.value
        val pPrice = s.priceLong ?: return
        val pQty = s.qtyLong ?: return
        val cPrice = s.childPriceLong ?: return
        val cQty = s.childQtyLong ?: return
        if (pPrice <= 0 || pQty <= 0 || cPrice <= 0 || cQty <= 0) return
        val childSide = if (s.side == OrderSide.BUY) OrderSide.SELL else OrderSide.BUY
        _uiState.update { it.copy(placing = true, message = null) }
        viewModelScope.launch {
            when (val r = repository.placeOto(symbolId, s.side, pPrice, pQty, childSide, cPrice, cQty)) {
                is ApiResult.Success -> {
                    val ack = r.data
                    _uiState.update {
                        it.copy(
                            placing = false,
                            message = if (ack.accepted) "OTO #${ack.otoId ?: "?"} · parent #${ack.parentOrderId ?: 0} → child on fill" else (ack.message ?: "OTO rejected"),
                            messageIsError = !ack.accepted,
                            sessionFills = ack.fills + it.sessionFills,
                        )
                    }
                    if (ack.accepted) refreshAccount()
                }
                is ApiResult.Failure -> _uiState.update { it.copy(placing = false, message = r.error.message, messageIsError = true) }
                is ApiResult.NetworkError -> _uiState.update { it.copy(placing = false, message = "Network error", messageIsError = true) }
            }
        }
    }

    /**
     * Apply an amend. A pure quantity REDUCE (same price) uses `PATCH new_qty` (in-place, keeps queue
     * priority). A price change or quantity increase is a REPLACE (cancel + new order).
     */
    private fun amend(clordid: String, newPrice: Long, newQty: Long, side: OrderSide) {
        val wo = _uiState.value.workingOrders.firstOrNull { it.clordid == clordid }
        val priceChanged = wo == null || newPrice != wo.price
        val qtyIncreased = wo != null && newQty > wo.qty
        _uiState.update { it.copy(placing = true, message = null) }
        viewModelScope.launch {
            if (wo != null && !priceChanged && !qtyIncreased) {
                // reduce-qty (or unchanged) -> in-place amend
                when (val r = repository.amendOrder(clordid, newQty, null)) {
                    is ApiResult.Success -> if (r.data.accepted) {
                        _uiState.update { st ->
                            st.copy(
                                placing = false,
                                amendingClordid = null,
                                message = "Amended to $newQty",
                                messageIsError = false,
                                workingOrders = st.workingOrders.map { if (it.clordid == clordid) it.copy(qty = newQty) else it },
                            )
                        }
                        refreshAccount()
                    } else _uiState.update { it.copy(placing = false, message = r.data.message ?: "Amend rejected", messageIsError = true) }
                    is ApiResult.Failure -> _uiState.update { it.copy(placing = false, message = r.error.message, messageIsError = true) }
                    is ApiResult.NetworkError -> _uiState.update { it.copy(placing = false, message = "Network error", messageIsError = true) }
                }
            } else {
                // replace: cancel then place a fresh order at the new price/qty
                repository.cancelOrder(clordid)
                val newCl = "t${System.currentTimeMillis()}${seq++ % 100}"
                when (val r = repository.placeOrder(symbolId, side, newPrice, newQty, newCl)) {
                    is ApiResult.Success -> {
                        val ack = r.data
                        if (ack.accepted) {
                            val filled = ack.fills.sumOf { f -> f.qty }
                            _uiState.update { st ->
                                val without = st.workingOrders.filterNot { it.clordid == clordid }
                                st.copy(
                                    placing = false,
                                    amendingClordid = null,
                                    message = "Replaced -> #${ack.orderId ?: "?"}",
                                    messageIsError = false,
                                    workingOrders = if (newQty - filled > 0) without + WorkingOrder(ack.clordid, side, newPrice, newQty - filled, ack.orderId) else without,
                                )
                            }
                            refreshAccount()
                        } else _uiState.update { it.copy(placing = false, message = ack.message ?: "Replace rejected", messageIsError = true) }
                    }
                    is ApiResult.Failure -> _uiState.update { it.copy(placing = false, message = r.error.message, messageIsError = true) }
                    is ApiResult.NetworkError -> _uiState.update { it.copy(placing = false, message = "Network error", messageIsError = true) }
                }
            }
        }
    }
}
