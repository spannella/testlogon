package com.testlogon.android.feature.markets.trade

import androidx.lifecycle.SavedStateHandle
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.exchange.OrderSide
import com.testlogon.android.data.exchange.TradingRepository
import com.testlogon.android.data.exchange.ExchangeRepository
import com.testlogon.android.data.exchange.FeeSchedule
import com.testlogon.android.data.exchange.FillsFees
import com.testlogon.android.data.feed.CurrentUserRepository
import com.testlogon.android.feature.paper.PaperAccountStore
import com.testlogon.android.feature.paper.PaperEngine
import com.testlogon.android.feature.paper.PaperEngine.PaperAccount
import com.testlogon.android.feature.paper.PaperEngine.PaperOrder
import com.testlogon.android.feature.paper.PaperModeStore
import com.testlogon.android.feature.paper.PaperTicketSupport
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
    private val exchangeRepository: ExchangeRepository,
    private val notifier: TradingNotifier,
    private val currentUserRepository: CurrentUserRepository,
    private val paperModeStore: PaperModeStore,
    private val paperAccountStore: PaperAccountStore,
    savedStateHandle: SavedStateHandle,
) : ViewModel() {

    private var wasLiquidating = false

    private val symbolId: Int = savedStateHandle.get<Int>(SymbolDetailDest.ARG_SYMBOL_ID) ?: 0

    private val _uiState = MutableStateFlow(TradingUiState())
    val uiState: StateFlow<TradingUiState> = _uiState.asStateFlow()

    private var seq = 0

    /** Cached paper account (client-side simulation) shared with the Paper screen via the store. */
    private var paperAccount: PaperAccount = PaperEngine.newAccount(PAPER_STARTING_CASH)

    init {
        val sym = symbolId.toString()
        _uiState.update {
            it.copy(
                marginConfig = it.marginConfig.copy(symbolText = sym),
                matchingAlgo = it.matchingAlgo.copy(symbolText = sym),
                spreadConfig = it.spreadConfig.copy(spreadSymbolText = sym),
                tradingParams = it.tradingParams.copy(symbolText = sym),
                spotIndex = it.spotIndex.copy(symbolText = sym),
                spotConfig = it.spotConfig.copy(symbolText = sym),
                pmCreateBinary = it.pmCreateBinary.copy(symbolText = sym),
                pmResolveBinary = it.pmResolveBinary.copy(symbolText = sym),
                stakeRequest = it.stakeRequest.copy(symbolText = sym),
                auctionRequest = it.auctionRequest.copy(symbolText = sym),
            )
        }
        resolveAdmin()
        refreshAccount()
        pollAccount()
        refreshPm()
        loadFees()
        refreshOrdersLive()
        resolveSymbols()
        loadStakeAuctionBrowse()
        if (TradingFeatures.SPOT_ENABLED) refreshSpot()
        observePaperMode()
        loadPaperAccount()
    }

    /** Load the shared paper account (or seed a fresh one) and project its cash into the ticket. */
    private fun loadPaperAccount() {
        viewModelScope.launch {
            paperAccount = paperAccountStore.load()
                ?: PaperEngine.newAccount(PAPER_STARTING_CASH).also { paperAccountStore.save(it) }
            _uiState.update { it.copy(paperCash = paperAccount.cash) }
        }
    }

    /** Mirror the durable paper-mode flag into the ticket; snap a non-paper type back to Limit on ON. */
    private fun observePaperMode() {
        viewModelScope.launch {
            paperModeStore.paperMode.collect { on ->
                _uiState.update {
                    it.copy(
                        paperMode = on,
                        orderType = if (on) PaperTicketSupport.snapToPaper(it.orderType) else it.orderType,
                        armed = null,
                    )
                }
            }
        }
    }

    /** Toggle paper mode (persisted; the observer re-projects state). */
    fun setPaperMode(enabled: Boolean) {
        notifier.tick()
        viewModelScope.launch { paperModeStore.setPaperMode(enabled) }
    }

    /**
     * Load the caller's fee schedule + the enriched fills-fees feed (custody-exchange-gaps). Both 404
     * until deployed; a failure just leaves the fee card hidden (no error surfaced on the ticket).
     */
    fun loadFees() {
        viewModelScope.launch {
            when (val r = repository.feeSchedule(symbolId)) {
                is ApiResult.Success -> _uiState.update { it.copy(feeSchedule = r.data) }
                else -> Unit
            }
        }
        viewModelScope.launch {
            when (val r = repository.fillsFees()) {
                is ApiResult.Success -> _uiState.update { it.copy(fillsFees = r.data) }
                else -> Unit
            }
        }
        viewModelScope.launch {
            when (val r = repository.liquidations()) {
                is ApiResult.Success -> _uiState.update { it.copy(liquidations = r.data) }
                else -> Unit
            }
        }
        viewModelScope.launch {
            when (val r = repository.fundingPayments()) {
                is ApiResult.Success -> _uiState.update { it.copy(fundingPayments = r.data) }
                else -> Unit
            }
        }
    }

    /**
     * Load the LIVE working-order set from the engine (order-management read). This is the source of
     * truth for the Orders section when present: it survives app restarts and reflects quote/OTO legs
     * the session list can't track. 404/undeployed or failure -> the section falls back to the local
     * session-tracked orders (the state is left unchanged so nothing flickers).
     */
    fun refreshOrdersLive() {
        viewModelScope.launch {
            when (val r = repository.ordersLive()) {
                is ApiResult.Success -> _uiState.update { it.copy(liveOrders = r.data) }
                else -> Unit
            }
        }
    }

    /** Resolve symbolId -> ticker so the account-wide liquidation/funding/fills feeds label symbols. */
    private fun resolveSymbols() {
        viewModelScope.launch {
            when (val r = exchangeRepository.symbols()) {
                is ApiResult.Success ->
                    _uiState.update { it.copy(symbolNames = r.data.associate { i -> i.symbolId to i.symbol }) }
                else -> Unit
            }
        }
    }

    /** Detect + track a binary prediction market on this symbol (404 -> not a PM -> stays null). */
    fun refreshPm() {
        viewModelScope.launch {
            when (val r = repository.pmState(symbolId)) {
                is ApiResult.Success -> _uiState.update { it.copy(pm = if (r.data.isBinary) r.data else null) }
                else -> Unit
            }
        }
    }

    /** Resolve whether the caller is an admin (gates the margin-config panel). Failure -> stays false. */
    private fun resolveAdmin() {
        viewModelScope.launch {
            when (val r = currentUserRepository.isAdmin()) {
                is ApiResult.Success -> { _uiState.update { it.copy(isAdmin = r.data) }; if (r.data) loadPmResolutions() }
                else -> Unit
            }
        }
    }

    // ---- Admin margin-config form ----

    private fun updateMc(block: (MarginConfigForm) -> MarginConfigForm) {
        _uiState.update { it.copy(marginConfig = block(it.marginConfig).let { f -> f.copy(error = null) }) }
    }

    fun setMcSymbol(text: String) = updateMc { it.copy(symbolText = digits(text, 9)) }
    fun setMcInitialMargin(text: String) = updateMc { it.copy(initialMarginText = digits(text, 9)) }
    fun setMcMaintenanceMargin(text: String) = updateMc { it.copy(maintenanceMarginText = digits(text, 9)) }
    fun setMcLiquidationFee(text: String) = updateMc { it.copy(liquidationFeeText = digits(text, 9)) }
    fun setMcHourlyBorrow(text: String) = updateMc { it.copy(hourlyBorrowText = digits(text, 9)) }
    fun setMcMakerFee(text: String) = updateMc { it.copy(makerFeeText = digits(text, 9)) }
    fun setMcTakerFee(text: String) = updateMc { it.copy(takerFeeText = digits(text, 9)) }
    fun setMcMaxPosition(text: String) = updateMc { it.copy(maxPositionText = digits(text, 12)) }

    fun clearMcResult() = _uiState.update { it.copy(marginConfig = it.marginConfig.copy(result = null, error = null)) }

    /** Submit the admin margin-config form. Only fires when [MarginConfigForm.canSubmit]. */
    fun submitMarginConfig() {
        val f = _uiState.value.marginConfig
        if (!f.canSubmit) return
        _uiState.update { it.copy(marginConfig = it.marginConfig.copy(submitting = true, error = null, result = null)) }
        viewModelScope.launch {
            when (
                val r = repository.marginConfig(
                    symbolId = f.symbolInt!!,
                    initialMarginBps = f.initialMarginLong!!,
                    maintenanceMarginBps = f.maintenanceMarginLong!!,
                    liquidationFeeBps = f.liquidationFeeLong!!,
                    hourlyBorrowRateBps = f.hourlyBorrowLong!!,
                    makerFeeBps = f.makerFeeLong!!,
                    takerFeeBps = f.takerFeeLong!!,
                    maxPositionQty = f.maxPositionLong!!,
                )
            ) {
                is ApiResult.Success -> _uiState.update { it.copy(marginConfig = it.marginConfig.copy(submitting = false, result = r.data)) }
                is ApiResult.Failure -> _uiState.update { it.copy(marginConfig = it.marginConfig.copy(submitting = false, error = r.error.message)) }
                is ApiResult.NetworkError -> _uiState.update { it.copy(marginConfig = it.marginConfig.copy(submitting = false, error = "Network error. Check your connection and try again.")) }
            }
        }
    }

    // ---- Admin engine-config forms (exchange-admin-config) ----

    private fun mpid(t: String) = t.filter { it.isLetterOrDigit() }.take(12)

    // Allow an optional leading '-' plus digits (for signed spread ratios).
    private fun signed(t: String): String {
        val neg = t.startsWith("-")
        val d = t.filter { it.isDigit() }.take(6)
        return if (neg) "-" + d else d
    }

    // matching_algo
    fun setAlgoSymbol(t: String) = _uiState.update { it.copy(matchingAlgo = it.matchingAlgo.copy(symbolText = digits(t, 9), error = null)) }
    fun setAlgo(v: Int) = _uiState.update { it.copy(matchingAlgo = it.matchingAlgo.copy(algo = v, error = null)) }
    fun setAlgoSpecialistMpid(t: String) = _uiState.update { it.copy(matchingAlgo = it.matchingAlgo.copy(specialistMpidText = mpid(t), error = null)) }
    fun setAlgoSpecialistPct(t: String) = _uiState.update { it.copy(matchingAlgo = it.matchingAlgo.copy(specialistPctText = digits(t, 3), error = null)) }
    fun clearAlgoResult() = _uiState.update { it.copy(matchingAlgo = it.matchingAlgo.copy(result = null, error = null)) }
    fun submitMatchingAlgo() {
        val f = _uiState.value.matchingAlgo
        if (!f.canSubmit) return
        _uiState.update { it.copy(matchingAlgo = it.matchingAlgo.copy(submitting = true, error = null, result = null)) }
        viewModelScope.launch {
            val r = repository.matchingAlgo(f.symbolInt!!, f.algo, if (f.algo >= 2) f.specialistMpid else null, if (f.algo >= 2) f.specialistPctInt else null)
            _uiState.update { it.copy(matchingAlgo = it.matchingAlgo.finish(r)) }
        }
    }

    // spread_config
    fun setSpreadSymbol(t: String) = _uiState.update { it.copy(spreadConfig = it.spreadConfig.copy(spreadSymbolText = digits(t, 9), error = null)) }
    fun setSpreadLeg1(t: String) = _uiState.update { it.copy(spreadConfig = it.spreadConfig.copy(leg1Text = digits(t, 9), error = null)) }
    fun setSpreadLeg2(t: String) = _uiState.update { it.copy(spreadConfig = it.spreadConfig.copy(leg2Text = digits(t, 9), error = null)) }
    fun setSpreadLeg1Ratio(t: String) = _uiState.update { it.copy(spreadConfig = it.spreadConfig.copy(leg1RatioText = signed(t), error = null)) }
    fun setSpreadLeg2Ratio(t: String) = _uiState.update { it.copy(spreadConfig = it.spreadConfig.copy(leg2RatioText = signed(t), error = null)) }
    fun clearSpreadResult() = _uiState.update { it.copy(spreadConfig = it.spreadConfig.copy(result = null, error = null)) }
    fun submitSpreadConfig() {
        val f = _uiState.value.spreadConfig
        if (!f.canSubmit) return
        _uiState.update { it.copy(spreadConfig = it.spreadConfig.copy(submitting = true, error = null, result = null)) }
        viewModelScope.launch {
            val r = repository.spreadConfig(f.spreadSymbolInt!!, f.leg1Int!!, f.leg2Int!!, f.leg1RatioInt, f.leg2RatioInt)
            _uiState.update { it.copy(spreadConfig = it.spreadConfig.finish(r)) }
        }
    }

    // trading_params
    fun setTpSymbol(t: String) = _uiState.update { it.copy(tradingParams = it.tradingParams.copy(symbolText = digits(t, 9), error = null)) }
    fun setTpMaxQty(t: String) = _uiState.update { it.copy(tradingParams = it.tradingParams.copy(maxQtyText = digits(t, 9), error = null)) }
    fun setTpMaxNotional(t: String) = _uiState.update { it.copy(tradingParams = it.tradingParams.copy(maxNotionalText = digits(t, 15), error = null)) }
    fun setTpPriceBand(t: String) = _uiState.update { it.copy(tradingParams = it.tradingParams.copy(priceBandPctText = digits(t, 9), error = null)) }
    fun setTpCircuitBreaker(t: String) = _uiState.update { it.copy(tradingParams = it.tradingParams.copy(circuitBreakerPctText = digits(t, 9), error = null)) }
    fun setTpMinBlock(t: String) = _uiState.update { it.copy(tradingParams = it.tradingParams.copy(minBlockSizeText = digits(t, 9), error = null)) }
    fun clearTpResult() = _uiState.update { it.copy(tradingParams = it.tradingParams.copy(result = null, error = null)) }
    fun submitTradingParams() {
        val f = _uiState.value.tradingParams
        if (!f.canSubmit) return
        _uiState.update { it.copy(tradingParams = it.tradingParams.copy(submitting = true, error = null, result = null)) }
        viewModelScope.launch {
            val r = repository.tradingParams(f.symbolInt!!, f.maxQtyInt, f.maxNotionalLong, f.priceBandPctLong, f.circuitBreakerPctLong, f.minBlockSizeInt)
            _uiState.update { it.copy(tradingParams = it.tradingParams.finish(r)) }
        }
    }

    // risk_config
    fun setRiskMaxNotional(t: String) = _uiState.update { it.copy(riskConfig = it.riskConfig.copy(maxNotionalText = digits(t, 15), error = null)) }
    fun setRiskWindow(t: String) = _uiState.update { it.copy(riskConfig = it.riskConfig.copy(windowSecondsText = digits(t, 9), error = null)) }
    fun setRiskMpid(t: String) = _uiState.update { it.copy(riskConfig = it.riskConfig.copy(mpidText = mpid(t), error = null)) }
    fun clearRiskResult() = _uiState.update { it.copy(riskConfig = it.riskConfig.copy(result = null, error = null)) }
    fun submitRiskConfig() {
        val f = _uiState.value.riskConfig
        if (!f.canSubmit) return
        _uiState.update { it.copy(riskConfig = it.riskConfig.copy(submitting = true, error = null, result = null)) }
        viewModelScope.launch {
            val r = repository.riskConfig(f.maxNotionalLong!!, f.windowSecondsInt!!, f.mpid)
            _uiState.update { it.copy(riskConfig = it.riskConfig.finish(r)) }
        }
    }

    // spot_index
    fun setSpotIndexSymbol(t: String) = _uiState.update { it.copy(spotIndex = it.spotIndex.copy(symbolText = digits(t, 9), error = null)) }
    fun setSpotIndexPrice(t: String) = _uiState.update { it.copy(spotIndex = it.spotIndex.copy(spotIndexPriceText = digits(t, 15), error = null)) }
    fun clearSpotIndexResult() = _uiState.update { it.copy(spotIndex = it.spotIndex.copy(result = null, error = null)) }
    fun submitSpotIndex() {
        val f = _uiState.value.spotIndex
        if (!f.canSubmit) return
        _uiState.update { it.copy(spotIndex = it.spotIndex.copy(submitting = true, error = null, result = null)) }
        viewModelScope.launch {
            val r = repository.spotIndex(f.symbolInt!!, f.spotIndexPriceLong!!)
            _uiState.update { it.copy(spotIndex = it.spotIndex.finish(r)) }
        }
    }

    // spot_config
    fun setSpotCfgSymbol(t: String) = _uiState.update { it.copy(spotConfig = it.spotConfig.copy(symbolText = digits(t, 9), error = null)) }
    fun setSpotCfgBase(t: String) = _uiState.update { it.copy(spotConfig = it.spotConfig.copy(baseAssetText = digits(t, 9), error = null)) }
    fun setSpotCfgQuote(t: String) = _uiState.update { it.copy(spotConfig = it.spotConfig.copy(quoteAssetText = digits(t, 9), error = null)) }
    fun clearSpotCfgResult() = _uiState.update { it.copy(spotConfig = it.spotConfig.copy(result = null, error = null)) }
    fun submitSpotConfig() {
        val f = _uiState.value.spotConfig
        if (!f.canSubmit) return
        _uiState.update { it.copy(spotConfig = it.spotConfig.copy(submitting = true, error = null, result = null)) }
        viewModelScope.launch {
            val r = repository.spotConfig(f.symbolInt!!, f.baseAssetInt!!, f.quoteAssetInt!!)
            _uiState.update { it.copy(spotConfig = it.spotConfig.finish(r)) }
        }
    }

        /** Keep the wallet / margin / position fresh while the VM is alive. */
    private fun pollAccount() {
        viewModelScope.launch {
            while (isActive) {
                delay(5_000L)
                refreshAccount()
                drainExecEvents()
                if (_uiState.value.pm != null) refreshPm()   // catch resolution while it's an active PM
            }
        }
    }

    fun setSide(side: OrderSide) { notifier.tick(); _uiState.update { it.copy(side = side, armed = null) } }
    fun setPrice(text: String) = _uiState.update { it.copy(priceText = text.filter { c -> c.isDigit() }.take(12), armed = null) }
    fun setQty(text: String) = _uiState.update { it.copy(qtyText = text.filter { c -> c.isDigit() }.take(9), armed = null) }
    fun setDeposit(text: String) = _uiState.update { it.copy(depositText = text.filter { c -> c.isDigit() }.take(12)) }
    fun setStop(text: String) = _uiState.update { it.copy(stopText = digits(text, 12), armed = null) }
    fun setBid(text: String) = _uiState.update { it.copy(bidText = digits(text, 12)) }
    fun setAsk(text: String) = _uiState.update { it.copy(askText = digits(text, 12)) }
    fun setChildPrice(text: String) = _uiState.update { it.copy(childPriceText = digits(text, 12)) }
    fun setChildQty(text: String) = _uiState.update { it.copy(childQtyText = digits(text, 9)) }
    fun setOrderType(t: OrderType) { notifier.tick(); _uiState.update { it.copy(orderType = t, amendingClordid = null, message = null, armed = null) } }
    fun setSection(s: TicketSection) = _uiState.update { it.copy(section = s, armed = null) }
    fun toggleOneTap() = _uiState.update { it.copy(oneTap = !it.oneTap) }

    /** Quick-size: set qty to a % of (no-leverage) buying power = availableBalance / refPrice. */
    fun setQtyPercent(pct: Int, refPrice: Long?) {
        val avail = _uiState.value.effectiveBuyingPower ?: return
        val px = refPrice ?: return
        if (px <= 0 || avail <= 0) return
        val maxQty = avail / px
        val q = (maxQty * pct / 100).coerceAtLeast(if (pct > 0) 1L else 0L)
        notifier.tick()
        _uiState.update { it.copy(qtyText = q.toString(), armed = null) }
    }

    /** Set qty to the maximum affordable at [refPrice] from available balance (no leverage). */
    fun setMaxQty(refPrice: Long?) {
        val avail = _uiState.value.effectiveBuyingPower
        val max = OrderMath.maxQtyForBalance(avail, refPrice ?: _uiState.value.entryRefPrice)
        if (max <= 0L) return
        notifier.tick()
        _uiState.update { it.copy(qtyText = max.toString(), armed = null) }
    }

    // ---- Position-size / risk calculator ----

    fun toggleRiskCalc() = _uiState.update { it.copy(riskCalcOpen = !it.riskCalcOpen) }
    fun setRiskAmount(text: String) = _uiState.update { it.copy(riskAmountText = digits(text, 15)) }
    fun setRiskStop(text: String) = _uiState.update { it.copy(riskStopText = digits(text, 12)) }

    /** Apply the risk-sized qty to the ticket (qty = riskAmount / |entry - stop|). No-op when it's 0. */
    fun applyRiskSize(refPrice: Long?) {
        val st = _uiState.value
        val q = st.riskSizedQty(refPrice)
        if (q <= 0L) return
        notifier.tick()
        _uiState.update { it.copy(qtyText = q.toString(), armed = null) }
    }

    // ---- One-click bid/ask / market prefills (the user still submits via the normal flow) ----

    /** Prefill a Buy limit at the best bid. */
    fun prefillBuyAtBid(bestBid: Long?) {
        val px = bestBid ?: return
        if (px <= 0L) return
        notifier.tick()
        _uiState.update { it.copy(orderType = OrderType.LIMIT, side = OrderSide.BUY, priceText = px.toString(), armed = null) }
    }

    /** Prefill a Sell limit at the best ask. */
    fun prefillSellAtAsk(bestAsk: Long?) {
        val px = bestAsk ?: return
        if (px <= 0L) return
        notifier.tick()
        _uiState.update { it.copy(orderType = OrderType.LIMIT, side = OrderSide.SELL, priceText = px.toString(), armed = null) }
    }

    /** Switch the ticket to a Market order on [side] (qty preserved; user submits via the normal flow). */
    fun prefillMarket(side: OrderSide) {
        notifier.tick()
        _uiState.update { it.copy(orderType = OrderType.MARKET, side = side, message = null, amendingClordid = null, armed = null) }
    }

    fun stepQty(delta: Long) {
        notifier.tick()
        val n = ((_uiState.value.qtyText.toLongOrNull() ?: 0L) + delta).coerceAtLeast(0L)
        _uiState.update { it.copy(qtyText = if (n == 0L) "" else n.toString(), armed = null) }
    }

    fun stepPrice(delta: Long) {
        notifier.tick()
        val n = ((_uiState.value.priceText.toLongOrNull() ?: 0L) + delta).coerceAtLeast(0L)
        _uiState.update { it.copy(priceText = if (n == 0L) "" else n.toString(), armed = null) }
    }

    fun stepStop(delta: Long) {
        notifier.tick()
        val n = ((_uiState.value.stopText.toLongOrNull() ?: 0L) + delta).coerceAtLeast(0L)
        _uiState.update { it.copy(stopText = if (n == 0L) "" else n.toString(), armed = null) }
    }
    fun setTif(t: String) = _uiState.update { it.copy(tif = t) }
    fun togglePostOnly() = _uiState.update { it.copy(postOnly = !it.postOnly) }
    fun toggleHidden() = _uiState.update { it.copy(hidden = !it.hidden) }
    fun toggleAon() = _uiState.update { it.copy(aon = !it.aon) }
    fun toggleAdvanced() = _uiState.update { it.copy(advancedOpen = !it.advancedOpen) }
    fun setDisplayQty(text: String) = _uiState.update { it.copy(displayText = digits(text, 9)) }
    fun setMinQty(text: String) = _uiState.update { it.copy(minQtyText = digits(text, 9)) }
    fun setExpiryMin(text: String) = _uiState.update { it.copy(expiryMinText = digits(text, 6)) }
    fun setFundingRate(text: String) = _uiState.update { it.copy(fundingRateText = digits(text, 9)) }
    fun setFundingQty(text: String) = _uiState.update { it.copy(fundingQtyText = digits(text, 9)) }
    fun setFundingDuration(text: String) = _uiState.update { it.copy(fundingDurationText = digits(text, 9)) }
    fun setFundingBorrow(borrow: Boolean) = _uiState.update { it.copy(fundingBorrow = borrow) }
    fun setSpotAsset(text: String) = _uiState.update { it.copy(spotAssetText = digits(text, 6)) }
    fun setSpotAmount(text: String) = _uiState.update { it.copy(spotAmountText = digits(text, 12)) }

    fun refreshSpot() {
        viewModelScope.launch {
            when (val r = repository.spotBalance()) {
                is ApiResult.Success -> _uiState.update { it.copy(spotBalance = r.data) }
                else -> Unit
            }
        }
    }

    fun spotDeposit() {
        val asset = _uiState.value.spotAssetInt ?: return
        val amount = _uiState.value.spotAmountLong ?: return
        if (amount <= 0) return
        _uiState.update { it.copy(placing = true, message = null) }
        viewModelScope.launch {
            when (val r = repository.spotDeposit(asset, amount)) {
                is ApiResult.Success -> {
                    val ack = r.data
                    _uiState.update {
                        it.copy(
                            placing = false,
                            spotAmountText = if (ack.accepted) "" else it.spotAmountText,
                            message = if (ack.accepted) "Spot deposited (asset $asset)" else (ack.message ?: "Spot deposit rejected"),
                            messageIsError = !ack.accepted,
                        )
                    }
                    if (ack.accepted) refreshSpot()
                }
                is ApiResult.Failure -> { _uiState.update { it.copy(placing = false, message = r.error.message, messageIsError = true) }; notifier.error() }
                is ApiResult.NetworkError -> { _uiState.update { it.copy(placing = false, message = "Network error", messageIsError = true) }; notifier.error() }
            }
        }
    }

    /** OCO: leg A = Buy/Sell selector + price/qty; leg B = opposite side + child price/qty. */
    private fun submitOco() {
        val s = _uiState.value
        val aPrice = s.priceLong ?: return
        val aQty = s.qtyLong ?: return
        val bPrice = s.childPriceLong ?: return
        val bQty = s.childQtyLong ?: return
        if (aPrice <= 0 || aQty <= 0 || bPrice <= 0 || bQty <= 0) return
        val bSide = if (s.side == OrderSide.BUY) OrderSide.SELL else OrderSide.BUY
        _uiState.update { it.copy(placing = true, message = null) }
        viewModelScope.launch {
            when (val r = repository.placeOco(symbolId, s.side, aPrice, aQty, bSide, bPrice, bQty)) {
                is ApiResult.Success -> {
                    val ack = r.data
                    _uiState.update { it.copy(placing = false, message = if (ack.accepted) "OCO #${ack.ocoId ?: "?"} placed" else (ack.message ?: "OCO rejected"), messageIsError = !ack.accepted) }
                    if (ack.accepted) refreshAccount()
                }
                is ApiResult.Failure -> { _uiState.update { it.copy(placing = false, message = r.error.message, messageIsError = true) }; notifier.error() }
                is ApiResult.NetworkError -> { _uiState.update { it.copy(placing = false, message = "Network error", messageIsError = true) }; notifier.error() }
            }
        }
    }

    /** Funding: borrow or lend into the on-book funding market. */
    private fun submitFunding() {
        val s = _uiState.value
        val rate = s.fundingRateLong ?: return
        val qty = s.fundingQtyLong ?: return
        if (rate <= 0 || qty <= 0) return
        _uiState.update { it.copy(placing = true, message = null) }
        viewModelScope.launch {
            when (val r = repository.placeFunding(rate, qty, s.fundingBorrow, s.fundingDurationLong, null)) {
                is ApiResult.Success -> {
                    val ack = r.data
                    _uiState.update { it.copy(placing = false, message = if (ack.accepted) "Funding ${if (s.fundingBorrow) "borrow" else "lend"} #${ack.fundingId ?: "?"}" else (ack.message ?: "Funding rejected"), messageIsError = !ack.accepted) }
                    if (ack.accepted) refreshAccount()
                }
                is ApiResult.Failure -> { _uiState.update { it.copy(placing = false, message = r.error.message, messageIsError = true) }; notifier.error() }
                is ApiResult.NetworkError -> { _uiState.update { it.copy(placing = false, message = "Network error", messageIsError = true) }; notifier.error() }
            }
        }
    }

    /**
     * Route the ticket's primary action to the right engine endpoint for the selected order type.
     * In PAPER mode (Market/Limit only) the order is simulated via [PaperEngine] instead of hitting
     * `/me/orders`; [bestBid]/[bestAsk]/[last] pick the simulated fill price.
     */
    fun submit(bestBid: Long? = null, bestAsk: Long? = null, last: Long? = null) {
        val s = _uiState.value
        val isMarketLike = s.paperMode || s.orderType == OrderType.MARKET
        if (isMarketLike && s.orderType == OrderType.MARKET && !s.oneTap && s.armed != "market") {
            notifier.warn()
            _uiState.update { it.copy(armed = "market", message = "Tap Confirm paper order".takeIf { s.paperMode } ?: "Tap Confirm to send the market order", messageIsError = false) }
            return
        }
        _uiState.update { it.copy(armed = null) }
        if (s.paperMode) { submitPaper(bestBid, bestAsk, last); return }
        when (s.orderType) {
            OrderType.LIMIT -> place()
            OrderType.MARKET -> place()
            OrderType.STOP -> submitAlgo("stop_market")
            OrderType.STOP_LIMIT -> submitAlgo("stop_limit")
            OrderType.TAKE_PROFIT -> submitAlgo("take_profit")
            OrderType.QUOTE -> submitQuote()
            OrderType.OTO -> submitOto()
            OrderType.OCO -> submitOco()
            OrderType.FUNDING -> submitFunding()
        }
    }

    /**
     * Simulate the ticket order via [PaperEngine] (paper mode). Only Market/Limit reach here (the UI
     * restricts the selector in paper mode). MARKET fills at the crossed price; LIMIT rests (or fills
     * if marketable). Persists the shared paper account and re-projects cash — NEVER hits /me/orders.
     */
    private fun submitPaper(bestBid: Long?, bestAsk: Long?, last: Long?) {
        val s = _uiState.value
        val isMarket = s.orderType == OrderType.MARKET
        val qty = s.qtyLong ?: return
        if (qty <= 0L) return
        val limit = if (isMarket) null else (s.priceLong ?: return)
        if (!isMarket && (limit == null || limit <= 0L)) return
        val marketPrice = PaperTicketSupport.marketPriceFor(s.side, bestBid, bestAsk, last)
        if (marketPrice == null) {
            _uiState.update { it.copy(message = "No live price yet — try again", messageIsError = true) }
            notifier.error(); return
        }
        val order = PaperOrder(
            id = "pt-" + System.currentTimeMillis() + "-" + (paperAccount.orders.size + 1),
            symbolId = symbolId,
            side = s.side,
            type = PaperTicketSupport.toPaperType(s.orderType),
            qty = qty,
            limitPrice = limit,
            createdTsMs = System.currentTimeMillis(),
        )
        val before = paperAccount
        paperAccount = PaperEngine.placeOrder(paperAccount, order, marketPrice)
        val filled = paperAccount.fills.lastOrNull()?.orderId == order.id
        val snapshot = paperAccount
        viewModelScope.launch { paperAccountStore.save(snapshot) }
        _uiState.update {
            it.copy(
                paperCash = paperAccount.cash,
                qtyText = if (paperAccount !== before) "" else it.qtyText,
                message = if (paperAccount === before) "Paper order rejected"
                    else if (filled) "Paper order filled @ $marketPrice" else "Paper limit order working",
                messageIsError = paperAccount === before,
            )
        }
        if (paperAccount !== before) notifier.success() else notifier.error()
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
                is ApiResult.Success -> {
                    val acct = r.data
                    if (acct.isLiquidating && !wasLiquidating) {
                        notifier.notifyDistress("⚠ Liquidation", "Your position is being liquidated")
                    }
                    wasLiquidating = acct.isLiquidating
                    _uiState.update { it.copy(account = acct) }
                }
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
                when {
                    ev.triggeredCount > 0 -> notifier.notifyTrigger("Algo triggered", "${ev.triggeredCount} algo order(s) triggered")
                    ev.otoTriggeredCount > 0 -> notifier.notifyTrigger("OTO triggered", "${ev.otoTriggeredCount} child order(s) fired")
                    ev.fills.isNotEmpty() -> notifier.notifyFill("Fill", "Filled ${ev.fills.sumOf { f -> f.qty }} on a resting order")
                    else -> {}
                }
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
                        refreshOrdersLive()
                        if (filled > 0) notifier.notifyFill("Order filled", "Filled $filled @ ${ack.fills.firstOrNull()?.price ?: price}") else notifier.success()
                    } else {
                        _uiState.update { it.copy(placing = false, message = ack.message ?: "Order rejected", messageIsError = true) }
                        notifier.error()
                    }
                }
                is ApiResult.Failure -> { _uiState.update { it.copy(placing = false, message = r.error.message, messageIsError = true) }; notifier.error() }
                is ApiResult.NetworkError -> { _uiState.update { it.copy(placing = false, message = "Network error", messageIsError = true) }; notifier.error() }
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
                    refreshOrdersLive()
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
                    if (ack.accepted) notifier.notifyFill("Position closed", "${if (side == OrderSide.SELL) "Sold" else "Bought"} $qty to flatten") else notifier.error()
                }
                is ApiResult.Failure -> { _uiState.update { it.copy(placing = false, message = r.error.message, messageIsError = true) }; notifier.error() }
                is ApiResult.NetworkError -> { _uiState.update { it.copy(placing = false, message = "Network error", messageIsError = true) }; notifier.error() }
            }
        }
    }

    /** Cancel ALL resting orders (server-side) via bulk_cancel. Clears quote/OTO legs we can't track. */
    fun cancelAll() {
        _uiState.update { it.copy(message = null) }
        viewModelScope.launch {
            when (val r = repository.cancelAll()) {
                is ApiResult.Success -> {
                    _uiState.update { it.copy(workingOrders = emptyList(), liveOrders = null, message = "Cancelled all (${r.data.cancelledCount})", messageIsError = false) }
                    refreshAccount()
                    refreshOrdersLive()
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
                is ApiResult.Failure -> { _uiState.update { it.copy(placing = false, message = r.error.message, messageIsError = true) }; notifier.error() }
                is ApiResult.NetworkError -> { _uiState.update { it.copy(placing = false, message = "Network error", messageIsError = true) }; notifier.error() }
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
                is ApiResult.Failure -> { _uiState.update { it.copy(placing = false, message = r.error.message, messageIsError = true) }; notifier.error() }
                is ApiResult.NetworkError -> { _uiState.update { it.copy(placing = false, message = "Network error", messageIsError = true) }; notifier.error() }
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
                is ApiResult.Failure -> { _uiState.update { it.copy(placing = false, message = r.error.message, messageIsError = true) }; notifier.error() }
                is ApiResult.NetworkError -> { _uiState.update { it.copy(placing = false, message = "Network error", messageIsError = true) }; notifier.error() }
            }
        }
    }

    /** Close with a confirm step (unless one-tap is on). The UI calls this; [closePosition] executes. */
    fun closePositionRequested(lastPrice: Long) {
        val s = _uiState.value
        if (s.account?.position == null) return
        if (!s.oneTap && s.armed != "close") {
            notifier.warn()
            _uiState.update { it.copy(armed = "close", message = "Tap Confirm close to flatten the position", messageIsError = false) }
            return
        }
        _uiState.update { it.copy(armed = null) }
        closePosition(lastPrice)
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
                        refreshOrdersLive()
                    } else _uiState.update { it.copy(placing = false, message = r.data.message ?: "Amend rejected", messageIsError = true) }
                    is ApiResult.Failure -> { _uiState.update { it.copy(placing = false, message = r.error.message, messageIsError = true) }; notifier.error() }
                    is ApiResult.NetworkError -> { _uiState.update { it.copy(placing = false, message = "Network error", messageIsError = true) }; notifier.error() }
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
                            refreshOrdersLive()
                        } else _uiState.update { it.copy(placing = false, message = ack.message ?: "Replace rejected", messageIsError = true) }
                    }
                    is ApiResult.Failure -> { _uiState.update { it.copy(placing = false, message = r.error.message, messageIsError = true) }; notifier.error() }
                    is ApiResult.NetworkError -> { _uiState.update { it.copy(placing = false, message = "Network error", messageIsError = true) }; notifier.error() }
                }
            }
        }
    }

    // ---- Admin prediction-markets forms (exchange-admin-config) ----

    // create binary
    fun setPmBinSymbol(t: String) = _uiState.update { it.copy(pmCreateBinary = it.pmCreateBinary.copy(symbolText = digits(t, 9), error = null)) }
    fun setPmBinFace(t: String) = _uiState.update { it.copy(pmCreateBinary = it.pmCreateBinary.copy(faceText = digits(t, 12), error = null)) }
    fun setPmBinResolver(t: String) = _uiState.update { it.copy(pmCreateBinary = it.pmCreateBinary.copy(resolverText = mpid(t), error = null)) }
    fun clearPmBinResult() = _uiState.update { it.copy(pmCreateBinary = it.pmCreateBinary.copy(result = null, error = null)) }
    fun submitPmCreateBinary() {
        val f = _uiState.value.pmCreateBinary
        if (!f.canSubmit) return
        _uiState.update { it.copy(pmCreateBinary = it.pmCreateBinary.copy(submitting = true, error = null, result = null)) }
        viewModelScope.launch {
            val r = repository.pmConfig(f.symbolInt!!, f.faceLong!!, f.resolver)
            _uiState.update { it.copy(pmCreateBinary = it.pmCreateBinary.finish(r)) }
            if (r is ApiResult.Success && r.data.applied) refreshPm()
        }
    }

    // create categorical (grouped)
    fun setPmCatGroup(t: String) = _uiState.update { it.copy(pmCreateCategorical = it.pmCreateCategorical.copy(groupText = digits(t, 9), error = null)) }
    fun setPmCatOutcomes(t: String) = _uiState.update { it.copy(pmCreateCategorical = it.pmCreateCategorical.copy(outcomesText = t.filter { c -> c.isDigit() || c == ',' || c == ' ' }.take(120), error = null)) }
    fun setPmCatFace(t: String) = _uiState.update { it.copy(pmCreateCategorical = it.pmCreateCategorical.copy(faceText = digits(t, 12), error = null)) }
    fun setPmCatResolver(t: String) = _uiState.update { it.copy(pmCreateCategorical = it.pmCreateCategorical.copy(resolverText = mpid(t), error = null)) }
    fun clearPmCatResult() = _uiState.update { it.copy(pmCreateCategorical = it.pmCreateCategorical.copy(result = null, error = null)) }
    fun submitPmCreateCategorical() {
        val f = _uiState.value.pmCreateCategorical
        if (!f.canSubmit) return
        _uiState.update { it.copy(pmCreateCategorical = it.pmCreateCategorical.copy(submitting = true, error = null, result = null)) }
        viewModelScope.launch {
            val r = repository.pmGroupConfig(f.groupInt!!, f.outcomes, f.faceLong!!, f.resolver)
            _uiState.update { it.copy(pmCreateCategorical = it.pmCreateCategorical.finish(r)) }
        }
    }

    // resolve binary
    fun setPmResolveSymbol(t: String) = _uiState.update { it.copy(pmResolveBinary = it.pmResolveBinary.copy(symbolText = digits(t, 9), error = null)) }
    fun setPmResolveYes(yes: Boolean) = _uiState.update { it.copy(pmResolveBinary = it.pmResolveBinary.copy(yes = yes, error = null)) }
    fun setPmResolveSource(t: String) = _uiState.update { it.copy(pmResolveBinary = it.pmResolveBinary.copy(sourceText = source(t), error = null)) }
    fun clearPmResolveResult() = _uiState.update { it.copy(pmResolveBinary = it.pmResolveBinary.copy(result = null, error = null)) }
    fun submitPmResolveBinary() {
        val f = _uiState.value.pmResolveBinary
        if (!f.canSubmit) return
        _uiState.update { it.copy(pmResolveBinary = it.pmResolveBinary.copy(submitting = true, error = null, result = null)) }
        viewModelScope.launch {
            val r = repository.pmResolve(f.symbolInt!!, f.outcome, f.source)
            _uiState.update { it.copy(pmResolveBinary = it.pmResolveBinary.finish(r)) }
            if (r is ApiResult.Success && r.data.applied) { refreshPm(); loadPmResolutions() }
        }
    }

    // resolve categorical
    fun setPmGroupResolveGroup(t: String) = _uiState.update { it.copy(pmResolveCategorical = it.pmResolveCategorical.copy(groupText = digits(t, 9), error = null)) }
    fun setPmGroupResolveWinning(t: String) = _uiState.update { it.copy(pmResolveCategorical = it.pmResolveCategorical.copy(winningText = digits(t, 9), error = null)) }
    fun setPmGroupResolveSource(t: String) = _uiState.update { it.copy(pmResolveCategorical = it.pmResolveCategorical.copy(sourceText = source(t), error = null)) }
    fun clearPmGroupResolveResult() = _uiState.update { it.copy(pmResolveCategorical = it.pmResolveCategorical.copy(result = null, error = null)) }
    fun submitPmResolveCategorical() {
        val f = _uiState.value.pmResolveCategorical
        if (!f.canSubmit) return
        _uiState.update { it.copy(pmResolveCategorical = it.pmResolveCategorical.copy(submitting = true, error = null, result = null)) }
        viewModelScope.launch {
            val r = repository.pmGroupResolve(f.groupInt!!, f.winningInt!!, f.source)
            _uiState.update { it.copy(pmResolveCategorical = it.pmResolveCategorical.finish(r)) }
            if (r is ApiResult.Success && r.data.applied) loadPmResolutions()
        }
    }

    /** Load the PM resolution audit log (admin). 404 -> empty; failure leaves the list unchanged. */
    fun loadPmResolutions() {
        viewModelScope.launch {
            when (val r = repository.pmResolutions()) {
                is ApiResult.Success -> _uiState.update { it.copy(pmResolutions = r.data) }
                else -> Unit
            }
        }
    }

    /** Sanitize an optional free-text resolution source (alnum + a few separators). */
    private fun source(t: String): String = t.filter { it.isLetterOrDigit() || it == '-' || it == '_' || it == ' ' || it == '.' }.take(40)

    /**
     * Load the STUB discovery browse feeds (open stake requests + auctions). Both return an empty list +
     * a note today (or 404 -> unavailable); a failure just leaves the browse subsections empty.
     */
    fun loadStakeAuctionBrowse() {
        viewModelScope.launch {
            when (val r = repository.stakeRequestsBrowse()) {
                is ApiResult.Success -> _uiState.update { it.copy(stakeRequestsBrowse = r.data) }
                else -> Unit
            }
        }
        viewModelScope.launch {
            when (val r = repository.auctionsBrowse()) {
                is ApiResult.Success -> _uiState.update { it.copy(auctionsBrowse = r.data) }
                else -> Unit
            }
        }
    }

    // ---- Trader staking + auctions (peer mechanisms). Trader-facing; 404 -> un-applied ack. ----

    // stake_request
    fun setStakeReqSymbol(t: String) = _uiState.update { it.copy(stakeRequest = it.stakeRequest.copy(symbolText = digits(t, 9), error = null)) }
    fun setStakeReqMinCollateral(t: String) = _uiState.update { it.copy(stakeRequest = it.stakeRequest.copy(minCollateralText = digits(t, 15), error = null)) }
    fun setStakeReqMaxPct(t: String) = _uiState.update { it.copy(stakeRequest = it.stakeRequest.copy(maxStakePctText = digits(t, 6), error = null)) }
    fun setStakeReqLockup(t: String) = _uiState.update { it.copy(stakeRequest = it.stakeRequest.copy(lockupSecondsText = digits(t, 9), error = null)) }
    fun setStakeReqDuration(t: String) = _uiState.update { it.copy(stakeRequest = it.stakeRequest.copy(durationSecondsText = digits(t, 9), error = null)) }
    fun clearStakeReqResult() = _uiState.update { it.copy(stakeRequest = it.stakeRequest.copy(result = null, error = null)) }
    fun submitStakeRequest() {
        val f = _uiState.value.stakeRequest
        if (!f.canSubmit) return
        _uiState.update { it.copy(stakeRequest = it.stakeRequest.copy(submitting = true, error = null, result = null)) }
        viewModelScope.launch {
            val r = repository.stakeRequest(f.symbolInt, f.minCollateralLong!!, f.maxStakePctLong!!, f.lockupSecondsInt!!, f.durationSecondsInt!!)
            _uiState.update { it.copy(stakeRequest = it.stakeRequest.finish(r)) }
        }
    }

    // stake_offer
    fun setStakeOfferRequestId(t: String) = _uiState.update { it.copy(stakeOffer = it.stakeOffer.copy(requestIdText = digits(t, 18), error = null)) }
    fun setStakeOfferCollateral(t: String) = _uiState.update { it.copy(stakeOffer = it.stakeOffer.copy(collateralText = digits(t, 15), error = null)) }
    fun setStakeOfferPct(t: String) = _uiState.update { it.copy(stakeOffer = it.stakeOffer.copy(stakePctText = digits(t, 6), error = null)) }
    fun clearStakeOfferResult() = _uiState.update { it.copy(stakeOffer = it.stakeOffer.copy(result = null, error = null)) }
    fun submitStakeOffer() {
        val f = _uiState.value.stakeOffer
        if (!f.canSubmit) return
        _uiState.update { it.copy(stakeOffer = it.stakeOffer.copy(submitting = true, error = null, result = null)) }
        viewModelScope.launch {
            val r = repository.stakeOffer(f.requestIdLong!!, f.collateralLong!!, f.stakePctLong!!)
            _uiState.update { it.copy(stakeOffer = it.stakeOffer.finish(r)) }
        }
    }

    // auction_request
    fun setAuctionReqSymbol(t: String) = _uiState.update { it.copy(auctionRequest = it.auctionRequest.copy(symbolText = digits(t, 9), error = null)) }
    fun setAuctionReqQty(t: String) = _uiState.update { it.copy(auctionRequest = it.auctionRequest.copy(qtyText = digits(t, 9), error = null)) }
    fun setAuctionReqReserve(t: String) = _uiState.update { it.copy(auctionRequest = it.auctionRequest.copy(reservePriceText = digits(t, 15), error = null)) }
    fun setAuctionReqDuration(t: String) = _uiState.update { it.copy(auctionRequest = it.auctionRequest.copy(durationSecondsText = digits(t, 9), error = null)) }
    fun clearAuctionReqResult() = _uiState.update { it.copy(auctionRequest = it.auctionRequest.copy(result = null, error = null)) }
    fun submitAuctionRequest() {
        val f = _uiState.value.auctionRequest
        if (!f.canSubmit) return
        _uiState.update { it.copy(auctionRequest = it.auctionRequest.copy(submitting = true, error = null, result = null)) }
        viewModelScope.launch {
            val r = repository.auctionRequest(f.symbolInt, f.qtyInt!!, f.reservePriceLong, f.durationSecondsInt)
            _uiState.update { it.copy(auctionRequest = it.auctionRequest.finish(r)) }
        }
    }

    // auction_bid
    fun setAuctionBidId(t: String) = _uiState.update { it.copy(auctionBid = it.auctionBid.copy(auctionIdText = digits(t, 18), error = null)) }
    fun setAuctionBidPrice(t: String) = _uiState.update { it.copy(auctionBid = it.auctionBid.copy(priceText = digits(t, 15), error = null)) }
    fun setAuctionBidQty(t: String) = _uiState.update { it.copy(auctionBid = it.auctionBid.copy(qtyText = digits(t, 9), error = null)) }
    fun clearAuctionBidResult() = _uiState.update { it.copy(auctionBid = it.auctionBid.copy(result = null, error = null)) }
    fun submitAuctionBid() {
        val f = _uiState.value.auctionBid
        if (!f.canSubmit) return
        _uiState.update { it.copy(auctionBid = it.auctionBid.copy(submitting = true, error = null, result = null)) }
        viewModelScope.launch {
            val r = repository.auctionBid(f.auctionIdLong!!, f.priceLong!!, f.qtyInt!!)
            _uiState.update { it.copy(auctionBid = it.auctionBid.finish(r)) }
        }
    }

    private companion object {
        /** Seed for a fresh shared paper account (matches the Paper screen's baseline). */
        const val PAPER_STARTING_CASH = 100_000L
    }
}
