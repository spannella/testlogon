package com.testlogon.android.feature.markets

import android.content.Context
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.exchange.ExchangeRepository
import com.testlogon.android.data.exchange.Instrument
import com.testlogon.android.data.exchange.TradingRepository
import com.testlogon.android.data.exchange.PmState
import com.testlogon.android.data.exchange.TradingUiPrefsStore
import com.testlogon.android.data.exchange.alerts.TradingAlertKind
import com.testlogon.android.data.exchange.alerts.PriceAlertsEvaluator
import com.testlogon.android.data.exchange.alerts.TradingAlertsPoller
import com.testlogon.android.feature.markets.trade.TradingNotifier
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.stateIn
import dagger.hilt.android.lifecycle.HiltViewModel
import dagger.hilt.android.qualifiers.ApplicationContext
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import javax.inject.Inject

/**
 * Drives [MarketsUiState] from [ExchangeRepository]. Loads the instrument catalogue, then polls each
 * instrument's top-of-book (order-book best bid/ask + last trade) every [POLL_MS] so the list shows
 * live-ish quotes, plus a periodic candle fetch that feeds each row's sparkline + % change. Starred
 * instruments (the watchlist) are persisted in SharedPreferences and surfaced via [MarketsUiState].
 */
@HiltViewModel
class MarketsViewModel @Inject constructor(
    private val repository: ExchangeRepository,
    private val trading: TradingRepository,
    private val prefsStore: TradingUiPrefsStore,
    private val alertsPoller: TradingAlertsPoller,
    private val priceAlerts: PriceAlertsEvaluator,
    private val notifier: TradingNotifier,
    @ApplicationContext appContext: Context,
) : ViewModel() {

    /** Unread trading-alerts count for the header bell badge. */
    val unreadAlerts = alertsPoller.unreadCount()
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5_000), 0)

    private val prefs = appContext.getSharedPreferences(PREFS, Context.MODE_PRIVATE)

    private val _uiState = MutableStateFlow(MarketsUiState(favorites = readFavorites()))
    val uiState: StateFlow<MarketsUiState> = _uiState.asStateFlow()

    /**
     * Per-symbol PM-probe cache for this VM instance: a real [PmState] when the symbol is a binary
     * prediction market, or the [PM_NOT_A_MARKET] sentinel once probed-and-not (so we never re-probe
     * a plain spot/perp). Absent = not yet probed.
     */
    private val pmProbeCache = HashMap<Int, PmState>()

    /**
     * One-shot auto-open of the saved default market. Emits the target symbolId exactly ONCE per app
     * process, only after the catalogue has loaded AND the saved default resolves to a symbol present
     * in the loaded list. The route consumes it and navigates via its existing onOpenSymbol lambda;
     * after consuming, [consumeAutoOpen] flips [autoOpened] so returning to the list shows the full
     * list (no loop; the list is always reachable).
     */
    private val _autoOpenSymbolId = MutableStateFlow<Int?>(null)
    val autoOpenSymbolId: StateFlow<Int?> = _autoOpenSymbolId.asStateFlow()

    /** Called by the route once it has consumed the auto-open target so it never re-fires. */
    fun consumeAutoOpen() {
        _autoOpenSymbolId.value = null
    }

    /**
     * Decide the auto-open target once symbols are loaded: fire only if a default is set, it exists in
     * the loaded catalogue, and the process-lifetime guard has not already fired.
     */
    private fun maybeAutoOpenDefault(instruments: List<Instrument>) {
        if (autoOpened) return
        val defaultId = prefsStore.currentDefaultSymbol()
        if (defaultId == TradingUiPrefsStore.NO_DEFAULT) return
        if (instruments.none { it.symbolId == defaultId }) return
        autoOpened = true
        _autoOpenSymbolId.value = defaultId
    }

    init {
        load()
        pollAlerts()
    }

    /** Poll the derived-alerts feeds while the Markets screen is alive; notify on each new alert. */
    private fun pollAlerts() {
        viewModelScope.launch {
            while (isActive) {
                alertsPoller.refresh().forEach { alert ->
                    notifier.notifyTradingAlert(
                        title = alert.title,
                        body = alert.body,
                        distress = alert.kind == TradingAlertKind.MARGIN_DISTRESS ||
                            alert.kind == TradingAlertKind.LIQUIDATION,
                    )
                }
                delay(ALERTS_POLL_MS)
            }
        }
    }

    fun onRetry() = load()

    /** Toggle an instrument in the persisted watchlist. */
    fun toggleFavorite(symbolId: Int) {
        val next = _uiState.value.favorites.toMutableSet().apply {
            if (!add(symbolId)) remove(symbolId)
        }
        prefs.edit().putStringSet(KEY_FAV, next.map { it.toString() }.toSet()).apply()
        _uiState.update { it.copy(favorites = next) }
    }

    private fun readFavorites(): Set<Int> =
        prefs.getStringSet(KEY_FAV, emptySet()).orEmpty().mapNotNull { it.toIntOrNull() }.toSet()

    private fun load() {
        _uiState.update { it.copy(phase = MarketsUiState.Phase.Loading, errorMessage = null) }
        viewModelScope.launch {
            when (val result = repository.symbols()) {
                is ApiResult.Success -> {
                    val instruments = result.data
                    if (instruments.isEmpty()) {
                        _uiState.update { it.copy(phase = MarketsUiState.Phase.Empty, rows = emptyList()) }
                    } else {
                        _uiState.update {
                            it.copy(
                                phase = MarketsUiState.Phase.Content,
                                rows = instruments.map { i -> MarketRow(instrument = i) },
                            )
                        }
                        maybeAutoOpenDefault(instruments)
                        refreshFundingRates(instruments)
                        probePredictionMarkets(instruments)
                        pollQuotes(instruments)
                    }
                }
                is ApiResult.Failure -> reduceError(result.error.message)
                is ApiResult.NetworkError -> reduceError(OFFLINE_FALLBACK)
            }
        }
    }

    /** Continuously refresh each instrument's top-of-book + sparkline while the VM is alive. */
    private suspend fun pollQuotes(instruments: List<Instrument>) {
        var tick = 0
        while (viewModelScope.isActive) {
            val lastTicks = HashMap<Int, Long>()
            for (instrument in instruments) {
                val book = (repository.orderBook(instrument.symbolId) as? ApiResult.Success)?.data
                val last = (repository.trades(instrument.symbolId) as? ApiResult.Success)
                    ?.data?.firstOrNull()?.price
                val lastPrice = last?.let { instrument.display(it) } ?: book?.mid
                val rawLast = last ?: book?.mid?.let { kotlin.math.round(it).toLong() }
                if (rawLast != null) lastTicks[instrument.symbolId] = rawLast

                // Candle-derived sparkline + % change; refreshed less often than the quote poll.
                var spark: List<Float>? = null
                var changePct: Double? = null
                if (tick % SPARK_EVERY == 0) {
                    val candles = (repository.candles(instrument.symbolId, SPARK_INTERVAL_SEC)
                        as? ApiResult.Success)?.data
                    if (!candles.isNullOrEmpty()) {
                        val closes = candles.map { instrument.display(it.close) }
                        spark = MarketSummaryMath.spark(closes, SPARK_POINTS)
                        changePct = MarketSummaryMath.changePctOf(closes, SPARK_POINTS)
                    }
                }

                _uiState.update { state ->
                    state.copy(
                        rows = state.rows.map { row ->
                            if (row.instrument.symbolId == instrument.symbolId) {
                                row.copy(
                                    lastPrice = lastPrice,
                                    bestBid = book?.bestBid ?: book?.bids?.firstOrNull()?.price,
                                    bestAsk = book?.bestAsk ?: book?.asks?.firstOrNull()?.price,
                                    spark = spark ?: row.spark,
                                    changePct = changePct ?: row.changePct,
                                )
                            } else {
                                row
                            }
                        },
                    )
                }
            }
            priceAlerts.evaluate(lastTicks, instruments).forEach { alert ->
                notifier.notifyTradingAlert(title = alert.title, body = alert.body, distress = false)
            }
            tick++
            delay(POLL_MS)
        }
    }

    /**
     * Read the account's recent perpetual funding payments once and fold the MOST-RECENT applied
     * rate (bps) per symbol onto its row. Degrades silently (empty feed / 404) leaving rates unknown.
     * Only perps carry a funding rate; spot rows are left untouched.
     */
    private fun refreshFundingRates(instruments: List<Instrument>) {
        viewModelScope.launch {
            val payments = (trading.fundingPayments() as? ApiResult.Success)?.data?.payments.orEmpty()
            if (payments.isEmpty()) return@launch
            // Most-recent payment per symbol wins (feed is not guaranteed ordered).
            val latestBySymbol = HashMap<Int, Int>()
            val latestTs = HashMap<Int, Long>()
            for (fp in payments) {
                val prev = latestTs[fp.symbolId]
                if (prev == null || fp.tsNs >= prev) {
                    latestTs[fp.symbolId] = fp.tsNs
                    latestBySymbol[fp.symbolId] = fp.fundingRateBps
                }
            }
            if (latestBySymbol.isEmpty()) return@launch
            _uiState.update { state ->
                state.copy(
                    rows = state.rows.map { row ->
                        val bps = latestBySymbol[row.instrument.symbolId]
                        if (bps != null) row.copy(latestFundingRateBps = bps) else row
                    },
                )
            }
        }
    }

    /**
     * LAZILY probe each listed symbol's binary prediction-market state (there is NO list endpoint) to
     * detect the PREDICTION class + surface implied-YES. Runs one sequential pass over the loaded
     * symbols (no storm), caches the yes/no result per symbolId for the process, and treats any
     * 404/failure as "not a PM" so a non-PM symbol never errors the list. Implied-YES is derived
     * whenever the row already has a last price.
     */
    private fun probePredictionMarkets(instruments: List<Instrument>) {
        viewModelScope.launch {
            for (instrument in instruments) {
                val id = instrument.symbolId
                val cached = pmProbeCache[id]
                val pm = if (cached == null) {
                    when (val r = trading.pmState(id)) {
                        is ApiResult.Success -> {
                            val isPm = r.data.isBinary
                            pmProbeCache[id] = if (isPm) r.data else PM_NOT_A_MARKET
                            if (isPm) r.data else null
                        }
                        // 404/error/offline -> definitively treat as not-a-PM and cache so we don't re-probe.
                        else -> { pmProbeCache[id] = PM_NOT_A_MARKET; null }
                    }
                } else if (cached === PM_NOT_A_MARKET) {
                    null
                } else {
                    cached
                }
                _uiState.update { state ->
                    state.copy(
                        rows = state.rows.map { row ->
                            if (row.instrument.symbolId == id) {
                                val impliedRaw = pm?.impliedYes(
                                    row.lastPrice?.let { kotlin.math.round(it).toLong() },
                                )
                                row.copy(
                                    isPrediction = pm != null,
                                    impliedYes = impliedRaw ?: row.impliedYes,
                                )
                            } else {
                                row
                            }
                        },
                    )
                }
            }
        }
    }

    private fun reduceError(message: String) {
        _uiState.update {
            if (it.rows.isNotEmpty()) {
                it.copy(phase = MarketsUiState.Phase.Content)
            } else {
                it.copy(phase = MarketsUiState.Phase.Error, errorMessage = message)
            }
        }
    }

    private companion object {
        /** Sentinel meaning "probed, and this symbol is NOT a prediction market" (cache negatives). */
        private val PM_NOT_A_MARKET = PmState(
            symbolId = -1,
            isBinary = false,
            resolved = false,
            outcomeYes = null,
            faceValue = 0L,
            resolverId = "",
        )
        /** Process-lifetime guard so the default-market auto-open fires at most once per app launch. */
        @Volatile
        private var autoOpened = false
        const val POLL_MS = 2_000L
        const val SPARK_EVERY = 5          // refresh sparkline/change every ~10s
        const val SPARK_INTERVAL_SEC = 60
        const val SPARK_POINTS = 30
        const val OFFLINE_FALLBACK = "Couldn't reach the market-data service. Tap retry."
        const val PREFS = "markets_prefs"
        const val KEY_FAV = "favorites"
        const val ALERTS_POLL_MS = 8_000L
    }
}
