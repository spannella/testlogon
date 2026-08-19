package com.testlogon.android.feature.home

import android.content.Context
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.custody.CustodyBalances
import com.testlogon.android.data.custody.CustodyRepository
import com.testlogon.android.data.exchange.ExchangeRepository
import com.testlogon.android.data.exchange.FillsFees
import com.testlogon.android.data.exchange.Instrument
import com.testlogon.android.data.exchange.MarginAccount
import com.testlogon.android.data.exchange.OrderSide
import com.testlogon.android.data.exchange.PriceMap
import com.testlogon.android.data.exchange.SpotBalance
import com.testlogon.android.data.exchange.TradingRepository
import com.testlogon.android.feature.markets.MarketSummaryMath
import dagger.hilt.android.lifecycle.HiltViewModel
import dagger.hilt.android.qualifiers.ApplicationContext
import kotlinx.coroutines.async
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import java.util.Locale
import javax.inject.Inject
import kotlin.math.round

/**
 * Read-only Trading Home / Dashboard ViewModel. Fans the independent card reads out in parallel
 * (custody balance, spot balance, margin account, indicative prices, recent fills, and the instrument
 * catalogue used to resolve the persisted watchlist) and folds them into a single [HomeUiState]. Each
 * card degrades on its own: any failed/undeployed source renders as empty/unavailable/UNKNOWN without
 * dropping the others. No writes, no money movement.
 *
 * The watchlist is the SAME persisted set the Markets screen owns (SharedPreferences "markets_prefs" /
 * "favorites"); the checklist "all set" dismissal persists in this feature's own prefs so re-opening
 * Home keeps the collapsed state.
 */
@HiltViewModel
class HomeViewModel @Inject constructor(
    private val custody: CustodyRepository,
    private val trading: TradingRepository,
    private val exchange: ExchangeRepository,
    @ApplicationContext appContext: Context,
) : ViewModel() {

    private val marketsPrefs = appContext.getSharedPreferences(MARKETS_PREFS, Context.MODE_PRIVATE)
    private val homePrefs = appContext.getSharedPreferences(HOME_PREFS, Context.MODE_PRIVATE)

    private val _uiState = MutableStateFlow(HomeUiState())
    val uiState: StateFlow<HomeUiState> = _uiState.asStateFlow()

    init {
        refresh()
    }

    fun refresh() {
        _uiState.value = HomeUiState(loading = true)
        viewModelScope.launch {
            _uiState.value = load()
        }
    }

    /** Persist the user's dismissal of the "all set" onboarding banner (survives re-open). */
    fun dismissOnboarding() {
        homePrefs.edit().putBoolean(KEY_ONBOARDING_DISMISSED, true).apply()
        _uiState.update { it.copy(onboarding = it.onboarding.copy(dismissed = true)) }
    }

    private suspend fun load(): HomeUiState = coroutineScope {
        val favorites = readFavorites()
        val custodyDef = async { custody.getBalance() }
        val spotDef = async { trading.spotBalance() }
        val marginDef = async { trading.marginAccount() }
        val pricesDef = async { trading.getPrices() }
        val fillsDef = async { trading.fillsFees() }
        val symbolsDef = async { exchange.symbols() }

        val custodyRes = custodyDef.await()
        val spotRes = spotDef.await()
        val marginRes = marginDef.await()
        val pricesRes = pricesDef.await()
        val fillsRes = fillsDef.await()
        val symbolsRes = symbolsDef.await()

        val prices = (pricesRes as? ApiResult.Success)?.data ?: PriceMap.unavailable()
        val symbols = (symbolsRes as? ApiResult.Success)?.data.orEmpty()

        val portfolio = buildPortfolio(custodyRes, spotRes, marginRes, prices)
        val watchlist = buildWatchlist(favorites, symbols)
        val activity = buildActivity(fillsRes, symbols)
        val onboarding = buildOnboarding(custodyRes, spotRes, marginRes, fillsRes)

        HomeUiState(
            loading = false,
            portfolio = portfolio,
            watchlist = watchlist,
            activity = activity,
            onboarding = onboarding,
        )
    }

    // ---- Portfolio summary card ----

    private fun buildPortfolio(
        custodyRes: ApiResult<CustodyBalances>,
        spotRes: ApiResult<SpotBalance>,
        marginRes: ApiResult<MarginAccount>,
        prices: PriceMap,
    ): HomePortfolio {
        val pm = prices.takeIf { !it.unavailable && it.hasPrices }
        val custodyOk = custodyRes is ApiResult.Success
        val spotOk = spotRes is ApiResult.Success
        val marginOk = marginRes is ApiResult.Success
        if (!custodyOk && !spotOk && !marginOk) {
            return HomePortfolio(loading = false, unavailable = true)
        }

        // USD-normalized equity when priced; otherwise a coarse source-native sum (its own caveat).
        var equityUsd = 0.0
        var nativeSum = 0.0
        var valuedSomething = false

        (custodyRes as? ApiResult.Success)?.data?.rows?.filter { it.amount > 0.0 }?.forEach { row ->
            nativeSum += row.amount
            pm?.priceFor(row.symbol)?.let { equityUsd += it * row.amount; valuedSomething = true }
        }
        (spotRes as? ApiResult.Success)?.data?.assets?.filter { it.balance > 0L }?.forEach { a ->
            nativeSum += a.balance.toDouble()
            a.symbol.takeIf { it.isNotBlank() }?.let { pm?.priceFor(it) }
                ?.let { equityUsd += it * a.balance.toDouble(); valuedSomething = true }
        }
        val margin = (marginRes as? ApiResult.Success)?.data
        if (margin != null) {
            nativeSum += margin.balance.toDouble()
            (pm?.priceFor("USDC") ?: pm?.priceFor("USD"))
                ?.let { equityUsd += it * margin.balance.toDouble(); valuedSomething = true }
        }

        val priced = pm != null && valuedSomething
        val equityText = if (priced) formatUsd(equityUsd) else formatQty(round(nativeSum).toLong())
        return HomePortfolio(
            loading = false,
            unavailable = false,
            equityText = equityText,
            priced = priced,
            pricesStub = priced && prices.stub,
            available = margin?.availableBalance,
            unrealizedPnl = margin?.position?.takeIf { it.qty != 0L }?.unrealizedPnl,
        )
    }

    // ---- Watchlist snapshot card ----

    private fun buildWatchlist(favorites: Set<Int>, symbols: List<Instrument>): HomeWatchlist {
        if (favorites.isEmpty()) {
            return HomeWatchlist(loading = false, hasStarred = false, rows = emptyList())
        }
        val byId = symbols.associateBy { it.symbolId }
        val rows = favorites.take(MAX_WATCH).sorted().map { id ->
            val inst = byId[id]
            HomeWatchRow(
                symbolId = id,
                symbol = inst?.symbol ?: fallbackSymbol(id),
                lastPriceText = null,
                changePct = null,
            )
        }
        return HomeWatchlist(loading = false, hasStarred = true, rows = rows)
    }

    /**
     * A best-effort per-row quote refresh (last trade / mid + candle % change), run after the initial
     * frame so the watchlist snapshot shows live-ish prices. Each row is independent: a failed read
     * simply leaves that row at "--". Called once from the screen's LaunchedEffect via [enrichWatchlist].
     */
    fun enrichWatchlist() {
        val rows = _uiState.value.watchlist.rows
        if (rows.isEmpty()) return
        viewModelScope.launch {
            rows.forEach { row ->
                val id = row.symbolId
                val last = (exchange.trades(id) as? ApiResult.Success)?.data?.firstOrNull()?.price
                val book = (exchange.orderBook(id) as? ApiResult.Success)?.data
                val rawPrice = last ?: book?.mid?.let { round(it).toLong() }
                val candles = (exchange.candles(id, SPARK_INTERVAL_SEC) as? ApiResult.Success)?.data
                val changePct = if (!candles.isNullOrEmpty()) {
                    MarketSummaryMath.changePctOf(candles.map { it.close.toDouble() }, SPARK_POINTS)
                } else {
                    null
                }
                val priceText = rawPrice?.let { formatQty(it) }
                _uiState.update { state ->
                    state.copy(
                        watchlist = state.watchlist.copy(
                            rows = state.watchlist.rows.map {
                                if (it.symbolId == id) {
                                    it.copy(lastPriceText = priceText ?: it.lastPriceText, changePct = changePct ?: it.changePct)
                                } else {
                                    it
                                }
                            },
                        ),
                    )
                }
            }
        }
    }

    // ---- Recent activity card ----

    private fun buildActivity(fillsRes: ApiResult<FillsFees>, symbols: List<Instrument>): HomeActivity {
        return when (fillsRes) {
            is ApiResult.Success -> {
                val names = symbols.associate { it.symbolId to it.symbol }
                val rows = fillsRes.data.fills.sortedByDescending { it.tsNs }.take(MAX_ACTIVITY).map { f ->
                    val isBuy = f.side == OrderSide.BUY
                    HomeActivityRow(
                        symbol = names[f.symbolId] ?: fallbackSymbol(f.symbolId),
                        sideLabel = when (f.side) {
                            OrderSide.BUY -> "Buy"
                            OrderSide.SELL -> "Sell"
                            else -> "--"
                        },
                        isBuy = isBuy,
                        qtyText = formatQty(f.qty),
                        priceText = formatQty(f.price),
                    )
                }
                HomeActivity(loading = false, unavailable = false, rows = rows)
            }
            is ApiResult.Failure -> HomeActivity(loading = false, unavailable = true)
            is ApiResult.NetworkError -> HomeActivity(loading = false, unavailable = true)
        }
    }

    // ---- Getting-started checklist ----

    private fun buildOnboarding(
        custodyRes: ApiResult<CustodyBalances>,
        spotRes: ApiResult<SpotBalance>,
        marginRes: ApiResult<MarginAccount>,
        fillsRes: ApiResult<FillsFees>,
    ): HomeOnboarding {
        val custodyFunded: Boolean? = (custodyRes as? ApiResult.Success)?.data
            ?.let { it.rows.any { r -> r.amount > 0.0 } }
        // trading funded = spot OR margin available > 0. Only UNKNOWN when BOTH reads were unavailable.
        val spotFunded = (spotRes as? ApiResult.Success)?.data?.assets?.any { it.available > 0L || it.balance > 0L }
        val marginFunded = (marginRes as? ApiResult.Success)?.data?.let { it.availableBalance > 0L || it.balance > 0L }
        val tradingFunded: Boolean? = when {
            spotFunded == null && marginFunded == null -> null
            spotFunded == true || marginFunded == true -> true
            else -> false
        }
        val hasFirstTrade: Boolean? = (fillsRes as? ApiResult.Success)?.data?.let { it.fills.isNotEmpty() }

        val steps = HomeOnboardingDeriver.derive(
            OnboardingInputs(
                custodyFunded = custodyFunded,
                tradingFunded = tradingFunded,
                hasFirstTrade = hasFirstTrade,
            ),
        )
        return HomeOnboarding(
            loading = false,
            steps = steps,
            dismissed = homePrefs.getBoolean(KEY_ONBOARDING_DISMISSED, false),
        )
    }

    // ---- helpers ----

    private fun readFavorites(): Set<Int> =
        marketsPrefs.getStringSet(KEY_FAV, emptySet()).orEmpty().mapNotNull { it.toIntOrNull() }.toSet()

    private fun formatUsd(v: Double): String = "$" + String.format(Locale.US, "%,.2f", v)

    private fun formatQty(v: Long): String = String.format(Locale.US, "%,d", v)

    private fun fallbackSymbol(symbolId: Int): String = when (symbolId) {
        1 -> "BTCUSDC"
        2 -> "ETHUSDC"
        3 -> "SOLUSDC"
        else -> "#" + symbolId
    }

    private companion object {
        const val MARKETS_PREFS = "markets_prefs"
        const val KEY_FAV = "favorites"
        const val HOME_PREFS = "home_prefs"
        const val KEY_ONBOARDING_DISMISSED = "onboarding_all_set_dismissed"
        const val MAX_WATCH = 6
        const val MAX_ACTIVITY = 5
        const val SPARK_INTERVAL_SEC = 60
        const val SPARK_POINTS = 30
    }
}
