package com.testlogon.android.feature.markets.alerts.pricealerts

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.exchange.ExchangeRepository
import com.testlogon.android.data.exchange.Instrument
import com.testlogon.android.data.exchange.alerts.PriceAlert
import com.testlogon.android.data.exchange.alerts.PriceAlertDirection
import com.testlogon.android.data.exchange.alerts.PriceAlertSubject
import com.testlogon.android.data.exchange.alerts.PriceAlertsEvaluator
import com.testlogon.android.data.strategies.StrategiesRepository
import com.testlogon.android.data.strategies.Strategy
import com.testlogon.android.data.tokens.Token
import com.testlogon.android.data.tokens.TokensRepository
import com.testlogon.android.feature.markets.trade.TradingNotifier
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import java.util.UUID
import javax.inject.Inject

@HiltViewModel
class PriceAlertsViewModel @Inject constructor(
    private val evaluator: PriceAlertsEvaluator,
    private val repository: ExchangeRepository,
    private val tokensRepository: TokensRepository,
    private val strategiesRepository: StrategiesRepository,
    private val notifier: TradingNotifier,
) : ViewModel() {

    private val _lastTicks = MutableStateFlow<Map<Int, Long>>(emptyMap())
    private val _instruments = MutableStateFlow<List<Instrument>>(emptyList())
    private val _tokens = MutableStateFlow<List<Token>>(emptyList())
    private val _strategies = MutableStateFlow<List<Strategy>>(emptyList())
    private val _tokenPrices = MutableStateFlow<Map<String, Long>>(emptyMap())
    private val _strategyNavs = MutableStateFlow<Map<String, Long>>(emptyMap())

    private val catalogues = combine(_instruments, _tokens, _strategies) { instruments, tokens, strategies ->
        Triple(instruments, tokens, strategies)
    }
    private val liveValues = combine(_lastTicks, _tokenPrices, _strategyNavs) { ticks, tokenPx, navs ->
        Triple(ticks, tokenPx, navs)
    }

    val uiState: StateFlow<PriceAlertsUiState> =
        combine(evaluator.alerts(), catalogues, liveValues) { alerts, cat, live ->
            PriceAlertsUiState(
                alerts = alerts,
                instruments = cat.first,
                tokens = cat.second,
                strategies = cat.third,
                lastTicks = live.first,
                tokenPriceById = live.second,
                strategyNavById = live.third,
            )
        }.stateIn(viewModelScope, SharingStarted.WhileSubscribed(5_000), PriceAlertsUiState())

    init {
        load()
    }

    private fun load() {
        viewModelScope.launch {
            val instruments = (repository.symbols() as? ApiResult.Success)?.data.orEmpty()
            _instruments.value = instruments
            _tokens.value = (tokensRepository.market() as? ApiResult.Success)?.data.orEmpty()
            _strategies.value = (strategiesRepository.market() as? ApiResult.Success)?.data.orEmpty()
            poll(instruments)
        }
    }

    private suspend fun poll(instruments: List<Instrument>) {
        while (viewModelScope.isActive) {
            val ticks = HashMap<Int, Long>()
            for (instrument in instruments) {
                val last = (repository.trades(instrument.symbolId) as? ApiResult.Success)
                    ?.data?.firstOrNull()?.price
                val book = (repository.orderBook(instrument.symbolId) as? ApiResult.Success)?.data
                val raw = last ?: book?.mid?.let { kotlin.math.round(it).toLong() }
                if (raw != null) ticks[instrument.symbolId] = raw
            }
            _lastTicks.update { ticks.ifEmpty { it } }

            val tokens = (tokensRepository.market() as? ApiResult.Success)?.data.orEmpty()
            if (tokens.isNotEmpty()) _tokens.value = tokens
            val tokenPrices = HashMap<String, Long>()
            val tokenLabels = HashMap<String, String>()
            tokens.forEach { t ->
                t.clearingPrice?.let { tokenPrices[t.tokenId] = it }
                tokenLabels[t.tokenId] = t.ticker.ifBlank { t.name }
            }
            if (tokenPrices.isNotEmpty()) _tokenPrices.update { tokenPrices }

            val strategies = (strategiesRepository.market() as? ApiResult.Success)?.data.orEmpty()
            if (strategies.isNotEmpty()) _strategies.value = strategies
            val navs = HashMap<String, Long>()
            val strategyLabels = HashMap<String, String>()
            strategies.forEach { s ->
                s.navPerUnit?.let { navs[s.strategyId] = it }
                strategyLabels[s.strategyId] = s.name
            }
            if (navs.isNotEmpty()) _strategyNavs.update { navs }

            (evaluator.evaluate(ticks, instruments) +
                evaluator.evaluateSubjects(PriceAlertSubject.TOKEN, tokenPrices, tokenLabels) +
                evaluator.evaluateSubjects(PriceAlertSubject.STRATEGY, navs, strategyLabels))
                .forEach { alert ->
                    notifier.notifyTradingAlert(title = alert.title, body = alert.body, distress = false)
                }

            delay(POLL_MS)
        }
    }

    fun add(symbolId: Int, direction: PriceAlertDirection, priceText: String, note: String?): Boolean {
        val instrument = _instruments.value.firstOrNull { it.symbolId == symbolId } ?: return false
        val ticks = parseTicks(priceText, instrument) ?: return false
        val alert = PriceAlert(
            id = UUID.randomUUID().toString(),
            symbolId = symbolId,
            direction = direction,
            priceTicks = ticks,
            note = note?.trim()?.takeIf { it.isNotEmpty() },
            createdTs = System.currentTimeMillis(),
            subject = PriceAlertSubject.SYMBOL,
            subjectId = symbolId.toString(),
            subjectLabel = instrument.symbol,
        )
        viewModelScope.launch { evaluator.add(alert) }
        return true
    }

    fun addToken(tokenId: String, direction: PriceAlertDirection, priceText: String, note: String?): Boolean {
        val token = _tokens.value.firstOrNull { it.tokenId == tokenId } ?: return false
        val cents = parseCents(priceText) ?: return false
        viewModelScope.launch {
            evaluator.add(
                PriceAlert(
                    id = UUID.randomUUID().toString(),
                    symbolId = -1,
                    direction = direction,
                    priceTicks = cents,
                    note = note?.trim()?.takeIf { it.isNotEmpty() },
                    createdTs = System.currentTimeMillis(),
                    subject = PriceAlertSubject.TOKEN,
                    subjectId = tokenId,
                    subjectLabel = token.ticker.ifBlank { token.name },
                ),
            )
        }
        return true
    }

    fun addStrategy(strategyId: String, direction: PriceAlertDirection, priceText: String, note: String?): Boolean {
        val strategy = _strategies.value.firstOrNull { it.strategyId == strategyId } ?: return false
        val cents = parseCents(priceText) ?: return false
        viewModelScope.launch {
            evaluator.add(
                PriceAlert(
                    id = UUID.randomUUID().toString(),
                    symbolId = -1,
                    direction = direction,
                    priceTicks = cents,
                    note = note?.trim()?.takeIf { it.isNotEmpty() },
                    createdTs = System.currentTimeMillis(),
                    subject = PriceAlertSubject.STRATEGY,
                    subjectId = strategyId,
                    subjectLabel = strategy.name,
                ),
            )
        }
        return true
    }

    fun delete(id: String) = viewModelScope.launch { evaluator.delete(id) }
    fun rearm(id: String) = viewModelScope.launch { evaluator.rearm(id) }

    companion object {
        private const val POLL_MS = 2_000L

        fun parseTicks(priceText: String, instrument: Instrument): Long? {
            val value = priceText.trim().toDoubleOrNull() ?: return null
            if (value <= 0.0 || value.isNaN() || value.isInfinite()) return null
            val scaler = instrument.priceScaler.coerceAtLeast(1)
            return kotlin.math.round(value * scaler).toLong()
        }

        fun parseCents(priceText: String): Long? {
            val value = priceText.trim().toDoubleOrNull() ?: return null
            if (value <= 0.0 || value.isNaN() || value.isInfinite()) return null
            return kotlin.math.round(value * 100.0).toLong()
        }
    }
}
