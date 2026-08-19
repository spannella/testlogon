package com.testlogon.android.feature.markets.alerts.pricealerts

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.exchange.ExchangeRepository
import com.testlogon.android.data.exchange.Instrument
import com.testlogon.android.data.exchange.alerts.PriceAlert
import com.testlogon.android.data.exchange.alerts.PriceAlertDirection
import com.testlogon.android.data.exchange.alerts.PriceAlertsEvaluator
import com.testlogon.android.feature.markets.trade.TradingNotifier
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import java.util.UUID
import javax.inject.Inject

/**
 * Drives the Price Alerts management screen. The alerts list is the persisted evaluator store stream;
 * the VM additionally loads the symbol catalogue for the add-form picker and polls each symbol's last
 * price (reusing [ExchangeRepository], consistent with the on-screen polling elsewhere) so each row
 * shows its live current price. It ALSO runs the evaluator on that same poll so an alert fires + notifies
 * even while the user is sitting on this screen (not only from the Markets list).
 */
@HiltViewModel
class PriceAlertsViewModel @Inject constructor(
    private val evaluator: PriceAlertsEvaluator,
    private val repository: ExchangeRepository,
    private val notifier: TradingNotifier,
) : ViewModel() {

    private val _lastTicks = MutableStateFlow<Map<Int, Long>>(emptyMap())
    private val _instruments = MutableStateFlow<List<Instrument>>(emptyList())

    val uiState: StateFlow<PriceAlertsUiState> =
        combine(evaluator.alerts(), _instruments, _lastTicks) { alerts, instruments, ticks ->
            PriceAlertsUiState(alerts = alerts, instruments = instruments, lastTicks = ticks)
        }.stateIn(viewModelScope, SharingStarted.WhileSubscribed(5_000), PriceAlertsUiState())

    init {
        load()
    }

    private fun load() {
        viewModelScope.launch {
            val instruments = (repository.symbols() as? ApiResult.Success)?.data.orEmpty()
            _instruments.value = instruments
            pollPrices(instruments)
        }
    }

    /** Poll last prices per symbol + run the evaluator while the screen is alive. */
    private suspend fun pollPrices(instruments: List<Instrument>) {
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
            evaluator.evaluate(ticks, instruments).forEach { alert ->
                notifier.notifyTradingAlert(title = alert.title, body = alert.body, distress = false)
            }
            delay(POLL_MS)
        }
    }

    /**
     * Add an alert from the form. [priceText] is the user's decimal input, converted to raw ticks via
     * the symbol scaler ([Instrument.priceScaler]). Returns false (and adds nothing) on invalid input.
     */
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
        )
        viewModelScope.launch { evaluator.add(alert) }
        return true
    }

    fun delete(id: String) = viewModelScope.launch { evaluator.delete(id) }
    fun rearm(id: String) = viewModelScope.launch { evaluator.rearm(id) }

    companion object {
        private const val POLL_MS = 2_000L

        /** Convert a user decimal string into raw ticks: round(decimal * priceScaler). Null if invalid. */
        fun parseTicks(priceText: String, instrument: Instrument): Long? {
            val value = priceText.trim().toDoubleOrNull() ?: return null
            if (value <= 0.0 || value.isNaN() || value.isInfinite()) return null
            val scaler = instrument.priceScaler.coerceAtLeast(1)
            return kotlin.math.round(value * scaler).toLong()
        }
    }
}
