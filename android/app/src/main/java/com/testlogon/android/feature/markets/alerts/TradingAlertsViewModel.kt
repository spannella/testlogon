package com.testlogon.android.feature.markets.alerts

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.data.exchange.alerts.TradingAlert
import com.testlogon.android.data.exchange.alerts.TradingAlertKind
import com.testlogon.android.data.exchange.alerts.TradingAlertsPoller
import com.testlogon.android.feature.markets.trade.TradingNotifier
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import javax.inject.Inject

/**
 * Drives the Trading Alerts screen. The alerts list + unread count are the persisted store streams;
 * the VM additionally polls [TradingAlertsPoller.refresh] on a cadence and raises a system
 * notification for each newly-detected alert (so a fill/liquidation is felt even off-screen).
 */
@HiltViewModel
class TradingAlertsViewModel @Inject constructor(
    private val poller: TradingAlertsPoller,
    private val notifier: TradingNotifier,
) : ViewModel() {

    val alerts: StateFlow<List<TradingAlert>> = poller.alerts()
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5_000), emptyList())

    val unreadCount: StateFlow<Int> = poller.unreadCount()
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5_000), 0)

    init {
        viewModelScope.launch {
            while (isActive) {
                poller.refresh().forEach { alert ->
                    notifier.notifyTradingAlert(
                        title = alert.title,
                        body = alert.body,
                        distress = alert.kind == TradingAlertKind.MARGIN_DISTRESS ||
                            alert.kind == TradingAlertKind.LIQUIDATION,
                    )
                }
                delay(POLL_MS)
            }
        }
    }

    fun markAllRead() = viewModelScope.launch { poller.markAllRead() }
    fun markRead(id: String) = viewModelScope.launch { poller.markRead(id) }
    fun clear() = viewModelScope.launch { poller.clear() }

    private companion object {
        const val POLL_MS = 8_000L
    }
}
