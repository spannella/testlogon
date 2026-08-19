package com.testlogon.android.feature.settings.trading

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.network.AppThemeMode
import com.testlogon.android.core.network.AppearancePreferences
import com.testlogon.android.core.network.ThemePreferencesStore
import com.testlogon.android.data.exchange.ExchangeRepository
import com.testlogon.android.data.exchange.Instrument
import com.testlogon.android.data.exchange.TradingUiPrefsStore
import com.testlogon.android.data.exchange.alerts.TradingAlertKind
import com.testlogon.android.data.exchange.alerts.TradingAlertPreferences
import com.testlogon.android.data.exchange.alerts.TradingAlertPrefsStore
import com.testlogon.android.data.exchange.alerts.TradingAlertsPoller
import com.testlogon.android.markets.MarketsWatchlistReset
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.launch
import javax.inject.Inject

/** A pickable market for the default-market selector. */
data class MarketChoice(val symbolId: Int, val symbol: String)

/** Everything the Trading-preferences screen renders. */
data class TradingPreferencesUiState(
    val appearance: AppearancePreferences = AppearancePreferences(),
    val markets: List<MarketChoice> = emptyList(),
    val defaultSymbolId: Int = TradingUiPrefsStore.NO_DEFAULT,
    val alertPrefs: TradingAlertPreferences = TradingAlertPreferences(),
    val notificationsGranted: Boolean = true,
    val resetDone: Boolean = false,
)

/**
 * Presenter for the Trading-preferences settings surface. Composes four device-local preference
 * sources (theme, default-market, per-kind alert toggles, watchlist reset) plus the market catalogue
 * read + the notification-permission read into one [TradingPreferencesUiState].
 *
 * All writes go straight to the singleton stores whose StateFlows the app already observes, so a change
 * here (e.g. theme) re-themes the whole app with no restart. The notification-permission REQUEST is a UI
 * concern (a launcher in the screen); this VM only exposes the read + a refresh hook.
 */
@HiltViewModel
class TradingPreferencesViewModel @Inject constructor(
    private val themeStore: ThemePreferencesStore,
    private val tradingUiPrefs: TradingUiPrefsStore,
    private val alertPrefs: TradingAlertPrefsStore,
    private val repository: ExchangeRepository,
    private val watchlistReset: MarketsWatchlistReset,
    private val alertsPoller: TradingAlertsPoller,
    private val permission: com.testlogon.android.notifications.NotificationPermissionState,
) : ViewModel() {

    private val markets = MutableStateFlow<List<MarketChoice>>(emptyList())
    private val notificationsGranted = MutableStateFlow(permission.isGranted())
    private val resetDone = MutableStateFlow(false)

    val uiState: StateFlow<TradingPreferencesUiState> = combine(
        themeStore.preferences,
        tradingUiPrefs.defaultSymbolId,
        alertPrefs.preferences,
        combine(markets, notificationsGranted, resetDone) { m, granted, reset -> Triple(m, granted, reset) },
    ) { appearance, defaultSym, alerts, (m, granted, reset) ->
        TradingPreferencesUiState(
            appearance = appearance,
            markets = m,
            defaultSymbolId = defaultSym,
            alertPrefs = alerts,
            notificationsGranted = granted,
            resetDone = reset,
        )
    }.stateIn(
        scope = viewModelScope,
        started = SharingStarted.WhileSubscribed(5_000),
        initialValue = TradingPreferencesUiState(notificationsGranted = permission.isGranted()),
    )

    init {
        loadMarkets()
    }

    private fun loadMarkets() {
        viewModelScope.launch {
            when (val result = repository.symbols()) {
                is ApiResult.Success ->
                    markets.value = result.data.map { i: Instrument -> MarketChoice(i.symbolId, i.symbol) }
                else -> Unit // leave empty; the picker degrades to "no markets available"
            }
        }
    }

    fun onModeSelected(mode: AppThemeMode) = themeStore.setMode(mode)

    fun onDefaultMarketSelected(symbolId: Int) {
        if (symbolId == TradingUiPrefsStore.NO_DEFAULT) tradingUiPrefs.clearDefaultSymbol()
        else tradingUiPrefs.setDefaultSymbol(symbolId)
    }

    fun onAlertKindToggled(kind: TradingAlertKind, enabled: Boolean) =
        alertPrefs.setEnabled(kind, enabled)

    /** Re-read the permission state (call after returning from the system prompt). */
    fun refreshNotificationState() {
        notificationsGranted.value = permission.isGranted()
    }

    /** Clear the persisted trading UI prefs (watchlist + default market + alert toggles). */
    fun onResetPrefs() {
        viewModelScope.launch {
            watchlistReset.clearWatchlist()
            tradingUiPrefs.clearDefaultSymbol()
            alertPrefs.reset()
            resetDone.value = true
        }
    }

    fun onResetShown() {
        resetDone.value = false
    }
}
