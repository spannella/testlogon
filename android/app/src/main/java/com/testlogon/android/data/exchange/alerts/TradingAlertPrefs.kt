package com.testlogon.android.data.exchange.alerts

import android.content.Context
import android.content.SharedPreferences
import dagger.hilt.android.qualifiers.ApplicationContext
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import javax.inject.Inject
import javax.inject.Singleton

/**
 * Per-kind opt-out preferences for derived trading alerts. Each of the five [TradingAlertKind]s can be
 * independently disabled; the [TradingAlertsPoller]/[TradingAlertsDetector] read [enabledKinds] and
 * skip emitting (but still advance their watermarks for) any disabled kind, so toggling a kind off then
 * on never back-fires the historical events it missed while off.
 *
 * Device-local SharedPreferences (like the watchlist + theme prefs) so the value is available
 * synchronously and survives with no backend round-trip. Default is ALL-ON (backward-compatible: an
 * account that never opened this screen behaves exactly as before).
 */
data class TradingAlertPreferences(
    val enabled: Map<TradingAlertKind, Boolean> = TradingAlertKind.entries.associateWith { true },
) {
    fun isEnabled(kind: TradingAlertKind): Boolean = enabled[kind] ?: true

    /** The set of currently-enabled kinds (what the detector filters against). */
    val enabledKinds: Set<TradingAlertKind>
        get() = TradingAlertKind.entries.filterTo(HashSet()) { isEnabled(it) }
}

@Singleton
class TradingAlertPrefsStore @Inject constructor(
    @ApplicationContext context: Context,
) {
    private val prefs: SharedPreferences =
        context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)

    private val _preferences = MutableStateFlow(read())

    /** Hot stream of the current per-kind toggles. Re-emits on every write. */
    val preferences: StateFlow<TradingAlertPreferences> = _preferences.asStateFlow()

    /** Snapshot of the enabled-kind set for the poller (no Flow collection needed on the hot path). */
    fun enabledKinds(): Set<TradingAlertKind> = _preferences.value.enabledKinds

    fun setEnabled(kind: TradingAlertKind, enabled: Boolean) {
        prefs.edit().putBoolean(key(kind), enabled).apply()
        _preferences.value = _preferences.value.copy(
            enabled = _preferences.value.enabled.toMutableMap().apply { put(kind, enabled) },
        )
    }

    /** Reset every kind back to the default (all-on). */
    fun reset() {
        prefs.edit().apply { TradingAlertKind.entries.forEach { remove(key(it)) } }.apply()
        _preferences.value = TradingAlertPreferences()
    }

    private fun read(): TradingAlertPreferences =
        TradingAlertPreferences(
            enabled = TradingAlertKind.entries.associateWith { prefs.getBoolean(key(it), true) },
        )

    private fun key(kind: TradingAlertKind) = KEY_PREFIX + kind.name

    private companion object {
        const val PREFS_NAME = "tl_trading_alert_prefs"
        const val KEY_PREFIX = "alert_kind_"
    }
}
