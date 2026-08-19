package com.testlogon.android.data.exchange

import android.content.Context
import android.content.SharedPreferences
import dagger.hilt.android.qualifiers.ApplicationContext
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import javax.inject.Inject
import javax.inject.Singleton

/**
 * Device-local trading-UI preferences that are not the watchlist (which lives in the markets_prefs
 * SharedPreferences owned by MarketsViewModel) and not the theme. Today this holds the user's default
 * market — the symbol the markets/trade landing should prefer as its initial selection.
 *
 * Persisted as the symbolId under [KEY_DEFAULT_SYMBOL] (== "md_default_symbol") in its own
 * SharedPreferences file, exposed as a [StateFlow] so the Trading-preferences screen reflects writes
 * immediately. Unset (== [NO_DEFAULT]) means "no preference — fall back to the catalogue's first".
 */
@Singleton
class TradingUiPrefsStore @Inject constructor(
    @ApplicationContext context: Context,
) {
    private val prefs: SharedPreferences =
        context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)

    private val _defaultSymbolId = MutableStateFlow(read())

    /** The persisted default symbolId, or [NO_DEFAULT] when the user has not chosen one. */
    val defaultSymbolId: StateFlow<Int> = _defaultSymbolId.asStateFlow()

    fun setDefaultSymbol(symbolId: Int) {
        prefs.edit().putInt(KEY_DEFAULT_SYMBOL, symbolId).apply()
        _defaultSymbolId.value = symbolId
    }

    fun clearDefaultSymbol() {
        prefs.edit().remove(KEY_DEFAULT_SYMBOL).apply()
        _defaultSymbolId.value = NO_DEFAULT
    }

    /** Snapshot read (for a landing screen that just wants the initial symbol once). */
    fun currentDefaultSymbol(): Int = _defaultSymbolId.value

    private fun read(): Int = prefs.getInt(KEY_DEFAULT_SYMBOL, NO_DEFAULT)

    companion object {
        const val NO_DEFAULT = -1
        private const val PREFS_NAME = "tl_trading_ui_prefs"
        // Wire key kept identical to the web/native contract in the ticket.
        const val KEY_DEFAULT_SYMBOL = "md_default_symbol"
    }
}
