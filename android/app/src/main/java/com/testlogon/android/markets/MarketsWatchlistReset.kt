package com.testlogon.android.markets

import android.content.Context
import dagger.hilt.android.qualifiers.ApplicationContext
import javax.inject.Inject
import javax.inject.Singleton

/**
 * A tiny injectable seam that clears the markets watchlist SharedPreferences (the starred instruments
 * persisted by MarketsViewModel under "markets_prefs" / "favorites"). Extracted so the Trading-
 * preferences "reset" control can wipe the watchlist without depending on the markets feature/VM.
 *
 * The key/name are kept byte-identical to MarketsViewModel's constants so a reset here and a read there
 * agree; if those ever move to a shared store this class collapses into it.
 */
@Singleton
class MarketsWatchlistReset @Inject constructor(
    @ApplicationContext private val context: Context,
) {
    fun clearWatchlist() {
        context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
            .edit()
            .remove(KEY_FAV)
            .apply()
    }

    private companion object {
        const val PREFS = "markets_prefs"
        const val KEY_FAV = "favorites"
    }
}
