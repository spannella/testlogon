package com.testlogon.android.feature.payouts

import com.testlogon.android.data.payouts.Payout
import java.util.concurrent.ConcurrentHashMap
import javax.inject.Inject
import javax.inject.Singleton

/**
 * AND-260 — process-lifetime cache of loaded payout rows, keyed by payout id.
 *
 * There is NO GET ui/payouts/{id} endpoint, so the detail screen is hydrated from the row the history
 * pager already loaded. The history pager [put]s each page here; the detail ViewModel [get]s by id. A
 * cold deep-link to a detail whose row was never loaded resolves to null -> a "reopen from history"
 * state (R7). Holds financial data in memory only (never persisted to disk; §8); [clear] on logout.
 */
@Singleton
class PayoutCache @Inject constructor() {

    private val byId = ConcurrentHashMap<String, Payout>()

    fun put(payouts: List<Payout>) {
        for (p in payouts) byId[p.payoutId] = p
    }

    fun get(id: String): Payout? = byId[id]

    fun clear() = byId.clear()
}
