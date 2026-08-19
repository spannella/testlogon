package com.testlogon.android.data.exchange.alerts

import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.exchange.FillsFees
import com.testlogon.android.data.exchange.FundingPayments
import com.testlogon.android.data.exchange.Liquidations
import com.testlogon.android.data.exchange.PmResolution
import com.testlogon.android.data.exchange.TradingRepository
import kotlinx.coroutines.flow.Flow
import javax.inject.Inject
import javax.inject.Singleton

/**
 * Derives trading alerts by polling the existing trader feed reads (there is no backend notifications
 * route). One [refresh] fetches the five feeds, runs the pure [TradingAlertsDetector] against the
 * persisted [TradingAlertsMarker], persists the advanced marker + any new alerts, and returns them so a
 * caller can raise system notifications. The very first refresh SEEDS the marker and emits nothing
 * (opening the app never floods with historical events).
 *
 * Feed calls degrade to empty on 404/error (each read already folds 404 -> empty in the repository;
 * here we additionally treat Failure/NetworkError as "no data this tick" so a transient outage doesn't
 * spuriously reset watermarks). The margin read is the one that can hard-fail (403 when not trade-
 * enabled) -> treated as null (no margin-distress signal), which is correct for a non-trading account.
 */
@Singleton
class TradingAlertsPoller @Inject constructor(
    private val trading: TradingRepository,
    private val store: TradingAlertsStore,
    private val clock: AlertClock,
) {
    /** The persisted recent-alerts list (newest first). */
    fun alerts(): Flow<List<TradingAlert>> = store.alerts()

    /** The persisted unread count for the bell badge. */
    fun unreadCount(): Flow<Int> = store.unreadCount()

    suspend fun markAllRead() = store.markAllRead()
    suspend fun markRead(id: String) = store.markRead(id)
    suspend fun clear() = store.clear()

    /**
     * Fetch the feeds, detect new events, persist, and return the freshly-detected alerts (empty on the
     * seeding pass or when nothing new). Never throws.
     */
    suspend fun refresh(): List<TradingAlert> {
        val feeds = TradingFeeds(
            fills = (trading.fillsFees() as? ApiResult.Success)?.data ?: FillsFees(emptyList(), 0),
            liquidations = (trading.liquidations() as? ApiResult.Success)?.data ?: Liquidations(emptyList(), 0),
            funding = (trading.fundingPayments() as? ApiResult.Success)?.data ?: FundingPayments(emptyList(), 0),
            margin = (trading.marginAccount() as? ApiResult.Success)?.data,
            pmResolutions = (trading.pmResolutions() as? ApiResult.Success)?.data ?: emptyList<PmResolution>(),
        )
        val result = TradingAlertsDetector.detect(feeds, store.marker(), clock.nowMs())
        store.setMarker(result.marker)
        if (result.newAlerts.isNotEmpty()) store.addAlerts(result.newAlerts)
        return result.newAlerts
    }
}

/** Injectable clock so the poller + detector are deterministic under test. */
fun interface AlertClock {
    fun nowMs(): Long
}
