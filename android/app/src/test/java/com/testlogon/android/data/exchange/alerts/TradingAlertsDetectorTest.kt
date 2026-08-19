package com.testlogon.android.data.exchange.alerts

import com.testlogon.android.data.exchange.FillFee
import com.testlogon.android.data.exchange.FillsFees
import com.testlogon.android.data.exchange.FundingPayment
import com.testlogon.android.data.exchange.FundingPayments
import com.testlogon.android.data.exchange.Liquidation
import com.testlogon.android.data.exchange.Liquidations
import com.testlogon.android.data.exchange.Liquidity
import com.testlogon.android.data.exchange.MarginAccount
import com.testlogon.android.data.exchange.OrderSide
import com.testlogon.android.data.exchange.PmResolution
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Unit coverage for the pure [TradingAlertsDetector.detect] new-event logic: seeding (first fetch fires
 * nothing), tsNs-watermark de-dupe on the three timestamp feeds, level-triggered margin distress, PM
 * list-growth detection, and marker advancement / stability across repeated identical polls.
 */
class TradingAlertsDetectorTest {

    private val NOW = 1_000L

    private fun fill(ts: Long, sym: Int = 1, price: Long = 100, qty: Long = 5, fee: Long = 1) =
        FillFee(sym, price, qty, OrderSide.BUY, Liquidity.MAKER, fee, 0, ts)

    private fun liq(ts: Long, sym: Int = 2, qty: Long = 3, mark: Long = 3000, pnl: Long = -50) =
        Liquidation(sym, qty, mark, pnl, 2, ts)

    private fun fund(ts: Long, sym: Int = 1, pay: Long = 10, received: Boolean = true) =
        FundingPayment(sym, 12, 100, 5, pay, received, ts)

    private fun margin(level: Int, liquidating: Boolean) =
        MarginAccount(1000, 900, 100, 0, null, level, liquidating, "MP")

    private fun pm(sym: Int, ts: Long) =
        PmResolution(sym, null, null, "yes", "resolver", ts, "engine")

    private fun feeds(
        fills: List<FillFee> = emptyList(),
        liqs: List<Liquidation> = emptyList(),
        funds: List<FundingPayment> = emptyList(),
        margin: MarginAccount? = null,
        pms: List<PmResolution> = emptyList(),
    ) = TradingFeeds(
        fills = FillsFees(fills, fills.size),
        liquidations = Liquidations(liqs, liqs.size),
        funding = FundingPayments(funds, funds.size),
        margin = margin,
        pmResolutions = pms,
    )

    // ---- seeding ----

    @Test
    fun firstFetch_seedsAndEmitsNothing() {
        val f = feeds(
            fills = listOf(fill(ts = 50), fill(ts = 70)),
            liqs = listOf(liq(ts = 40)),
            funds = listOf(fund(ts = 30)),
            margin = margin(level = 2, liquidating = false),
            pms = listOf(pm(1, 10), pm(2, 20)),
        )
        val r = TradingAlertsDetector.detect(f, TradingAlertsMarker(), NOW)

        assertTrue("first fetch must fire no alerts", r.newAlerts.isEmpty())
        assertTrue(r.marker.seeded)
        // Watermarks adopt the current maxima so history never re-fires.
        assertEquals(70L, r.marker.lastFillTsNs)
        assertEquals(40L, r.marker.lastLiquidationTsNs)
        assertEquals(30L, r.marker.lastFundingTsNs)
        assertEquals(2, r.marker.marginDistressLevel)
        assertEquals(2, r.marker.pmResolutionCount)
    }

    @Test
    fun seededThenIdenticalFeeds_emitNothing() {
        val f = feeds(fills = listOf(fill(ts = 70)), margin = margin(0, false))
        val seeded = TradingAlertsDetector.detect(f, TradingAlertsMarker(), NOW).marker
        val r = TradingAlertsDetector.detect(f, seeded, NOW)
        assertTrue(r.newAlerts.isEmpty())
    }

    // ---- fills ----

    @Test
    fun newFill_beyondWatermark_fires_onlyForNewer() {
        val seed = feeds(fills = listOf(fill(ts = 70)))
        val marker = TradingAlertsDetector.detect(seed, TradingAlertsMarker(), NOW).marker

        val next = feeds(fills = listOf(fill(ts = 70), fill(ts = 80), fill(ts = 90)))
        val r = TradingAlertsDetector.detect(next, marker, NOW)

        assertEquals(2, r.newAlerts.size)
        assertTrue(r.newAlerts.all { it.kind == TradingAlertKind.FILL })
        // Emitted oldest-new first (chronological read order).
        assertEquals(80L, r.newAlerts.first().eventTsNs)
        assertEquals(90L, r.newAlerts.last().eventTsNs)
        assertEquals(90L, r.marker.lastFillTsNs)
    }

    @Test
    fun sameFillTwice_dedupesById() {
        val seed = feeds()
        val marker = TradingAlertsDetector.detect(seed, TradingAlertsMarker(), NOW).marker
        val next = feeds(fills = listOf(fill(ts = 80)))
        val first = TradingAlertsDetector.detect(next, marker, NOW)
        assertEquals(1, first.newAlerts.size)
        // Re-poll with the same feed + advanced marker: watermark suppresses it.
        val second = TradingAlertsDetector.detect(next, first.marker, NOW)
        assertTrue(second.newAlerts.isEmpty())
    }

    // ---- liquidations + funding ----

    @Test
    fun newLiquidationAndFunding_fire() {
        val marker = TradingAlertsDetector.detect(feeds(), TradingAlertsMarker(), NOW).marker
        val next = feeds(liqs = listOf(liq(ts = 5)), funds = listOf(fund(ts = 5, pay = -20, received = false)))
        val r = TradingAlertsDetector.detect(next, marker, NOW)
        assertEquals(setOf(TradingAlertKind.LIQUIDATION, TradingAlertKind.FUNDING), r.newAlerts.map { it.kind }.toSet())
        assertTrue(r.newAlerts.first { it.kind == TradingAlertKind.FUNDING }.body.contains("Paid"))
    }

    // ---- margin distress (level-triggered) ----

    @Test
    fun marginDistress_firesOnRisingEdge_notWhileElevated() {
        var marker = TradingAlertsDetector.detect(feeds(margin = margin(0, false)), TradingAlertsMarker(), NOW).marker

        // Rise 0 -> 2 fires once.
        val rise = TradingAlertsDetector.detect(feeds(margin = margin(2, false)), marker, NOW)
        assertEquals(1, rise.newAlerts.size)
        assertEquals(TradingAlertKind.MARGIN_DISTRESS, rise.newAlerts.single().kind)
        marker = rise.marker

        // Staying at level 2 does NOT re-fire.
        val stay = TradingAlertsDetector.detect(feeds(margin = margin(2, false)), marker, NOW)
        assertTrue(stay.newAlerts.isEmpty())
        marker = stay.marker

        // Dropping to 0 then rising again is a fresh edge.
        marker = TradingAlertsDetector.detect(feeds(margin = margin(0, false)), marker, NOW).marker
        val reRise = TradingAlertsDetector.detect(feeds(margin = margin(2, false)), marker, NOW)
        assertEquals(1, reRise.newAlerts.size)
    }

    @Test
    fun liquidatingFlag_edgeFires() {
        val marker = TradingAlertsDetector.detect(feeds(margin = margin(1, false)), TradingAlertsMarker(), NOW).marker
        val r = TradingAlertsDetector.detect(feeds(margin = margin(1, true)), marker, NOW)
        assertEquals(1, r.newAlerts.size)
        assertTrue(r.newAlerts.single().title.contains("Liquidation"))
    }

    @Test
    fun nullMargin_producesNoDistressAndDoesNotCrash() {
        val marker = TradingAlertsDetector.detect(feeds(margin = margin(3, true)), TradingAlertsMarker(), NOW).marker
        // Margin read failed this tick (null) -> no distress signal; distress mark resets to 0.
        val r = TradingAlertsDetector.detect(feeds(margin = null), marker, NOW)
        assertTrue(r.newAlerts.none { it.kind == TradingAlertKind.MARGIN_DISTRESS })
        assertEquals(0, r.marker.marginDistressLevel)
        assertFalse(r.marker.marginLiquidating)
    }

    // ---- PM resolutions (list growth) ----

    @Test
    fun pmResolutions_fireOnlyForNewlyAppendedRows() {
        val marker = TradingAlertsDetector.detect(feeds(pms = listOf(pm(1, 10))), TradingAlertsMarker(), NOW).marker
        val next = feeds(pms = listOf(pm(1, 10), pm(2, 20), pm(3, 30)))
        val r = TradingAlertsDetector.detect(next, marker, NOW)
        assertEquals(2, r.newAlerts.size)
        assertTrue(r.newAlerts.all { it.kind == TradingAlertKind.PM_RESOLVED })
        assertEquals(3, r.marker.pmResolutionCount)
    }

    // ---- combined ----

    @Test
    fun mixedNewEvents_allFire_withAdvancedMarker() {
        val marker = TradingAlertsDetector.detect(feeds(margin = margin(0, false)), TradingAlertsMarker(), NOW).marker
        val next = feeds(
            fills = listOf(fill(ts = 100)),
            liqs = listOf(liq(ts = 100)),
            funds = listOf(fund(ts = 100)),
            margin = margin(1, false),
            pms = listOf(pm(9, 99)),
        )
        val r = TradingAlertsDetector.detect(next, marker, NOW)
        assertEquals(
            setOf(
                TradingAlertKind.FILL,
                TradingAlertKind.LIQUIDATION,
                TradingAlertKind.FUNDING,
                TradingAlertKind.MARGIN_DISTRESS,
                TradingAlertKind.PM_RESOLVED,
            ),
            r.newAlerts.map { it.kind }.toSet(),
        )
        assertEquals(100L, r.marker.lastFillTsNs)
        assertEquals(1, r.marker.pmResolutionCount)
        // Every alert carries the injected clock.
        assertTrue(r.newAlerts.all { it.createdAtMs == NOW })
    }
}
