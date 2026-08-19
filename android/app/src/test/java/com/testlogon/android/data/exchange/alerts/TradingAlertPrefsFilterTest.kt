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
 * Coverage for the per-kind enabled-filter added to [TradingAlertsDetector.detect]: a disabled kind is
 * dropped from the emitted alerts, the OTHER kinds still fire, and — crucially — the marker still
 * advances for the disabled kind so re-enabling it later never back-fires the events missed while off.
 */
class TradingAlertPrefsFilterTest {

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

    private val allKinds = TradingAlertKind.entries.toSet()

    @Test
    fun defaultAllOn_matchesUnfilteredBehaviour() {
        val marker = TradingAlertsDetector.detect(feeds(), TradingAlertsMarker(), NOW).marker
        val next = feeds(fills = listOf(fill(ts = 80)), liqs = listOf(liq(ts = 80)))

        val withoutArg = TradingAlertsDetector.detect(next, marker, NOW)
        val withAllKinds = TradingAlertsDetector.detect(next, marker, NOW, allKinds)

        assertEquals(withoutArg.newAlerts.map { it.kind }, withAllKinds.newAlerts.map { it.kind })
        assertEquals(2, withAllKinds.newAlerts.size)
    }

    @Test
    fun disabledKind_isDroppedButOthersFire() {
        val marker = TradingAlertsDetector.detect(feeds(margin = margin(0, false)), TradingAlertsMarker(), NOW).marker
        val next = feeds(
            fills = listOf(fill(ts = 100)),
            liqs = listOf(liq(ts = 100)),
            funds = listOf(fund(ts = 100)),
            margin = margin(2, false),
            pms = listOf(pm(9, 99)),
        )

        // Fills disabled; everything else on.
        val enabled = allKinds - TradingAlertKind.FILL
        val r = TradingAlertsDetector.detect(next, marker, NOW, enabled)

        assertFalse("fill kind must be suppressed", r.newAlerts.any { it.kind == TradingAlertKind.FILL })
        assertEquals(
            setOf(
                TradingAlertKind.LIQUIDATION,
                TradingAlertKind.FUNDING,
                TradingAlertKind.MARGIN_DISTRESS,
                TradingAlertKind.PM_RESOLVED,
            ),
            r.newAlerts.map { it.kind }.toSet(),
        )
    }

    @Test
    fun emptyEnabledSet_emitsNothing() {
        val marker = TradingAlertsDetector.detect(feeds(), TradingAlertsMarker(), NOW).marker
        val next = feeds(fills = listOf(fill(ts = 80)), funds = listOf(fund(ts = 80)))
        val r = TradingAlertsDetector.detect(next, marker, NOW, emptySet())
        assertTrue(r.newAlerts.isEmpty())
    }

    @Test
    fun markerStillAdvances_whileKindDisabled_soReEnablingDoesNotBackfire() {
        val marker = TradingAlertsDetector.detect(feeds(), TradingAlertsMarker(), NOW).marker

        // Tick 1: a fill arrives while FILL alerts are DISABLED -> emitted nothing, but watermark moves.
        val tick1 = feeds(fills = listOf(fill(ts = 80)))
        val r1 = TradingAlertsDetector.detect(tick1, marker, NOW, allKinds - TradingAlertKind.FILL)
        assertTrue(r1.newAlerts.isEmpty())
        assertEquals("watermark must advance even for a suppressed kind", 80L, r1.marker.lastFillTsNs)

        // Tick 2: user re-enables FILL, same feed re-polled -> the ts=80 fill must NOT back-fire.
        val r2 = TradingAlertsDetector.detect(tick1, r1.marker, NOW, allKinds)
        assertTrue("re-enabling must not replay events missed while off", r2.newAlerts.isEmpty())

        // Only a genuinely newer fill fires after re-enabling.
        val tick3 = feeds(fills = listOf(fill(ts = 80), fill(ts = 90)))
        val r3 = TradingAlertsDetector.detect(tick3, r2.marker, NOW, allKinds)
        assertEquals(1, r3.newAlerts.size)
        assertEquals(90L, r3.newAlerts.single().eventTsNs)
    }
}
