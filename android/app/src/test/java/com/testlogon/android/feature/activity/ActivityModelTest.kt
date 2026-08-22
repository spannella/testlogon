package com.testlogon.android.feature.activity

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
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/** Pure unit tests for the Activity Center model (normalizers + timeline algebra). */
class ActivityModelTest {

    private val nowMs = 1_700_000_000_000L

    // Nanoseconds for a couple of distinct days.
    private val day1Ns = 1_699_900_000_000_000_000L
    private val day2Ns = 1_699_990_000_000_000_000L

    private fun fill(sym: Int, ns: Long, side: OrderSide?, fee: Long = 5L) = FillFee(
        symbolId = sym, price = 100L, qty = 2L, side = side,
        liquidity = Liquidity.MAKER, fee = fee, feeAsset = 0, tsNs = ns,
    )

    private fun funding(sym: Int, ns: Long, payment: Long, received: Boolean) = FundingPayment(
        symbolId = sym, fundingRateBps = 3, markPrice = 100L, positionQty = 10L,
        payment = payment, received = received, tsNs = ns,
    )

    private fun liq(sym: Int, ns: Long) = Liquidation(
        symbolId = sym, qty = 4L, markPrice = 90L, realizedPnl = -50L, fee = 2L, tsNs = ns,
    )

    private fun margin(level: Int, liquidating: Boolean) = MarginAccount(
        // minimal — only distressLevel / isLiquidating drive the normalizer; the rest are safe defaults.
        balance = 0L, availableBalance = 0L, reservedMargin = 0L, numPositions = 0,
        position = null, distressLevel = level, isLiquidating = liquidating, mpid = "",
    )

    private fun pm(sym: Int, outcome: String, ts: Long) = PmResolution(
        symbolId = sym, groupId = null, winningSymbolId = null, outcome = outcome,
        resolverId = "r", ts = ts, source = "admin",
    )

    @Test fun fromFills_mapsCategoryAndSeverity() {
        val evs = ActivityModel.fromFills(FillsFees(listOf(fill(1, day1Ns, OrderSide.BUY)), 1), nowMs)
        assertEquals(1, evs.size)
        assertEquals(ActivityCategory.TRADE, evs[0].category)
        assertEquals("FILL", evs[0].kind)
        assertEquals(ActivitySeverity.SUCCESS, evs[0].severity)
        assertEquals(5L, evs[0].amountCents)
    }

    @Test fun fromFills_sellIsInfo() {
        val evs = ActivityModel.fromFills(FillsFees(listOf(fill(1, day1Ns, OrderSide.SELL)), 1), nowMs)
        assertEquals(ActivitySeverity.INFO, evs[0].severity)
    }

    @Test fun fromFills_zeroTsFallsBackToNow() {
        val evs = ActivityModel.fromFills(FillsFees(listOf(fill(1, 0L, OrderSide.BUY)), 1), nowMs)
        assertEquals(nowMs, evs[0].ts)
    }

    @Test fun fromFunding_receivedIsSuccess_paidIsWarning() {
        val recv = ActivityModel.fromFunding(FundingPayments(listOf(funding(1, day1Ns, 20L, true)), 1), nowMs)
        val paid = ActivityModel.fromFunding(FundingPayments(listOf(funding(1, day1Ns, -20L, false)), 1), nowMs)
        assertEquals(ActivitySeverity.SUCCESS, recv[0].severity)
        assertEquals(ActivityCategory.FUNDING, recv[0].category)
        assertEquals(ActivitySeverity.WARNING, paid[0].severity)
        assertEquals(-20L, paid[0].amountCents)
    }

    @Test fun fromLiquidations_isCritical() {
        val evs = ActivityModel.fromLiquidations(Liquidations(listOf(liq(1, day1Ns)), 1), nowMs)
        assertEquals(ActivityCategory.LIQUIDATION, evs[0].category)
        assertEquals(ActivitySeverity.CRITICAL, evs[0].severity)
    }

    @Test fun fromMargin_healthyProducesNothing() {
        assertTrue(ActivityModel.fromMargin(margin(0, false), nowMs).isEmpty())
        assertTrue(ActivityModel.fromMargin(null, nowMs).isEmpty())
    }

    @Test fun fromMargin_distressProducesOneCriticalRiskEvent() {
        val evs = ActivityModel.fromMargin(margin(2, false), nowMs)
        assertEquals(1, evs.size)
        assertEquals(ActivityCategory.RISK, evs[0].category)
        assertEquals(ActivitySeverity.CRITICAL, evs[0].severity)
        assertEquals(nowMs, evs[0].ts)
    }

    @Test fun fromMargin_liquidatingTitle() {
        val evs = ActivityModel.fromMargin(margin(3, true), nowMs)
        assertEquals("Liquidation in progress", evs[0].title)
    }

    @Test fun fromPmResolutions_secondsScaledToMillis() {
        val evs = ActivityModel.fromPmResolutions(listOf(pm(1, "yes", 1_699_000_000L)), nowMs)
        assertEquals(ActivityCategory.SYSTEM, evs[0].category)
        assertEquals(1_699_000_000L * 1000L, evs[0].ts)
    }

    @Test fun mergeEvents_sortsDescAndDedupesById() {
        val a = ActivityModel.fromFills(FillsFees(listOf(fill(1, day1Ns, OrderSide.BUY)), 1), nowMs)
        val b = ActivityModel.fromFunding(FundingPayments(listOf(funding(1, day2Ns, 10L, true)), 1), nowMs)
        // include a duplicate of 'a' to exercise de-dupe
        val merged = ActivityModel.mergeEvents(a, b, a)
        assertEquals(2, merged.size)
        // day2 funding is newer than day1 fill -> first
        assertTrue(merged[0].ts >= merged[1].ts)
        assertEquals("FUNDING", merged[0].kind)
    }

    @Test fun filterByCategory_nullReturnsAll_andFilters() {
        val fills = ActivityModel.fromFills(FillsFees(listOf(fill(1, day1Ns, OrderSide.BUY)), 1), nowMs)
        val funds = ActivityModel.fromFunding(FundingPayments(listOf(funding(1, day2Ns, 10L, true)), 1), nowMs)
        val all = ActivityModel.mergeEvents(fills, funds)
        assertEquals(2, ActivityModel.filterByCategory(all, null).size)
        assertEquals(1, ActivityModel.filterByCategory(all, ActivityCategory.TRADE).size)
        assertTrue(ActivityModel.filterByCategory(all, ActivityCategory.MONEY).isEmpty())
    }

    @Test fun groupByDay_bucketsByUtcDay_newestFirst() {
        val d1 = ActivityModel.fromFills(FillsFees(listOf(fill(1, day1Ns, OrderSide.BUY)), 1), nowMs)
        val d2 = ActivityModel.fromFunding(FundingPayments(listOf(funding(1, day2Ns, 10L, true)), 1), nowMs)
        val merged = ActivityModel.mergeEvents(d1, d2)
        val days = ActivityModel.groupByDay(merged)
        assertEquals(2, days.size)
        assertTrue("newest day first", days[0].dayKey > days[1].dayKey)
        assertEquals(1, days[0].events.size)
    }

    @Test fun groupByDay_sameDayEventsGrouped() {
        val ns2 = day1Ns + 60_000_000_000L // +60s, same UTC day
        val evs = ActivityModel.fromFills(
            FillsFees(listOf(fill(1, day1Ns, OrderSide.BUY), fill(2, ns2, OrderSide.SELL)), 2), nowMs,
        )
        val days = ActivityModel.groupByDay(evs)
        assertEquals(1, days.size)
        assertEquals(2, days[0].events.size)
    }

    @Test fun unreadCount_countsStrictlyNewer() {
        val evs = ActivityModel.mergeEvents(
            ActivityModel.fromFills(FillsFees(listOf(fill(1, day1Ns, OrderSide.BUY)), 1), nowMs),
            ActivityModel.fromFunding(FundingPayments(listOf(funding(1, day2Ns, 10L, true)), 1), nowMs),
        )
        // last-seen at the day1 fill's ts -> only the day2 funding is unread.
        val day1Ms = day1Ns / 1_000_000L
        assertEquals(1, ActivityModel.unreadCount(evs, day1Ms))
        assertEquals(2, ActivityModel.unreadCount(evs, 0L))
        assertEquals(0, ActivityModel.unreadCount(evs, Long.MAX_VALUE))
    }

    @Test fun newestTs_emptyIsZero_elseMax() {
        assertEquals(0L, ActivityModel.newestTs(emptyList()))
        val evs = ActivityModel.fromFunding(FundingPayments(listOf(funding(1, day2Ns, 10L, true)), 1), nowMs)
        assertEquals(day2Ns / 1_000_000L, ActivityModel.newestTs(evs))
    }

    @Test fun emptyFeeds_produceNoEvents() {
        val merged = ActivityModel.mergeEvents(
            ActivityModel.fromFills(FillsFees(emptyList(), 0), nowMs),
            ActivityModel.fromFunding(FundingPayments(emptyList(), 0), nowMs),
            ActivityModel.fromLiquidations(Liquidations(emptyList(), 0), nowMs),
            ActivityModel.fromMargin(null, nowMs),
            ActivityModel.fromPmResolutions(emptyList(), nowMs),
        )
        assertTrue(merged.isEmpty())
        assertTrue(ActivityModel.groupByDay(merged).isEmpty())
        assertNull(merged.firstOrNull()?.route)
    }
}
