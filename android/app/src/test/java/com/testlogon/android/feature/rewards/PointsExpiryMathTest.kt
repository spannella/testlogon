package com.testlogon.android.feature.rewards

import com.testlogon.android.data.rewards.PointsExpiry
import com.testlogon.android.data.rewards.PointsExpiryLot
import com.testlogon.android.data.rewards.RewardsHistoryEntry
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.util.Calendar
import java.util.TimeZone

/**
 * Pure math for the POINTS STATEMENT + POINTS EXPIRY surface: 12-month FIFO expiry, expiring-soon (60d),
 * running-balance statement rows, period filter, CSV export, and the authoritative/client resolve. No
 * Android / Compose / Hilt. All timestamps are epoch millis (UTC).
 */
class PointsExpiryMathTest {

    private fun utc(year: Int, month1: Int, day: Int): Long {
        val cal = Calendar.getInstance(TimeZone.getTimeZone("UTC"))
        cal.clear()
        cal.set(year, month1 - 1, day, 0, 0, 0)
        return cal.timeInMillis
    }

    private fun entry(ts: Long, points: Long, type: String = "", desc: String = "activity") =
        RewardsHistoryEntry(ts = ts, type = type, description = desc, points = points, cashCents = 0L, status = "")

    // ---- policy constants ----

    @Test
    fun policyConstants_matchWebCanon() {
        assertEquals(12, PointsExpiryMath.EXPIRY_MONTHS)
        assertEquals(60, PointsExpiryMath.EXPIRING_SOON_DAYS)
    }

    // ---- addMonths ----

    @Test
    fun addMonths_advancesTwelveMonths() {
        val start = utc(2025, 3, 15)
        val plus12 = PointsExpiryMath.addMonths(start, 12)
        assertEquals("2026-03-15", PointsExpiryMath.formatDateUtc(plus12))
    }

    @Test
    fun addMonths_clampsEndOfMonth() {
        // Jan 31 + 1 month -> Feb 28 (2025 not a leap year).
        val jan31 = utc(2025, 1, 31)
        val feb = PointsExpiryMath.addMonths(jan31, 1)
        assertEquals("2025-02-28", PointsExpiryMath.formatDateUtc(feb))
    }

    // ---- computeExpiryFromHistory ----

    @Test
    fun compute_emptyHistory_isEmpty() {
        val r = PointsExpiryMath.computeExpiryFromHistory(emptyList(), utc(2025, 6, 1))
        assertTrue(r.lots.isEmpty())
        assertEquals(0L, r.expiringSoonPoints)
        assertEquals(0L, r.nextExpiryPoints)
        assertEquals(0L, r.livePoints)
    }

    @Test
    fun compute_singleEarn_expiresTwelveMonthsLater() {
        val earn = utc(2025, 1, 10)
        val r = PointsExpiryMath.computeExpiryFromHistory(listOf(entry(earn, 500L)), utc(2025, 2, 1))
        assertEquals(1, r.lots.size)
        assertEquals(500L, r.lots.first().pointsRemaining)
        assertEquals("2026-01-10", PointsExpiryMath.formatDateUtc(r.lots.first().expiresTs))
        assertEquals(500L, r.livePoints)
    }

    @Test
    fun compute_fifo_consumesOldestFirst() {
        // Earn 100 (Jan), earn 200 (Mar), redeem 150 -> oldest lot (100) fully gone, second lot -> 150 left.
        val entries = listOf(
            entry(utc(2025, 1, 1), 100L),
            entry(utc(2025, 3, 1), 200L),
            entry(utc(2025, 4, 1), -150L, type = "redeem"),
        )
        val r = PointsExpiryMath.computeExpiryFromHistory(entries, utc(2025, 5, 1))
        assertEquals(1, r.lots.size)
        assertEquals(150L, r.lots.first().pointsRemaining)
        assertEquals(150L, r.livePoints)
        // The surviving lot is the March earn -> expires 2026-03-01.
        assertEquals("2026-03-01", PointsExpiryMath.formatDateUtc(r.lots.first().expiresTs))
    }

    @Test
    fun compute_dropsAlreadyExpiredLots() {
        // Earn Jan 2024 -> expires Jan 2025. As of Jun 2025 it is already expired and must be dropped.
        val entries = listOf(
            entry(utc(2024, 1, 1), 300L),
            entry(utc(2025, 5, 1), 200L),
        )
        val r = PointsExpiryMath.computeExpiryFromHistory(entries, utc(2025, 6, 1))
        assertEquals(1, r.lots.size)
        assertEquals(200L, r.lots.first().pointsRemaining)
    }

    @Test
    fun compute_expiringSoon_within60Days() {
        // Earn on 2024-07-01 -> expires 2025-07-01. As of 2025-06-01 that is 30 days out -> expiring soon.
        val soon = entry(utc(2024, 7, 1), 400L)
        // Earn on 2024-10-01 -> expires 2025-10-01, ~120 days out -> NOT soon.
        val later = entry(utc(2024, 10, 1), 600L)
        val r = PointsExpiryMath.computeExpiryFromHistory(listOf(soon, later), utc(2025, 6, 1))
        assertEquals(400L, r.expiringSoonPoints)
        // Next expiry is the soonest (2025-07-01, 400 pts).
        assertEquals(400L, r.nextExpiryPoints)
        assertEquals("2025-07-01", PointsExpiryMath.formatDateUtc(r.nextExpiryTs))
    }

    @Test
    fun compute_redeemBeyondEarns_leavesNothing() {
        val entries = listOf(
            entry(utc(2025, 1, 1), 100L),
            entry(utc(2025, 2, 1), -500L, type = "redeem"),
        )
        val r = PointsExpiryMath.computeExpiryFromHistory(entries, utc(2025, 3, 1))
        assertTrue(r.lots.isEmpty())
        assertEquals(0L, r.livePoints)
    }

    @Test
    fun compute_zeroPointEntry_isIgnored() {
        val entries = listOf(
            entry(utc(2025, 1, 1), 0L, desc = "informational"),
            entry(utc(2025, 2, 1), 250L),
        )
        val r = PointsExpiryMath.computeExpiryFromHistory(entries, utc(2025, 3, 1))
        assertEquals(1, r.lots.size)
        assertEquals(250L, r.lots.first().pointsRemaining)
    }

    // ---- statementRows ----

    @Test
    fun statementRows_runningBalance_newestFirst() {
        val entries = listOf(
            entry(utc(2025, 1, 1), 100L),
            entry(utc(2025, 2, 1), 50L),
            entry(utc(2025, 3, 1), -30L),
        )
        val rows = PointsExpiryMath.statementRows(entries)
        assertEquals(3, rows.size)
        // Newest first.
        assertEquals(utc(2025, 3, 1), rows[0].ts)
        // Running balances: 100, 150, 120 chronologically; newest row shows 120.
        assertEquals(120L, rows[0].runningBalance)
        assertEquals(150L, rows[0].balanceBefore)
        assertEquals(100L, rows[2].runningBalance)
    }

    @Test
    fun statementRows_empty_isEmpty() {
        assertTrue(PointsExpiryMath.statementRows(emptyList()).isEmpty())
    }

    // ---- period filter ----

    @Test
    fun filterByPeriod_thisYearAndMonth() {
        val entries = listOf(
            entry(utc(2024, 12, 1), 10L),
            entry(utc(2025, 5, 1), 20L),
            entry(utc(2025, 6, 15), 30L),
        )
        val rows = PointsExpiryMath.statementRows(entries)
        val now = utc(2025, 6, 20)
        assertEquals(3, PointsExpiryMath.filterByPeriod(rows, PointsExpiryMath.StatementPeriod.ALL, now).size)
        assertEquals(2, PointsExpiryMath.filterByPeriod(rows, PointsExpiryMath.StatementPeriod.THIS_YEAR, now).size)
        assertEquals(1, PointsExpiryMath.filterByPeriod(rows, PointsExpiryMath.StatementPeriod.THIS_MONTH, now).size)
    }

    // ---- CSV ----

    @Test
    fun expiryToCsv_headerAndRows_quotedFields() {
        val entries = listOf(entry(utc(2025, 1, 5), 100L, type = "earn", desc = "Referral, bonus"))
        val rows = PointsExpiryMath.statementRows(entries)
        val csv = PointsExpiryMath.expiryToCsv(rows)
        assertTrue(csv.startsWith("date,type,description,points,running_balance\n"))
        assertTrue(csv.contains("2025-01-05"))
        // Comma inside description must be quoted so columns are preserved.
        assertTrue(csv.contains("\"Referral, bonus\""))
        assertTrue(csv.contains("+100"))
    }

    @Test
    fun expiryToCsv_empty_headerOnly() {
        val csv = PointsExpiryMath.expiryToCsv(emptyList())
        assertEquals("date,type,description,points,running_balance\n", csv)
    }

    // ---- formatting ----

    @Test
    fun signed_andSignedLabel() {
        assertEquals("+250", PointsExpiryMath.signed(250L))
        assertEquals("-100", PointsExpiryMath.signed(-100L))
        assertEquals("0", PointsExpiryMath.signed(0L))
        assertEquals("+1,250 pts", PointsExpiryMath.signedPointsLabel(1250L))
        assertEquals("-100 pts", PointsExpiryMath.signedPointsLabel(-100L))
    }

    // ---- resolve (authoritative vs client) ----

    @Test
    fun resolve_prefersAuthoritativeWhenPresent() {
        val client = PointsExpiryMath.computeExpiryFromHistory(
            listOf(entry(utc(2024, 7, 1), 400L)), utc(2025, 6, 1),
        )
        val authoritative = PointsExpiry(
            policyMonths = 12,
            expiringSoonPoints = 999L,
            nextExpiryTs = utc(2025, 12, 1),
            nextExpiryPoints = 999L,
            lots = listOf(PointsExpiryLot(earnedTs = utc(2024, 12, 1), pointsRemaining = 999L, expiresTs = utc(2025, 12, 1))),
            available = true,
        )
        val resolved = PointsExpiryMath.resolve(authoritative, client)
        assertFalse(resolved.estimated)
        assertEquals(999L, resolved.expiringSoonPoints)
    }

    @Test
    fun resolve_fallsBackToClientWhenUnavailable() {
        val client = PointsExpiryMath.computeExpiryFromHistory(
            listOf(entry(utc(2024, 7, 1), 400L)), utc(2025, 6, 1),
        )
        val resolved = PointsExpiryMath.resolve(PointsExpiry.unavailable(), client)
        assertTrue(resolved.estimated)
        assertEquals(400L, resolved.expiringSoonPoints)
        assertEquals(1, resolved.lots.size)
    }
}
