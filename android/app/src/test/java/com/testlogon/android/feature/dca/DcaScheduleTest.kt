package com.testlogon.android.feature.dca

import com.testlogon.android.data.dca.DcaFrequency
import com.testlogon.android.data.dca.DcaPlan
import com.testlogon.android.data.dca.DcaStatus
import com.testlogon.android.data.dca.DcaTarget
import com.testlogon.android.data.dca.DcaTargetKind
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Pure schedule + budget math for DCA / recurring buys. All times are epoch-ms in UTC.
 *
 * Anchors used (verified against the proleptic-Gregorian UTC calendar):
 *  - 2024-01-01 00:00:00 UTC = 1_704_067_200_000 ms, a MONDAY (ISO dow = 1).
 *  - 2024-02-29 00:00:00 UTC = 1_709_164_800_000 ms (leap day).
 */
class DcaScheduleTest {

    private val day = DcaSchedule.MS_PER_DAY
    private val mon2024 = 1_704_067_200_000L // 2024-01-01 UTC, Monday

    private fun plan(
        amountCents: Long = 1_000L,
        frequency: DcaFrequency = DcaFrequency.DAILY,
        dayOfWeek: Int? = null,
        dayOfMonth: Int? = null,
        startTs: Long = mon2024,
        endTs: Long? = null,
        totalBudgetCents: Long? = null,
        status: DcaStatus = DcaStatus.ACTIVE,
        spentCents: Long = 0L,
    ) = DcaPlan(
        planId = "p1",
        target = DcaTarget(DcaTargetKind.SYMBOL, "1", "BTCUSDC"),
        amountCents = amountCents,
        frequency = frequency,
        dayOfWeek = dayOfWeek,
        dayOfMonth = dayOfMonth,
        startTs = startTs,
        endTs = endTs,
        totalBudgetCents = totalBudgetCents,
        status = status,
        spentCents = spentCents,
    )

    // ---- nextRun: daily ----

    @Test
    fun nextRun_daily_beforeStart_returnsStartDay() {
        val p = plan(frequency = DcaFrequency.DAILY, startTs = mon2024)
        assertEquals(mon2024, DcaSchedule.nextRun(p, mon2024 - 10 * day))
    }

    @Test
    fun nextRun_daily_midDay_returnsSameDayStart() {
        val p = plan(frequency = DcaFrequency.DAILY, startTs = mon2024)
        // A from-time in the afternoon of day+3 -> the run lands at the START of that same day.
        val from = mon2024 + 3 * day + 43_200_000L
        assertEquals(mon2024 + 3 * day, DcaSchedule.nextRun(p, from))
    }

    // ---- nextRun: weekly ----

    @Test
    fun nextRun_weekly_advancesToTargetDow() {
        // Start Monday; want Wednesday (ISO 3) -> +2 days.
        val p = plan(frequency = DcaFrequency.WEEKLY, dayOfWeek = 3, startTs = mon2024)
        assertEquals(mon2024 + 2 * day, DcaSchedule.nextRun(p, mon2024))
    }

    @Test
    fun nextRun_weekly_targetIsStartDow_returnsStart() {
        // Start Monday; want Monday (ISO 1) -> same day.
        val p = plan(frequency = DcaFrequency.WEEKLY, dayOfWeek = 1, startTs = mon2024)
        assertEquals(mon2024, DcaSchedule.nextRun(p, mon2024))
    }

    @Test
    fun nextRun_weekly_wrapsToNextWeek() {
        // From a Wednesday, want Tuesday (ISO 2) -> should wrap 6 days forward.
        val wed = mon2024 + 2 * day
        val p = plan(frequency = DcaFrequency.WEEKLY, dayOfWeek = 2, startTs = mon2024)
        assertEquals(wed + 6 * day, DcaSchedule.nextRun(p, wed))
    }

    // ---- nextRun: monthly ----

    @Test
    fun nextRun_monthly_landsOnDayOfMonth() {
        // Start 2024-01-01, want the 15th -> 2024-01-15.
        val p = plan(frequency = DcaFrequency.MONTHLY, dayOfMonth = 15, startTs = mon2024)
        val jan15 = mon2024 + 14 * day
        assertEquals(jan15, DcaSchedule.nextRun(p, mon2024))
    }

    @Test
    fun nextRun_monthly_afterDom_rollsToNextMonth() {
        // Want the 1st but ask from the 15th -> next month's 1st (Feb 1 = +31 days from Jan 1).
        val p = plan(frequency = DcaFrequency.MONTHLY, dayOfMonth = 1, startTs = mon2024)
        val jan15 = mon2024 + 14 * day
        val feb1 = mon2024 + 31 * day
        assertEquals(feb1, DcaSchedule.nextRun(p, jan15))
    }

    @Test
    fun nextRun_monthly_dayOfMonthAbove28_isCappedTo28() {
        // Contract: day_of_month > 28 is capped at 28 so Feb is never skipped.
        val p = plan(frequency = DcaFrequency.MONTHLY, dayOfMonth = 31, startTs = mon2024)
        // From Feb 1 2024 -> Feb 28 (capped), NOT skipped.
        val feb1 = mon2024 + 31 * day
        val feb28 = feb1 + 27 * day
        assertEquals(feb28, DcaSchedule.nextRun(p, feb1))
    }

    // ---- start / end / status guards ----

    @Test
    fun nextRun_pastEnd_returnsNull() {
        val p = plan(frequency = DcaFrequency.DAILY, startTs = mon2024, endTs = mon2024 + 2 * day)
        assertNull(DcaSchedule.nextRun(p, mon2024 + 5 * day))
    }

    @Test
    fun nextRun_cancelledOrCompleted_returnsNull() {
        assertNull(DcaSchedule.nextRun(plan(status = DcaStatus.CANCELLED), mon2024))
        assertNull(DcaSchedule.nextRun(plan(status = DcaStatus.COMPLETED), mon2024))
    }

    @Test
    fun nextRun_budgetExhausted_returnsNull() {
        // total 1000, spent 500, amount 1000 -> remaining 500 < 1000 -> no run.
        val p = plan(amountCents = 1_000L, totalBudgetCents = 1_000L, spentCents = 500L)
        assertNull(DcaSchedule.nextRun(p, mon2024))
    }

    @Test
    fun nextRun_unknownFrequency_returnsNull() {
        assertNull(DcaSchedule.nextRun(plan(frequency = DcaFrequency.UNKNOWN), mon2024))
    }

    // ---- upcomingRuns ----

    @Test
    fun upcomingRuns_daily_returnsNConsecutiveDays() {
        val p = plan(frequency = DcaFrequency.DAILY, startTs = mon2024)
        val runs = DcaSchedule.upcomingRuns(p, mon2024, 5)
        assertEquals(listOf(mon2024, mon2024 + day, mon2024 + 2 * day, mon2024 + 3 * day, mon2024 + 4 * day), runs)
    }

    @Test
    fun upcomingRuns_weekly_returnsWeeklyCadence() {
        val p = plan(frequency = DcaFrequency.WEEKLY, dayOfWeek = 1, startTs = mon2024)
        val runs = DcaSchedule.upcomingRuns(p, mon2024, 3)
        assertEquals(listOf(mon2024, mon2024 + 7 * day, mon2024 + 14 * day), runs)
    }

    @Test
    fun upcomingRuns_stopsAtEnd() {
        // End after the 3rd day -> only 3 daily runs fit.
        val p = plan(frequency = DcaFrequency.DAILY, startTs = mon2024, endTs = mon2024 + 2 * day)
        val runs = DcaSchedule.upcomingRuns(p, mon2024, 10)
        assertEquals(3, runs.size)
    }

    @Test
    fun upcomingRuns_stopsWhenBudgetRunsOut() {
        // Budget funds exactly 2 buys of 1000 (spent 0, total 2000).
        val p = plan(amountCents = 1_000L, frequency = DcaFrequency.DAILY, totalBudgetCents = 2_000L)
        val runs = DcaSchedule.upcomingRuns(p, mon2024, 10)
        assertEquals(2, runs.size)
    }

    // ---- budget helpers ----

    @Test
    fun budgetRemaining_null_whenUncapped() {
        assertNull(DcaSchedule.budgetRemainingCents(plan(totalBudgetCents = null)))
    }

    @Test
    fun budgetRemaining_flooredAtZero() {
        val p = plan(totalBudgetCents = 1_000L, spentCents = 1_500L)
        assertEquals(0L, DcaSchedule.budgetRemainingCents(p))
    }

    @Test
    fun estimatedRunsRemaining_integerFloor() {
        val p = plan(amountCents = 1_000L, totalBudgetCents = 3_500L, spentCents = 0L)
        assertEquals(3, DcaSchedule.estimatedRunsRemaining(p))
    }

    @Test
    fun budgetProgress_ratioAndBounds() {
        val p = plan(totalBudgetCents = 1_000L, spentCents = 250L)
        assertEquals(0.25f, DcaSchedule.budgetProgress(p)!!, 0.0001f)
        // over-spend clamps to 1.
        val over = plan(totalBudgetCents = 1_000L, spentCents = 5_000L)
        assertEquals(1.0f, DcaSchedule.budgetProgress(over)!!, 0.0001f)
        // uncapped -> null.
        assertNull(DcaSchedule.budgetProgress(plan(totalBudgetCents = null)))
    }

    // ---- validatePlan ----

    @Test
    fun validate_rejectsNonPositiveAmount() {
        val v = DcaSchedule.validatePlan(0L, DcaFrequency.DAILY, null, null, mon2024, null, null)
        assertTrue(v is DcaSchedule.Validation.Invalid)
    }

    @Test
    fun validate_weeklyRequiresDayOfWeek() {
        val bad = DcaSchedule.validatePlan(1_000L, DcaFrequency.WEEKLY, null, null, mon2024, null, null)
        assertTrue(bad is DcaSchedule.Validation.Invalid)
        val ok = DcaSchedule.validatePlan(1_000L, DcaFrequency.WEEKLY, 3, null, mon2024, null, null)
        assertEquals(DcaSchedule.Validation.Ok, ok)
    }

    @Test
    fun validate_monthlyRequiresDayOfMonth() {
        val bad = DcaSchedule.validatePlan(1_000L, DcaFrequency.MONTHLY, null, null, mon2024, null, null)
        assertTrue(bad is DcaSchedule.Validation.Invalid)
        val ok = DcaSchedule.validatePlan(1_000L, DcaFrequency.MONTHLY, null, 15, mon2024, null, null)
        assertEquals(DcaSchedule.Validation.Ok, ok)
    }

    @Test
    fun validate_endMustBeAfterStart() {
        val bad = DcaSchedule.validatePlan(1_000L, DcaFrequency.DAILY, null, null, mon2024, mon2024, null)
        assertTrue(bad is DcaSchedule.Validation.Invalid)
    }

    @Test
    fun validate_totalBudgetMustCoverOneBuy() {
        val bad = DcaSchedule.validatePlan(1_000L, DcaFrequency.DAILY, null, null, mon2024, null, 500L)
        assertTrue(bad is DcaSchedule.Validation.Invalid)
        val ok = DcaSchedule.validatePlan(1_000L, DcaFrequency.DAILY, null, null, mon2024, null, 1_000L)
        assertEquals(DcaSchedule.Validation.Ok, ok)
    }

    @Test
    fun validate_happyPathDaily() {
        assertEquals(
            DcaSchedule.Validation.Ok,
            DcaSchedule.validatePlan(2_500L, DcaFrequency.DAILY, null, null, mon2024, mon2024 + 30 * day, 50_000L),
        )
    }

    @Test
    fun nextRun_notNull_forActiveDaily_sanity() {
        assertNotNull(DcaSchedule.nextRun(plan(), mon2024))
    }
}
