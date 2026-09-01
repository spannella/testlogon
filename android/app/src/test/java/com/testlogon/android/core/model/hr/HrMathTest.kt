package com.testlogon.android.core.model.hr

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

/** HRM-009 — pure JVM unit tests for [HrMath] (no Android / network deps). */
class HrMathTest {

    private fun line(cents: Long, currency: String = "USD") =
        PayrollLine(employmentId = "e", partyId = "p", gross = HrMoney(cents, currency))

    private fun employment(
        rateCents: Long,
        period: PayPeriod,
        start: Long? = null,
        end: Long? = null,
        currency: String = "USD",
    ) = Employment(
        employmentId = "e1",
        partyId = "p1",
        positionId = "pos1",
        orgPartyId = "org1",
        status = EmploymentStatus.ACTIVE,
        startDateEpochSeconds = start,
        endDateEpochSeconds = end,
        payRate = HrMoney(rateCents, currency),
        payPeriod = period,
        createdAtEpochSeconds = null,
        updatedAtEpochSeconds = null,
    )

    private fun run(lines: List<PayrollLine>) = PayrollRun(
        payrollRunId = "r1",
        periodStartEpochSeconds = null,
        periodEndEpochSeconds = null,
        status = PayrollRunStatus.DRAFT,
        lines = lines,
        approvedBy = null,
        postedAtEpochSeconds = null,
        createdAtEpochSeconds = null,
        updatedAtEpochSeconds = null,
    )

    @Test
    fun totalGrossCents_sumsLines() {
        assertEquals(0L, HrMath.totalGrossCents(emptyList()))
        assertEquals(6000L, HrMath.totalGrossCents(listOf(line(1000), line(2000), line(3000))))
    }

    @Test
    fun runGrossTotal_usesFirstLineCurrency() {
        val total = HrMath.runGrossTotal(run(listOf(line(2500, "EUR"), line(2500, "EUR"))))
        assertEquals(5000L, total.cents)
        assertEquals("EUR", total.currency)
    }

    @Test
    fun runGrossTotal_emptyUsesFallbackCurrency() {
        val total = HrMath.runGrossTotal(run(emptyList()), fallbackCurrency = "GBP")
        assertEquals(0L, total.cents)
        assertEquals("GBP", total.currency)
    }

    @Test
    fun formatMoney_padsMinorUnits() {
        assertEquals("12.34 USD", HrMath.formatMoney(HrMoney(1234, "usd")))
        assertEquals("12.05 USD", HrMath.formatMoney(HrMoney(1205, "USD")))
        assertEquals("0.00 USD", HrMath.formatMoney(HrMoney(0, "USD")))
    }

    @Test
    fun formatMoney_handlesNegative() {
        assertEquals("-5.00 USD", HrMath.formatMoney(HrMoney(-500, "USD")))
    }

    @Test
    fun tenureDays_nullWhenNoStart() {
        assertNull(HrMath.tenureDays(null, null, nowEpochSeconds = 1_000_000))
        assertNull(HrMath.tenureDays(0, null, nowEpochSeconds = 1_000_000))
    }

    @Test
    fun tenureDays_nullWhenStartInFuture() {
        assertNull(HrMath.tenureDays(2_000_000, null, nowEpochSeconds = 1_000_000))
    }

    @Test
    fun tenureDays_countsWholeDays() {
        val start = HrMath.SECONDS_PER_DAY // day 1 (positive; 0 means "no date")
        val now = 11L * HrMath.SECONDS_PER_DAY + 500L // 10 days after start + change
        assertEquals(10L, HrMath.tenureDays(start, null, now))
    }

    @Test
    fun tenureDays_usesEndWhenPresent() {
        val start = HrMath.SECONDS_PER_DAY
        val end = 4L * HrMath.SECONDS_PER_DAY // 3 days after start
        assertEquals(3L, HrMath.tenureDays(start, end, nowEpochSeconds = 999L * HrMath.SECONDS_PER_DAY))
    }

    @Test
    fun tenureLabel_days() {
        assertEquals("0 days", HrMath.tenureLabel(0))
        assertEquals("1 day", HrMath.tenureLabel(1))
        assertEquals("29 days", HrMath.tenureLabel(29))
        assertNull(HrMath.tenureLabel(null))
    }

    @Test
    fun tenureLabel_months() {
        assertEquals("2 months", HrMath.tenureLabel(90))
        assertEquals("1 month", HrMath.tenureLabel(30))
    }

    @Test
    fun tenureLabel_years() {
        assertEquals("1 year", HrMath.tenureLabel(366))
        val twoYearsFourMonths = (2 * 365.25 + 4 * 30.4375).toLong()
        assertEquals("2 years, 4 months", HrMath.tenureLabel(twoYearsFourMonths))
    }

    @Test
    fun annualizedCents_perPeriod() {
        assertEquals(120_000L, HrMath.annualizedCents(10_000, PayPeriod.MONTHLY))
        assertEquals(260_000L, HrMath.annualizedCents(10_000, PayPeriod.BIWEEKLY))
        assertEquals(520_000L, HrMath.annualizedCents(10_000, PayPeriod.WEEKLY))
        assertEquals(52_000L * 40, HrMath.annualizedCents(1_000, PayPeriod.HOURLY))
        assertNull(HrMath.annualizedCents(1_000, PayPeriod.UNKNOWN))
    }

    @Test
    fun annualizedComp_preservesCurrency() {
        val comp = HrMath.annualizedComp(employment(10_000, PayPeriod.MONTHLY, currency = "CAD"))
        assertEquals(120_000L, comp?.cents)
        assertEquals("CAD", comp?.currency)
        assertNull(HrMath.annualizedComp(employment(10_000, PayPeriod.UNKNOWN)))
    }

    @Test
    fun payRateLabel_suffixesPeriod() {
        assertEquals("100.00 USD / month", HrMath.payRateLabel(employment(10_000, PayPeriod.MONTHLY)))
        assertEquals("10.00 USD / hour", HrMath.payRateLabel(employment(1_000, PayPeriod.HOURLY)))
        assertEquals("100.00 USD", HrMath.payRateLabel(employment(10_000, PayPeriod.UNKNOWN)))
    }
}
