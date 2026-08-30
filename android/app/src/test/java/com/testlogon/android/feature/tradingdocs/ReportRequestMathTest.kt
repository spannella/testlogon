package com.testlogon.android.feature.tradingdocs

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/** FE-171 — pure JVM tests for the report-request catalog, validation, payload shaping and filenames. */
class ReportRequestMathTest {

    @Test
    fun reportTypes_catalogCodesAndOrder() {
        assertEquals(listOf("statement", "pnl", "fills", "1099"), REPORT_TYPES.map { it.code })
    }

    @Test
    fun reportTypes_formatsAndParamNeeds() {
        val fills = reportTypeOf("fills")!!
        assertEquals(ReportFormat.CSV, fills.format)
        assertTrue(fills.needsPeriod)
        assertFalse(fills.needsTaxYear)

        val form1099 = reportTypeOf("1099")!!
        assertEquals(ReportFormat.PDF, form1099.format)
        assertFalse(form1099.needsPeriod)
        assertTrue(form1099.needsTaxYear)
    }

    @Test
    fun reportTypeOf_isCaseInsensitive_andNullForUnknown() {
        assertEquals("statement", reportTypeOf("STATEMENT")?.code)
        assertNull(reportTypeOf("nope"))
    }

    @Test
    fun validate_unknownType_singleError() {
        assertEquals(listOf("Unknown report type."), validateReportRequest("bogus"))
    }

    @Test
    fun validate_statement_needsPeriod() {
        val errs = validateReportRequest("statement", periodStart = null, periodEnd = null)
        assertEquals(1, errs.size)
        assertTrue(errs.single().contains("start", ignoreCase = true))
    }

    @Test
    fun validate_pnl_needsPeriod() {
        assertFalse(validateReportRequest("pnl", periodStart = 100, periodEnd = 200).isNotEmpty())
    }

    @Test
    fun validate_fills_startBeforeEnd() {
        val errs = validateReportRequest("fills", periodStart = 500, periodEnd = 100)
        assertEquals(1, errs.size)
        assertTrue(errs.single().contains("before", ignoreCase = true))
    }

    @Test
    fun validate_fills_equalDates_isError() {
        assertTrue(validateReportRequest("fills", periodStart = 100, periodEnd = 100).isNotEmpty())
    }

    @Test
    fun validate_period_ok_isEmpty() {
        assertTrue(validateReportRequest("statement", periodStart = 100, periodEnd = 200).isEmpty())
    }

    @Test
    fun validate_1099_needsTaxYear() {
        val errs = validateReportRequest("1099", taxYear = null)
        assertEquals(1, errs.size)
        assertTrue(errs.single().contains("tax year", ignoreCase = true))
    }

    @Test
    fun validate_1099_implausibleYear_isError() {
        assertTrue(validateReportRequest("1099", taxYear = 1800).isNotEmpty())
    }

    @Test
    fun validate_1099_ok_isEmpty() {
        assertTrue(validateReportRequest("1099", taxYear = 2024).isEmpty())
    }

    @Test
    fun payload_period_onlyIncludesPeriodParams() {
        val p = requestPayload("statement", periodStart = 100, periodEnd = 200, taxYear = 2024)
        assertEquals("statement", p["type"])
        assertEquals(100L, p["period_start"])
        assertEquals(200L, p["period_end"])
        assertFalse(p.containsKey("tax_year"))
    }

    @Test
    fun payload_1099_onlyIncludesTaxYear() {
        val p = requestPayload("1099", periodStart = 100, periodEnd = 200, taxYear = 2024)
        assertEquals("1099", p["type"])
        assertEquals(2024, p["tax_year"])
        assertFalse(p.containsKey("period_start"))
        assertFalse(p.containsKey("period_end"))
    }

    @Test
    fun payload_alwaysCarriesType() {
        assertEquals("pnl", requestPayload("pnl").getValue("type"))
    }

    @Test
    fun filename_period_pdf() {
        assertEquals("statement_100_200.pdf", reportFilename("statement", periodStart = 100, periodEnd = 200))
    }

    @Test
    fun filename_fills_csv() {
        assertEquals("fills_100_200.csv", reportFilename("fills", periodStart = 100, periodEnd = 200))
    }

    @Test
    fun filename_1099_year_pdf() {
        assertEquals("1099_2024.pdf", reportFilename("1099", taxYear = 2024))
    }

    @Test
    fun filename_unknownType_defaultsPdf() {
        assertEquals("weird.pdf", reportFilename("weird"))
    }
}
