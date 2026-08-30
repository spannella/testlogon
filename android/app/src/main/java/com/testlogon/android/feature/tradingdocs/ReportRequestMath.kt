package com.testlogon.android.feature.tradingdocs

import java.util.Locale

/**
 * FE-171 (EPIC H) — PURE (no Android deps), JVM-testable helpers for REQUESTING a trading document
 * (account statement / P&L report / fills CSV / 1099). Kept framework-free so the report-type catalog,
 * request validation, request-payload shaping and filename derivation are unit-tested without
 * Robolectric (mirrors the FE-170 [TradingDocsMath] idiom).
 *
 * Backend contract (BE-170 request/generate): POST ui/trading-documents/request
 *   { type, period_start?, period_end?, tax_year? }
 * where period_start/period_end are epoch-SECONDS Longs and tax_year is an Int. The generated file
 * then lands in the FE-170 "Trading Documents" list once ready (degrade-on-404 everywhere).
 */

/** Report output format. */
enum class ReportFormat { PDF, CSV }

/**
 * A requestable report type. [needsPeriod] => a start+end date range is required; [needsTaxYear] => a
 * tax year is required (mutually exclusive by product rule: statement/pnl/fills need a period, 1099
 * needs a tax year).
 */
data class ReportType(
    /** BE-170 `type` code (also the FE-170 list `type`). */
    val code: String,
    val label: String,
    val format: ReportFormat,
    val needsPeriod: Boolean,
    val needsTaxYear: Boolean,
)

/** Canonical, display-ordered catalog of requestable report types. */
val REPORT_TYPES: List<ReportType> = listOf(
    ReportType("statement", "Account statement", ReportFormat.PDF, needsPeriod = true, needsTaxYear = false),
    ReportType("pnl", "Profit & Loss report", ReportFormat.PDF, needsPeriod = true, needsTaxYear = false),
    ReportType("fills", "Fills (CSV)", ReportFormat.CSV, needsPeriod = true, needsTaxYear = false),
    ReportType("1099", "1099 tax form", ReportFormat.PDF, needsPeriod = false, needsTaxYear = true),
)

/** Look up a [ReportType] by its BE-170 `type` code (case-insensitive); null if unknown. */
fun reportTypeOf(code: String): ReportType? =
    REPORT_TYPES.firstOrNull { it.code.equals(code, ignoreCase = true) }

/**
 * Validate a report request. Returns a (possibly empty) list of human-readable errors; an EMPTY list
 * means the request is well-formed and may be submitted.
 *
 * Rules:
 *  - Unknown [type] -> a single "unknown report type" error.
 *  - Period-based types (statement / pnl / fills) need BOTH [periodStart] and [periodEnd], and start
 *    must be strictly before end.
 *  - 1099 needs a plausible [taxYear] (>= 1900).
 */
fun validateReportRequest(
    type: String,
    periodStart: Long? = null,
    periodEnd: Long? = null,
    taxYear: Int? = null,
): List<String> {
    val rt = reportTypeOf(type) ?: return listOf("Unknown report type.")
    val errors = mutableListOf<String>()
    if (rt.needsPeriod) {
        if (periodStart == null || periodEnd == null) {
            errors += "Select a start and end date."
        } else if (periodStart >= periodEnd) {
            errors += "Start date must be before end date."
        }
    }
    if (rt.needsTaxYear) {
        if (taxYear == null) {
            errors += "Select a tax year."
        } else if (taxYear < 1900) {
            errors += "Select a valid tax year."
        }
    }
    return errors
}

/**
 * Shape the BE-170 request payload for [type]. Only the parameters RELEVANT to the type are included
 * (period-based types carry period_start/period_end; 1099 carries tax_year); irrelevant params are
 * dropped. Assumes the request already passed [validateReportRequest].
 */
fun requestPayload(
    type: String,
    periodStart: Long? = null,
    periodEnd: Long? = null,
    taxYear: Int? = null,
): Map<String, Any> {
    val rt = reportTypeOf(type)
    val payload = linkedMapOf<String, Any>("type" to (rt?.code ?: type))
    if (rt?.needsPeriod == true) {
        periodStart?.let { payload["period_start"] = it }
        periodEnd?.let { payload["period_end"] = it }
    }
    if (rt?.needsTaxYear == true) {
        taxYear?.let { payload["tax_year"] = it }
    }
    return payload
}

private val UNSAFE_FILENAME = Regex("[^A-Za-z0-9._-]+")

/**
 * A SAFE, portable filename for a report request (used for a client-side export or as a display hint):
 * "<type>_<period|year>.<ext>", stripped of filesystem-unsafe characters.
 */
fun reportFilename(
    type: String,
    periodStart: Long? = null,
    periodEnd: Long? = null,
    taxYear: Int? = null,
): String {
    val rt = reportTypeOf(type)
    val ext = when (rt?.format) {
        ReportFormat.CSV -> "csv"
        else -> "pdf"
    }
    val code = rt?.code ?: type
    val suffix = when {
        rt?.needsTaxYear == true && taxYear != null -> taxYear.toString()
        rt?.needsPeriod == true && periodStart != null && periodEnd != null -> "${periodStart}_$periodEnd"
        else -> null
    }
    val base = (if (suffix != null) "${code}_$suffix" else code)
        .lowercase(Locale.ROOT)
        .replace(UNSAFE_FILENAME, "_")
        .trim('_')
        .ifBlank { "report" }
    return "$base.$ext"
}
