package com.testlogon.android.feature.hr

import com.testlogon.android.core.model.hr.EmploymentStatus
import com.testlogon.android.core.model.hr.PayPeriod
import com.testlogon.android.core.model.hr.PayrollRunStatus
import com.testlogon.android.core.model.hr.PositionStatus
import java.text.DateFormat
import java.util.Date
import java.util.Locale

/**
 * HRM-009 — pure, JVM-testable HR label/date formatting (no Android types), mirroring the AND-243
 * InvoiceFormat helpers. Dates use [DateFormat]/[Date] (NOT java.time, API26+). Status label mapping is
 * total (an UNKNOWN enum falls back to a readable dash-free literal).
 */

/** Epoch-seconds -> localized medium date string, or null when [epochSeconds] is null. */
fun formatHrDate(epochSeconds: Long?, locale: Locale = Locale.getDefault()): String? {
    if (epochSeconds == null) return null
    return DateFormat.getDateInstance(DateFormat.MEDIUM, locale).format(Date(epochSeconds * 1000L))
}

fun positionStatusLabel(status: PositionStatus): String = when (status) {
    PositionStatus.OPEN -> "Open"
    PositionStatus.FILLED -> "Filled"
    PositionStatus.CLOSED -> "Closed"
    PositionStatus.UNKNOWN -> "Unknown"
}

fun employmentStatusLabel(status: EmploymentStatus): String = when (status) {
    EmploymentStatus.ACTIVE -> "Active"
    EmploymentStatus.TERMINATED -> "Terminated"
    EmploymentStatus.ON_LEAVE -> "On leave"
    EmploymentStatus.UNKNOWN -> "Unknown"
}

fun payPeriodLabel(period: PayPeriod): String = when (period) {
    PayPeriod.MONTHLY -> "Monthly"
    PayPeriod.BIWEEKLY -> "Biweekly"
    PayPeriod.WEEKLY -> "Weekly"
    PayPeriod.HOURLY -> "Hourly"
    PayPeriod.UNKNOWN -> "Unknown"
}

fun payrollStatusLabel(status: PayrollRunStatus): String = when (status) {
    PayrollRunStatus.DRAFT -> "Draft"
    PayrollRunStatus.APPROVED -> "Approved"
    PayrollRunStatus.POSTED -> "Posted"
    PayrollRunStatus.UNKNOWN -> "Unknown"
}
