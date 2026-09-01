package com.testlogon.android.core.model.hr

/**
 * HRM-009 (Android) — framework-free HR / Payroll domain models.
 *
 * Conventions (matching core-model/invoices, core-model/syndicates):
 *  - Money is integer cents + ISO-4217 currency (the backend's `*_cents`). No BigDecimal / float.
 *  - Timestamps/dates are epoch-SECONDS Longs (NOT java.time) so this stays JVM-unit-testable; screens
 *    format via a pure helper. A 0 / null value maps to null.
 *  - Enums use an UNKNOWN fallback for forward compatibility (the backend statuses are free strings).
 *
 * These are pure data classes; DTO -> domain mapping lives in the app-layer repository (which owns the
 * Retrofit DTOs). This module has NO network/Android dependency.
 */

/** Integer cents + ISO-4217 currency. */
data class HrMoney(val cents: Long, val currency: String)

/** Position lifecycle. Backend values: OPEN | FILLED | CLOSED. */
enum class PositionStatus {
    OPEN, FILLED, CLOSED, UNKNOWN;

    companion object {
        fun fromWire(value: String?): PositionStatus = when (value?.uppercase()) {
            "OPEN" -> OPEN
            "FILLED" -> FILLED
            "CLOSED" -> CLOSED
            else -> UNKNOWN
        }
    }
}

/** Employment lifecycle. Backend values: ACTIVE | TERMINATED | ON_LEAVE. */
enum class EmploymentStatus {
    ACTIVE, TERMINATED, ON_LEAVE, UNKNOWN;

    companion object {
        fun fromWire(value: String?): EmploymentStatus = when (value?.uppercase()) {
            "ACTIVE" -> ACTIVE
            "TERMINATED" -> TERMINATED
            "ON_LEAVE" -> ON_LEAVE
            else -> UNKNOWN
        }
    }
}

/** Pay cadence. Backend values: MONTHLY | BIWEEKLY | WEEKLY | HOURLY. */
enum class PayPeriod {
    MONTHLY, BIWEEKLY, WEEKLY, HOURLY, UNKNOWN;

    companion object {
        fun fromWire(value: String?): PayPeriod = when (value?.uppercase()) {
            "MONTHLY" -> MONTHLY
            "BIWEEKLY" -> BIWEEKLY
            "WEEKLY" -> WEEKLY
            "HOURLY" -> HOURLY
            else -> UNKNOWN
        }
    }
}

/** Payroll-run lifecycle. Backend values: DRAFT | APPROVED | POSTED. */
enum class PayrollRunStatus {
    DRAFT, APPROVED, POSTED, UNKNOWN;

    companion object {
        fun fromWire(value: String?): PayrollRunStatus = when (value?.uppercase()) {
            "DRAFT" -> DRAFT
            "APPROVED" -> APPROVED
            "POSTED" -> POSTED
            else -> UNKNOWN
        }
    }
}

/** A job position. [department] may be blank/absent. */
data class Position(
    val positionId: String,
    val title: String,
    val department: String?,
    val status: PositionStatus,
    val createdAtEpochSeconds: Long?,
    val updatedAtEpochSeconds: Long?,
)

/** An employment record (a party in a position, at a pay rate). */
data class Employment(
    val employmentId: String,
    val partyId: String,
    val positionId: String,
    val orgPartyId: String,
    val status: EmploymentStatus,
    val startDateEpochSeconds: Long?,
    val endDateEpochSeconds: Long?,
    val payRate: HrMoney,
    val payPeriod: PayPeriod,
    val createdAtEpochSeconds: Long?,
    val updatedAtEpochSeconds: Long?,
)

/** A single payroll line: gross pay for one employment within a run. */
data class PayrollLine(
    val employmentId: String,
    val partyId: String,
    val gross: HrMoney,
)

/** A payroll run header + its embedded lines. */
data class PayrollRun(
    val payrollRunId: String,
    val periodStartEpochSeconds: Long?,
    val periodEndEpochSeconds: Long?,
    val status: PayrollRunStatus,
    val lines: List<PayrollLine>,
    val approvedBy: String?,
    val postedAtEpochSeconds: Long?,
    val createdAtEpochSeconds: Long?,
    val updatedAtEpochSeconds: Long?,
)

/** One page of items + the forward cursor (null / blank = end of pagination). */
data class HrPage<T>(val items: List<T>, val nextCursor: String?)
