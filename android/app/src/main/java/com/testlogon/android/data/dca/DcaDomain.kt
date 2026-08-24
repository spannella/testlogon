package com.testlogon.android.data.dca

/**
 * Null-safe domain models for the DCA / RECURRING-BUYS surface. Wire DTOs are coerced here so the
 * ViewModel / UI never see nullable wire fields. Money is integer CENTS end-to-end; schedule times are
 * epoch-millis Longs. filled_qty / price are kept as display STRINGS (the contract does not pin a unit /
 * scaler for them, so they are shown verbatim rather than mis-scaled).
 */

/** What a recurring buy purchases. */
enum class DcaTargetKind(val wire: String) {
    SYMBOL("symbol"),
    TOKEN("token"),
    STRATEGY("strategy"),
    UNKNOWN("unknown");

    companion object {
        fun fromWire(v: String?): DcaTargetKind = when (v?.trim()?.lowercase()) {
            "symbol" -> SYMBOL
            "token" -> TOKEN
            "strategy" -> STRATEGY
            else -> UNKNOWN
        }
    }
}

/** How often a plan buys. */
enum class DcaFrequency(val wire: String) {
    DAILY("daily"),
    WEEKLY("weekly"),
    MONTHLY("monthly"),
    UNKNOWN("unknown");

    companion object {
        fun fromWire(v: String?): DcaFrequency = when (v?.trim()?.lowercase()) {
            "daily" -> DAILY
            "weekly" -> WEEKLY
            "monthly" -> MONTHLY
            else -> UNKNOWN
        }
    }
}

/** Plan lifecycle. */
enum class DcaStatus(val wire: String) {
    ACTIVE("active"),
    PAUSED("paused"),
    COMPLETED("completed"),
    CANCELLED("cancelled"),
    UNKNOWN("unknown");

    companion object {
        fun fromWire(v: String?): DcaStatus = when (v?.trim()?.lowercase()) {
            "active" -> ACTIVE
            "paused" -> PAUSED
            "completed" -> COMPLETED
            "cancelled", "canceled" -> CANCELLED
            else -> UNKNOWN
        }
    }
}

/** The buy target: a kind + backend id + human label. */
data class DcaTarget(
    val kind: DcaTargetKind,
    val id: String,
    val label: String,
)

/**
 * A recurring-buy plan. [dayOfWeek] (1=Mon..7=Sun) is only meaningful for [DcaFrequency.WEEKLY];
 * [dayOfMonth] (1..31, capped to 28 at run-time) only for [DcaFrequency.MONTHLY]. Times are epoch-ms.
 */
data class DcaPlan(
    val planId: String,
    val target: DcaTarget,
    val amountCents: Long,
    val frequency: DcaFrequency,
    val dayOfWeek: Int? = null,
    val dayOfMonth: Int? = null,
    val startTs: Long,
    val endTs: Long? = null,
    val totalBudgetCents: Long? = null,
    val funding: String = "usd_wallet",
    val status: DcaStatus,
    val nextRunTs: Long? = null,
    val spentCents: Long = 0L,
    val buysCount: Int = 0,
    val createdTs: Long = 0L,
) {
    val isMutable: Boolean get() = status == DcaStatus.ACTIVE || status == DcaStatus.PAUSED
}

/**
 * One executed (or attempted) recurring buy. [ts] is epoch-MILLIS (converted from the wire seconds).
 * [filledQty] is base units; [priceCents] is the fill price in CENTS; both null until executed.
 */
data class DcaRun(
    val ts: Long,
    val amountCents: Long,
    val filledQty: Long?,
    val priceCents: Long?,
    val status: String,
    val note: String? = null,
)
