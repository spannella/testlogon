package com.testlogon.android.data.custody

/*
 * Domain models for the custody feature: null-safe, UI-ready projections of the wire DTOs. The
 * repository maps DTO -> domain (defaulting blanks, parsing money strings to Double for validation /
 * Max, and normalizing status codes to a sealed enum) so composables never touch raw wire shapes.
 */

/** A custodial asset row (one asset on one chain) with its available balance. */
data class CustodyAsset(
    val asset: String,
    val chain: String,
    val name: String,
    val symbol: String,
    val decimals: Int,
    val network: String,
    val balanceText: String,
    val balance: Double,
    val addressAvailable: Boolean,
) {
    /** Stable list key. */
    val key: String get() = "$asset::$chain"
}

data class CustodyDepositAddress(
    val asset: String,
    val chain: String,
    val network: String,
    val address: String,
    val memo: String?,
)

/** A pending/observed on-chain deposit. */
data class CustodyDeposit(
    val id: String,
    val asset: String,
    val chain: String,
    val amountText: String,
    val status: String,
    val confirmations: Int,
)

/** Normalized withdrawal lifecycle status. */
enum class WithdrawalStatus(val wire: String, val label: String) {
    SCREENING("screening", "Screening"),
    SIGNED("signed", "Signed"),
    PENDING_APPROVAL("pending_approval", "Pending approval"),
    BLOCKED("blocked", "Blocked"),
    REJECTED("rejected", "Rejected"),
    BROADCAST("broadcast", "Broadcast"),
    SETTLED("settled", "Settled"),
    UNKNOWN("", "Unknown");

    /** Terminal statuses no longer advance, so the Activity poller can stop watching them. */
    val isTerminal: Boolean
        get() = this == BLOCKED || this == REJECTED || this == SETTLED

    companion object {
        fun from(wire: String?): WithdrawalStatus =
            entries.firstOrNull { it.wire == wire?.trim()?.lowercase() } ?: UNKNOWN
    }
}

/** The immediate result of submitting a withdrawal. */
data class CustodyWithdrawalResult(
    val id: String,
    val status: WithdrawalStatus,
    val asset: String,
    val chain: String,
    val amountText: String,
    val destination: String,
    val signature: String?,
    val digest: String?,
    val approvalsRequired: Int?,
    val approvals: Int?,
    /** Best-effort human reason on a blocked/rejected outcome (detail, else error). */
    val reason: String?,
    val category: String?,
)

/** A withdrawal record (list + detail projections share this shape). */
data class CustodyWithdrawal(
    val id: String,
    val asset: String,
    val chain: String,
    val network: String,
    val recipient: String,
    val amountText: String,
    val status: WithdrawalStatus,
    val approvals: List<String>,
    val approvalsCount: Int,
    val approvalsRequired: Int,
    val signature: String?,
    val digest: String?,
    val reason: String?,
    val category: String?,
    val timelockUntilMs: Long?,
    val createdMs: Long?,
)

data class CustodyApproveResult(
    val withdrawalId: String,
    val status: WithdrawalStatus,
    val approvals: List<String>,
    val approvalsRequired: Int,
)

data class CustodyReleaseResult(
    val withdrawalId: String,
    val status: WithdrawalStatus,
    val signature: String?,
    val digest: String?,
)

data class CustodyAuditEntry(
    val seq: Long,
    val action: String,
    val detail: String,
    val tsMs: Long,
    val prev: String,
    val hash: String,
)

data class CustodyAudit(
    val entries: List<CustodyAuditEntry>,
    val verifiedOk: Boolean? = null,
    val verifiedCount: Int? = null,
)
