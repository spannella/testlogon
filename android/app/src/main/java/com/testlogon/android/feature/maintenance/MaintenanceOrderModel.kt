package com.testlogon.android.feature.maintenance

import com.testlogon.android.core.network.maintenance.MaintenanceOrderDto
import java.time.Instant

/**
 * WOV — feature domain + DTO mappers + PURE status logic for the Maintenance Work Orders surface.
 * Android-free + JVM-testable.
 *
 * Enums carry the wire token + a lenient UNKNOWN fallback (mirrors the core-network signing enums'
 * fromToken discipline) so an unrecognized server value never throws. Timestamps are Unix-second Longs
 * on the wire; 0/null degrade to null [Instant].
 */

/** Work-order priority (mirrors WoPriority). */
enum class WoPriority(val token: String) {
    URGENT("urgent"),
    HIGH("high"),
    NORMAL("normal"),
    LOW("low"),
    UNKNOWN("unknown"),
    ;

    companion object {
        fun fromToken(t: String?): WoPriority = entries.firstOrNull { it.token == t } ?: UNKNOWN
    }
}

/** Work-order lifecycle status (mirrors WoStatus). */
enum class WoStatus(val token: String) {
    OPEN("open"),
    ASSIGNED("assigned"),
    IN_PROGRESS("in_progress"),
    COMPLETED("completed"),
    CANCELLED("cancelled"),
    UNKNOWN("unknown"),
    ;

    /** Terminal states accept no further transition. */
    val isTerminal: Boolean get() = this == COMPLETED || this == CANCELLED

    companion object {
        fun fromToken(t: String?): WoStatus = entries.firstOrNull { it.token == t } ?: UNKNOWN
    }
}

/** One maintenance work order (mapped from [MaintenanceOrderDto]). */
data class MaintenanceOrder(
    val workOrderId: String,
    val propertyId: String,
    val title: String,
    val description: String? = null,
    val priority: WoPriority = WoPriority.NORMAL,
    val status: WoStatus = WoStatus.OPEN,
    val unitId: String? = null,
    val vendorId: String? = null,
    val assigneeSub: String? = null,
    val scheduledFor: Instant? = null,
    val costCents: Long? = null,
    val createdAt: Instant? = null,
    val updatedAt: Instant? = null,
    val completedAt: Instant? = null,
    val escrowAmountCents: Long? = null,
    val escrowStatus: String? = null,
)

private fun epochToInstant(sec: Long?): Instant? =
    sec?.takeIf { it > 0 }?.let { Instant.ofEpochSecond(it) }

/** Maps a transport work order to the feature domain. */
fun MaintenanceOrderDto.toDomain(): MaintenanceOrder = MaintenanceOrder(
    workOrderId = workOrderId,
    propertyId = propertyId,
    title = title,
    description = description,
    priority = WoPriority.fromToken(priority),
    status = WoStatus.fromToken(woStatus),
    unitId = unitId,
    vendorId = vendorId,
    assigneeSub = assigneeSub,
    scheduledFor = epochToInstant(scheduledFor),
    costCents = costCents,
    createdAt = epochToInstant(createdAt),
    updatedAt = epochToInstant(updatedAt),
    completedAt = epochToInstant(completedAt),
    escrowAmountCents = escrowAmountCents,
    escrowStatus = escrowStatus,
)

/**
 * PURE work-order state machine: the set of [WoStatus] a work order may transition INTO from [from].
 * Mirrors the backend's allowed transitions (open -> assigned/in_progress/cancelled; assigned ->
 * in_progress/cancelled; in_progress -> completed/cancelled). Terminal + UNKNOWN states allow nothing.
 *
 * `open -> completed` is intentionally NOT offered directly (work must be picked up first); the caller
 * moves through in_progress. This drives which status buttons the detail UI enables.
 */
fun allowedTransitions(from: WoStatus): Set<WoStatus> = when (from) {
    WoStatus.OPEN -> setOf(WoStatus.ASSIGNED, WoStatus.IN_PROGRESS, WoStatus.CANCELLED)
    WoStatus.ASSIGNED -> setOf(WoStatus.IN_PROGRESS, WoStatus.CANCELLED)
    WoStatus.IN_PROGRESS -> setOf(WoStatus.COMPLETED, WoStatus.CANCELLED)
    WoStatus.COMPLETED, WoStatus.CANCELLED, WoStatus.UNKNOWN -> emptySet()
}

/** True iff [target] is a legal next status from [from]. */
fun canTransition(from: WoStatus, target: WoStatus): Boolean = target in allowedTransitions(from)

/**
 * PURE list ordering for the board: OPEN/ASSIGNED/IN_PROGRESS first (active), then terminal; within a
 * status, higher priority first, then most-recently-updated first. Stable + total so the UI list is
 * deterministic.
 */
fun sortForBoard(orders: List<MaintenanceOrder>): List<MaintenanceOrder> {
    fun statusRank(s: WoStatus): Int = when (s) {
        WoStatus.IN_PROGRESS -> 0
        WoStatus.ASSIGNED -> 1
        WoStatus.OPEN -> 2
        WoStatus.COMPLETED -> 3
        WoStatus.CANCELLED -> 4
        WoStatus.UNKNOWN -> 5
    }
    fun priorityRank(p: WoPriority): Int = when (p) {
        WoPriority.URGENT -> 0
        WoPriority.HIGH -> 1
        WoPriority.NORMAL -> 2
        WoPriority.LOW -> 3
        WoPriority.UNKNOWN -> 4
    }
    return orders.sortedWith(
        compareBy<MaintenanceOrder> { statusRank(it.status) }
            .thenBy { priorityRank(it.priority) }
            .thenByDescending { it.updatedAt ?: Instant.EPOCH },
    )
}
