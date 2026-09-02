package com.testlogon.android.feature.maintenance

import java.time.Instant

/**
 * WOV — PURE work-order + vendor status logic (Android-free, JVM-testable). This is the single home for
 * the derived rules the maintenance UI drives off of: vendor status toggles + filters, board-column
 * ordering + bucketing of work orders into columns, and small label/derivation helpers. The work-order
 * state machine ([allowedTransitions] / [canTransition] / [sortForBoard]) lives in MaintenanceOrderModel.kt
 * and is intentionally NOT duplicated here.
 */

// ---------------------------------------------------------------------------
// Vendor status logic
// ---------------------------------------------------------------------------

/** Human label for a vendor status. */
fun vendorStatusLabel(status: VendorStatus): String = when (status) {
    VendorStatus.ACTIVE -> "Active"
    VendorStatus.INACTIVE -> "Inactive"
    VendorStatus.UNKNOWN -> "Unknown"
}

/** The action label for the status toggle button (what the tap will DO). */
fun vendorToggleActionLabel(status: VendorStatus): String = when (status) {
    VendorStatus.ACTIVE -> "Deactivate"
    VendorStatus.INACTIVE -> "Activate"
    VendorStatus.UNKNOWN -> "Activate"
}

/**
 * True iff a status toggle is a meaningful mutation from [current] to [target]. UNKNOWN is never a
 * valid target (the wire only accepts active/inactive) and a no-op (same status) is rejected so the UI
 * doesn't fire a pointless write.
 */
fun canSetVendorStatus(current: VendorStatus, target: VendorStatus): Boolean =
    target != VendorStatus.UNKNOWN && target != current

/**
 * PURE filter of a vendor list to a [status] (null keeps all) then a [tradeCategory] (null/blank keeps
 * all), preserving input order. Mirrors the server-side status/trade_category query filter so the UI
 * can filter an already-loaded page without a round-trip.
 */
fun filterVendors(
    vendors: List<Vendor>,
    status: VendorStatus? = null,
    tradeCategory: String? = null,
): List<Vendor> = vendors.filter { v ->
    (status == null || v.status == status) &&
        (tradeCategory.isNullOrBlank() || v.tradeCategory == tradeCategory)
}

/**
 * PURE ordering for the vendor directory: ACTIVE before INACTIVE before UNKNOWN, then by name
 * (case-insensitive), then vendor id (stable + total). Deterministic list rendering.
 */
fun sortVendors(vendors: List<Vendor>): List<Vendor> {
    fun statusRank(s: VendorStatus): Int = when (s) {
        VendorStatus.ACTIVE -> 0
        VendorStatus.INACTIVE -> 1
        VendorStatus.UNKNOWN -> 2
    }
    return vendors.sortedWith(
        compareBy<Vendor> { statusRank(it.status) }
            .thenBy { it.name.lowercase() }
            .thenBy { it.vendorId },
    )
}

// ---------------------------------------------------------------------------
// Work-order board columns
// ---------------------------------------------------------------------------

/**
 * The default board columns to fall back on when the server layout is empty/unavailable (mirrors the
 * backend _DEFAULT_WO_COLUMNS). Ordered open -> assigned -> in_progress -> completed -> cancelled.
 */
fun defaultBoardColumns(): List<WoBoardColumn> = listOf(
    WoBoardColumn("wo_open", "Open", WoStatus.OPEN, 0),
    WoBoardColumn("wo_assigned", "Assigned", WoStatus.ASSIGNED, 1),
    WoBoardColumn("wo_in_progress", "In Progress", WoStatus.IN_PROGRESS, 2),
    WoBoardColumn("wo_completed", "Completed", WoStatus.COMPLETED, 3),
    WoBoardColumn("wo_cancelled", "Cancelled", WoStatus.CANCELLED, 4),
)

/**
 * PURE ordering of the server-provided board columns by their `order` field (stable; ties broken by
 * column id). Unknown-status columns are kept (they still render, just at their given order).
 */
fun sortBoardColumns(columns: List<WoBoardColumn>): List<WoBoardColumn> =
    columns.sortedWith(compareBy<WoBoardColumn> { it.order }.thenBy { it.columnId })

/**
 * PURE bucketing of [orders] into the board [columns]: each column maps to the subset of orders whose
 * status matches the column's status key, board-sorted within the column. Returns a list of
 * (column -> orders) pairs in board-column order. An UNKNOWN-status order lands in no column (dropped
 * from the board view, mirroring the server's fixed column set).
 */
fun bucketOrdersByColumn(
    orders: List<MaintenanceOrder>,
    columns: List<WoBoardColumn>,
): List<Pair<WoBoardColumn, List<MaintenanceOrder>>> {
    val sortedColumns = sortBoardColumns(columns)
    return sortedColumns.map { col ->
        col to sortForBoard(orders.filter { it.status == col.statusKey })
    }
}

/** Count of orders in a given column's status bucket (for a column-header badge). */
fun columnOrderCount(orders: List<MaintenanceOrder>, column: WoBoardColumn): Int =
    orders.count { it.status == column.statusKey }

// ---------------------------------------------------------------------------
// Small derivations
// ---------------------------------------------------------------------------

/** True iff the vendor was updated after it was created (i.e. edited at least once). */
fun vendorWasEdited(vendor: Vendor): Boolean {
    val created = vendor.createdAt ?: return false
    val updated = vendor.updatedAt ?: return false
    return updated.isAfter(created)
}

/** True iff [vendor] is linked to a platform account (has a non-blank user_sub). */
fun vendorIsLinked(vendor: Vendor): Boolean = !vendor.userSub.isNullOrBlank()

/** Newest-first instant for stable display; EPOCH when absent. */
fun vendorSortInstant(vendor: Vendor): Instant =
    vendor.updatedAt ?: vendor.createdAt ?: Instant.EPOCH
