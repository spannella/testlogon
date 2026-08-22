package com.testlogon.android.feature.markets.trade

import com.testlogon.android.data.exchange.OrderSide

/** The two client-side execution algorithms. */
enum class AlgoKind { TWAP, ICEBERG }

/** Lifecycle of a client-side algo. Terminal states: DONE, CANCELLED. */
enum class AlgoStatus { RUNNING, PAUSED, DONE, CANCELLED }

/**
 * A durable, framework-free snapshot of one client-side algo order. The scheduler ([AlgoManager]) owns
 * live timers; this value graph is what persists (via [AlgoOrderStore]) and what the Active-Algos monitor
 * renders. All prices/quantities are raw int64 ticks (scaler = 1).
 *
 * TWAP fires one child per slice on a fixed cadence; ICEBERG places one visible clip and replenishes the
 * next when the prior is (assumed) filled. Both place children through the SAME submit path as the ticket
 * and respect paper-mode ([paperMode]).
 *
 * [placedQty] is the running total of child quantity actually submitted; [nextFireAtMs] is the wall-clock
 * time the next child is due (for the monitor countdown); [message] carries the last child result.
 */
data class AlgoOrder(
    val id: String,
    val kind: AlgoKind,
    val symbolId: Int,
    val symbolLabel: String,
    val side: OrderSide,
    val totalQty: Long,
    val limitPrice: Long?,          // null = market children (TWAP) / market clips (iceberg)
    val paperMode: Boolean,
    // TWAP params
    val slices: Int = 0,
    val durationMs: Long = 0L,
    val sliceIntervalMs: Long = 0L,
    // ICEBERG params
    val visibleQty: Long = 0L,
    // progress
    val childrenDone: Int = 0,      // slices fired (TWAP) / clips placed (iceberg)
    val childrenTotal: Int = 0,     // total slices (TWAP) / total clips (iceberg)
    val placedQty: Long = 0L,
    val status: AlgoStatus = AlgoStatus.RUNNING,
    val createdTsMs: Long = 0L,
    val nextFireAtMs: Long? = null, // wall-clock due time for the next child (RUNNING only)
    val message: String? = null,
) {
    val isTerminal: Boolean get() = status == AlgoStatus.DONE || status == AlgoStatus.CANCELLED
    val remainingQty: Long get() = (totalQty - placedQty).coerceAtLeast(0L)
    /** 0..1 progress by quantity placed. */
    val progress: Float get() = if (totalQty <= 0L) 0f else (placedQty.toFloat() / totalQty.toFloat()).coerceIn(0f, 1f)
}
