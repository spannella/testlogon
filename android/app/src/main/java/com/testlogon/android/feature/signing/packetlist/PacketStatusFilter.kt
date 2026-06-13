package com.testlogon.android.feature.signing.packetlist

import com.testlogon.android.core.model.ApiError
import com.testlogon.android.core.network.signing.PacketStatus
import com.testlogon.android.feature.signing.model.SignaturePacket

/**
 * AND-344 - PURE in-memory status filter + UI envelope for a (caller-supplied) list of signature
 * packets.
 *
 * !! NO BACKEND LIST ENDPOINT !!
 * The web composer (and the AND-339 API) loads ONE packet by id - there is NO list/browse endpoint on
 * the server. Accordingly this is NOT a data source and does NOT fetch anything: [applyFilter] is a pure
 * function over a list the CALLER already holds (today, in the single-packet world, that list is at most
 * one packet). Do NOT invent a list endpoint to back this; if/when a backend list arrives, the caller
 * supplies it and this filter is unchanged.
 *
 * This file is Android-free and JVM-testable.
 */

/** The status buckets a caller can filter a packet list by ([ALL] is the no-op pass-through). */
enum class PacketStatusFilter {
    ALL,
    DRAFT,
    SENT,
    PARTIALLY_SIGNED,
    COMPLETED,
    CANCELLED,
    EXPIRED,
    ;

    /**
     * The AND-339 [PacketStatus] this filter selects, or null for [ALL]. UNKNOWN has no filter (it is
     * only ever matched by [ALL]).
     */
    fun toStatus(): PacketStatus? = when (this) {
        ALL -> null
        DRAFT -> PacketStatus.DRAFT
        SENT -> PacketStatus.SENT
        PARTIALLY_SIGNED -> PacketStatus.PARTIALLY_SIGNED
        COMPLETED -> PacketStatus.COMPLETED
        CANCELLED -> PacketStatus.CANCELLED
        EXPIRED -> PacketStatus.EXPIRED
    }
}

/**
 * PURE filter: returns the [packets] whose [SignaturePacket.status] matches [filter], or all of them for
 * [PacketStatusFilter.ALL]. Order is preserved. No I/O, no endpoint - see the file KDoc.
 */
fun applyFilter(
    packets: List<SignaturePacket>,
    filter: PacketStatusFilter,
): List<SignaturePacket> {
    val target = filter.toStatus() ?: return packets
    return packets.filter { it.status == target }
}

/**
 * The UI envelope for the (filtered) packet list surface. [Content] additionally carries the active
 * [filter], a pull-to-refresh flag and a retained [staleError] (a refresh that failed while content was
 * already showing - mirrors the stale-display discipline used by AND-340's PacketDetail).
 */
sealed interface PacketListUiState {

    /** Initial load (the caller is sourcing the list). */
    data object Loading : PacketListUiState

    /** A non-empty filtered list. */
    data class Content(
        val packets: List<SignaturePacket>,
        val filter: PacketStatusFilter,
        val isRefreshing: Boolean = false,
        val staleError: ApiError? = null,
    ) : PacketListUiState

    /** The list is empty (either no packets at all, or none match the active filter). */
    data object Empty : PacketListUiState

    /** A terminal load error with no prior content to fall back to. */
    data class Error(val error: ApiError) : PacketListUiState
}
