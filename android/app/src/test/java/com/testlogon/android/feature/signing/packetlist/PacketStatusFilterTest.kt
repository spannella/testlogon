package com.testlogon.android.feature.signing.packetlist

import com.testlogon.android.core.model.ApiError
import com.testlogon.android.core.network.signing.PacketRole
import com.testlogon.android.core.network.signing.PacketStatus
import com.testlogon.android.feature.signing.model.SignaturePacket
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * AND-344 - tests for the PURE [applyFilter] (ALL + each status) and the [PacketListUiState] envelope
 * mapping (Empty vs Content vs stale-error). There is NO backend list endpoint - this only filters a
 * caller-supplied list.
 */
class PacketStatusFilterTest {

    private fun packet(id: String, status: PacketStatus) = SignaturePacket(
        packetId = id,
        status = status,
        ownerUserId = "owner",
        sourcePath = "/docs/$id.pdf",
        role = PacketRole.SIGNER,
    )

    private val all = listOf(
        packet("d", PacketStatus.DRAFT),
        packet("s", PacketStatus.SENT),
        packet("p", PacketStatus.PARTIALLY_SIGNED),
        packet("c", PacketStatus.COMPLETED),
        packet("x", PacketStatus.CANCELLED),
        packet("e", PacketStatus.EXPIRED),
    )

    @Test
    fun applyFilter_all_returnsEverything_inOrder() {
        val out = applyFilter(all, PacketStatusFilter.ALL)
        assertEquals(all, out)
    }

    @Test
    fun applyFilter_eachStatus_selectsOnlyThatStatus() {
        assertEquals(listOf("d"), applyFilter(all, PacketStatusFilter.DRAFT).map { it.packetId })
        assertEquals(listOf("s"), applyFilter(all, PacketStatusFilter.SENT).map { it.packetId })
        assertEquals(
            listOf("p"),
            applyFilter(all, PacketStatusFilter.PARTIALLY_SIGNED).map { it.packetId },
        )
        assertEquals(listOf("c"), applyFilter(all, PacketStatusFilter.COMPLETED).map { it.packetId })
        assertEquals(listOf("x"), applyFilter(all, PacketStatusFilter.CANCELLED).map { it.packetId })
        assertEquals(listOf("e"), applyFilter(all, PacketStatusFilter.EXPIRED).map { it.packetId })
    }

    @Test
    fun applyFilter_noMatch_returnsEmpty() {
        val onlyDrafts = listOf(packet("d", PacketStatus.DRAFT))
        assertTrue(applyFilter(onlyDrafts, PacketStatusFilter.COMPLETED).isEmpty())
    }

    @Test
    fun toStatus_allIsNull_othersMap() {
        assertEquals(null, PacketStatusFilter.ALL.toStatus())
        assertEquals(PacketStatus.DRAFT, PacketStatusFilter.DRAFT.toStatus())
        assertEquals(PacketStatus.EXPIRED, PacketStatusFilter.EXPIRED.toStatus())
    }

    @Test
    fun uiState_content_carriesFilterAndFlags() {
        val state = PacketListUiState.Content(
            packets = applyFilter(all, PacketStatusFilter.SENT),
            filter = PacketStatusFilter.SENT,
            isRefreshing = true,
        )
        assertEquals(PacketStatusFilter.SENT, state.filter)
        assertTrue(state.isRefreshing)
        assertEquals(null, state.staleError)
        assertEquals(1, state.packets.size)
    }

    @Test
    fun uiState_content_staleError_retainsContentAndError() {
        val error = ApiError(ApiError.STATUS_NETWORK, "offline")
        val state = PacketListUiState.Content(
            packets = all,
            filter = PacketStatusFilter.ALL,
            staleError = error,
        )
        assertEquals(error, state.staleError)
        assertEquals(all, state.packets)
    }

    @Test
    fun uiState_empty_andError_areDistinctEnvelopes() {
        val empty: PacketListUiState = PacketListUiState.Empty
        val error: PacketListUiState = PacketListUiState.Error(ApiError(500, "boom"))
        assertTrue(empty is PacketListUiState.Empty)
        assertTrue(error is PacketListUiState.Error)
    }
}
