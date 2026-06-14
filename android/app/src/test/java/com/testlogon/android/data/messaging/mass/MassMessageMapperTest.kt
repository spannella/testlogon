package com.testlogon.android.data.messaging.mass

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/** AND-160 — pure mapper tests: DTO -> domain, isCancellable derivation, cancel reconciliation. */
class MassMessageMapperTest {

    @Test
    fun summary_mapsAllFields() {
        val dto = MassMessageCampaignSummaryDto(
            campaignId = "mmc_1",
            mode = "scheduled",
            status = "processing",
            sendAt = 1760003600,
            createdAt = 1760003500,
            updatedAt = 1760003600,
            counters = MassMessageCountersDto(total = 3, queued = 1, sent = 1, failed = 0, cancelled = 1),
        )
        val domain = dto.toDomain()
        assertEquals("mmc_1", domain.id)
        assertEquals(CampaignStatus.PROCESSING, domain.status)
        assertEquals(CampaignMode.SCHEDULED, domain.mode)
        assertEquals(1760003600L, domain.sendAtEpochSeconds)
        assertEquals(1760003500L, domain.createdAtEpochSeconds)
        assertEquals(3, domain.counters.total)
        assertEquals(1, domain.counters.cancelled)
        assertTrue(domain.isCancellable) // processing
    }

    @Test
    fun isCancellable_acrossAllStatuses() {
        fun status(s: String) = MassMessageCampaignSummaryDto(campaignId = "x", status = s).toDomain()
        assertTrue(status("pending").isCancellable)
        assertTrue(status("scheduled").isCancellable)
        assertTrue(status("processing").isCancellable)
        assertFalse(status("completed").isCancellable)
        assertFalse(status("failed").isCancellable)
        assertFalse(status("cancelled").isCancellable)
        assertEquals(CampaignStatus.UNKNOWN, status("weird").status)
    }

    @Test
    fun createResponse_carriesAcceptedAndRejected() {
        val dto = MassMessageCreateCampaignResponseDto(
            campaignId = "mmc_2",
            mode = "immediate",
            status = "pending",
            acceptedCount = 2,
            acceptedConversationIds = listOf("c1", "c2"),
            rejected = listOf(MassMessageRejectedDestinationDto("c3", "not_a_participant")),
        )
        val result = dto.toResult()
        assertEquals(2, result.acceptedCount)
        assertEquals(listOf("c1", "c2"), result.acceptedConversationIds)
        assertEquals(1, result.rejected.size)
        assertEquals("c3", result.rejected.single().conversationId)
        assertEquals("not_a_participant", result.rejected.single().reason)
        assertEquals(CampaignStatus.PENDING, result.campaign.status)
    }

    @Test
    fun cancelResponse_reconcilesWithPriorMetadata() {
        val prior = MassCampaign(
            id = "mmc_3",
            status = CampaignStatus.PROCESSING,
            mode = CampaignMode.SCHEDULED,
            sendAtEpochSeconds = 1760003600,
            createdAtEpochSeconds = 1760003000,
            updatedAtEpochSeconds = 1760003500,
            counters = CampaignCounters(total = 10),
        )
        val dto = MassMessageCancelCampaignResponseDto(
            campaignId = "mmc_3",
            status = "cancelled",
            cancelledDestinations = 4,
            updatedAt = 1760005000,
            counters = MassMessageCountersDto(total = 10, sent = 6, cancelled = 4),
        )
        val reconciled = dto.toDomain(prior)
        assertEquals(CampaignStatus.CANCELLED, reconciled.status)
        assertEquals(CampaignMode.SCHEDULED, reconciled.mode) // from prior
        assertEquals(1760003000L, reconciled.createdAtEpochSeconds) // from prior
        assertEquals(1760005000L, reconciled.updatedAtEpochSeconds) // from cancel
        assertEquals(4, reconciled.counters.cancelled)
    }
}
