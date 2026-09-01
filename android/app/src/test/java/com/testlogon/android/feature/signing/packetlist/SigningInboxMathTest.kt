package com.testlogon.android.feature.signing.packetlist

import com.testlogon.android.core.model.ApiError
import com.testlogon.android.core.network.signing.PacketStatus
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/** SUX-008 — pure tests for the signing inbox fold (buildInboxState) + degrade-on-404 contract. */
class SigningInboxMathTest {

    private fun item(id: String, status: PacketStatus = PacketStatus.SENT) =
        SigningInboxItem(packetId = id, status = status)

    private fun loaded(bucket: SigningInboxBucket, vararg ids: String) =
        BucketLoad(bucket, items = ids.map { item(it) })

    private fun failed(bucket: SigningInboxBucket, status: Int) =
        BucketLoad(bucket, failure = ApiError(status = status, message = "x"))

    @Test
    fun allBucketsEmpty_isEmpty() {
        val state = buildInboxState(
            listOf(
                BucketLoad(SigningInboxBucket.AWAITING),
                BucketLoad(SigningInboxBucket.SENT),
                BucketLoad(SigningInboxBucket.COMPLETED),
                BucketLoad(SigningInboxBucket.DRAFTS),
            ),
        )
        assertEquals(SigningInboxUiState.Empty, state)
    }

    @Test
    fun nonEmptyBuckets_becomeSectionsInCanonicalOrder() {
        val state = buildInboxState(
            listOf(
                loaded(SigningInboxBucket.DRAFTS, "d1"),
                loaded(SigningInboxBucket.AWAITING, "a1", "a2"),
                BucketLoad(SigningInboxBucket.SENT), // empty -> omitted
                loaded(SigningInboxBucket.COMPLETED, "c1"),
            ),
        )
        assertTrue(state is SigningInboxUiState.Content)
        val content = state as SigningInboxUiState.Content
        assertEquals(
            listOf(
                SigningInboxBucket.AWAITING,
                SigningInboxBucket.COMPLETED,
                SigningInboxBucket.DRAFTS,
            ),
            content.sections.map { it.bucket },
        )
        assertEquals(2, content.awaitingCount)
        assertEquals(4, content.totalCount)
    }

    @Test
    fun oneBucket404_dropsThatBucketOnly() {
        // awaiting 404s (flag-partial), the rest load -> content still renders from the loaded buckets.
        val state = buildInboxState(
            listOf(
                failed(SigningInboxBucket.AWAITING, 404),
                loaded(SigningInboxBucket.SENT, "s1"),
                BucketLoad(SigningInboxBucket.COMPLETED),
                BucketLoad(SigningInboxBucket.DRAFTS),
            ),
        )
        assertTrue(state is SigningInboxUiState.Content)
        val content = state as SigningInboxUiState.Content
        assertEquals(listOf(SigningInboxBucket.SENT), content.sections.map { it.bucket })
        assertEquals(0, content.awaitingCount)
    }

    @Test
    fun allBucketsFail404_isError_withThe404() {
        val state = buildInboxState(
            listOf(
                failed(SigningInboxBucket.AWAITING, 404),
                failed(SigningInboxBucket.SENT, 404),
                failed(SigningInboxBucket.COMPLETED, 404),
                failed(SigningInboxBucket.DRAFTS, 404),
            ),
        )
        assertTrue(state is SigningInboxUiState.Error)
        assertEquals(404, (state as SigningInboxUiState.Error).error.status)
    }

    @Test
    fun allBucketsFailMixed_prefers404AsSurfacedError() {
        val state = buildInboxState(
            listOf(
                failed(SigningInboxBucket.AWAITING, 500),
                failed(SigningInboxBucket.SENT, 404),
                failed(SigningInboxBucket.COMPLETED, 500),
                failed(SigningInboxBucket.DRAFTS, 500),
            ),
        )
        assertTrue(state is SigningInboxUiState.Error)
        assertEquals(404, (state as SigningInboxUiState.Error).error.status)
    }

    @Test
    fun dtoMapper_parsesStatusAndTitle() {
        val dto = com.testlogon.android.core.network.signing.SigningInboxItemDto(
            packetId = "p1",
            status = "partially_signed",
            sourceName = "Lease.pdf",
        )
        val domain = dto.toDomain()
        assertEquals(PacketStatus.PARTIALLY_SIGNED, domain.status)
        assertEquals("Lease.pdf", domain.displayTitle)
    }

    @Test
    fun dtoMapper_unknownStatus_fallsBack_andTitleFallsBackToId() {
        val dto = com.testlogon.android.core.network.signing.SigningInboxItemDto(
            packetId = "p2",
            status = "weird_status",
            sourceName = null,
        )
        val domain = dto.toDomain()
        assertEquals(PacketStatus.UNKNOWN, domain.status)
        assertEquals("p2", domain.displayTitle)
    }
}
