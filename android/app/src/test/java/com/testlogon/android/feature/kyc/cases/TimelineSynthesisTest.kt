package com.testlogon.android.feature.kyc.cases

import com.testlogon.android.core.model.kyc.KycCaseFile
import com.testlogon.android.core.model.kyc.KycCaseOut
import com.testlogon.android.core.model.kyc.KycCaseReviewRef
import com.testlogon.android.core.model.kyc.KycCaseStatus
import com.testlogon.android.feature.kyc.cases.model.TimelineKind
import com.testlogon.android.feature.kyc.cases.model.synthesizeTimeline
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.time.Instant

/**
 * AND-329 - unit tests for the PURE [synthesizeTimeline] over sample [KycCaseOut] values. There is no wire
 * history array; the events are derived from the case fields and ordered oldest -> newest. Uses the default
 * token label resolver (no Android resources).
 */
class TimelineSynthesisTest {

    private fun case(
        status: KycCaseStatus,
        createdAt: Long,
        updatedAt: Long,
        files: List<KycCaseFile> = emptyList(),
        submission: Map<String, Any?> = emptyMap(),
        review: KycCaseReviewRef? = null,
    ) = KycCaseOut(
        kyc_case_id = "case_1",
        user_sub = "u1",
        status = status,
        files = files,
        submission = submission,
        review = review,
        created_at = createdAt,
        updated_at = updatedAt,
        version = 1,
    )

    @Test
    fun draftCase_onlyCreatedAndCurrent_orderedByTime() {
        val timeline = synthesizeTimeline(
            case(status = KycCaseStatus.DRAFT, createdAt = 1_000L, updatedAt = 2_000L),
        )

        assertEquals(listOf(TimelineKind.CREATED, TimelineKind.CURRENT), timeline.map { it.kind })
        assertEquals(Instant.ofEpochSecond(1_000L), timeline.first().at)
        assertEquals(Instant.ofEpochSecond(2_000L), timeline.last().at)
    }

    @Test
    fun fullCase_includesDocumentsSubmittedAndDecision_inChronologicalOrder() {
        val timeline = synthesizeTimeline(
            case(
                status = KycCaseStatus.REJECTED,
                createdAt = 1_000L,
                updatedAt = 5_000L,
                files = listOf(KycCaseFile(type = "id_front", uploaded_at = 2_000L)),
                submission = mapOf("submitted_by" to "u1"),
                review = KycCaseReviewRef(
                    decision = "reject",
                    decided_at = 4_000L,
                    reason_codes = listOf("doc_unreadable", "name_mismatch"),
                ),
            ),
        )

        // created(1000) -> documents(2000) -> decision(4000) -> submitted/current(5000).
        val kinds = timeline.map { it.kind }
        assertTrue(kinds.contains(TimelineKind.CREATED))
        assertTrue(kinds.contains(TimelineKind.DOCUMENTS))
        assertTrue(kinds.contains(TimelineKind.SUBMITTED))
        assertTrue(kinds.contains(TimelineKind.DECISION))
        assertTrue(kinds.contains(TimelineKind.CURRENT))

        // Ordered oldest -> newest.
        val times = timeline.map { it.at }
        assertEquals(times.sorted(), times)

        val decision = timeline.first { it.kind == TimelineKind.DECISION }
        assertEquals(Instant.ofEpochSecond(4_000L), decision.at)
        assertEquals("doc_unreadable, name_mismatch", decision.note)
    }

    @Test
    fun decisionWithoutDecidedAt_isOmitted() {
        val timeline = synthesizeTimeline(
            case(
                status = KycCaseStatus.UNDER_REVIEW,
                createdAt = 1_000L,
                updatedAt = 2_000L,
                review = KycCaseReviewRef(decision = "approve", decided_at = null),
            ),
        )

        assertTrue(timeline.none { it.kind == TimelineKind.DECISION })
    }
}
