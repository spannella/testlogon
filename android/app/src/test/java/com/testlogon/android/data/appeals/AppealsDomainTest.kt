package com.testlogon.android.data.appeals

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class AppealsDomainTest {

    private fun dto(
        appealId: String = "apl_1",
        status: String = "submitted",
        enforcementType: String? = "suspension",
        sourceTicketId: String? = "tkt_1",
        decidedAt: Long? = null,
        decisionNote: String? = null,
        modifiedEnforcementType: String? = null,
        modifiedDurationDays: Int? = null,
    ) = AppealDto(
        appealId = appealId,
        enforcementId = "enf_1",
        enforcementType = enforcementType,
        sourceTicketId = sourceTicketId,
        appealText = "Please reconsider.",
        status = status,
        createdAt = 1_700_000_000L,
        updatedAt = 1_700_000_100L,
        decidedAt = decidedAt,
        decisionNote = decisionNote,
        modifiedEnforcementType = modifiedEnforcementType,
        modifiedDurationDays = modifiedDurationDays,
    )

    // ---- status string -> enum ----

    @Test
    fun status_submitted_mapsToSubmitted() {
        assertEquals(AppealStatus.SUBMITTED, dto(status = "submitted").toDomain().status)
    }

    @Test
    fun status_underReview_mapsToUnderReview() {
        assertEquals(AppealStatus.UNDER_REVIEW, dto(status = "under_review").toDomain().status)
    }

    @Test
    fun status_upheld_mapsToUpheld() {
        assertEquals(AppealStatus.UPHELD, dto(status = "upheld").toDomain().status)
    }

    @Test
    fun status_modified_mapsToModified() {
        assertEquals(AppealStatus.MODIFIED, dto(status = "modified").toDomain().status)
    }

    @Test
    fun status_reversed_mapsToReversed() {
        assertEquals(AppealStatus.REVERSED, dto(status = "reversed").toDomain().status)
    }

    @Test
    fun status_withdrawn_mapsToWithdrawn() {
        assertEquals(AppealStatus.WITHDRAWN, dto(status = "withdrawn").toDomain().status)
    }

    @Test
    fun status_unrecognized_mapsToUnknown() {
        assertEquals(AppealStatus.UNKNOWN, dto(status = "banana").toDomain().status)
    }

    @Test
    fun status_blank_mapsToUnknown() {
        assertEquals(AppealStatus.UNKNOWN, dto(status = "").toDomain().status)
    }

    @Test
    fun status_isCaseInsensitive() {
        assertEquals(AppealStatus.UNDER_REVIEW, dto(status = "UNDER_REVIEW").toDomain().status)
    }

    // ---- canWithdraw ----

    @Test
    fun canWithdraw_trueForSubmitted() {
        assertTrue(dto(status = "submitted").toDomain().canWithdraw)
    }

    @Test
    fun canWithdraw_trueForUnderReview() {
        assertTrue(dto(status = "under_review").toDomain().canWithdraw)
    }

    @Test
    fun canWithdraw_falseForDecidedAndWithdrawnAndUnknown() {
        assertFalse(dto(status = "upheld").toDomain().canWithdraw)
        assertFalse(dto(status = "modified").toDomain().canWithdraw)
        assertFalse(dto(status = "reversed").toDomain().canWithdraw)
        assertFalse(dto(status = "withdrawn").toDomain().canWithdraw)
        assertFalse(dto(status = "banana").toDomain().canWithdraw)
    }

    @Test
    fun isDecided_trueOnlyForUpheldModifiedReversed() {
        assertTrue(AppealStatus.UPHELD.isDecided)
        assertTrue(AppealStatus.MODIFIED.isDecided)
        assertTrue(AppealStatus.REVERSED.isDecided)
        assertFalse(AppealStatus.SUBMITTED.isDecided)
        assertFalse(AppealStatus.UNDER_REVIEW.isDecided)
        assertFalse(AppealStatus.WITHDRAWN.isDecided)
        assertFalse(AppealStatus.UNKNOWN.isDecided)
    }

    // ---- decision fields / timestamps ----

    @Test
    fun decisionFields_mapThrough() {
        val appeal = dto(
            status = "modified",
            decidedAt = 1_700_000_500L,
            decisionNote = "Reduced to a warning.",
            modifiedEnforcementType = "warning",
            modifiedDurationDays = 7,
        ).toDomain()

        assertEquals(1_700_000_500L, appeal.decidedAtSeconds)
        assertEquals("Reduced to a warning.", appeal.decisionNote)
        assertEquals("warning", appeal.modifiedEnforcementType)
        assertEquals(7, appeal.modifiedDurationDays)
        assertTrue(appeal.hasDecision)
    }

    @Test
    fun coreFieldsAndTimestamps_mapThrough() {
        val appeal = dto(appealId = "apl_99").toDomain()
        assertEquals("apl_99", appeal.id)
        assertEquals("enf_1", appeal.enforcementId)
        assertEquals("Please reconsider.", appeal.appealText)
        assertEquals(1_700_000_000L, appeal.createdAtSeconds)
        assertEquals(1_700_000_100L, appeal.updatedAtSeconds)
    }

    @Test
    fun blankOptionalStrings_becomeNull() {
        val appeal = dto(
            enforcementType = "",
            sourceTicketId = "  ",
            decisionNote = "",
            modifiedEnforcementType = "",
        ).toDomain()
        assertNull(appeal.enforcementType)
        assertNull(appeal.sourceTicketId)
        assertNull(appeal.decisionNote)
        assertNull(appeal.modifiedEnforcementType)
    }

    @Test
    fun nullDecidedAt_mapsToNull() {
        assertNull(dto(decidedAt = null).toDomain().decidedAtSeconds)
    }

    // ---- list / page ----

    @Test
    fun listDto_mapsItemsAndPassesThroughNextCursor() {
        val list = AppealListDto(
            items = listOf(dto(appealId = "a1"), dto(appealId = "a2")),
            nextCursor = "cursor_xyz",
        )
        val pageDomain = list.toDomain()
        assertEquals(2, pageDomain.appeals.size)
        assertEquals("a1", pageDomain.appeals[0].id)
        assertEquals("a2", pageDomain.appeals[1].id)
        assertEquals("cursor_xyz", pageDomain.nextCursor)
        assertFalse(pageDomain.isEmpty)
    }

    @Test
    fun emptyListDto_mapsToEmptyPage_withNullCursor() {
        val pageDomain = AppealListDto(items = emptyList(), nextCursor = null).toDomain()
        assertTrue(pageDomain.appeals.isEmpty())
        assertTrue(pageDomain.isEmpty)
        assertNull(pageDomain.nextCursor)
    }
}
