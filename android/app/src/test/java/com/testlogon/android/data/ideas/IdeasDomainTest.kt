package com.testlogon.android.data.ideas

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Unit tests for the product-ideas DTO -> domain mappers and value objects: [IdeaStatus.from] string
 * folding (incl. UNKNOWN), [IdeaDto.toDomain] field threading (id / title / description / status /
 * rejectionReason / createdAt), [IdeaListDto.toDomain] list + next_cursor mapping, and
 * [IdeasPage.isEmpty].
 */
class IdeasDomainTest {

    private fun dto(
        ideaId: String = "idea_1",
        title: String = "Dark mode",
        description: String = "Add a dark theme.",
        status: String = "submitted",
        rejectionReason: String? = null,
        createdAt: Long = 1_750_000_000L,
        updatedAt: Long = 1_750_000_500L,
    ) = IdeaDto(
        ideaId = ideaId,
        title = title,
        description = description,
        status = status,
        rejectionReason = rejectionReason,
        createdAt = createdAt,
        updatedAt = updatedAt,
    )

    // ---- IdeaStatus.from ----

    @Test
    fun status_from_mapsKnownValues() {
        assertEquals(IdeaStatus.SUBMITTED, IdeaStatus.from("submitted"))
        assertEquals(IdeaStatus.TRIAGING, IdeaStatus.from("triaging"))
        assertEquals(IdeaStatus.ACCEPTED, IdeaStatus.from("accepted"))
        assertEquals(IdeaStatus.REJECTED, IdeaStatus.from("rejected"))
        assertEquals(IdeaStatus.CONVERTED, IdeaStatus.from("converted"))
    }

    @Test
    fun status_from_isCaseInsensitive() {
        assertEquals(IdeaStatus.ACCEPTED, IdeaStatus.from("ACCEPTED"))
        assertEquals(IdeaStatus.TRIAGING, IdeaStatus.from("Triaging"))
    }

    @Test
    fun status_from_unknownOrNull_mapsToUnknown() {
        assertEquals(IdeaStatus.UNKNOWN, IdeaStatus.from("something_else"))
        assertEquals(IdeaStatus.UNKNOWN, IdeaStatus.from(""))
        assertEquals(IdeaStatus.UNKNOWN, IdeaStatus.from(null))
    }

    // ---- IdeaDto.toDomain ----

    @Test
    fun ideaDto_toDomain_mapsFields() {
        val idea = dto(
            ideaId = "idea_42",
            title = "Calendar sync",
            description = "Two-way sync with Google Calendar.",
            status = "accepted",
            rejectionReason = "n/a but present",
            createdAt = 1_751_111_111L,
        ).toDomain()

        assertEquals("idea_42", idea.id)
        assertEquals("Calendar sync", idea.title)
        assertEquals("Two-way sync with Google Calendar.", idea.description)
        assertEquals(IdeaStatus.ACCEPTED, idea.status)
        assertEquals("n/a but present", idea.rejectionReason)
        assertEquals(1_751_111_111L, idea.createdAtSeconds)
    }

    @Test
    fun ideaDto_toDomain_blankRejectionReason_mapsToNull() {
        assertNull(dto(rejectionReason = null).toDomain().rejectionReason)
        assertNull(dto(rejectionReason = "   ").toDomain().rejectionReason)
    }

    // ---- IdeaListDto.toDomain ----

    @Test
    fun ideaListDto_toDomain_mapsListAndNextCursor() {
        val list = IdeaListDto(
            ideas = listOf(dto(ideaId = "a"), dto(ideaId = "b")),
            nextCursor = "cursor_xyz",
        ).toDomain()

        assertEquals(2, list.ideas.size)
        assertEquals("a", list.ideas[0].id)
        assertEquals("b", list.ideas[1].id)
        assertEquals("cursor_xyz", list.nextCursor)
    }

    @Test
    fun ideaListDto_toDomain_emptyList_nullCursor() {
        val list = IdeaListDto(ideas = emptyList(), nextCursor = null).toDomain()
        assertTrue(list.ideas.isEmpty())
        assertNull(list.nextCursor)
    }

    // ---- IdeasPage.isEmpty ----

    @Test
    fun ideasPage_isEmpty_trueForEmptyList() {
        assertTrue(IdeasPage(ideas = emptyList(), nextCursor = null).isEmpty)
    }

    @Test
    fun ideasPage_isEmpty_falseWhenIdeasPresent() {
        assertFalse(IdeasPage(ideas = listOf(dto().toDomain()), nextCursor = null).isEmpty)
    }
}
