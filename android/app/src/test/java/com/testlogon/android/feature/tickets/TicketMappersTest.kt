package com.testlogon.android.feature.tickets

import com.testlogon.android.core.network.tickets.SpaceMemberOut
import com.testlogon.android.core.network.tickets.SpaceTicketMessage
import com.testlogon.android.core.network.tickets.SpaceTicketOut
import com.testlogon.android.core.network.tickets.TicketSpaceOut
import com.testlogon.android.feature.tickets.data.toDomain
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

/**
 * AND-372 - tests for the DTO -> domain mappers: memberCount derives from members.size, embedded members /
 * messages map element-wise, enum-like fields (visibility / status / role) are kept RAW (unknown-safe), the
 * subject comes from the `title` wire key, and ownerSub / assignedToSub are null (not on the verified DTO).
 */
class TicketMappersTest {

    @Test
    fun space_mapsMemberCountFromMembersSize_andKeepsVisibilityRaw() {
        val dto = TicketSpaceOut(
            spaceId = "s1",
            name = "Support",
            visibility = "shared",
            members = listOf(
                SpaceMemberOut(userSub = "u1", role = "owner"),
                SpaceMemberOut(userSub = "u2", role = "viewer"),
            ),
            updatedAt = 1234L,
        )

        val space = dto.toDomain()
        assertEquals("s1", space.spaceId)
        assertEquals("Support", space.name)
        assertEquals("shared", space.visibility)
        assertEquals(2, space.memberCount)
        assertEquals(2, space.members.size)
        assertEquals("u1", space.members[0].userSub)
        assertEquals("owner", space.members[0].role)
        assertEquals(1234L, space.updatedAt)
    }

    @Test
    fun space_emptyMembers_memberCountZero_unknownVisibilityKeptRaw() {
        val dto = TicketSpaceOut(spaceId = "s1", visibility = "weird")
        val space = dto.toDomain()
        assertEquals(0, space.memberCount)
        assertEquals("weird", space.visibility)
    }

    @Test
    fun ticket_mapsSubjectFromTitle_statusRaw_ownerAndAssigneeNull_messagesEmbedded() {
        val dto = SpaceTicketOut(
            ticketId = "t1",
            spaceId = "s1",
            title = "Cannot log in",
            status = "in_progress",
            updatedAt = 999L,
            messages = listOf(
                SpaceTicketMessage(messageId = "m1", senderSub = "u1", body = "first", createdAt = 10L),
                SpaceTicketMessage(messageId = "m2", senderSub = "u2", body = "second", createdAt = 20L),
            ),
        )

        val ticket = dto.toDomain()
        assertEquals("t1", ticket.ticketId)
        assertEquals("s1", ticket.spaceId)
        assertEquals("Cannot log in", ticket.subject)
        assertEquals("in_progress", ticket.status)
        assertNull(ticket.ownerSub)
        assertNull(ticket.assignedToSub)
        assertEquals(999L, ticket.updatedAt)
        assertEquals(2, ticket.messages.size)
        assertEquals("first", ticket.messages[0].body)
        assertEquals("u2", ticket.messages[1].senderSub)
    }

    @Test
    fun ticket_unknownStatusKeptRaw() {
        val ticket = SpaceTicketOut(ticketId = "t1", status = "escalated").toDomain()
        assertEquals("escalated", ticket.status)
    }

    @Test
    fun message_mapsAllFields() {
        val message = SpaceTicketMessage(
            messageId = "m1",
            senderSub = "u1",
            senderRole = "agent",
            body = "hello",
            createdAt = 42L,
        ).toDomain()
        assertEquals("m1", message.messageId)
        assertEquals("u1", message.senderSub)
        assertEquals("agent", message.senderRole)
        assertEquals("hello", message.body)
        assertEquals(42L, message.createdAt)
    }
}
