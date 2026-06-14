package com.testlogon.android.core.network.tickets

import com.squareup.moshi.JsonDataException
import com.squareup.moshi.Moshi
import com.squareup.moshi.kotlin.reflect.KotlinJsonAdapterFactory
import com.testlogon.android.core.network.json.BigDecimalAdapter
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * AND-371 - DTO-level Moshi tests for the AND-371 ticket spaces transport (mirrors OrgDtoJsonTest /
 * SponsorshipDtoJsonTest).
 *
 * Focus: NAMED + list envelope decoding, embedded members / messages / activity, enum-like raw-String
 * tolerance (incl. an UNKNOWN value that must NOT throw), OPTIONAL-field + empty-list defaults, EXTRA-key
 * tolerance, and required-field enforcement. The Moshi is built like NetworkModule.provideMoshi
 * (BigDecimalAdapter + the reflective KotlinJsonAdapterFactory). core-network has no test dependency on
 * core-testing, so the JSON is inline. KDoc avoids the comment-terminator pair.
 */
class TicketDtoJsonTest {

    private val moshi: Moshi = Moshi.Builder()
        .add(BigDecimalAdapter)
        .add(KotlinJsonAdapterFactory())
        .build()

    // ---- space round-trip with embedded members + enum-likes ----

    @Test
    fun space_roundTrips_withEmbeddedMembers_andEnumLikeStrings() {
        val adapter = moshi.adapter(TicketSpaceOut::class.java)
        val json = """{"space_id":"sp_1","name":"Support","visibility":"shared",
            "members":[{"user_sub":"usr_a","role":"owner"},{"user_sub":"usr_b","role":"editor"}],
            "created_at":1700000000,"updated_at":1700000100,"extra":"ignored"}"""
        val space = requireNotNull(adapter.fromJson(json))
        assertEquals("sp_1", space.spaceId)
        assertEquals(TicketConstants.SpaceVisibility.SHARED, space.visibility)
        assertEquals(2, space.members.size)
        assertEquals(TicketConstants.SpaceRole.OWNER, space.members[0].role)

        // round-trips back through Moshi without loss
        val decoded = requireNotNull(adapter.fromJson(adapter.toJson(space)))
        assertEquals(space, decoded)
    }

    @Test
    fun space_sparseBody_defaultsOptionalsAndEmptyMembers() {
        val adapter = moshi.adapter(TicketSpaceOut::class.java)
        val space = requireNotNull(adapter.fromJson("""{"space_id":"sp_1"}"""))
        assertNull(space.name)
        assertNull(space.visibility)
        assertNull(space.createdAt)
        assertTrue(space.members.isEmpty())
    }

    // ---- ticket round-trip with embedded messages + activity ----

    @Test
    fun ticket_roundTrips_withMessagesAndActivity_senderRoleAndSenderSub_noAuthorType() {
        val adapter = moshi.adapter(SpaceTicketOut::class.java)
        val json = """{"ticket_id":"tk_1","space_id":"sp_1","title":"Cannot log in",
            "status":"in_progress","created_at":1700000000,"updated_at":1700000200,
            "messages":[{"message_id":"m_1","sender_sub":"usr_a","sender_role":"reporter",
              "body":"Help","created_at":1700000010}],
            "activity":[{"activity_id":"a_1","activity_type":"status_changed","actor_sub":"usr_b",
              "created_at":1700000020}]}"""
        val ticket = requireNotNull(adapter.fromJson(json))
        assertEquals("tk_1", ticket.ticketId)
        assertEquals(TicketConstants.TicketStatus.IN_PROGRESS, ticket.status)
        assertEquals(1, ticket.messages.size)
        // sender_role is a free String + sender_sub (there is NO author_type)
        assertEquals("reporter", ticket.messages[0].senderRole)
        assertEquals("usr_a", ticket.messages[0].senderSub)
        assertEquals("Help", ticket.messages[0].body)
        assertEquals(1, ticket.activity.size)
        assertEquals("status_changed", ticket.activity[0].activityType)

        val decoded = requireNotNull(adapter.fromJson(adapter.toJson(ticket)))
        assertEquals(ticket, decoded)
    }

    @Test
    fun ticket_sparseBody_defaultsOptionalsAndEmptyMessageActivityLists() {
        val adapter = moshi.adapter(SpaceTicketOut::class.java)
        val ticket = requireNotNull(adapter.fromJson("""{"ticket_id":"tk_1"}"""))
        assertNull(ticket.title)
        assertNull(ticket.status)
        assertNull(ticket.spaceId)
        assertTrue(ticket.messages.isEmpty())
        assertTrue(ticket.activity.isEmpty())
    }

    // ---- enum-like fields tolerate UNKNOWN / unexpected values without throwing ----

    @Test
    fun enumLikeFields_decodeUnknownValues_asPlainStrings_neverThrows() {
        val spaceAdapter = moshi.adapter(TicketSpaceOut::class.java)
        val space = requireNotNull(
            spaceAdapter.fromJson(
                """{"space_id":"sp_x","visibility":"top_secret",
                    "members":[{"user_sub":"usr_z","role":"superadmin"}]}""",
            ),
        )
        // unexpected server values are retained verbatim, not rejected
        assertEquals("top_secret", space.visibility)
        assertEquals("superadmin", space.members[0].role)

        val ticketAdapter = moshi.adapter(SpaceTicketOut::class.java)
        val ticket = requireNotNull(
            ticketAdapter.fromJson(
                """{"ticket_id":"tk_x","status":"escalated",
                    "messages":[{"message_id":"m_x","sender_role":"robot_overlord"}]}""",
            ),
        )
        assertEquals("escalated", ticket.status)
        assertEquals("robot_overlord", ticket.messages[0].senderRole)
    }

    // ---- envelope decoding (named + list) ----

    @Test
    fun spaceEnvelope_decodesNamedSpace() {
        val adapter = moshi.adapter(TicketSpaceEnvelope::class.java)
        val envelope = requireNotNull(
            adapter.fromJson("""{"space":{"space_id":"sp_1","name":"Support"}}"""),
        )
        assertEquals("sp_1", envelope.space.spaceId)
        assertEquals("Support", envelope.space.name)
    }

    @Test
    fun ticketEnvelope_decodesNamedTicket() {
        val adapter = moshi.adapter(SpaceTicketEnvelope::class.java)
        val envelope = requireNotNull(
            adapter.fromJson("""{"ticket":{"ticket_id":"tk_1","status":"open"}}"""),
        )
        assertEquals("tk_1", envelope.ticket.ticketId)
        assertEquals(TicketConstants.TicketStatus.OPEN, envelope.ticket.status)
    }

    @Test
    fun spaceListEnvelope_decodesItemsAndNextCursor_andEmptyDefaults() {
        val adapter = moshi.adapter(TicketSpaceListEnvelope::class.java)
        val full = requireNotNull(
            adapter.fromJson(
                """{"items":[{"space_id":"sp_1"},{"space_id":"sp_2"}],"next_cursor":"cur_2"}""",
            ),
        )
        assertEquals(2, full.items.size)
        assertEquals("cur_2", full.nextCursor)

        // empty body: items default to empty list, next_cursor to null
        val empty = requireNotNull(adapter.fromJson("""{}"""))
        assertTrue(empty.items.isEmpty())
        assertNull(empty.nextCursor)
    }

    @Test
    fun ticketListEnvelope_decodesItemsAndNextCursor_andEmptyDefaults() {
        val adapter = moshi.adapter(SpaceTicketListEnvelope::class.java)
        val full = requireNotNull(
            adapter.fromJson(
                """{"items":[{"ticket_id":"tk_1"}],"next_cursor":null}""",
            ),
        )
        assertEquals(1, full.items.size)
        assertNull(full.nextCursor)

        val empty = requireNotNull(adapter.fromJson("""{}"""))
        assertTrue(empty.items.isEmpty())
        assertNull(empty.nextCursor)
    }

    // ---- required-field enforcement ----

    @Test
    fun space_missingRequiredSpaceId_throws() {
        val adapter = moshi.adapter(TicketSpaceOut::class.java)
        assertThrows(JsonDataException::class.java) {
            adapter.fromJson("""{"name":"Support"}""")
        }
    }

    @Test
    fun ticket_missingRequiredTicketId_throws() {
        val adapter = moshi.adapter(SpaceTicketOut::class.java)
        assertThrows(JsonDataException::class.java) {
            adapter.fromJson("""{"status":"open"}""")
        }
    }

    @Test
    fun member_missingRequiredUserSub_throws() {
        val adapter = moshi.adapter(SpaceMemberOut::class.java)
        assertThrows(JsonDataException::class.java) {
            adapter.fromJson("""{"role":"owner"}""")
        }
    }
}
