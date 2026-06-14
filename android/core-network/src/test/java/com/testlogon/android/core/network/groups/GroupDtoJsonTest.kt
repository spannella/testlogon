package com.testlogon.android.core.network.groups

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
 * AND-355 - DTO-level Moshi tests for the AND-355 group transport (mirrors OrgDtoJsonTest).
 *
 * Focus: ENVELOPE decoding ({groups}, {members,count}), OPTIONAL-field defaults (nulls), EXTRA-key
 * tolerance, and required-field enforcement. The Moshi is built like NetworkModule.provideMoshi
 * (BigDecimalAdapter + the reflective KotlinJsonAdapterFactory). core-network has no test dependency on
 * core-testing, so the JSON is inline. KDoc avoids the comment-terminator character pair.
 */
class GroupDtoJsonTest {

    private val moshi: Moshi = Moshi.Builder()
        .add(BigDecimalAdapter)
        .add(KotlinJsonAdapterFactory())
        .build()

    private fun groupListAdapter() = moshi.adapter(GroupListResponse::class.java)
    private fun membersAdapter() = moshi.adapter(GroupMembersResponse::class.java)
    private fun groupAdapter() = moshi.adapter(UserGroupDto::class.java)

    // ---- ENVELOPE decodes ----

    @Test
    fun groups_decodesEnvelope_withOptionalNullsAndExtraKeys() {
        val json = """{"groups":[
            {"group_id":"grp_1","name":"Hikers","my_role":"admin","extra":"ignored"},
            {"group_id":"grp_2","name":"Readers"}
        ],"unknown_top":1}"""
        val response = requireNotNull(groupListAdapter().fromJson(json))
        assertEquals(2, response.groups.size)
        assertEquals("admin", response.groups[0].myRole)
        // optional fields default to null when absent
        assertNull(response.groups[1].myRole)
        assertNull(response.groups[1].memberCount)
        assertNull(response.groups[1].coverImageUrl)
    }

    @Test
    fun members_decodeEnvelope_withCount_andOptionalFields() {
        val json = """{"members":[
            {"user_id":"usr_a","role":"admin","status":"active","display_name":"Ann",
             "joined_at":"2026-01-01","promoted_at":"2026-02-01","unknown":1},
            {"user_id":"usr_b","status":"invited"}
        ],"count":2}"""
        val response = requireNotNull(membersAdapter().fromJson(json))
        assertEquals(2, response.count)
        assertEquals(2, response.members.size)
        assertEquals("Ann", response.members[0].displayName)
        // the invited member is a pending entry (status raw)
        assertEquals("invited", response.members[1].status)
        assertNull(response.members[1].role)
        assertNull(response.members[1].displayName)
    }

    @Test
    fun members_envelope_missingCount_defaultsNull() {
        val json = """{"members":[{"user_id":"usr_a","status":"active"}]}"""
        val response = requireNotNull(membersAdapter().fromJson(json))
        assertNull(response.count)
        assertEquals(1, response.members.size)
    }

    @Test
    fun groupDetail_decodesObject_withDescription() {
        val json = """{"group_id":"grp_1","name":"Hikers","description":"trails","member_count":5,
                       "my_role":"moderator","admin_user_id":"usr_admin"}"""
        val group = requireNotNull(groupAdapter().fromJson(json))
        assertEquals("Hikers", group.name)
        assertEquals("trails", group.description)
        assertEquals(5, group.memberCount)
        assertEquals("moderator", group.myRole)
    }

    // ---- required-field enforcement ----

    @Test
    fun group_missingRequiredGroupId_throws() {
        assertThrows(JsonDataException::class.java) {
            groupListAdapter().fromJson("""{"groups":[{"name":"Hikers"}]}""")
        }
    }

    @Test
    fun member_missingRequiredUserId_throws() {
        assertThrows(JsonDataException::class.java) {
            membersAdapter().fromJson("""{"members":[{"role":"member"}]}""")
        }
    }

    // ---- request DTO round-trips ----

    @Test
    fun inviteIn_roundTrips() {
        val adapter = moshi.adapter(GroupInviteIn::class.java)
        val decoded = requireNotNull(adapter.fromJson(adapter.toJson(GroupInviteIn(userId = "usr_x"))))
        assertEquals("usr_x", decoded.userId)
        assertTrue(adapter.toJson(GroupInviteIn(userId = "usr_x")).contains("user_id"))
    }

    @Test
    fun updateRoleIn_roundTrips() {
        val adapter = moshi.adapter(GroupUpdateRoleIn::class.java)
        val decoded = requireNotNull(adapter.fromJson(adapter.toJson(GroupUpdateRoleIn(role = "member"))))
        assertEquals("member", decoded.role)
    }
}
