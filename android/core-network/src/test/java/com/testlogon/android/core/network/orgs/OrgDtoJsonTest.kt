package com.testlogon.android.core.network.orgs

import com.squareup.moshi.JsonDataException
import com.squareup.moshi.Moshi
import com.squareup.moshi.Types
import com.squareup.moshi.kotlin.reflect.KotlinJsonAdapterFactory
import com.testlogon.android.core.network.json.BigDecimalAdapter
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Test

/**
 * AND-353 - DTO-level Moshi tests for the AND-353 org transport (mirrors SigningDtoJsonTest).
 *
 * Focus: BARE ARRAY decoding, OPTIONAL-field defaults (nulls), EXTRA-key tolerance, and required-field
 * enforcement. The Moshi is built like NetworkModule.provideMoshi (BigDecimalAdapter + the reflective
 * KotlinJsonAdapterFactory). core-network has no test dependency on :core-testing, so the JSON is inline.
 * KDoc avoids the comment-terminator character pair.
 */
class OrgDtoJsonTest {

    private val moshi: Moshi = Moshi.Builder()
        .add(BigDecimalAdapter)
        .add(KotlinJsonAdapterFactory())
        .build()

    private fun orgListAdapter() =
        moshi.adapter<List<OrgOut>>(Types.newParameterizedType(List::class.java, OrgOut::class.java))

    private fun memberListAdapter() = moshi.adapter<List<OrgMemberOut>>(
        Types.newParameterizedType(List::class.java, OrgMemberOut::class.java),
    )

    private fun inviteListAdapter() = moshi.adapter<List<OrgInviteOut>>(
        Types.newParameterizedType(List::class.java, OrgInviteOut::class.java),
    )

    // ---- BARE ARRAY decodes ----

    @Test
    fun orgs_decodesBareArray_withOptionalNullsAndExtraKeys() {
        val json = """[
            {"org_id":"org_1","org_name":"Acme","org_role":"admin","extra":"ignored"},
            {"org_id":"org_2"}
        ]"""
        val orgs = requireNotNull(orgListAdapter().fromJson(json))
        assertEquals(2, orgs.size)
        assertEquals("Acme", orgs[0].orgName)
        // optional fields default to null when absent
        assertNull(orgs[1].orgName)
        assertNull(orgs[1].orgRole)
    }

    @Test
    fun members_decodeBareArray_withOptionalFieldsAndExtraKeys() {
        val json = """[
            {"user_sub":"usr_a","org_role":"owner","status":"active","joined_at":"2026-01-01",
             "storage_used_bytes":2048,"last_active_at":"2026-06-01","unknown_field":1},
            {"user_sub":"usr_b"}
        ]"""
        val members = requireNotNull(memberListAdapter().fromJson(json))
        assertEquals(2, members.size)
        assertEquals(2048L, members[0].storageUsedBytes)
        // sparse member: only user_sub present, the rest default to null
        assertEquals("usr_b", members[1].userSub)
        assertNull(members[1].orgRole)
        assertNull(members[1].status)
        assertNull(members[1].storageUsedBytes)
    }

    @Test
    fun invites_decodeBareArray_withOptionalToken() {
        val json = """[
            {"invite_id":"inv_1","email":"a@x.com","org_role":"member","token":"tok_1"},
            {"invite_id":"inv_2","email":"b@x.com"}
        ]"""
        val invites = requireNotNull(inviteListAdapter().fromJson(json))
        assertEquals(2, invites.size)
        assertEquals("tok_1", invites[0].token)
        assertNull(invites[1].token)
        assertNull(invites[1].orgRole)
    }

    // ---- required-field enforcement ----

    @Test
    fun org_missingRequiredOrgId_throws() {
        assertThrows(JsonDataException::class.java) {
            orgListAdapter().fromJson("""[{"org_name":"Acme"}]""")
        }
    }

    @Test
    fun member_missingRequiredUserSub_throws() {
        assertThrows(JsonDataException::class.java) {
            memberListAdapter().fromJson("""[{"org_role":"member"}]""")
        }
    }

    // ---- request DTO round-trips ----

    @Test
    fun inviteReq_roundTrips() {
        val adapter = moshi.adapter(OrgMemberInviteReq::class.java)
        val req = OrgMemberInviteReq(email = "new@x.com", orgRole = "viewer")
        val decoded = requireNotNull(adapter.fromJson(adapter.toJson(req)))
        assertEquals("new@x.com", decoded.email)
        assertEquals("viewer", decoded.orgRole)
    }

    @Test
    fun roleUpdateReq_roundTrips() {
        val adapter = moshi.adapter(OrgMemberRoleUpdateReq::class.java)
        val req = OrgMemberRoleUpdateReq(orgRole = "admin")
        val decoded = requireNotNull(adapter.fromJson(adapter.toJson(req)))
        assertEquals("admin", decoded.orgRole)
    }
}
