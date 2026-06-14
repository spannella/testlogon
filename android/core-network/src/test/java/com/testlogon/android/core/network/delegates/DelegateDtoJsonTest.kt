package com.testlogon.android.core.network.delegates

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
 * AND-359 - DTO-level Moshi tests for the AND-359 delegate transport (mirrors OrgDtoJsonTest).
 *
 * Focus: BARE ARRAY decoding, the permissions LIST, OPTIONAL-field defaults (nulls), EXTRA-key tolerance,
 * and required-field enforcement. The Moshi is built like NetworkModule.provideMoshi (BigDecimalAdapter +
 * the reflective KotlinJsonAdapterFactory). core-network has no test dependency on core-testing, so the
 * JSON is inline. KDoc avoids the comment-terminator character pair.
 */
class DelegateDtoJsonTest {

    private val moshi: Moshi = Moshi.Builder()
        .add(BigDecimalAdapter)
        .add(KotlinJsonAdapterFactory())
        .build()

    private fun managedListAdapter() = moshi.adapter<List<ManagedCreatorOut>>(
        Types.newParameterizedType(List::class.java, ManagedCreatorOut::class.java),
    )

    @Test
    fun managed_decodesBareArray_withPermissionsListOptionalsAndExtraKeys() {
        val json = """[
            {"creator_id":"cr_1","permissions":["read","post"],"preset":"editor","status":"active",
             "label":"Acme","accepted_at":"2026-01-01","extra":"ignored"},
            {"creator_id":"cr_2"}
        ]"""
        val managed = requireNotNull(managedListAdapter().fromJson(json))
        assertEquals(2, managed.size)
        assertEquals(listOf("read", "post"), managed[0].permissions)
        assertEquals("editor", managed[0].preset)
        assertEquals("Acme", managed[0].label)
        // sparse row: permissions defaults to empty, optional fields default to null
        assertEquals(emptyList<String>(), managed[1].permissions)
        assertNull(managed[1].preset)
        assertNull(managed[1].status)
        assertNull(managed[1].label)
        assertNull(managed[1].acceptedAt)
    }

    @Test
    fun managed_missingRequiredCreatorId_throws() {
        assertThrows(JsonDataException::class.java) {
            managedListAdapter().fromJson("""[{"label":"Acme"}]""")
        }
    }

    @Test
    fun managed_singleObjectAdapter_decodesPermissionsList() {
        val adapter = moshi.adapter(ManagedCreatorOut::class.java)
        val decoded = requireNotNull(
            adapter.fromJson("""{"creator_id":"cr_3","permissions":["audit"]}"""),
        )
        assertEquals("cr_3", decoded.creatorId)
        assertEquals(listOf("audit"), decoded.permissions)
    }

    @Test
    fun invite_decodesAndRespondReqRoundTrips() {
        val inviteAdapter = moshi.adapter(DelegateInviteOut::class.java)
        val invite = requireNotNull(
            inviteAdapter.fromJson("""{"invite_id":"inv_1","creator_id":"cr_9","permissions":["read"]}"""),
        )
        assertEquals("inv_1", invite.inviteId)
        assertEquals("cr_9", invite.creatorId)

        val respondAdapter = moshi.adapter(DelegateInviteRespondReq::class.java)
        val req = DelegateInviteRespondReq(accept = true)
        val rt = requireNotNull(respondAdapter.fromJson(respondAdapter.toJson(req)))
        assertEquals(true, rt.accept)
    }
}
