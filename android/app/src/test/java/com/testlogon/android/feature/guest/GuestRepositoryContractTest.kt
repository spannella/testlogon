package com.testlogon.android.feature.guest

import com.squareup.moshi.Moshi
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.network.error.ApiErrorParser
import com.testlogon.android.data.broadcast.InputsApi
import com.testlogon.android.core.testing.net.Fixtures
import com.testlogon.android.core.testing.net.MockBackendRule
import com.testlogon.android.core.testing.net.bodyJson
import com.testlogon.android.core.testing.net.retrofit
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test

/**
 * AND-312 — MockWebServer contract tests for [GuestRepositoryImpl]. Verifies the create-invite POST body
 * (join_mode / label / expiry_minutes) -> 201 decode, the accept POST body { display_name } -> 200 decode,
 * the revoke / promote / remove POST (path + verb, 200 { ok }), the mute POST body { muted }, the merge of
 * listInvites + listInputs(guest filter) into the right derived Guest list, and 422 detail mapping. Each
 * request body is read ONCE.
 */
class GuestRepositoryContractTest {

    @get:Rule
    val backend = MockBackendRule()

    private val moshi: Moshi = Moshi.Builder().build()

    private fun repo(): GuestRepositoryImpl {
        val retrofit = backend.retrofit(moshi)
        return GuestRepositoryImpl(
            api = retrofit.create(GuestApi::class.java),
            inputsApi = retrofit.create(InputsApi::class.java),
            errorParser = ApiErrorParser(moshi),
        )
    }

    @Test
    fun createInvite_postsBody_decodes201() = runTest {
        backend.enqueue(Fixtures.okBody(INVITE_JSON, code = 201))
        val result = repo().createInvite("bcs_1", joinMode = "browser", label = "Ada", expiryMinutes = 30)
        assertTrue(result is ApiResult.Success)
        val invite = (result as ApiResult.Success).data
        assertEquals("inv_1", invite.inviteId)
        assertEquals(InviteStatus.PENDING, invite.status)
        assertEquals("https://testlogon.app/guest/accept?inviteId=inv_1", invite.url)

        val req = backend.takeRequest()
        assertEquals("POST", req.method)
        assertEquals("/broadcast/sessions/bcs_1/guest-invites", req.requestUrl?.encodedPath)
        val body = req.bodyJson()
        assertEquals("browser", body["join_mode"])
        assertEquals("Ada", body["label"])
        assertEquals(30.0, body["expiry_minutes"])
    }

    @Test
    fun acceptInvite_postsDisplayName_decodes200() = runTest {
        backend.enqueue(Fixtures.okBody(ACCEPT_JSON))
        val result = repo().acceptInvite("bcs_1", "inv_1", displayName = "Ada Lovelace")
        assertTrue(result is ApiResult.Success)
        val accepted = (result as ApiResult.Success).data
        assertEquals("in_9", accepted.inputId)
        assertEquals("rtmps://ingest/app", accepted.ingestUrl)

        val req = backend.takeRequest()
        assertEquals("POST", req.method)
        assertEquals("/broadcast/sessions/bcs_1/guest-invites/inv_1/accept", req.requestUrl?.encodedPath)
        assertEquals("Ada Lovelace", req.bodyJson()["display_name"])
    }

    @Test
    fun revoke_postsToRevokePath_ok() = runTest {
        backend.enqueue(Fixtures.okBody("""{"ok":true}"""))
        val result = repo().revokeInvite("bcs_1", "inv_1")
        assertTrue(result is ApiResult.Success)
        val req = backend.takeRequest()
        assertEquals("POST", req.method)
        assertEquals("/broadcast/sessions/bcs_1/guest-invites/inv_1/revoke", req.requestUrl?.encodedPath)
    }

    @Test
    fun promote_postsToPromotePath_ok() = runTest {
        backend.enqueue(Fixtures.okBody("""{"ok":true}"""))
        val result = repo().promote("bcs_1", "in_9")
        assertTrue(result is ApiResult.Success)
        val req = backend.takeRequest()
        assertEquals("POST", req.method)
        assertEquals("/broadcast/sessions/bcs_1/guests/in_9/promote", req.requestUrl?.encodedPath)
    }

    @Test
    fun remove_postsToRemovePath_emptyOk() = runTest {
        // An empty 200 body is still success.
        backend.enqueue(Fixtures.okBody(""))
        val result = repo().remove("bcs_1", "in_9")
        assertTrue(result is ApiResult.Success)
        val req = backend.takeRequest()
        assertEquals("POST", req.method)
        assertEquals("/broadcast/sessions/bcs_1/guests/in_9/remove", req.requestUrl?.encodedPath)
    }

    @Test
    fun setMuted_postsMutedBody_tracksClientSide() = runTest {
        backend.enqueue(Fixtures.okBody("""{"ok":true}"""))
        val result = repo().setMuted("bcs_1", "in_9", muted = true)
        assertTrue(result is ApiResult.Success)
        val req = backend.takeRequest()
        assertEquals("POST", req.method)
        assertEquals("/broadcast/sessions/bcs_1/guests/in_9/mute", req.requestUrl?.encodedPath)
        assertEquals(true, req.bodyJson()["muted"])
    }

    @Test
    fun refreshGuests_mergesInvitesAndGuestInputs_derivesStatus() = runTest {
        // refresh order: 1) listInvites, 2) listInputs.
        backend.enqueue(Fixtures.okBody(INVITE_LIST_JSON))
        backend.enqueue(Fixtures.okBody(INPUT_LIST_JSON))

        val result = repo().refreshGuests("bcs_1")
        assertTrue(result is ApiResult.Success)
        val guests = (result as ApiResult.Success).data
        // inv_1 (accepted, joined to live input in_9) + inv_2 (pending, no input) = 2 rows; the non-guest
        // input in_1 (input_type=primary) is filtered out and never surfaces.
        assertEquals(2, guests.size)

        val onAir = guests.first { it.inputId == "in_9" }
        assertEquals(GuestStatus.ONAIR, onAir.status)
        assertTrue(onAir.isLive)
        assertEquals("inv_1", onAir.inviteId)

        val invited = guests.first { it.inviteId == "inv_2" }
        assertEquals(GuestStatus.INVITED, invited.status)

        val invitesReq = backend.takeRequest()
        assertEquals("GET", invitesReq.method)
        assertEquals("/broadcast/sessions/bcs_1/guest-invites", invitesReq.requestUrl?.encodedPath)
        val inputsReq = backend.takeRequest()
        assertEquals("/broadcast/sessions/bcs_1/inputs", inputsReq.requestUrl?.encodedPath)
    }

    @Test
    fun refreshGuests_unknownInviteStatus_doesNotThrow() = runTest {
        backend.enqueue(Fixtures.okBody(INVITE_LIST_UNKNOWN_STATUS_JSON))
        backend.enqueue(Fixtures.okBody("""{"session_id":"bcs_1","count":0,"max_inputs":4,"inputs":[]}"""))
        val result = repo().refreshGuests("bcs_1")
        assertTrue(result is ApiResult.Success)
        val guest = (result as ApiResult.Success).data.single()
        // Unknown wire status coerces to PENDING -> INVITED (never throws), and there is no input.
        assertEquals(GuestStatus.INVITED, guest.status)
        assertNull(guest.connectedAt)
    }

    @Test
    fun createInvite_422_mapsToFailureWithStatus() = runTest {
        backend.enqueue(
            Fixtures.error(
                """[{"loc":["body","expiry_minutes"],"msg":"out of range","type":"value_error"}]""",
                422,
            ),
        )
        val result = repo().createInvite("bcs_1", "browser", "Guest", 9999)
        assertTrue(result is ApiResult.Failure)
        assertEquals(422, (result as ApiResult.Failure).error.status)
    }

    private companion object {
        const val INVITE_JSON = """
            {"invite_id":"inv_1","session_id":"bcs_1","input_id":null,"join_mode":"browser",
             "status":"pending","expires_at":1700003600,"created_at":"2026-06-12T10:00:00Z",
             "accepted_at":null,"invite_url":"https://testlogon.app/guest/accept?inviteId=inv_1",
             "ingest_url":null,"stream_key":"sk_secret_never_logged","guest_user_id":null,
             "guest_display_name":null}
        """

        const val ACCEPT_JSON = """
            {"invite_id":"inv_1","input_id":"in_9","join_mode":"rtmp","session_id":"bcs_1",
             "ingest_url":"rtmps://ingest/app"}
        """

        const val INVITE_LIST_JSON = """
            {"session_id":"bcs_1","count":2,"invites":[
              {"invite_id":"inv_1","session_id":"bcs_1","input_id":"in_9","join_mode":"rtmp",
               "status":"accepted","expires_at":1700003600,"created_at":"2026-06-12T10:00:00Z",
               "accepted_at":1700000100,"guest_display_name":"Ada"},
              {"invite_id":"inv_2","session_id":"bcs_1","input_id":null,"join_mode":"browser",
               "status":"pending","expires_at":1700003600,"created_at":"2026-06-12T10:05:00Z"}
            ]}
        """

        const val INPUT_LIST_JSON = """
            {"session_id":"bcs_1","count":2,"max_inputs":4,"inputs":[
              {"input_id":"in_1","session_id":"bcs_1","input_type":"primary","label":"Host camera",
               "is_live":true,"position":0,"created_by":"usr_42"},
              {"input_id":"in_9","session_id":"bcs_1","input_type":"guest","label":"Ada",
               "is_live":true,"position":1,"connected_at":1700000100,"created_by":"usr_42"}
            ]}
        """

        const val INVITE_LIST_UNKNOWN_STATUS_JSON = """
            {"session_id":"bcs_1","count":1,"invites":[
              {"invite_id":"inv_3","session_id":"bcs_1","input_id":null,"join_mode":"browser",
               "status":"quantum_superposition","created_at":"2026-06-12T10:05:00Z"}
            ]}
        """
    }
}
