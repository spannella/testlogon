package com.testlogon.android.core.network.orgs

import com.squareup.moshi.Moshi
import com.squareup.moshi.Types
import com.squareup.moshi.kotlin.reflect.KotlinJsonAdapterFactory
import com.testlogon.android.core.network.json.BigDecimalAdapter
import kotlinx.coroutines.test.runTest
import okhttp3.OkHttpClient
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import okhttp3.mockwebserver.RecordedRequest
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import retrofit2.Retrofit
import retrofit2.converter.moshi.MoshiConverterFactory

/**
 * AND-353 - hermetic request-shape / decode tests for the AND-353 [OrgsApi] (mirrors SigningApiTest).
 *
 * Everything is hermetic: MockWebServer only, a production-style Moshi (BigDecimalAdapter + the
 * reflective KotlinJsonAdapterFactory, like NetworkModule.provideMoshi - the org DTOs use no enum
 * adapters since org_role is a plain String on the wire), and runTest. No real dev host. core-network
 * has no test dependency on :core-testing, so the JSON bodies are inline. KDoc avoids the
 * comment-terminator character pair.
 */
class OrgsApiTest {

    private lateinit var server: MockWebServer

    private val moshi: Moshi = Moshi.Builder()
        .add(BigDecimalAdapter)
        .add(KotlinJsonAdapterFactory())
        .build()

    private val mapAdapter = moshi.adapter<Map<String, Any?>>(
        Types.newParameterizedType(Map::class.java, String::class.java, Any::class.java),
    )

    private fun api(): OrgsApi = Retrofit.Builder()
        .baseUrl(server.url("/"))
        .client(OkHttpClient())
        .addConverterFactory(MoshiConverterFactory.create(moshi))
        .build()
        .create(OrgsApi::class.java)

    private fun RecordedRequest.bodyMap(): Map<String, Any?> {
        val raw = body.readUtf8()
        if (raw.isBlank()) return emptyMap()
        return mapAdapter.fromJson(raw) ?: emptyMap()
    }

    private fun jsonResponse(body: String, code: Int = 200) =
        MockResponse().setResponseCode(code).setHeader("Content-Type", "application/json").setBody(body)

    @Before
    fun setUp() {
        server = MockWebServer().apply { start() }
    }

    @After
    fun tearDown() {
        server.shutdown()
    }

    // ---- BARE ARRAY decodes ----

    @Test
    fun listOrgs_decodesBareArray() = runTest {
        server.enqueue(
            jsonResponse(
                """[{"org_id":"org_1","org_name":"Acme","org_role":"admin"},
                   {"org_id":"org_2","org_role":"member"}]""",
            ),
        )

        val orgs = api().listOrgs()

        val recorded = server.takeRequest()
        assertEquals("GET", recorded.method)
        assertEquals("/ui/orgs", recorded.requestUrl?.encodedPath)
        assertEquals(2, orgs.size)
        assertEquals("org_1", orgs[0].orgId)
        assertEquals("admin", orgs[0].orgRole)
        assertEquals("member", orgs[1].orgRole)
    }

    @Test
    fun listMembers_decodesBareArray_andSubstitutesOrgIdPath() = runTest {
        server.enqueue(
            jsonResponse(
                """[{"user_sub":"usr_a","org_role":"owner","status":"active","joined_at":"2026-01-01",
                     "storage_used_bytes":1024,"last_active_at":"2026-06-01"}]""",
            ),
        )

        val members = api().listMembers("org_1")

        val recorded = server.takeRequest()
        assertEquals("GET", recorded.method)
        assertEquals("/ui/orgs/org_1/members", recorded.requestUrl?.encodedPath)
        assertEquals(1, members.size)
        assertEquals("usr_a", members[0].userSub)
        assertEquals("owner", members[0].orgRole)
        assertEquals("active", members[0].status)
        assertEquals(1024L, members[0].storageUsedBytes)
    }

    @Test
    fun listPendingInvites_decodesBareArray() = runTest {
        server.enqueue(
            jsonResponse(
                """[{"invite_id":"inv_1","org_id":"org_1","org_name":"Acme","email":"a@x.com",
                     "org_role":"member","status":"pending"}]""",
            ),
        )

        val invites = api().listPendingInvites()

        val recorded = server.takeRequest()
        assertEquals("GET", recorded.method)
        assertEquals("/ui/orgs/invites/pending", recorded.requestUrl?.encodedPath)
        assertEquals(1, invites.size)
        assertEquals("inv_1", invites[0].inviteId)
        assertEquals("a@x.com", invites[0].email)
    }

    // ---- invite POSTs the right body + path -> 201 OrgInviteOut ----

    @Test
    fun inviteMember_postsBody_returns201Invite() = runTest {
        server.enqueue(
            jsonResponse(
                """{"invite_id":"inv_2","org_id":"org_1","email":"new@x.com","org_role":"viewer",
                    "status":"pending"}""",
                code = 201,
            ),
        )

        val invite = api().inviteMember(
            "org_1",
            OrgMemberInviteReq(email = "new@x.com", orgRole = "viewer"),
        )

        val recorded = server.takeRequest()
        assertEquals("POST", recorded.method)
        assertEquals("/ui/orgs/org_1/members/invite", recorded.requestUrl?.encodedPath)
        assertEquals("application/json", recorded.getHeader("Content-Type"))
        val body = recorded.bodyMap()
        assertEquals("new@x.com", body["email"])
        assertEquals("viewer", body["org_role"])
        assertEquals("inv_2", invite.inviteId)
        assertEquals("viewer", invite.orgRole)
    }

    // ---- changeRole PATCH path has trailing /role + body org_role ----

    @Test
    fun changeRole_patchesRolePath_withBody() = runTest {
        server.enqueue(MockResponse().setResponseCode(200))

        val response = api().changeRole(
            "org_1",
            "usr_a",
            OrgMemberRoleUpdateReq(orgRole = "admin"),
        )

        val recorded = server.takeRequest()
        assertEquals("PATCH", recorded.method)
        assertEquals("/ui/orgs/org_1/members/usr_a/role", recorded.requestUrl?.encodedPath)
        val body = recorded.bodyMap()
        assertEquals("admin", body["org_role"])
        assertTrue(response.isSuccessful)
    }

    // ---- removeMember DELETE -> 204 empty success ----

    @Test
    fun removeMember_deletes_204Empty_isSuccessful() = runTest {
        server.enqueue(MockResponse().setResponseCode(204))

        val response = api().removeMember("org_1", "usr_a")

        val recorded = server.takeRequest()
        assertEquals("DELETE", recorded.method)
        assertEquals("/ui/orgs/org_1/members/usr_a", recorded.requestUrl?.encodedPath)
        assertTrue(response.isSuccessful)
        assertEquals(204, response.code())
    }

    // ---- transferOwnership POSTs the separate endpoint ----

    @Test
    fun transferOwnership_postsNewOwnerSub() = runTest {
        server.enqueue(MockResponse().setResponseCode(200))

        api().transferOwnership("org_1", TransferOwnershipReq(newOwnerUserSub = "usr_b"))

        val recorded = server.takeRequest()
        assertEquals("POST", recorded.method)
        assertEquals("/ui/orgs/org_1/transfer-ownership", recorded.requestUrl?.encodedPath)
        assertEquals("usr_b", recorded.bodyMap()["new_owner_user_sub"])
    }

    // ---- AND-354: acceptInvite POSTs the accept path with a {token} body ----

    @Test
    fun acceptInvite_postsAcceptPath_withTokenBody() = runTest {
        server.enqueue(MockResponse().setResponseCode(200))

        val response = api().acceptInvite("inv_1", OrgInviteAcceptReq(token = "tok_abc"))

        val recorded = server.takeRequest()
        assertEquals("POST", recorded.method)
        assertEquals("/ui/orgs/invites/inv_1/accept", recorded.requestUrl?.encodedPath)
        assertEquals("application/json", recorded.getHeader("Content-Type"))
        assertEquals("tok_abc", recorded.bodyMap()["token"])
        assertTrue(response.isSuccessful)
    }

    // ---- AND-354: declineInvite POSTs the decline path -> 204 empty ----

    @Test
    fun declineInvite_postsDeclinePath_204Empty_isSuccessful() = runTest {
        server.enqueue(MockResponse().setResponseCode(204))

        val response = api().declineInvite("inv_1")

        val recorded = server.takeRequest()
        assertEquals("POST", recorded.method)
        assertEquals("/ui/orgs/invites/inv_1/decline", recorded.requestUrl?.encodedPath)
        assertTrue(response.isSuccessful)
        assertEquals(204, response.code())
    }
}
