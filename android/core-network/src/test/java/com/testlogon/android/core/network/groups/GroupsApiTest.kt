package com.testlogon.android.core.network.groups

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
 * AND-355 - hermetic request-shape / decode tests for the AND-355 [GroupsApi] (mirrors OrgsApiTest).
 *
 * Everything is hermetic: MockWebServer only, a production-style Moshi (BigDecimalAdapter + the reflective
 * KotlinJsonAdapterFactory, like NetworkModule.provideMoshi - the group DTOs use no enum adapters since
 * my_role / role are plain Strings on the wire), and runTest. No real dev host. core-network has no test
 * dependency on core-testing, so the JSON bodies are inline. KDoc avoids the comment-terminator pair.
 */
class GroupsApiTest {

    private lateinit var server: MockWebServer

    private val moshi: Moshi = Moshi.Builder()
        .add(BigDecimalAdapter)
        .add(KotlinJsonAdapterFactory())
        .build()

    private val mapAdapter = moshi.adapter<Map<String, Any?>>(
        Types.newParameterizedType(Map::class.java, String::class.java, Any::class.java),
    )

    private fun api(): GroupsApi = Retrofit.Builder()
        .baseUrl(server.url("/"))
        .client(OkHttpClient())
        .addConverterFactory(MoshiConverterFactory.create(moshi))
        .build()
        .create(GroupsApi::class.java)

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

    // ---- ENVELOPE decodes ----

    @Test
    fun listMyGroups_decodesGroupsEnvelope() = runTest {
        server.enqueue(
            jsonResponse(
                """{"groups":[
                     {"group_id":"grp_1","name":"Hikers","member_count":3,"my_role":"admin",
                      "admin_user_id":"usr_admin","cover_image_url":"https://x/c.png"},
                     {"group_id":"grp_2","name":"Readers","my_role":"member"}
                   ]}""",
            ),
        )

        val response = api().listMyGroups()

        val recorded = server.takeRequest()
        assertEquals("GET", recorded.method)
        assertEquals("/ui/groups", recorded.requestUrl?.encodedPath)
        assertEquals(2, response.groups.size)
        assertEquals("grp_1", response.groups[0].groupId)
        assertEquals("admin", response.groups[0].myRole)
        assertEquals("usr_admin", response.groups[0].adminUserId)
        assertEquals("member", response.groups[1].myRole)
    }

    @Test
    fun getGroup_decodesDetailObject_andSubstitutesGroupIdPath() = runTest {
        server.enqueue(
            jsonResponse(
                """{"group_id":"grp_1","name":"Hikers","description":"trails",
                    "member_count":5,"my_role":"moderator","admin_user_id":"usr_admin"}""",
            ),
        )

        val group = api().getGroup("grp_1")

        val recorded = server.takeRequest()
        assertEquals("GET", recorded.method)
        assertEquals("/ui/groups/grp_1", recorded.requestUrl?.encodedPath)
        assertEquals("Hikers", group.name)
        assertEquals("moderator", group.myRole)
        assertEquals("trails", group.description)
    }

    @Test
    fun listMembers_decodesMembersEnvelope_withCount() = runTest {
        server.enqueue(
            jsonResponse(
                """{"members":[
                     {"user_id":"usr_a","role":"admin","status":"active","display_name":"Ann",
                      "joined_at":"2026-01-01","promoted_at":"2026-02-01"},
                     {"user_id":"usr_b","role":"member","status":"invited"}
                   ],"count":2}""",
            ),
        )

        val response = api().listMembers("grp_1")

        val recorded = server.takeRequest()
        assertEquals("GET", recorded.method)
        assertEquals("/ui/groups/grp_1/members", recorded.requestUrl?.encodedPath)
        assertEquals(2, response.count)
        assertEquals(2, response.members.size)
        assertEquals("usr_a", response.members[0].userId)
        assertEquals("Ann", response.members[0].displayName)
        assertEquals("invited", response.members[1].status)
    }

    // ---- invite POSTs {user_id} -> the invitee becomes pending ----

    @Test
    fun invite_postsUserIdBody_andPath() = runTest {
        server.enqueue(MockResponse().setResponseCode(200))

        val response = api().invite("grp_1", GroupInviteIn(userId = "usr_new"))

        val recorded = server.takeRequest()
        assertEquals("POST", recorded.method)
        assertEquals("/ui/groups/grp_1/invite", recorded.requestUrl?.encodedPath)
        assertEquals("application/json", recorded.getHeader("Content-Type"))
        assertEquals("usr_new", recorded.bodyMap()["user_id"])
        assertTrue(response.isSuccessful)
    }

    // ---- changeRole PATCH .../role with {role}; tokens substituted ----

    @Test
    fun changeRole_patchesRolePath_withRoleBody() = runTest {
        server.enqueue(MockResponse().setResponseCode(200))

        val response = api().changeRole("grp_1", "usr_a", GroupUpdateRoleIn(role = "moderator"))

        val recorded = server.takeRequest()
        assertEquals("PATCH", recorded.method)
        assertEquals("/ui/groups/grp_1/members/usr_a/role", recorded.requestUrl?.encodedPath)
        assertEquals("moderator", recorded.bodyMap()["role"])
        assertTrue(response.isSuccessful)
    }

    // ---- removeMember DELETE -> 200 ----

    @Test
    fun removeMember_deletes_isSuccessful() = runTest {
        server.enqueue(MockResponse().setResponseCode(200))

        val response = api().removeMember("grp_1", "usr_a")

        val recorded = server.takeRequest()
        assertEquals("DELETE", recorded.method)
        assertEquals("/ui/groups/grp_1/members/usr_a", recorded.requestUrl?.encodedPath)
        assertTrue(response.isSuccessful)
    }

    // ---- leave POST .../leave (no body) -> 200 ----

    @Test
    fun leave_postsLeavePath_noBody_isSuccessful() = runTest {
        server.enqueue(MockResponse().setResponseCode(200))

        val response = api().leave("grp_1")

        val recorded = server.takeRequest()
        assertEquals("POST", recorded.method)
        assertEquals("/ui/groups/grp_1/leave", recorded.requestUrl?.encodedPath)
        assertEquals(0L, recorded.bodySize)
        assertTrue(response.isSuccessful)
    }
}
