package com.testlogon.android.core.network.delegates

import com.squareup.moshi.Moshi
import com.squareup.moshi.kotlin.reflect.KotlinJsonAdapterFactory
import com.testlogon.android.core.network.json.BigDecimalAdapter
import kotlinx.coroutines.test.runTest
import okhttp3.OkHttpClient
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Before
import org.junit.Test
import retrofit2.Retrofit
import retrofit2.converter.moshi.MoshiConverterFactory

/**
 * AND-359 - hermetic request-shape / decode tests for the AND-359 [DelegatesApi] (mirrors OrgsApiTest).
 *
 * Everything is hermetic: MockWebServer only, a production-style Moshi (BigDecimalAdapter + the
 * reflective KotlinJsonAdapterFactory, like NetworkModule.provideMoshi), and runTest. No real dev host.
 * core-network has no test dependency on core-testing, so the JSON bodies are inline. KDoc avoids the
 * comment-terminator character pair.
 */
class DelegatesApiTest {

    private lateinit var server: MockWebServer

    private val moshi: Moshi = Moshi.Builder()
        .add(BigDecimalAdapter)
        .add(KotlinJsonAdapterFactory())
        .build()

    private fun api(): DelegatesApi = Retrofit.Builder()
        .baseUrl(server.url("/"))
        .client(OkHttpClient())
        .addConverterFactory(MoshiConverterFactory.create(moshi))
        .build()
        .create(DelegatesApi::class.java)

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

    @Test
    fun listManagedCreators_decodesBareArray_andGetsManagedPath() = runTest {
        server.enqueue(
            jsonResponse(
                """[
                    {"creator_id":"cr_1","permissions":["read","post"],"preset":"editor",
                     "status":"active","label":"Acme Studio","accepted_at":"2026-01-01"},
                    {"creator_id":"cr_2"}
                ]""",
            ),
        )

        val managed = api().listManagedCreators()

        val recorded = server.takeRequest()
        assertEquals("GET", recorded.method)
        assertEquals("/ui/delegates/managed", recorded.requestUrl?.encodedPath)
        assertEquals(2, managed.size)
        assertEquals("cr_1", managed[0].creatorId)
        assertEquals(listOf("read", "post"), managed[0].permissions)
        assertEquals("editor", managed[0].preset)
        assertEquals("Acme Studio", managed[0].label)
        assertEquals("2026-01-01", managed[0].acceptedAt)
        // sparse row: permissions defaults to empty, optional fields null
        assertEquals("cr_2", managed[1].creatorId)
        assertEquals(emptyList<String>(), managed[1].permissions)
    }

    @Test
    fun listInvites_decodesBareArray_andGetsInvitesPath() = runTest {
        server.enqueue(
            jsonResponse(
                """[{"invite_id":"inv_1","creator_id":"cr_9","permissions":["read"],"label":"Studio"}]""",
            ),
        )

        val invites = api().listInvites()

        val recorded = server.takeRequest()
        assertEquals("GET", recorded.method)
        assertEquals("/ui/delegates/invites", recorded.requestUrl?.encodedPath)
        assertEquals(1, invites.size)
        assertEquals("inv_1", invites[0].inviteId)
        assertEquals("cr_9", invites[0].creatorId)
    }

    @Test
    fun respondInvite_postsRespondPath_withAcceptBody() = runTest {
        server.enqueue(MockResponse().setResponseCode(204))

        val response = api().respondInvite("inv_1", DelegateInviteRespondReq(accept = true))

        val recorded = server.takeRequest()
        assertEquals("POST", recorded.method)
        assertEquals("/ui/delegates/invites/inv_1/respond", recorded.requestUrl?.encodedPath)
        assertEquals("application/json", recorded.getHeader("Content-Type"))
        assertEquals(true, response.isSuccessful)
    }
}
