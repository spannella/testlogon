package com.testlogon.android.data.messaging

import com.squareup.moshi.Moshi
import com.testlogon.android.core.testing.net.Fixtures
import com.testlogon.android.core.testing.net.MockBackendRule
import com.testlogon.android.core.testing.net.retrofit
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import retrofit2.HttpException

/**
 * AND-153 / AND-156 — MockWebServer contract test for `GET /messaging/contacts/search`.
 *
 * Verifies (against the real OpenAPI contract `search_contact_messaging_contacts_search_get`): the
 * resolved path, GET verb, query params (q + limit, NO cursor), and decode of the BARE Contact[]
 * array (`{user_id, display_name}` only). A 422 (bad/blank q) surfaces as HttpException.
 */
class ContactSearchApiContractTest {

    @get:Rule
    val backend = MockBackendRule()

    private val moshi: Moshi = Moshi.Builder().build()

    private fun api(): MessagingApi = backend.retrofit(moshi).create(MessagingApi::class.java)

    @Test
    fun searchContacts_decodesBareArray_sendsQueryAndLimit_noCursor() = runTest {
        backend.enqueue(
            Fixtures.okBody(
                """
                [
                  {"user_id":"u_1029","display_name":"Alice Nguyen"},
                  {"user_id":"u_2048","display_name":"Khalil Brooks"}
                ]
                """.trimIndent(),
            ),
        )
        val list = api().searchContacts(query = "ali", limit = 20)
        assertEquals(2, list.size)
        assertEquals("u_1029", list[0].userId)
        assertEquals("Alice Nguyen", list[0].displayName)

        val req = backend.takeRequest()
        assertEquals("GET", req.method)
        assertEquals("/messaging/contacts/search", req.requestUrl?.encodedPath)
        assertEquals("ali", req.requestUrl?.queryParameter("q"))
        assertEquals("20", req.requestUrl?.queryParameter("limit"))
        assertNull(req.requestUrl?.queryParameter("cursor")) // no pagination on this endpoint
    }

    @Test
    fun searchContacts_decodesEmptyArray() = runTest {
        backend.enqueue(Fixtures.okBody("[]"))
        val list = api().searchContacts(query = "zzz", limit = 20)
        assertTrue(list.isEmpty())
    }

    @Test
    fun searchContacts_422_throwsHttpException() = runTest {
        backend.enqueue(
            Fixtures.error(
                """[{"loc":["query","q"],"msg":"ensure this value has at least 1 character","type":"string_too_short"}]""",
                code = 422,
            ),
        )
        var threw = false
        try {
            api().searchContacts(query = "x".repeat(65), limit = 20)
        } catch (e: HttpException) {
            threw = true
            assertEquals(422, e.code())
        }
        assertTrue(threw)
    }
}
