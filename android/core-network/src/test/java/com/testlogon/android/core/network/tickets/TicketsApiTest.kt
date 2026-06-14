package com.testlogon.android.core.network.tickets

import com.squareup.moshi.Moshi
import com.squareup.moshi.kotlin.reflect.KotlinJsonAdapterFactory
import com.testlogon.android.core.network.json.BigDecimalAdapter
import kotlinx.coroutines.test.runTest
import okhttp3.OkHttpClient
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import retrofit2.HttpException
import retrofit2.Retrofit
import retrofit2.converter.moshi.MoshiConverterFactory

/**
 * AND-371 - hermetic request-shape / decode tests for the [TicketsApi] (mirrors OrgsApiTest /
 * SponsorshipApiTest).
 *
 * Everything is hermetic: MockWebServer only, a production-style Moshi (BigDecimalAdapter + the reflective
 * KotlinJsonAdapterFactory, like NetworkModule.provideMoshi - no enum adapter needed since status / role /
 * visibility / sender_role decode as raw Strings), and runTest. No real dev host. core-network has no test
 * dependency on core-testing, so the JSON bodies are inline. KDoc avoids the comment-terminator pair.
 */
class TicketsApiTest {

    private lateinit var server: MockWebServer

    private val moshi: Moshi = Moshi.Builder()
        .add(BigDecimalAdapter)
        .add(KotlinJsonAdapterFactory())
        .build()

    private fun ticketsApi(): TicketsApi = Retrofit.Builder()
        .baseUrl(server.url("/"))
        .client(OkHttpClient())
        .addConverterFactory(MoshiConverterFactory.create(moshi))
        .build()
        .create(TicketsApi::class.java)

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

    // ---- listSpaces: list envelope { items, next_cursor }, relative path, no cursor by default ----

    @Test
    fun listSpaces_decodesListEnvelope_relativePath_noCursorByDefault() = runTest {
        server.enqueue(
            jsonResponse(
                """{"items":[
                     {"space_id":"sp_1","name":"Support","visibility":"shared","created_at":1700000000},
                     {"space_id":"sp_2"}
                   ],"next_cursor":"cur_2"}""",
            ),
        )

        val envelope = ticketsApi().listSpaces()

        val recorded = server.takeRequest()
        assertEquals("GET", recorded.method)
        assertEquals("/ticket-spaces", recorded.requestUrl?.encodedPath)
        // no cursor sent when omitted (Retrofit drops null @Query)
        assertNull(recorded.requestUrl?.query)
        assertEquals(2, envelope.items.size)
        assertEquals("sp_1", envelope.items[0].spaceId)
        assertEquals("shared", envelope.items[0].visibility)
        assertEquals("cur_2", envelope.nextCursor)
        // sparse space: members default to empty
        assertTrue(envelope.items[1].members.isEmpty())
    }

    @Test
    fun listSpaces_passesCursorQuery_whenProvided() = runTest {
        server.enqueue(jsonResponse("""{"items":[],"next_cursor":null}"""))

        val envelope = ticketsApi().listSpaces(cursor = "cur_1")

        val recorded = server.takeRequest()
        assertEquals("/ticket-spaces", recorded.requestUrl?.encodedPath)
        assertEquals("cur_1", recorded.requestUrl?.queryParameter("cursor"))
        assertTrue(envelope.items.isEmpty())
        assertNull(envelope.nextCursor)
    }

    // ---- getSpace: NAMED {space} envelope with embedded members[], {spaceId} path ----

    @Test
    fun getSpace_decodesNamedEnvelope_withEmbeddedMembers_substitutesSpaceIdPath() = runTest {
        server.enqueue(
            jsonResponse(
                """{"space":{"space_id":"sp_1","name":"Support","visibility":"private",
                     "members":[{"user_sub":"usr_a","role":"owner"},{"user_sub":"usr_b","role":"viewer"}],
                     "created_at":1700000000,"updated_at":1700000100}}""",
            ),
        )

        val envelope = ticketsApi().getSpace("sp_1")

        val recorded = server.takeRequest()
        assertEquals("GET", recorded.method)
        assertEquals("/ticket-spaces/sp_1", recorded.requestUrl?.encodedPath)
        assertEquals("sp_1", envelope.space.spaceId)
        assertEquals("private", envelope.space.visibility)
        assertEquals(2, envelope.space.members.size)
        assertEquals("usr_a", envelope.space.members[0].userSub)
        assertEquals("owner", envelope.space.members[0].role)
        assertEquals(1700000100L, envelope.space.updatedAt)
    }

    // ---- listTickets: list envelope, {spaceId} path, cursor query ----

    @Test
    fun listTickets_decodesListEnvelope_substitutesSpaceIdPath_passesCursor() = runTest {
        server.enqueue(
            jsonResponse(
                """{"items":[
                     {"ticket_id":"tk_1","space_id":"sp_1","title":"Cannot log in","status":"open"},
                     {"ticket_id":"tk_2","status":"done"}
                   ],"next_cursor":"cur_t2"}""",
            ),
        )

        val envelope = ticketsApi().listTickets("sp_1", cursor = "cur_t1")

        val recorded = server.takeRequest()
        assertEquals("GET", recorded.method)
        assertEquals("/ticket-spaces/sp_1/tickets", recorded.requestUrl?.encodedPath)
        assertEquals("cur_t1", recorded.requestUrl?.queryParameter("cursor"))
        assertEquals(2, envelope.items.size)
        assertEquals("tk_1", envelope.items[0].ticketId)
        assertEquals("open", envelope.items[0].status)
        assertEquals("cur_t2", envelope.nextCursor)
        // sparse ticket: messages + activity default to empty
        assertTrue(envelope.items[1].messages.isEmpty())
        assertTrue(envelope.items[1].activity.isEmpty())
    }

    // ---- getTicket: NAMED {ticket} envelope with embedded messages[] + activity[], both @Path tokens ----

    @Test
    fun getTicket_decodesNamedEnvelope_withMessagesAndActivity_substitutesBothPaths() = runTest {
        server.enqueue(
            jsonResponse(
                """{"ticket":{"ticket_id":"tk_1","space_id":"sp_1","title":"Cannot log in",
                     "status":"in_progress","created_at":1700000000,"updated_at":1700000200,
                     "messages":[
                       {"message_id":"m_1","sender_sub":"usr_a","sender_role":"reporter",
                        "body":"Help","created_at":1700000010}
                     ],
                     "activity":[
                       {"activity_id":"a_1","activity_type":"status_changed","actor_sub":"usr_b",
                        "created_at":1700000020}
                     ]}}""",
            ),
        )

        val envelope = ticketsApi().getTicket("sp_1", "tk_1")

        val recorded = server.takeRequest()
        assertEquals("GET", recorded.method)
        assertEquals("/ticket-spaces/sp_1/tickets/tk_1", recorded.requestUrl?.encodedPath)
        assertEquals("tk_1", envelope.ticket.ticketId)
        assertEquals("in_progress", envelope.ticket.status)
        assertEquals(1, envelope.ticket.messages.size)
        assertEquals("m_1", envelope.ticket.messages[0].messageId)
        assertEquals("reporter", envelope.ticket.messages[0].senderRole)
        assertEquals("usr_a", envelope.ticket.messages[0].senderSub)
        assertEquals("Help", envelope.ticket.messages[0].body)
        assertEquals(1, envelope.ticket.activity.size)
        assertEquals("status_changed", envelope.ticket.activity[0].activityType)
    }

    // ---- error surfaces ----

    @Test
    fun getSpace_404_surfacesAsHttpException() = runTest {
        server.enqueue(MockResponse().setResponseCode(404))

        val error = runCatching { ticketsApi().getSpace("missing") }.exceptionOrNull()

        val recorded = server.takeRequest()
        assertEquals("/ticket-spaces/missing", recorded.requestUrl?.encodedPath)
        assertTrue(error is HttpException)
        assertEquals(404, (error as HttpException).code())
    }

    @Test
    fun listSpaces_500_surfacesAsHttpException() = runTest {
        server.enqueue(MockResponse().setResponseCode(500))

        val error = runCatching { ticketsApi().listSpaces() }.exceptionOrNull()

        assertTrue(error is HttpException)
        assertEquals(500, (error as HttpException).code())
    }

    // ---- AND-373: replyToTicket POSTs {body}, both @Path tokens, returns the whole-ticket envelope ----

    @Test
    fun replyToTicket_postsBody_substitutesBothPaths_returnsWholeTicketEnvelope() = runTest {
        server.enqueue(
            jsonResponse(
                """{"ticket":{"ticket_id":"tk_1","space_id":"sp_1","title":"Cannot log in",
                     "status":"open","messages":[
                       {"message_id":"m_1","sender_sub":"usr_a","body":"Help","created_at":1700000010},
                       {"message_id":"m_2","sender_sub":"usr_b","body":"On it","created_at":1700000020}
                     ]}}""",
            ),
        )

        val envelope = ticketsApi().replyToTicket("sp_1", "tk_1", SpaceTicketMessageReq(body = "On it"))

        val recorded = server.takeRequest()
        assertEquals("POST", recorded.method)
        assertEquals("/ticket-spaces/sp_1/tickets/tk_1/messages", recorded.requestUrl?.encodedPath)
        // request body carries {"body":"On it"}
        val sentBody = recorded.body.readUtf8()
        assertTrue(sentBody.contains(""""body":"On it""""))
        // response is the WHOLE ticket; the new message is messages.last()
        assertEquals("m_2", envelope.ticket.messages.last().messageId)
        assertEquals("On it", envelope.ticket.messages.last().body)
    }

    @Test
    fun replyToTicket_422_surfacesAsHttpException() = runTest {
        server.enqueue(
            MockResponse().setResponseCode(422).setHeader("Content-Type", "application/json")
                .setBody("""{"detail":[{"loc":["body","body"],"msg":"too long","type":"value_error"}]}"""),
        )

        val error = runCatching {
            ticketsApi().replyToTicket("sp_1", "tk_1", SpaceTicketMessageReq(body = "x"))
        }.exceptionOrNull()

        val recorded = server.takeRequest()
        assertEquals("/ticket-spaces/sp_1/tickets/tk_1/messages", recorded.requestUrl?.encodedPath)
        assertTrue(error is HttpException)
        assertEquals(422, (error as HttpException).code())
    }

    @Test
    fun replyToTicket_403_errorEnvelope_surfacesAsHttpException() = runTest {
        server.enqueue(
            MockResponse().setResponseCode(403).setHeader("Content-Type", "application/json")
                .setBody("""{"error":{"code":"role_required","message":"nope"}}"""),
        )

        val error = runCatching {
            ticketsApi().replyToTicket("sp_1", "tk_1", SpaceTicketMessageReq(body = "x"))
        }.exceptionOrNull()

        assertTrue(error is HttpException)
        assertEquals(403, (error as HttpException).code())
    }
}
