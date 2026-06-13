package com.testlogon.android.feature.tickets

import androidx.paging.PagingSource
import com.squareup.moshi.Moshi
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.network.error.ApiErrorParser
import com.testlogon.android.core.network.tickets.SpaceMemberOut
import com.testlogon.android.core.network.tickets.SpaceTicketEnvelope
import com.testlogon.android.core.network.tickets.SpaceTicketListEnvelope
import com.testlogon.android.core.network.tickets.SpaceTicketMessage
import com.testlogon.android.core.network.tickets.SpaceTicketOut
import com.testlogon.android.core.network.tickets.TicketSpaceEnvelope
import com.testlogon.android.core.network.tickets.TicketSpaceListEnvelope
import com.testlogon.android.core.network.tickets.TicketSpaceOut
import com.testlogon.android.core.model.tickets.SpaceMember
import com.testlogon.android.core.model.tickets.TicketSpace
import com.testlogon.android.feature.tickets.data.TicketsPagingSource
import com.testlogon.android.feature.tickets.data.TicketsRepository
import com.testlogon.android.feature.tickets.data.TicketsRepositoryImpl
import com.testlogon.android.feature.tickets.testing.FakeTicketsApi
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * AND-372 - tests for [TicketsRepositoryImpl]: getSpaces maps the list envelope (member count from members.size),
 * getSpace unwraps the named {space} envelope, getTicket unwraps the named {ticket} envelope (embedded messages),
 * and a 401 surfaces as Failure(status=401) for the VM's NavigateToLogin handoff. Also a direct
 * [TicketsPagingSource].load() test (first-page items + nextKey from next_cursor, blank-cursor termination,
 * http-error -> Error). Recording fakes record the @Path / @Query BEFORE throwing.
 */
class TicketsRepositoryTest {

    private fun repo(api: FakeTicketsApi) = TicketsRepositoryImpl(
        api = api,
        errorParser = ApiErrorParser(Moshi.Builder().build()),
    )

    @Test
    fun getSpaces_mapsItems_memberCountFromMembersSize() = runTest {
        val api = FakeTicketsApi(
            spaces = {
                TicketSpaceListEnvelope(
                    items = listOf(
                        TicketSpaceOut(
                            spaceId = "s1",
                            name = "Support",
                            visibility = "shared",
                            members = listOf(
                                SpaceMemberOut(userSub = "u1"),
                                SpaceMemberOut(userSub = "u2"),
                            ),
                        ),
                    ),
                    nextCursor = null,
                )
            },
        )
        val result = repo(api).getSpaces()

        assertTrue(result is ApiResult.Success)
        val spaces = (result as ApiResult.Success).data
        assertEquals("s1", spaces.single().spaceId)
        assertEquals(2, spaces.single().memberCount)
        assertEquals("shared", spaces.single().visibility)
        assertNull(api.listSpacesCursors.single())
    }

    @Test
    fun getSpace_unwrapsNamedEnvelope() = runTest {
        val api = FakeTicketsApi(
            space = { TicketSpaceEnvelope(space = TicketSpaceOut(spaceId = "s1", name = "Helpdesk")) },
        )
        val result = repo(api).getSpace("s1")

        assertTrue(result is ApiResult.Success)
        assertEquals("Helpdesk", (result as ApiResult.Success).data.name)
        assertEquals("s1", api.getSpaceIds.single())
    }

    @Test
    fun getTicket_unwrapsNamedEnvelope_andEmbeddedMessages() = runTest {
        val api = FakeTicketsApi(
            ticket = {
                SpaceTicketEnvelope(
                    ticket = SpaceTicketOut(
                        ticketId = "t1",
                        title = "Issue",
                        status = "open",
                        messages = listOf(
                            SpaceTicketMessage(messageId = "m1", senderSub = "u1", body = "hi"),
                        ),
                    ),
                )
            },
        )
        val result = repo(api).getTicket("s1", "t1")

        assertTrue(result is ApiResult.Success)
        val ticket = (result as ApiResult.Success).data
        assertEquals("Issue", ticket.subject)
        assertEquals(1, ticket.messages.size)
        assertEquals("hi", ticket.messages.single().body)
        assertEquals("s1" to "t1", api.getTicketArgs.single())
    }

    @Test
    fun getSpaces_401_isFailureWithStatus401() = runTest {
        val api = FakeTicketsApi(spaces = { throw FakeTicketsApi.httpTicketError(401) })
        val result = repo(api).getSpaces()
        assertTrue(result is ApiResult.Failure)
        assertEquals(401, (result as ApiResult.Failure).error.status)
        // recorded BEFORE throwing
        assertEquals(1, api.listSpacesCursors.size)
    }

    @Test
    fun getTicket_httpError_isFailure() = runTest {
        val api = FakeTicketsApi(ticket = { throw FakeTicketsApi.httpTicketError(500) })
        val result = repo(api).getTicket("s1", "t1")
        assertTrue(result is ApiResult.Failure)
        assertEquals("s1" to "t1", api.getTicketArgs.single())
    }

    // ---- AND-373: reply + canPostInSpace ----

    @Test
    fun reply_mapsReturnedTicket_newMessageIsMessagesLast_andPostsBody() = runTest {
        val api = FakeTicketsApi(
            reply = {
                SpaceTicketEnvelope(
                    ticket = SpaceTicketOut(
                        ticketId = "t1",
                        title = "Issue",
                        status = "open",
                        messages = listOf(
                            SpaceTicketMessage(messageId = "m1", senderSub = "other", body = "hi"),
                            SpaceTicketMessage(messageId = "m2", senderSub = "me", body = "reply!"),
                        ),
                    ),
                )
            },
        )
        val result = repo(api).reply("s1", "t1", "reply!")

        assertTrue(result is ApiResult.Success)
        val ticket = (result as ApiResult.Success).data
        assertEquals("m2", ticket.messages.last().messageId)
        assertEquals("reply!", ticket.messages.last().body)
        // recorded BEFORE returning: @Path + body shape
        val recorded = api.replyArgs.single()
        assertEquals("s1", recorded.first)
        assertEquals("t1", recorded.second)
        assertEquals("reply!", recorded.third.body)
    }

    @Test
    fun reply_422_isFailure_recordedBeforeThrow() = runTest {
        val api = FakeTicketsApi(reply = { throw FakeTicketsApi.httpTicketError(422) })
        val result = repo(api).reply("s1", "t1", "x")
        assertTrue(result is ApiResult.Failure)
        assertEquals(422, (result as ApiResult.Failure).error.status)
        assertEquals(1, api.replyArgs.size)
    }

    @Test
    fun reply_403_isFailure() = runTest {
        val api = FakeTicketsApi(reply = { throw FakeTicketsApi.httpTicketError(403) })
        val result = repo(api).reply("s1", "t1", "x")
        assertTrue(result is ApiResult.Failure)
        assertEquals(403, (result as ApiResult.Failure).error.status)
    }

    @Test
    fun canPostInSpace_trueForEditorOrOwner_falseForViewerOrNonMember() {
        fun spaceWith(role: String?) = TicketSpace(
            spaceId = "s1",
            members = listOf(SpaceMember(userSub = "me", role = role)),
        )
        assertTrue(TicketsRepository.canPostInSpace(spaceWith("editor"), "me"))
        assertTrue(TicketsRepository.canPostInSpace(spaceWith("owner"), "me"))
        assertFalse(TicketsRepository.canPostInSpace(spaceWith("viewer"), "me"))
        // non-member (no matching sub) -> false
        assertFalse(TicketsRepository.canPostInSpace(spaceWith("owner"), "someone_else"))
        // null currentSub -> false
        assertFalse(TicketsRepository.canPostInSpace(spaceWith("owner"), null))
    }

    @Test
    fun pagingSource_firstPage_mapsItems_andNextKeyFromCursor() = runTest {
        val api = FakeTicketsApi(
            tickets = {
                SpaceTicketListEnvelope(
                    items = listOf(
                        SpaceTicketOut(ticketId = "t1", title = "A"),
                        SpaceTicketOut(ticketId = "t2", title = "B"),
                    ),
                    nextCursor = "cur2",
                )
            },
        )
        val source = TicketsPagingSource(api, spaceId = "s1")
        val result = source.load(PagingSource.LoadParams.Refresh(null, 20, false))

        assertTrue(result is PagingSource.LoadResult.Page)
        val page = result as PagingSource.LoadResult.Page
        assertEquals(listOf("t1", "t2"), page.data.map { it.ticketId })
        assertNull(page.prevKey)
        assertEquals("cur2", page.nextKey)
        assertEquals("s1" to null, api.listTicketsArgs.single())
    }

    @Test
    fun pagingSource_blankCursor_endsPagination() = runTest {
        val api = FakeTicketsApi(
            tickets = {
                SpaceTicketListEnvelope(items = listOf(SpaceTicketOut(ticketId = "t1")), nextCursor = "")
            },
        )
        val page = TicketsPagingSource(api, spaceId = "s1")
            .load(PagingSource.LoadParams.Refresh(null, 20, false)) as PagingSource.LoadResult.Page
        assertNull(page.nextKey)
    }

    @Test
    fun pagingSource_httpError_becomesLoadResultError() = runTest {
        val api = FakeTicketsApi(tickets = { throw FakeTicketsApi.httpTicketError(500) })
        val result = TicketsPagingSource(api, spaceId = "s1")
            .load(PagingSource.LoadParams.Refresh(null, 20, false))
        assertTrue(result is PagingSource.LoadResult.Error)
    }
}
