package com.testlogon.android.feature.tickets.testing

import androidx.paging.PagingData
import com.testlogon.android.core.model.ApiError
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.model.LogoutReason
import com.testlogon.android.core.model.tickets.SpaceMember
import com.testlogon.android.core.model.tickets.Ticket
import com.testlogon.android.core.model.tickets.TicketMessage
import com.testlogon.android.core.model.tickets.TicketSpace
import com.testlogon.android.core.network.tickets.SpaceTicketEnvelope
import com.testlogon.android.core.network.tickets.SpaceTicketListEnvelope
import com.testlogon.android.core.network.tickets.SpaceTicketMessageReq
import com.testlogon.android.core.network.tickets.SpaceTicketOut
import com.testlogon.android.core.network.tickets.TicketSpaceEnvelope
import com.testlogon.android.core.network.tickets.TicketSpaceListEnvelope
import com.testlogon.android.core.network.tickets.TicketSpaceOut
import com.testlogon.android.core.network.tickets.TicketsApi
import com.testlogon.android.data.auth.AuthStateStore
import com.testlogon.android.feature.tickets.data.TicketsRepository
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.flowOf
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.ResponseBody.Companion.toResponseBody
import retrofit2.HttpException
import retrofit2.Response

/**
 * AND-372 - in-memory fakes for the tickets unit tests.
 *
 * The :app unit-test classpath has NO moshi-kotlin KotlinJsonAdapterFactory, so :app tests use a FAKE
 * AND-371 [TicketsApi] (no Moshi). Each call RECORDS its args / call-count BEFORE honouring a configured throw,
 * so a test can assert the @Path / @Query was passed even when the call fails. Helper / recording names are
 * distinct (the -Ticket- infix) and never shadow an interface method.
 */
class FakeTicketsApi(
    var spaces: () -> TicketSpaceListEnvelope = { TicketSpaceListEnvelope(items = emptyList(), nextCursor = null) },
    var space: () -> TicketSpaceEnvelope = { TicketSpaceEnvelope(space = TicketSpaceOut(spaceId = "s1")) },
    var tickets: () -> SpaceTicketListEnvelope = { SpaceTicketListEnvelope(items = emptyList(), nextCursor = null) },
    var ticket: () -> SpaceTicketEnvelope = { SpaceTicketEnvelope(ticket = SpaceTicketOut(ticketId = "t1")) },
    var reply: () -> SpaceTicketEnvelope = { SpaceTicketEnvelope(ticket = SpaceTicketOut(ticketId = "t1")) },
) : TicketsApi {

    val listSpacesCursors = mutableListOf<String?>()
    val getSpaceIds = mutableListOf<String>()
    val listTicketsArgs = mutableListOf<Pair<String, String?>>()
    val getTicketArgs = mutableListOf<Pair<String, String>>()

    /** AND-373 - records each replyToTicket as (spaceId, ticketId, requestBody) BEFORE honouring a throw. */
    val replyArgs = mutableListOf<Triple<String, String, SpaceTicketMessageReq>>()

    override suspend fun listSpaces(cursor: String?): TicketSpaceListEnvelope {
        listSpacesCursors += cursor
        return spaces()
    }

    override suspend fun getSpace(spaceId: String): TicketSpaceEnvelope {
        getSpaceIds += spaceId
        return space()
    }

    override suspend fun listTickets(spaceId: String, cursor: String?): SpaceTicketListEnvelope {
        listTicketsArgs += spaceId to cursor
        return tickets()
    }

    override suspend fun getTicket(spaceId: String, ticketId: String): SpaceTicketEnvelope {
        getTicketArgs += spaceId to ticketId
        return ticket()
    }

    override suspend fun replyToTicket(
        spaceId: String,
        ticketId: String,
        body: SpaceTicketMessageReq,
    ): SpaceTicketEnvelope {
        replyArgs += Triple(spaceId, ticketId, body)
        return reply()
    }

    companion object {
        /** Builds an HttpException with [status] (used to simulate a 401 / 500). */
        fun httpTicketError(status: Int): HttpException = HttpException(
            Response.error<Any>(
                status,
                """{"detail":"boom"}""".toResponseBody("application/json".toMediaType()),
            ),
        )
    }
}

/** A fake AuthStateStore exposing a fixed viewer user_sub (distinct name from the other feature fakes). */
class FakeTicketsAuthStore(viewerSub: String?) : AuthStateStore {
    private val sub = MutableStateFlow(viewerSub)
    override val userSub: StateFlow<String?> = sub.asStateFlow()
    override val isAuthenticated: StateFlow<Boolean> = MutableStateFlow(viewerSub != null).asStateFlow()
    override suspend fun setAuthenticated(userSub: String) {
        sub.value = userSub
    }
    override suspend fun clear(reason: LogoutReason) {
        sub.value = null
    }
    override suspend fun lastLogoutReason(): LogoutReason? = null
    override suspend fun clearLogoutReason() = Unit
}

/**
 * A fake [TicketsRepository] for the ViewModel tests. The spaces / space / ticket results are independently
 * swappable so a test can vary a second (refresh) read. The paged ticket list returns empty PagingData (the
 * VMs under test do not page in unit tests). Mutating helpers are absent (the surface is READ-ONLY).
 */
class FakeTicketsRepo(
    var spacesResult: ApiResult<List<TicketSpace>> = ApiResult.Success(emptyList()),
    var spaceResult: ApiResult<TicketSpace> = ApiResult.Success(TicketSpace(spaceId = "s1", name = "Support")),
    var ticketResult: ApiResult<Ticket> = ApiResult.Success(Ticket(ticketId = "t1")),
    var replyResult: ApiResult<Ticket> = ApiResult.Success(Ticket(ticketId = "t1")),
) : TicketsRepository {

    var getSpacesCallCount = 0
    var getSpaceCallCount = 0
    var getTicketCallCount = 0

    /** AND-373 - records each reply as (spaceId, ticketId, body) so a test can assert the POSTed text. */
    val replyArgs = mutableListOf<Triple<String, String, String>>()

    override suspend fun getSpaces(): ApiResult<List<TicketSpace>> {
        getSpacesCallCount++
        return spacesResult
    }

    override suspend fun getSpace(spaceId: String): ApiResult<TicketSpace> {
        getSpaceCallCount++
        return spaceResult
    }

    override fun ticketsPager(spaceId: String): Flow<PagingData<Ticket>> = flowOf(PagingData.empty())

    override suspend fun getTicket(spaceId: String, ticketId: String): ApiResult<Ticket> {
        getTicketCallCount++
        return ticketResult
    }

    override suspend fun reply(spaceId: String, ticketId: String, body: String): ApiResult<Ticket> {
        replyArgs += Triple(spaceId, ticketId, body)
        return replyResult
    }

    companion object {
        fun ticketsFailure(status: Int = 500): ApiResult.Failure =
            ApiResult.Failure(ApiError(status = status, message = "boom"))

        /** A small domain space builder for the spaces-list ViewModel tests. */
        fun space(
            id: String,
            name: String? = "Space $id",
            visibility: String? = "private",
            memberCount: Int = 2,
            updatedAt: Long? = 100L,
        ): TicketSpace = TicketSpace(
            spaceId = id,
            name = name,
            visibility = visibility,
            members = emptyList(),
            memberCount = memberCount,
            updatedAt = updatedAt,
        )

        /** AND-373 - a domain space whose single member [memberSub] holds [role] (for canPost gating tests). */
        fun spaceWithMember(
            memberSub: String,
            role: String?,
            id: String = "s1",
        ): TicketSpace = TicketSpace(
            spaceId = id,
            name = "Support",
            visibility = "private",
            members = listOf(SpaceMember(userSub = memberSub, role = role)),
            memberCount = 1,
            updatedAt = 100L,
        )

        /** A small domain message builder for the thread ViewModel tests. */
        fun message(
            id: String,
            senderSub: String?,
            body: String? = "body $id",
            createdAt: Long? = 100L,
        ): TicketMessage = TicketMessage(
            messageId = id,
            senderSub = senderSub,
            senderRole = null,
            body = body,
            createdAt = createdAt,
        )

        /** A small domain ticket builder (with embedded messages) for the thread ViewModel tests. */
        fun ticketWith(
            id: String = "t1",
            subject: String? = "Subject $id",
            status: String? = "open",
            messages: List<TicketMessage> = emptyList(),
        ): Ticket = Ticket(
            ticketId = id,
            spaceId = "s1",
            subject = subject,
            status = status,
            messages = messages,
        )
    }
}
