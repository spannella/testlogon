package com.testlogon.android.feature.tickets.data

import androidx.paging.Pager
import androidx.paging.PagingConfig
import androidx.paging.PagingData
import com.squareup.moshi.JsonDataException
import com.squareup.moshi.JsonEncodingException
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.model.tickets.Ticket
import com.testlogon.android.core.model.tickets.TicketSpace
import com.testlogon.android.core.network.error.ApiErrorParser
import com.testlogon.android.core.network.tickets.TicketsApi
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.withContext
import retrofit2.HttpException
import java.io.IOException
import java.net.SocketTimeoutException
import javax.inject.Inject
import javax.inject.Singleton

/**
 * AND-372 - READ-ONLY data layer for the ticket-spaces (support / helpdesk) surface, over the AND-371
 * [TicketsApi]. AND-371 was TRANSPORT ONLY (no repo / domain); THIS ticket adds the domain + mappers + repo.
 *
 * SPACES are loaded as a bounded last-good list ([getSpaces], a single first-page GET - the spaces-list cursor
 * is not paged this wave); the TICKETS WITHIN a space are Paging 3 ([ticketsPager], cursor-keyed via the AND-371
 * next_cursor). The detail reads ([getSpace], [getTicket]) map the RAW DTO (named-envelope unwrap {space} /
 * {ticket}) to the core-model domain and fold into [ApiResult] via [call] (mirrors AND-358 / AND-365).
 *
 * This ticket performs NO mutations (composing / replying / member or status edits are AND-373, OUT OF SCOPE).
 *
 * ROOM CACHE DEFERRED: there is intentionally NO Room-backed cache and NO Room migration this wave. The
 * stale-while-offline snapshot is kept IN-MEMORY in the ViewModels (an isStale flag over the last-good content),
 * NOT on disk; persistence across process death is DEFERRED to a later ticket.
 */
interface TicketsRepository {

    /** GET the caller's ticket spaces (first page), mapped to domain. (member count from members.size) */
    suspend fun getSpaces(): ApiResult<List<TicketSpace>>

    /** GET one ticket space (named {space} envelope unwrap), mapped. Idempotent. */
    suspend fun getSpace(spaceId: String): ApiResult<TicketSpace>

    /** A cold [PagingData] stream of the tickets in [spaceId] (cursor-keyed); re-collect to refresh. */
    fun ticketsPager(spaceId: String): Flow<PagingData<Ticket>>

    /** GET one ticket (named {ticket} envelope unwrap; embeds messages[] oldest-first), mapped. Idempotent. */
    suspend fun getTicket(spaceId: String, ticketId: String): ApiResult<Ticket>

    companion object {
        const val PAGE_SIZE = 20
        const val PREFETCH_DISTANCE = 6
    }
}

@Singleton
class TicketsRepositoryImpl @Inject constructor(
    private val api: TicketsApi,
    private val errorParser: ApiErrorParser,
) : TicketsRepository {

    override suspend fun getSpaces(): ApiResult<List<TicketSpace>> =
        withContext(Dispatchers.IO) {
            call { api.listSpaces().items.map { it.toDomain() } }
        }

    override suspend fun getSpace(spaceId: String): ApiResult<TicketSpace> =
        withContext(Dispatchers.IO) {
            call { api.getSpace(spaceId).space.toDomain() }
        }

    override fun ticketsPager(spaceId: String): Flow<PagingData<Ticket>> =
        Pager(
            config = pagingConfig(),
            pagingSourceFactory = { TicketsPagingSource(api, spaceId) },
        ).flow

    override suspend fun getTicket(spaceId: String, ticketId: String): ApiResult<Ticket> =
        withContext(Dispatchers.IO) {
            call { api.getTicket(spaceId, ticketId).ticket.toDomain() }
        }

    private fun pagingConfig() = PagingConfig(
        pageSize = TicketsRepository.PAGE_SIZE,
        initialLoadSize = TicketsRepository.PAGE_SIZE,
        prefetchDistance = TicketsRepository.PREFETCH_DISTANCE,
        enablePlaceholders = false,
    )

    /**
     * Folds a block into [ApiResult]. HTTP errors -> Failure (via [ApiErrorParser], preserving the status, so a
     * 401 surfaces as Failure(status=401) for the VM's NavigateToLogin handoff); malformed JSON -> Failure;
     * transport failures -> NetworkError. JsonEncodingException precedes IOException (it is a subtype).
     * Cancellation is re-thrown. Mirrors AND-358 / AND-365.
     */
    private suspend fun <T> call(block: suspend () -> T): ApiResult<T> = try {
        ApiResult.Success(block())
    } catch (e: CancellationException) {
        throw e
    } catch (e: HttpException) {
        ApiResult.Failure(errorParser.from(e))
    } catch (e: JsonEncodingException) {
        ApiResult.Failure(errorParser.fromThrowable(e))
    } catch (e: JsonDataException) {
        ApiResult.Failure(errorParser.fromThrowable(e))
    } catch (e: IOException) {
        ApiResult.NetworkError(e, isTimeout = e is SocketTimeoutException)
    }
}
