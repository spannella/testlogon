package com.testlogon.android.feature.tickets.data

import androidx.paging.PagingSource
import androidx.paging.PagingState
import com.testlogon.android.core.model.tickets.Ticket
import com.testlogon.android.core.network.tickets.TicketsApi
import kotlinx.coroutines.CancellationException
import retrofit2.HttpException
import java.io.IOException

/**
 * AND-372 - cursor-keyed Paging 3 source over the AND-371 [TicketsApi.listTickets] endpoint (the tickets WITHIN
 * one space). Mirrors the AND-358 CollaborationsPagingSource idiom (network-only, forward-only).
 *
 * Keys are the opaque `next_cursor` Strings returned by the backend; the listing is forward-only (prevKey null)
 * and a null / blank cursor terminates pagination. Each [SpaceTicketOut] is mapped to the domain [Ticket]
 * before use (a list row carries empty messages[]). HttpException / IOException become LoadResult.Error;
 * CancellationException is re-thrown so Paging cancellation works. getRefreshKey returns null (pull-to-refresh
 * re-anchors at the first page).
 *
 * ROOM CACHE DEFERRED: this is a NETWORK-backed PagingSource - there is NO Room-backed cache and NO
 * RemoteMediator (no Room migration this wave). Offline persistence is DEFERRED to a later ticket.
 */
class TicketsPagingSource(
    private val api: TicketsApi,
    private val spaceId: String,
) : PagingSource<String, Ticket>() {

    override suspend fun load(params: LoadParams<String>): LoadResult<String, Ticket> = try {
        val envelope = api.listTickets(spaceId = spaceId, cursor = params.key)
        LoadResult.Page(
            data = envelope.items.map { it.toDomain() },
            prevKey = null,
            nextKey = envelope.nextCursor?.takeIf { it.isNotBlank() },
        )
    } catch (e: CancellationException) {
        throw e
    } catch (e: HttpException) {
        LoadResult.Error(e)
    } catch (e: IOException) {
        LoadResult.Error(e)
    }

    override fun getRefreshKey(state: PagingState<String, Ticket>): String? = null
}
