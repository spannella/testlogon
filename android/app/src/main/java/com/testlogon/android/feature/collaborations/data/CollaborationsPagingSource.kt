package com.testlogon.android.feature.collaborations.data

import androidx.paging.PagingSource
import androidx.paging.PagingState
import com.testlogon.android.core.model.collaborations.Collaboration
import com.testlogon.android.core.network.collaborations.CollaborationsApi
import kotlinx.coroutines.CancellationException
import retrofit2.HttpException
import java.io.IOException

/**
 * AND-358 - cursor-keyed Paging 3 source over the [CollaborationsApi] list endpoint. Mirrors the AND-356
 * SyndicateFeedPagingSource idiom (network-only, forward-only).
 *
 * Keys are the opaque `next_cursor` Strings returned by the backend; the listing is forward-only (prevKey
 * null) and a null / blank cursor terminates pagination. The DTO is mapped to the domain before use.
 * HttpException / IOException become LoadResult.Error; CancellationException is re-thrown so Paging
 * cancellation works. getRefreshKey returns null (pull-to-refresh re-anchors at the first page).
 *
 * ROOM CACHE DEFERRED: this is a NETWORK-backed PagingSource - there is NO Room-backed cache and NO
 * RemoteMediator (no Room migration this wave). Offline persistence is DEFERRED to a later ticket.
 */
class CollaborationsPagingSource(
    private val api: CollaborationsApi,
) : PagingSource<String, Collaboration>() {

    override suspend fun load(params: LoadParams<String>): LoadResult<String, Collaboration> = try {
        val out = api.listCollaborations(cursor = params.key)
        LoadResult.Page(
            data = out.itemsOrEmpty().map { it.toDomain() },
            prevKey = null,
            nextKey = out.normalizedCursor(),
        )
    } catch (e: CancellationException) {
        throw e
    } catch (e: HttpException) {
        LoadResult.Error(e)
    } catch (e: IOException) {
        LoadResult.Error(e)
    }

    override fun getRefreshKey(state: PagingState<String, Collaboration>): String? = null
}
