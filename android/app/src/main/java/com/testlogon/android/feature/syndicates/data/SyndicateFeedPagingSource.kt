package com.testlogon.android.feature.syndicates.data

import androidx.paging.PagingSource
import androidx.paging.PagingState
import com.testlogon.android.core.model.syndicates.SyndicateFeedItem
import com.testlogon.android.core.network.syndicates.SyndicateApi
import kotlinx.coroutines.CancellationException
import retrofit2.HttpException
import java.io.IOException

/**
 * AND-356 - cursor-keyed Paging 3 source over the [SyndicateApi] feed endpoint for one syndicate. Mirrors
 * the AND-332 FilesPagingSource idiom (network-only, forward-only).
 *
 * Keys are the opaque `next_cursor` Strings returned by the backend; the listing is forward-only (prevKey
 * null) and a null / blank cursor terminates pagination (a single-page feed renders without an append
 * footer). The DTO is mapped to the domain (SyndicatePostOut.toDomain) before use. HttpException /
 * IOException become LoadResult.Error; CancellationException is re-thrown so Paging cancellation works.
 * getRefreshKey returns null (pull-to-refresh re-anchors at the first page).
 *
 * ROOM CACHE DEFERRED: this is a NETWORK-backed PagingSource - there is NO Room-backed cache and NO
 * RemoteMediator (no Room migration this wave). Offline persistence is DEFERRED to a later ticket.
 */
class SyndicateFeedPagingSource(
    private val api: SyndicateApi,
    private val syndicateId: String,
) : PagingSource<String, SyndicateFeedItem>() {

    override suspend fun load(params: LoadParams<String>): LoadResult<String, SyndicateFeedItem> = try {
        val out = api.getFeed(syndicateId = syndicateId, cursor = params.key)
        LoadResult.Page(
            data = out.posts.map { it.toDomain() },
            prevKey = null,
            nextKey = out.nextCursor?.takeIf { it.isNotBlank() },
        )
    } catch (e: CancellationException) {
        throw e
    } catch (e: HttpException) {
        LoadResult.Error(e)
    } catch (e: IOException) {
        LoadResult.Error(e)
    }

    override fun getRefreshKey(state: PagingState<String, SyndicateFeedItem>): String? = null
}
