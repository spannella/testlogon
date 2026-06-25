package com.testlogon.android.feature.groups.data

import androidx.paging.PagingSource
import androidx.paging.PagingState
import com.testlogon.android.core.model.groups.GroupFeedPost
import com.testlogon.android.core.network.groups.GroupsApi
import kotlinx.coroutines.CancellationException
import retrofit2.HttpException
import java.io.IOException

/**
 * Batch-8 (#11) - cursor-keyed Paging 3 source over the [GroupsApi] group-feed endpoint. Network-only,
 * forward-only (prevKey null); a null/blank cursor terminates pagination. The DTO is mapped to the domain
 * before use. HttpException/IOException -> LoadResult.Error; CancellationException re-thrown. Mirrors the
 * AND-356 SyndicateFeedPagingSource.
 */
class GroupFeedPagingSource(
    private val api: GroupsApi,
    private val groupId: String,
) : PagingSource<String, GroupFeedPost>() {

    override suspend fun load(params: LoadParams<String>): LoadResult<String, GroupFeedPost> = try {
        val out = api.getGroupFeed(groupId = groupId, cursor = params.key, limit = params.loadSize)
        LoadResult.Page(
            data = out.posts.map { it.toDomain() },
            prevKey = null,
            nextKey = out.cursor?.takeIf { it.isNotBlank() && (out.hasMore ?: false) },
        )
    } catch (e: CancellationException) {
        throw e
    } catch (e: HttpException) {
        LoadResult.Error(e)
    } catch (e: IOException) {
        LoadResult.Error(e)
    }

    override fun getRefreshKey(state: PagingState<String, GroupFeedPost>): String? = null
}
