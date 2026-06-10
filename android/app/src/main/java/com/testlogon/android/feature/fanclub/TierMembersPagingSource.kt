package com.testlogon.android.feature.fanclub

import androidx.paging.PagingSource
import androidx.paging.PagingState
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.fanclub.FanClubMember
import com.testlogon.android.data.fanclub.FanClubRepository

/**
 * AND-240 — cursor-keyed Paging 3 source over [FanClubRepository.getTierMembers].
 *
 * Keys are opaque cursor strings; the roster is forward-only (prevKey always null), so [getRefreshKey]
 * returns null (refresh re-anchors at the first page). Repository failures become [LoadResult.Error];
 * CancellationException propagates because the repository re-throws it.
 */
class TierMembersPagingSource(
    private val repository: FanClubRepository,
    private val tierId: String,
) : PagingSource<String, FanClubMember>() {

    override suspend fun load(params: LoadParams<String>): LoadResult<String, FanClubMember> =
        when (val result = repository.getTierMembers(tierId, cursor = params.key, limit = params.loadSize)) {
            is ApiResult.Success -> LoadResult.Page(
                data = result.data.members,
                prevKey = null,
                nextKey = result.data.nextCursor,
            )
            is ApiResult.Failure -> LoadResult.Error(TierMembersLoadException(result.error.message))
            is ApiResult.NetworkError -> LoadResult.Error(result.cause)
        }

    override fun getRefreshKey(state: PagingState<String, FanClubMember>): String? = null
}

/** Carries a mapped, human-readable message for a non-2xx member-page load failure. */
class TierMembersLoadException(message: String) : Exception(message)
