package com.testlogon.android.feature.fanclub

import androidx.lifecycle.SavedStateHandle
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import androidx.paging.Pager
import androidx.paging.PagingConfig
import androidx.paging.PagingData
import androidx.paging.cachedIn
import com.testlogon.android.data.fanclub.FanClubMember
import com.testlogon.android.data.fanclub.FanClubRepository
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.flatMapLatest
import javax.inject.Inject

/** AND-240 — header/aux state (the list body's load states come from LazyPagingItems). */
data class TierMembersHeaderState(
    val tierName: String? = null,
    val totalCount: Int? = null,
)

/**
 * AND-240 — tier members presentation logic: a cached Paging 3 stream of [FanClubMember].
 *
 * The list's CombinedLoadStates (collected on the screen) drive loading/empty/error/append branches, so
 * this ViewModel owns the cached pager + a refresh trigger + the header [StateFlow]. [refresh] re-anchors
 * via flatMapLatest; the stream is cachedIn(viewModelScope) to survive config changes. The total count is
 * passed in via the route (sourced from the verified TierOut.member_count) rather than re-fetched.
 */
@OptIn(ExperimentalCoroutinesApi::class)
@HiltViewModel
class TierMembersViewModel @Inject constructor(
    savedStateHandle: SavedStateHandle,
    private val repository: FanClubRepository,
) : ViewModel() {

    private val tierId: String = checkNotNull(savedStateHandle[ARG_TIER_ID]) {
        "TierMembersViewModel requires a '$ARG_TIER_ID' nav argument"
    }

    private val refreshTrigger = MutableStateFlow(0L)

    val members: Flow<PagingData<FanClubMember>> =
        refreshTrigger
            .flatMapLatest {
                Pager(
                    config = PagingConfig(
                        pageSize = PAGE_SIZE,
                        prefetchDistance = PREFETCH_DISTANCE,
                        initialLoadSize = PAGE_SIZE,
                        enablePlaceholders = false,
                    ),
                    pagingSourceFactory = { TierMembersPagingSource(repository, tierId) },
                ).flow
            }
            .cachedIn(viewModelScope)

    private val _header = MutableStateFlow(
        TierMembersHeaderState(
            tierName = savedStateHandle.get<String?>(ARG_TIER_NAME)?.takeIf { it.isNotBlank() },
            totalCount = savedStateHandle.get<Int?>(ARG_MEMBER_COUNT)?.takeIf { it >= 0 },
        ),
    )
    val header: StateFlow<TierMembersHeaderState> = _header.asStateFlow()

    /** Invalidate the roster and re-fetch from the first page. */
    fun refresh() {
        refreshTrigger.value = refreshTrigger.value + 1L
    }

    companion object {
        const val ARG_TIER_ID = "tierId"
        const val ARG_TIER_NAME = "tierName"
        const val ARG_MEMBER_COUNT = "memberCount"

        // pageSize 50 matches the server's documented `limit` default (max 200).
        private const val PAGE_SIZE = 50
        private const val PREFETCH_DISTANCE = 10
    }
}
