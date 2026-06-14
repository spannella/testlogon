package com.testlogon.android.feature.activity

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import androidx.paging.Pager
import androidx.paging.PagingConfig
import androidx.paging.PagingData
import androidx.paging.cachedIn
import com.testlogon.android.data.activity.ActivityEvent
import com.testlogon.android.data.activity.ActivityRepository
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.flatMapLatest
import javax.inject.Inject

/**
 * AND-095 — Activity feed presentation logic: a cached Paging 3 stream of [ActivityEvent].
 *
 * The list's own CombinedLoadStates (collected on the screen via collectAsLazyPagingItems) drive the
 * loading / empty / error / append-footer branches, so this ViewModel only owns the cached pager and
 * a refresh trigger. [refresh] re-anchors the pager at the head via flatMapLatest, and the stream is
 * cachedIn(viewModelScope) so it survives configuration changes / resubscription without re-fetching.
 */
@OptIn(ExperimentalCoroutinesApi::class)
@HiltViewModel
class ActivityViewModel @Inject constructor(
    private val repository: ActivityRepository,
) : ViewModel() {

    private val refreshTrigger = MutableStateFlow(0L)

    val items: Flow<PagingData<ActivityEvent>> =
        refreshTrigger
            .flatMapLatest {
                Pager(
                    config = PagingConfig(
                        pageSize = PAGE_SIZE,
                        prefetchDistance = PREFETCH_DISTANCE,
                        initialLoadSize = INITIAL_LOAD_SIZE,
                        enablePlaceholders = false,
                    ),
                    pagingSourceFactory = { ActivityPagingSource(repository) },
                ).flow
            }
            .cachedIn(viewModelScope)

    /** Invalidate the page feed and re-fetch from the head. */
    fun refresh() {
        refreshTrigger.value = refreshTrigger.value + 1L
    }

    private companion object {
        const val PAGE_SIZE = 20
        const val PREFETCH_DISTANCE = 10
        const val INITIAL_LOAD_SIZE = 20
    }
}
