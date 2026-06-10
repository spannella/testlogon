package com.testlogon.android.feature.videos

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import androidx.paging.Pager
import androidx.paging.PagingConfig
import androidx.paging.PagingData
import androidx.paging.cachedIn
import com.testlogon.android.data.videos.VideoSummary
import com.testlogon.android.data.videos.VideosApi
import com.testlogon.android.data.videos.VideosRepository
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.flatMapLatest
import javax.inject.Inject

/**
 * AND-189 — Videos library presentation logic. The paged video stream comes from a
 * [VideosPagingSource] wrapped in a cached Pager; Paging 3 owns list state (Loading/Empty/Error map
 * from LoadState in the screen). [refresh] bumps a trigger so a new PagingSource re-anchors at page 1.
 */
@OptIn(ExperimentalCoroutinesApi::class)
@HiltViewModel
class VideosViewModel @Inject constructor(
    private val repository: VideosRepository,
) : ViewModel() {

    private val refreshTrigger = MutableStateFlow(0L)

    val videos: Flow<PagingData<VideoSummary>> =
        refreshTrigger
            .flatMapLatest {
                Pager(
                    config = PagingConfig(
                        pageSize = VideosApi.LIBRARY_PAGE_SIZE,
                        initialLoadSize = VideosApi.LIBRARY_PAGE_SIZE,
                        prefetchDistance = PREFETCH_DISTANCE,
                        enablePlaceholders = false,
                    ),
                    pagingSourceFactory = { VideosPagingSource(repository) },
                ).flow
            }
            .cachedIn(viewModelScope)

    fun refresh() {
        refreshTrigger.value = refreshTrigger.value + 1L
    }

    companion object {
        private const val PREFETCH_DISTANCE = 8
    }
}
