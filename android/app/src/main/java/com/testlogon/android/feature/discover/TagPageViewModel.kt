package com.testlogon.android.feature.discover

import java.net.URLDecoder
import androidx.lifecycle.SavedStateHandle
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import androidx.paging.Pager
import androidx.paging.PagingConfig
import androidx.paging.PagingData
import androidx.paging.cachedIn
import com.testlogon.android.data.discover.DiscoverApi
import com.testlogon.android.data.discover.TagRepository
import com.testlogon.android.data.feed.FeedPost
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.flatMapLatest
import javax.inject.Inject

/** AND-183 — header/meta state for the tag page (the list itself is driven by LoadState). */
data class TagPageUiState(
    val tag: String,
    val titleDisplay: String,
)

/**
 * AND-183 — tag-page presentation logic. The `tag` is decoded from [SavedStateHandle] (survives
 * process death and App Link entry); the paged post stream comes from a [TagPagingSource] wrapped in a
 * cached Pager. [refresh] bumps a trigger so a new PagingSource is created (re-anchors at page 1).
 */
@OptIn(ExperimentalCoroutinesApi::class)
@HiltViewModel
class TagPageViewModel @Inject constructor(
    private val repository: TagRepository,
    savedStateHandle: SavedStateHandle,
) : ViewModel() {

    val tag: String =
        URLDecoder.decode(checkNotNull(savedStateHandle.get<String>(ARG_TAG)) { "missing tag arg" }, "UTF-8")

    val uiState: TagPageUiState = TagPageUiState(tag = tag, titleDisplay = "#$tag")

    private val refreshTrigger = MutableStateFlow(0L)

    val content: Flow<PagingData<FeedPost>> =
        refreshTrigger
            .flatMapLatest {
                Pager(
                    config = PagingConfig(
                        pageSize = DiscoverApi.TAG_PAGE_SIZE,
                        initialLoadSize = DiscoverApi.TAG_PAGE_SIZE,
                        prefetchDistance = PREFETCH_DISTANCE,
                        enablePlaceholders = false,
                    ),
                    pagingSourceFactory = { TagPagingSource(repository, tag) },
                ).flow
            }
            .cachedIn(viewModelScope)

    fun refresh() {
        refreshTrigger.value = refreshTrigger.value + 1L
    }

    companion object {
        const val ARG_TAG = "tag"
        private const val PREFETCH_DISTANCE = 6
    }
}
