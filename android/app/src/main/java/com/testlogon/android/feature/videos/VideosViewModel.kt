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
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
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

    // #5 — optimistic "just uploaded" placeholders. A freshly uploaded video may still be PENDING
    // server-side (probing/encoding) when the user returns to the gallery; show it right away as a
    // processing tile so the upload visibly "landed", then let the paged list (which auto-polls while
    // anything is processing) take over. A placeholder is dropped once the real row with the same id
    // shows up in the page (see [reconcilePending]).
    private val _pending = MutableStateFlow<List<VideoSummary>>(emptyList())
    val pending: StateFlow<List<VideoSummary>> = _pending.asStateFlow()

    /** Records a just-uploaded video as a pending tile and refreshes the page to pull it in. */
    fun onUploaded(videoId: String, title: String) {
        if (videoId.isBlank()) { refresh(); return }
        if (_pending.value.none { it.id == videoId }) {
            _pending.value = listOf(
                VideoSummary(
                    id = videoId,
                    title = title.ifBlank { "Uploading…" },
                    thumbnailUrl = null,
                    durationSec = null,
                    status = "probing",
                ),
            ) + _pending.value
        }
        refresh()
    }

    /** Drops placeholders whose real row has now arrived in the loaded page (matched by id). */
    fun reconcilePending(loadedIds: Set<String>) {
        if (_pending.value.isEmpty()) return
        val remaining = _pending.value.filter { it.id !in loadedIds }
        if (remaining.size != _pending.value.size) _pending.value = remaining
    }

    fun refresh() {
        refreshTrigger.value = refreshTrigger.value + 1L
    }

    companion object {
        private const val PREFETCH_DISTANCE = 8
    }
}
