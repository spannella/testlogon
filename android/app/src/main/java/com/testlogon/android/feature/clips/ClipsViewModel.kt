package com.testlogon.android.feature.clips

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import androidx.paging.Pager
import androidx.paging.PagingConfig
import androidx.paging.PagingData
import androidx.paging.cachedIn
import com.testlogon.android.data.bookmarks.Bookmark
import com.testlogon.android.data.bookmarks.FeedBookmarkRepository
import com.testlogon.android.data.clips.Clip
import com.testlogon.android.data.clips.ClipsApi
import com.testlogon.android.data.clips.ClipsRepository
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.flatMapLatest
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import javax.inject.Inject

/**
 * AND-196 — local (non-paging) chrome for the clips pager: mute preference + the active page index
 * mirroring the PagerState.settledPage for the playback controller and telemetry.
 */
data class ClipsUiState(
    val muted: Boolean = false,
    val activePage: Int = 0,
)

/**
 * AND-196 — Clips vertical-pager presentation. The paged clip stream comes from a
 * [ClipsFeedPagingSource] wrapped in a cached Pager; Paging 3 owns list state (Loading/Empty/Error map
 * from LoadState in the screen). [refresh] bumps a trigger so a new PagingSource re-anchors at page 1.
 * The chrome [ui] holds the mute toggle (persisted by the screen) and the settled active page.
 *
 * P0-consumer/bookmarks: the clip bookmark action is now real. Saved video ids come from the shared
 * [FeedBookmarkRepository] ("video" content type), the icon fill is driven by [savedVideoIds], toggling
 * fires the optimistic add/remove, and [onClipsVisible] seeds initial state via /ui/bookmarks/status.
 */
@OptIn(ExperimentalCoroutinesApi::class)
@HiltViewModel
class ClipsViewModel @Inject constructor(
    private val repository: ClipsRepository,
    private val bookmarks: FeedBookmarkRepository,
) : ViewModel() {

    private val refreshTrigger = MutableStateFlow(0L)

    private val _ui = MutableStateFlow(ClipsUiState())
    val ui: StateFlow<ClipsUiState> = _ui.asStateFlow()

    /** Reactive set of saved video ids (drives the filled/outlined bookmark icon on each clip). */
    val savedVideoIds: StateFlow<Set<String>> =
        bookmarks.savedIdsFor(Bookmark.CONTENT_TYPE_VIDEO)
            .map { it }
            .stateIn(viewModelScope, SharingStarted.Eagerly, emptySet())

    val clips: Flow<PagingData<Clip>> =
        refreshTrigger
            .flatMapLatest {
                Pager(
                    config = PagingConfig(
                        pageSize = ClipsApi.FEED_PAGE_SIZE,
                        initialLoadSize = ClipsApi.FEED_PAGE_SIZE,
                        prefetchDistance = PREFETCH_DISTANCE,
                        enablePlaceholders = false,
                    ),
                    pagingSourceFactory = { ClipsFeedPagingSource(repository) },
                ).flow
            }
            .cachedIn(viewModelScope)

    fun refresh() {
        refreshTrigger.update { it + 1L }
    }

    fun setActivePage(page: Int) {
        _ui.update { it.copy(activePage = page) }
    }

    fun toggleMute() {
        _ui.update { it.copy(muted = !it.muted) }
    }

    fun setMuted(muted: Boolean) {
        _ui.update { it.copy(muted = muted) }
    }

    /** Optimistically toggle the saved-state of a clip's source video against /ui/bookmarks. */
    fun toggleBookmark(videoId: String) {
        if (videoId.isBlank()) return
        val currentlySaved = videoId in savedVideoIds.value
        viewModelScope.launch {
            bookmarks.setBookmarked(Bookmark.CONTENT_TYPE_VIDEO, videoId, !currentlySaved)
        }
    }

    /** Seed the saved-state cache for the currently visible clips (best-effort; max 25 per call). */
    fun onClipsVisible(videoIds: List<String>) {
        val ids = videoIds.filter { it.isNotBlank() }.distinct().take(STATUS_BATCH)
        if (ids.isEmpty()) return
        viewModelScope.launch {
            bookmarks.hydrate(Bookmark.CONTENT_TYPE_VIDEO, ids)
        }
    }

    companion object {
        private const val PREFETCH_DISTANCE = 2
        private const val STATUS_BATCH = 25
    }
}
