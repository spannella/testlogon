package com.testlogon.android.feature.saved

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import androidx.paging.Pager
import androidx.paging.PagingConfig
import androidx.paging.PagingData
import androidx.paging.cachedIn
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.bookmarks.Bookmark
import com.testlogon.android.data.bookmarks.BookmarksRepository
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.receiveAsFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import javax.inject.Inject

/** Screen-level overlay state for the Saved list (optimistic removals + undo target). */
data class SavedUiState(
    /** Composite "type/id" keys hidden optimistically; filtered out of the rendered list. */
    val removedKeys: Set<String> = emptySet(),
    /** The last successfully-unsaved bookmark, available for Undo via a snackbar. */
    val undoTarget: Bookmark? = null,
)

/** One-shot effects consumed by the screen (not replayed on rotation). */
sealed interface SavedEvent {
    data class ShowError(val message: String) : SavedEvent
    data class ShowUndo(val bookmark: Bookmark) : SavedEvent
}

/**
 * AND-095 — Saved presentation logic: a cached Paging 3 stream of [Bookmark] plus an optimistic
 * unsave/undo overlay.
 *
 * Paging 3 has no in-place delete, so a visual removal is modelled as a [removedKeys] filter set
 * applied to the paged data; the screen filters against it. On unsave the key is added immediately
 * (optimistic) and the DELETE fired; on failure the key is removed (the row reappears) and a
 * ShowError effect is emitted. Undo re-creates the bookmark via POST and un-hides it. A 404 on
 * DELETE is treated by the repository as already-removed (Success), so the row stays gone with no
 * error. One-shot effects ride a Channel + receiveAsFlow.
 */
@HiltViewModel
class SavedViewModel @Inject constructor(
    private val repository: BookmarksRepository,
) : ViewModel() {

    val items: Flow<PagingData<Bookmark>> =
        Pager(
            config = PagingConfig(
                pageSize = PAGE_SIZE,
                prefetchDistance = PREFETCH_DISTANCE,
                initialLoadSize = INITIAL_LOAD_SIZE,
                enablePlaceholders = false,
            ),
            pagingSourceFactory = { repository.pagingSource() },
        ).flow.cachedIn(viewModelScope)

    private val _state = MutableStateFlow(SavedUiState())
    val state: StateFlow<SavedUiState> = _state.asStateFlow()

    private val _events = Channel<SavedEvent>(Channel.BUFFERED)
    val events: Flow<SavedEvent> = _events.receiveAsFlow()

    /** Optimistically hide the row, fire DELETE, and offer Undo on success / rollback on failure. */
    fun onUnsave(bookmark: Bookmark) {
        val key = bookmark.key
        if (key in _state.value.removedKeys) return
        _state.update { it.copy(removedKeys = it.removedKeys + key, undoTarget = bookmark) }
        viewModelScope.launch {
            when (repository.unsave(bookmark.contentType, bookmark.contentId)) {
                is ApiResult.Success -> _events.trySend(SavedEvent.ShowUndo(bookmark))
                is ApiResult.Failure, is ApiResult.NetworkError -> {
                    // Rollback: un-hide the row and clear the pending undo.
                    _state.update {
                        it.copy(removedKeys = it.removedKeys - key, undoTarget = null)
                    }
                    _events.trySend(SavedEvent.ShowError(UNSAVE_FAILED))
                }
            }
        }
    }

    /** Re-create the last-unsaved bookmark (Undo) and un-hide it; restore on failure. */
    fun onUndo() {
        val target = _state.value.undoTarget ?: return
        _state.update { it.copy(undoTarget = null) }
        viewModelScope.launch {
            when (repository.resave(target)) {
                is ApiResult.Success ->
                    _state.update { it.copy(removedKeys = it.removedKeys - target.key) }
                is ApiResult.Failure, is ApiResult.NetworkError ->
                    _events.trySend(SavedEvent.ShowError(UNDO_FAILED))
            }
        }
    }

    fun onUndoDismissed() {
        _state.update { it.copy(undoTarget = null) }
    }

    private companion object {
        const val PAGE_SIZE = 20
        const val PREFETCH_DISTANCE = 8
        const val INITIAL_LOAD_SIZE = 20
        const val UNSAVE_FAILED = "Couldn't remove this from saved — try again."
        const val UNDO_FAILED = "Couldn't restore this bookmark — try again."
    }
}
