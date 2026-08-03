package com.testlogon.android.feature.feed.scheduled

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.feed.ScheduledPost
import com.testlogon.android.data.feed.ScheduledPostsRepository
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

/** PAR-13 — render state for the scheduled-posts management screen. */
data class ScheduledPostsUiState(
    val loading: Boolean = true,
    val posts: List<ScheduledPost> = emptyList(),
    val loadError: String? = null,
    val nextCursor: String? = null,
    val loadingMore: Boolean = false,
    /** Post ids with an in-flight cancel (row shows a spinner / disabled). */
    val cancelling: Set<String> = emptySet(),
) {
    val isEmpty: Boolean get() = !loading && loadError == null && posts.isEmpty()
    val canLoadMore: Boolean get() = nextCursor != null && !loadingMore
}

/** PAR-13 — one-shot effects (snackbars) for the scheduled-posts screen. */
sealed interface ScheduledPostsEffect {
    data class ShowMessage(val message: String) : ScheduledPostsEffect
}

/**
 * PAR-13 — drives the scheduled-posts list: loads the caller's pending scheduled posts (GET
 * /posts/scheduled), pages via the opaque cursor, and cancels a scheduled post (POST
 * /posts/{id}/cancel) with an optimistic row removal that rolls back on failure.
 */
@HiltViewModel
class ScheduledPostsViewModel @Inject constructor(
    private val repository: ScheduledPostsRepository,
) : ViewModel() {

    private val _uiState = MutableStateFlow(ScheduledPostsUiState())
    val uiState: StateFlow<ScheduledPostsUiState> = _uiState.asStateFlow()

    private val _effects = Channel<ScheduledPostsEffect>(Channel.BUFFERED)
    val effects: Flow<ScheduledPostsEffect> = _effects.receiveAsFlow()

    init {
        load()
    }

    /** Fresh load (also used for retry + pull-to-refresh). */
    fun load() {
        _uiState.update { it.copy(loading = true, loadError = null) }
        viewModelScope.launch {
            when (val r = repository.getScheduledPosts(cursor = null)) {
                is ApiResult.Success -> _uiState.update {
                    it.copy(
                        loading = false,
                        posts = r.data.items,
                        nextCursor = r.data.nextCursor,
                        loadError = null,
                    )
                }
                is ApiResult.Failure -> _uiState.update {
                    it.copy(loading = false, loadError = r.error.message)
                }
                is ApiResult.NetworkError -> _uiState.update {
                    it.copy(loading = false, loadError = OFFLINE_MESSAGE)
                }
            }
        }
    }

    /** Append the next cursor page, if any. */
    fun loadMore() {
        val cursor = _uiState.value.nextCursor ?: return
        if (_uiState.value.loadingMore) return
        _uiState.update { it.copy(loadingMore = true) }
        viewModelScope.launch {
            when (val r = repository.getScheduledPosts(cursor = cursor)) {
                is ApiResult.Success -> _uiState.update {
                    it.copy(
                        loadingMore = false,
                        posts = it.posts + r.data.items,
                        nextCursor = r.data.nextCursor,
                    )
                }
                is ApiResult.Failure -> {
                    _uiState.update { it.copy(loadingMore = false) }
                    _effects.send(ScheduledPostsEffect.ShowMessage(r.error.message))
                }
                is ApiResult.NetworkError -> {
                    _uiState.update { it.copy(loadingMore = false) }
                    _effects.send(ScheduledPostsEffect.ShowMessage(OFFLINE_MESSAGE))
                }
            }
        }
    }

    /**
     * PAR-13 — cancel a scheduled post. Optimistically removes the row + marks it cancelling; on failure
     * the row is restored (rollback) and a message is surfaced.
     */
    fun cancel(postId: String) {
        val current = _uiState.value.posts
        val removed = current.firstOrNull { it.postId == postId } ?: return
        val index = current.indexOf(removed)
        // Optimistic remove.
        _uiState.update {
            it.copy(
                posts = it.posts.filterNot { p -> p.postId == postId },
                cancelling = it.cancelling + postId,
            )
        }
        viewModelScope.launch {
            when (val r = repository.cancelScheduledPost(postId)) {
                is ApiResult.Success -> {
                    _uiState.update { it.copy(cancelling = it.cancelling - postId) }
                }
                is ApiResult.Failure -> {
                    rollback(removed, index, postId)
                    _effects.send(ScheduledPostsEffect.ShowMessage(r.error.message))
                }
                is ApiResult.NetworkError -> {
                    rollback(removed, index, postId)
                    _effects.send(ScheduledPostsEffect.ShowMessage(OFFLINE_MESSAGE))
                }
            }
        }
    }

    private fun rollback(post: ScheduledPost, index: Int, postId: String) {
        _uiState.update { s ->
            val restored = s.posts.toMutableList()
            val at = index.coerceIn(0, restored.size)
            restored.add(at, post)
            s.copy(posts = restored, cancelling = s.cancelling - postId)
        }
    }

    private companion object {
        const val OFFLINE_MESSAGE = "You're offline. Try again."
    }
}
