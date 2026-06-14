package com.testlogon.android.feature.feed

import androidx.lifecycle.SavedStateHandle
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import androidx.paging.Pager
import androidx.paging.PagingConfig
import androidx.paging.PagingData
import androidx.paging.cachedIn
import androidx.paging.insertHeaderItem
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.feed.Comment
import com.testlogon.android.data.feed.CommentsRepository
import com.testlogon.android.navigation.PostDetailDest
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.flow.receiveAsFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import java.util.UUID
import javax.inject.Inject

/** AND-174 — composer state for the comment input. */
data class ComposerState(
    val text: String = "",
    val replyTo: Comment? = null,
    val sending: Boolean = false,
) {
    val canSend: Boolean get() = text.isNotBlank() && !sending
}

/** AND-174 — one-shot comments UI effects (snackbars). */
sealed interface CommentsEffect {
    data class ShowError(val message: String) : CommentsEffect
    /** Notifies the AND-100 host so it can adjust the post's displayed comment count. */
    data class CommentCountChanged(val delta: Int) : CommentsEffect
}

/**
 * AND-174 — comments presentation logic for a single post.
 *
 * The paged list is a cached Paging 3 stream; locally-originated comments (optimistic + failed) live in
 * a side [pending] StateFlow and are merged ahead of the server page via insertHeaderItem so the differ
 * stays stable. send() inserts an optimistic pending header, clears the composer, and posts; on success
 * the pending entry is removed and the list is refreshed (signalled via [refreshSignal]) so the server
 * entity lands; on failure the entry flips to failed with Retry / Discard. Replies are gated behind
 * [repliesSupported] (false by default — no backend replies endpoint).
 */
@HiltViewModel
class CommentsViewModel @Inject constructor(
    private val repository: CommentsRepository,
    savedStateHandle: SavedStateHandle,
) : ViewModel() {

    val postId: String = savedStateHandle.get<String>(PostDetailDest.ARG_POST_ID).orEmpty()

    val repliesSupported: Boolean get() = repository.repliesSupported

    private val pending = MutableStateFlow<List<Comment>>(emptyList())

    private val _composer = MutableStateFlow(ComposerState())
    val composer: StateFlow<ComposerState> = _composer.asStateFlow()

    /** Bumped to force the LazyPagingItems to refresh after a successful add/delete reconcile. */
    private val _refreshSignal = MutableStateFlow(0L)
    val refreshSignal: StateFlow<Long> = _refreshSignal.asStateFlow()

    private val _effects = Channel<CommentsEffect>(Channel.BUFFERED)
    val effects: Flow<CommentsEffect> = _effects.receiveAsFlow()

    private val basePager: Flow<PagingData<Comment>> = Pager(
        config = PagingConfig(
            pageSize = PAGE_SIZE,
            initialLoadSize = PAGE_SIZE,
            prefetchDistance = PREFETCH_DISTANCE,
            enablePlaceholders = false,
        ),
        pagingSourceFactory = { CommentsPagingSource(repository, postId) },
    ).flow.cachedIn(viewModelScope)

    /** Server page with not-yet-reconciled local comments prepended (newest at the head). */
    val comments: Flow<PagingData<Comment>> =
        combine(basePager, pending) { page, locals ->
            locals.foldRight(page) { c, acc -> acc.insertHeaderItem(item = c) }
        }

    fun onBodyChange(text: String) {
        _composer.update { it.copy(text = text) }
    }

    /** No-op when replies are unsupported (the default). */
    fun startReply(parent: Comment) {
        if (!repliesSupported) return
        _composer.update { it.copy(replyTo = parent) }
    }

    fun cancelReply() {
        _composer.update { it.copy(replyTo = null) }
    }

    fun send() {
        val current = _composer.value
        val body = current.text.trim()
        if (body.isEmpty() || current.sending) return
        val parentId = current.replyTo?.id?.takeIf { repliesSupported }
        val localKey = UUID.randomUUID().toString()
        val optimistic = Comment(
            id = localKey,
            postId = postId,
            parentId = parentId,
            authorId = "",
            body = body,
            createdAtEpochSeconds = System.currentTimeMillis() / 1000L,
            updatedAtEpochSeconds = null,
            canDelete = true,
            pending = true,
            localKey = localKey,
        )
        pending.update { listOf(optimistic) + it }
        _composer.value = ComposerState() // clear text + reply, keep sending=false (button stays usable)
        postComment(localKey, body, parentId, isReply = parentId != null)
    }

    fun retry(localKey: String) {
        val entry = pending.value.firstOrNull { it.localKey == localKey } ?: return
        pending.update { list -> list.map { if (it.localKey == localKey) it.copy(pending = true, failed = false) else it } }
        postComment(localKey, entry.body, entry.parentId, isReply = entry.parentId != null)
    }

    fun discard(localKey: String) {
        pending.update { list -> list.filterNot { it.localKey == localKey } }
    }

    fun delete(comment: Comment) {
        if (!comment.canDelete) return
        viewModelScope.launch {
            when (val result = repository.deleteComment(postId, comment.id)) {
                is ApiResult.Success -> {
                    _effects.trySend(CommentsEffect.CommentCountChanged(-1))
                    _refreshSignal.value = _refreshSignal.value + 1L
                }
                is ApiResult.Failure -> _effects.trySend(CommentsEffect.ShowError(result.error.message))
                is ApiResult.NetworkError -> _effects.trySend(CommentsEffect.ShowError(OFFLINE_MESSAGE))
            }
        }
    }

    private fun postComment(localKey: String, body: String, parentId: String?, isReply: Boolean) {
        viewModelScope.launch {
            when (val result = repository.addComment(postId, body, parentId)) {
                is ApiResult.Success -> {
                    pending.update { list -> list.filterNot { it.localKey == localKey } }
                    if (!isReply) _effects.trySend(CommentsEffect.CommentCountChanged(+1))
                    _refreshSignal.value = _refreshSignal.value + 1L
                }
                is ApiResult.Failure -> markFailed(localKey, result.error.message)
                is ApiResult.NetworkError -> markFailed(localKey, OFFLINE_MESSAGE)
            }
        }
    }

    private fun markFailed(localKey: String, message: String) {
        pending.update { list ->
            list.map { if (it.localKey == localKey) it.copy(pending = false, failed = true) else it }
        }
        _effects.trySend(CommentsEffect.ShowError(message))
    }

    private companion object {
        const val PAGE_SIZE = 20
        const val PREFETCH_DISTANCE = 5
        const val OFFLINE_MESSAGE = "You're offline. Try again."
    }
}
