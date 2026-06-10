package com.testlogon.android.feature.feed

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import androidx.paging.Pager
import androidx.paging.PagingConfig
import androidx.paging.PagingData
import androidx.paging.cachedIn
import androidx.paging.filter
import androidx.paging.map
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.feed.FeedPost
import com.testlogon.android.data.feed.FeedRepository
import com.testlogon.android.data.feed.LikeState
import com.testlogon.android.data.feed.PostActionsRepository
import com.testlogon.android.data.feed.PostEngagementRepository
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.Job
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.flow.flatMapLatest
import kotlinx.coroutines.flow.receiveAsFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import javax.inject.Inject

/**
 * AND-102 / AND-173 / AND-175 — Feed presentation logic: a cached Paging 3 stream of [FeedPost] with
 * an optimistic like overlay and client-side hide/not-interested suppression.
 *
 * The pager flow is immutable + cachedIn(viewModelScope); two side stores are combined onto it without
 * re-fetching:
 *  - [likeOverrides] (post id -> [LikeState]) — optimistic like toggle (AND-173). Applied via map; a
 *    tap supersedes any in-flight request for the same post (last-write-wins), and a failed mutation
 *    rolls the override back to the pre-tap state + emits a ShowError effect.
 *  - [PostActionsRepository.suppressed] — durable hidden/not-interested ids (AND-175). Applied via
 *    filter so suppressed posts drop out immediately and stay out across refresh/pagination.
 */
@OptIn(ExperimentalCoroutinesApi::class)
@HiltViewModel
class FeedViewModel @Inject constructor(
    private val repository: FeedRepository,
    private val engagement: PostEngagementRepository,
    private val actions: PostActionsRepository,
) : ViewModel() {

    private val refreshTrigger = MutableStateFlow(0L)

    private val likeOverrides = MutableStateFlow<Map<String, LikeState>>(emptyMap())
    private val likeJobs = mutableMapOf<String, Job>()

    private val pager: Flow<PagingData<FeedPost>> =
        refreshTrigger
            .flatMapLatest {
                Pager(
                    config = PagingConfig(
                        pageSize = PAGE_SIZE,
                        prefetchDistance = PREFETCH_DISTANCE,
                        initialLoadSize = INITIAL_LOAD_SIZE,
                        enablePlaceholders = false,
                    ),
                    pagingSourceFactory = { FeedPagingSource(repository) },
                ).flow
            }
            .cachedIn(viewModelScope)

    val items: Flow<PagingData<FeedPost>> =
        combine(pager, likeOverrides, actions.suppressed) { data, overrides, suppressed ->
            data
                .filter { it.id !in suppressed }
                .map { post -> overrides[post.id]?.let { post.applyLike(it) } ?: post }
        }

    private val _events = Channel<FeedEvent>(Channel.BUFFERED)

    /** One-shot UI effects (snackbars, the deferred unlock CTA hand-off). */
    val events: Flow<FeedEvent> = _events.receiveAsFlow()

    /** Invalidate the feed and re-fetch from the head. */
    fun refresh() {
        refreshTrigger.value = refreshTrigger.value + 1L
    }

    fun onUnlockClick(postId: String) {
        _events.trySend(FeedEvent.UnlockRequested(postId))
    }

    // ---- AND-173: like / unlike ----

    fun onLikeToggle(post: FeedPost) {
        val target = !post.likedByMe
        val before = LikeState(post.likedByMe, post.likeCount)
        val optimistic = LikeState(
            liked = target,
            likeCount = (post.likeCount + if (target) 1 else -1).coerceAtLeast(0),
        )
        likeOverrides.update { it + (post.id to optimistic) }

        likeJobs.remove(post.id)?.cancel() // supersede in-flight request for this post
        val job = viewModelScope.launch {
            try {
                when (val r = engagement.setLiked(post.id, target, optimistic.likeCount)) {
                    is ApiResult.Success -> likeOverrides.update { it + (post.id to r.data) }
                    is ApiResult.Failure -> rollbackLike(post.id, before, r.error.message)
                    is ApiResult.NetworkError -> rollbackLike(post.id, before, OFFLINE_LIKE_MESSAGE)
                }
            } catch (e: CancellationException) {
                throw e // superseded by a newer tap; no rollback, no error
            }
        }
        likeJobs[post.id] = job
        // Remove only if still the current job (a newer tap may have replaced it before completion).
        job.invokeOnCompletion { if (likeJobs[post.id] === job) likeJobs.remove(post.id) }
    }

    private fun rollbackLike(postId: String, before: LikeState, message: String) {
        likeOverrides.update { it + (postId to before) }
        _events.trySend(FeedEvent.ShowError(message))
    }

    // ---- AND-175: hide / not-interested ----

    fun onHide(postId: String, index: Int) = suppress(FeedAction.Hide(postId, index))

    fun onNotInterested(postId: String, index: Int) =
        suppress(FeedAction.NotInterested(postId, index))

    private fun suppress(action: FeedAction) {
        viewModelScope.launch {
            val result = when (action) {
                is FeedAction.Hide -> actions.hide(action.postId)
                is FeedAction.NotInterested -> actions.notInterested(action.postId)
            }
            when (result) {
                is ApiResult.Success ->
                    _events.trySend(FeedEvent.Suppressed(action))
                is ApiResult.Failure ->
                    _events.trySend(FeedEvent.SuppressFailed(action, result.error.message))
                is ApiResult.NetworkError ->
                    _events.trySend(FeedEvent.SuppressFailed(action, OFFLINE_HIDE_MESSAGE))
            }
        }
    }

    /** Undo a hide/not-interested: restore the post (POST /feed/unhide). */
    fun onUndo(action: FeedAction) {
        viewModelScope.launch {
            when (val r = actions.unhide(action.postId)) {
                is ApiResult.Success -> Unit // suppression row already removed -> post returns via combine
                is ApiResult.Failure -> _events.trySend(FeedEvent.ShowError(r.error.message))
                is ApiResult.NetworkError -> _events.trySend(FeedEvent.ShowError(OFFLINE_HIDE_MESSAGE))
            }
        }
    }

    /** Retry a failed hide/not-interested. */
    fun onRetry(action: FeedAction) = suppress(action)

    private companion object {
        const val PAGE_SIZE = 20
        const val PREFETCH_DISTANCE = 10
        const val INITIAL_LOAD_SIZE = 20
        const val OFFLINE_LIKE_MESSAGE = "Couldn't update like. Try again."
        const val OFFLINE_HIDE_MESSAGE = "Couldn't hide post. Tap to retry."
    }
}

/** A hide / not-interested action carrying the post id and its captured feed index (for rollback). */
sealed interface FeedAction {
    val postId: String
    val index: Int

    data class Hide(override val postId: String, override val index: Int) : FeedAction
    data class NotInterested(override val postId: String, override val index: Int) : FeedAction
}

/** One-shot feed UI effects. */
sealed interface FeedEvent {
    /** The viewer tapped a locked post's CTA; the unlock transaction is deferred to E24. */
    data class UnlockRequested(val postId: String) : FeedEvent

    /** Generic transient error snackbar (e.g. like rollback). */
    data class ShowError(val message: String) : FeedEvent

    /** A post was hidden/not-interested; show an Undo snackbar. */
    data class Suppressed(val action: FeedAction) : FeedEvent

    /** A hide/not-interested failed; show a Retry snackbar. */
    data class SuppressFailed(val action: FeedAction, val message: String) : FeedEvent
}

/** Applies an optimistic / reconciled [LikeState] over a post (AND-173). */
private fun FeedPost.applyLike(state: LikeState): FeedPost =
    copy(likedByMe = state.liked, likeCount = state.likeCount)
