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
import com.testlogon.android.data.bookmarks.FeedBookmarkRepository
import com.testlogon.android.data.feed.FeedPost
import com.testlogon.android.data.feed.FeedRefreshBus
import com.testlogon.android.data.feed.FeedRepository
import com.testlogon.android.data.feed.LikeState
import com.testlogon.android.data.feed.Poll
import com.testlogon.android.data.feed.PollRepository
import com.testlogon.android.data.feed.PollVoteResult
import com.testlogon.android.data.feed.PostActionsRepository
import com.testlogon.android.data.feed.CurrentUserRepository
import com.testlogon.android.data.feed.PostEngagementRepository
import com.testlogon.android.data.feed.applyVote
import com.testlogon.android.data.feed.reactedByMe
import com.testlogon.android.data.feed.toggledReaction
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.Job
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.flow.flatMapLatest
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.receiveAsFlow
import kotlinx.coroutines.flow.stateIn
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
    private val bookmarks: FeedBookmarkRepository,
    private val polls: PollRepository,
    private val displayNames: com.testlogon.android.data.profile.DisplayNameResolver,
    private val currentUser: CurrentUserRepository,
    private val feedRefreshBus: FeedRefreshBus,
) : ViewModel() {

    /** author id (email/user_sub) -> display name, resolved lazily for visible posts. */
    val authorNames: StateFlow<Map<String, String>> = displayNames.names

    /** ID15 - author id -> profile_photo_url, resolved alongside the name for visible posts. */
    val authorPhotos: StateFlow<Map<String, String>> = displayNames.photos

    // FD12/FD13 — the signed-in user's id, so the feed can show an Edit affordance and hide the
    // Tip action on the viewer's own posts. Resolved once; null until known (treat as 'not mine').
    private val _currentUserSub = MutableStateFlow<String?>(null)
    val currentUserSub: StateFlow<String?> = _currentUserSub.asStateFlow()

    init {
        viewModelScope.launch {
            val r = currentUser.currentUserSub()
            if (r is ApiResult.Success) _currentUserSub.value = r.data
        }
        // #18 — re-page the feed from the head whenever a post is published (#18a) or edited (#18b),
        // so the main feed is a shared source of truth that updates in place without a restart.
        viewModelScope.launch {
            feedRefreshBus.refreshes.collect { refresh() }
        }
    }

    /** Kick off (cached) resolution of an author's display name; UI reads it from [authorNames]. */
    fun resolveAuthor(authorId: String) {
        displayNames.resolve(authorId)
    }

    private val refreshTrigger = MutableStateFlow(0L)

    private val likeOverrides = MutableStateFlow<Map<String, LikeState>>(emptyMap())
    private val likeJobs = mutableMapOf<String, Job>()

    // #20 — optimistic emoji-reaction overlay (post id -> tallies), applied like the like overlay.
    private val reactionOverrides = MutableStateFlow<Map<String, List<com.testlogon.android.data.feed.ReactionTally>>>(emptyMap())
    private val reactionJobs = mutableMapOf<String, Job>()

    // AND-176 — per-post bookmark toggle serialization (last-write-wins).
    private val bookmarkJobs = mutableMapOf<String, Job>()

    // AND-179 — per-post poll vote state + in-flight guard.
    private val pollStates = MutableStateFlow<Map<String, PollCardState>>(emptyMap())
    val pollUiStates: StateFlow<Map<String, PollCardState>> = pollStates.asStateFlow()

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
        combine(pager, likeOverrides, actions.suppressed, reactionOverrides) { data, overrides, suppressed, reactions ->
            data
                .filter { it.id !in suppressed }
                .map { post ->
                    val withLike = overrides[post.id]?.let { post.applyLike(it) } ?: post
                    reactions[post.id]?.let { withLike.copy(reactions = it) } ?: withLike
                }
        }

    /** AND-176 — reactive set of saved post ids (drives the per-post bookmark icon). */
    val savedIds: StateFlow<Set<String>> =
        bookmarks.savedIds.stateIn(viewModelScope, SharingStarted.Eagerly, emptySet())

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

    // ---- #20: emoji reactions (distinct from like) ----

    fun onToggleReaction(post: FeedPost, emoji: String) {
        val before = reactionOverrides.value[post.id] ?: post.reactions
        val after = before.toggledReaction(emoji)
        val add = after.reactedByMe(emoji)
        reactionOverrides.update { it + (post.id to after) }
        reactionJobs.remove(post.id)?.cancel()
        val job = viewModelScope.launch {
            try {
                when (val r = engagement.setReaction(post.id, emoji, add)) {
                    is ApiResult.Success -> Unit
                    is ApiResult.Failure -> {
                        reactionOverrides.update { it + (post.id to before) }
                        _events.trySend(FeedEvent.ShowError(r.error.message))
                    }
                    is ApiResult.NetworkError -> {
                        reactionOverrides.update { it + (post.id to before) }
                        _events.trySend(FeedEvent.ShowError(OFFLINE_LIKE_MESSAGE))
                    }
                }
            } catch (e: CancellationException) {
                throw e // superseded by a newer tap
            }
        }
        reactionJobs[post.id] = job
        job.invokeOnCompletion { if (reactionJobs[post.id] === job) reactionJobs.remove(post.id) }
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

    // ---- AND-176: bookmark toggle ----

    /**
     * Optimistic bookmark toggle. [currentlySaved] is the icon state the user tapped from; the desired
     * end-state is its inverse. Per-post jobs are serialized (a new tap cancels the prior in-flight one)
     * so the final committed state matches the last intent (FR-7).
     */
    fun onToggleBookmark(postId: String, currentlySaved: Boolean) {
        val desired = !currentlySaved
        bookmarkJobs.remove(postId)?.cancel()
        val job = viewModelScope.launch {
            try {
                when (val r = bookmarks.setBookmarked(postId, desired)) {
                    is ApiResult.Success -> Unit // Room already reflects the desired state.
                    is ApiResult.Failure ->
                        _events.trySend(FeedEvent.BookmarkFailed(postId, desired, BOOKMARK_FAIL_MESSAGE))
                    is ApiResult.NetworkError ->
                        _events.trySend(FeedEvent.BookmarkFailed(postId, desired, BOOKMARK_FAIL_MESSAGE))
                }
            } catch (e: CancellationException) {
                throw e // superseded by a newer tap
            }
        }
        bookmarkJobs[postId] = job
        job.invokeOnCompletion { if (bookmarkJobs[postId] === job) bookmarkJobs.remove(postId) }
    }

    /** Retry a failed bookmark toggle for the same desired state. */
    fun onRetryBookmark(postId: String, desired: Boolean) {
        bookmarkJobs.remove(postId)?.cancel()
        val job = viewModelScope.launch {
            when (bookmarks.setBookmarked(postId, desired)) {
                is ApiResult.Success -> Unit
                else -> _events.trySend(FeedEvent.BookmarkFailed(postId, desired, BOOKMARK_FAIL_MESSAGE))
            }
        }
        bookmarkJobs[postId] = job
        job.invokeOnCompletion { if (bookmarkJobs[postId] === job) bookmarkJobs.remove(postId) }
    }

    // ---- AND-179: poll voting ----

    /** Seed the per-post poll state from the loaded post if not already tracked. Idempotent. */
    fun ensurePollState(post: FeedPost) {
        val poll = post.poll ?: return
        if (pollStates.value.containsKey(post.id)) return
        pollStates.update { it + (post.id to initialPollStateFor(poll)) }
    }

    fun onPollOptionSelected(postId: String, questionId: String, optionId: String) {
        val current = pollStates.value[postId] ?: return
        val poll = current.poll
        if (!poll.isInteractive) return // closed -> no-op (FR-6)
        if (current is PollCardState.Voting) return // FR-3 double-submit guard
        pollStates.update { it + (postId to PollCardState.Voting(poll, questionId, optionId)) }
        viewModelScope.launch {
            val next: PollCardState = when (val r = polls.vote(postId, questionId, optionId)) {
                is ApiResult.Success -> PollCardState.Results(poll.applyVote(r.data))
                is ApiResult.Failure -> PollCardState.Error(poll, questionId, r.error.message)
                is ApiResult.NetworkError -> PollCardState.Error(poll, questionId, OFFLINE_POLL_MESSAGE)
            }
            pollStates.update { it + (postId to next) }
        }
    }

    /** Retry a failed vote for the same (question, option). */
    fun onPollRetry(postId: String, questionId: String, optionId: String) {
        val current = pollStates.value[postId] ?: return
        pollStates.update { it + (postId to PollCardState.Idle(current.poll)) }
        onPollOptionSelected(postId, questionId, optionId)
    }

    private companion object {
        const val PAGE_SIZE = 20
        const val PREFETCH_DISTANCE = 10
        const val INITIAL_LOAD_SIZE = 20
        const val OFFLINE_LIKE_MESSAGE = "Couldn't update like. Try again."
        const val OFFLINE_HIDE_MESSAGE = "Couldn't hide post. Tap to retry."
        const val BOOKMARK_FAIL_MESSAGE = "Couldn't save post. Retry."
        const val OFFLINE_POLL_MESSAGE = "Couldn't submit vote. Tap to retry."
    }
}

/** AND-179 — per-poll UI state held by [FeedViewModel], keyed by post id. */
sealed interface PollCardState {
    val poll: Poll

    data class Idle(override val poll: Poll) : PollCardState
    data class Voting(override val poll: Poll, val questionId: String, val pendingOptionId: String) : PollCardState
    data class Results(override val poll: Poll) : PollCardState
    data class Error(override val poll: Poll, val questionId: String, val message: String) : PollCardState
}

/** Seed state: a closed poll or one already voted on every question opens read-only; else selectable. */
internal fun initialPollStateFor(poll: Poll): PollCardState =
    if (poll.closed || (poll.questions.isNotEmpty() && poll.questions.all { it.hasVoted })) {
        PollCardState.Results(poll)
    } else {
        PollCardState.Idle(poll)
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

    /** AND-176 — a bookmark toggle failed; show a Retry snackbar for the same desired state. */
    data class BookmarkFailed(val postId: String, val desired: Boolean, val message: String) : FeedEvent
}

/** Applies an optimistic / reconciled [LikeState] over a post (AND-173). */
private fun FeedPost.applyLike(state: LikeState): FeedPost =
    copy(likedByMe = state.liked, likeCount = state.likeCount)
