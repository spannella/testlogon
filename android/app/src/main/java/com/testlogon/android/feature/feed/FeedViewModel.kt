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
import com.testlogon.android.data.ads.AdClickAttributionStore
import com.testlogon.android.data.ads.AdCtaClicker
import com.testlogon.android.data.ads.CtaAction
import com.testlogon.android.data.ads.AdEvent
import com.testlogon.android.data.ads.AdTrackRepository
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
import com.testlogon.android.data.feed.applyResultsPage
import com.testlogon.android.data.feed.applyVote
import com.testlogon.android.data.feed.applyWriteIn
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
    private val adTracker: AdTrackRepository,
    private val adAttribution: AdClickAttributionStore,
    private val adCtaClicker: AdCtaClicker,
) : ViewModel() {

    /** author id (email/user_sub) -> display name, resolved lazily for visible posts. */
    val authorNames: StateFlow<Map<String, String>> = displayNames.names

    /** ID15 - author id -> profile_photo_url, resolved alongside the name for visible posts. */
    val authorPhotos: StateFlow<Map<String, String>> = displayNames.photos

    // FD12/FD13 — the signed-in user's id, so the feed can show an Edit affordance and hide the
    // Tip action on the viewer's own posts. Resolved once; null until known (treat as 'not mine').
    private val _currentUserSub = MutableStateFlow<String?>(null)
    val currentUserSub: StateFlow<String?> = _currentUserSub.asStateFlow()

    // #18 — declared BEFORE init{}: the FeedRefreshBus is a replay=1 SharedFlow, so a refresh signalled
    // before this VM subscribes (e.g. a post just published, incl. a group post) is delivered the instant
    // init{} starts collecting. refresh() touches refreshTrigger, so it MUST already be initialized here
    // or that replayed signal NPEs during construction (crashes the Feed tab on open).
    private val refreshTrigger = MutableStateFlow(0L)

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

    private val likeOverrides = MutableStateFlow<Map<String, LikeState>>(emptyMap())
    private val likeJobs = mutableMapOf<String, Job>()

    // #20 — optimistic emoji-reaction overlay (post id -> tallies), applied like the like overlay.
    private val reactionOverrides = MutableStateFlow<Map<String, List<com.testlogon.android.data.feed.ReactionTally>>>(emptyMap())

    // TIP-204 - money-reaction (tip) overlay (post id -> tip badges), applied like the reaction overlay
    // so a tip-react shows a money-reaction chip immediately (before a feed refetch).
    private val tipReactionOverrides = MutableStateFlow<Map<String, List<com.testlogon.android.data.feed.TipReactionBadge>>>(emptyMap())
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
        combine(pager, likeOverrides, actions.suppressed, reactionOverrides, tipReactionOverrides) { data, overrides, suppressed, reactions, tipReactions ->
            data
                .filter { it.id !in suppressed }
                .map { post ->
                    val withLike = overrides[post.id]?.let { post.applyLike(it) } ?: post
                    val withReactions = reactions[post.id]?.let { withLike.copy(reactions = it) } ?: withLike
                    tipReactions[post.id]?.let { withReactions.copy(tipReactions = it) } ?: withReactions
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

    /**
     * TIP-204 - record a successful post tip-REACTION so the money-reaction chip renders immediately
     * (overlay). The authoritative badge lands on the next feed refetch.
     */
    fun applyTipReactionBadge(postId: String, badge: com.testlogon.android.data.feed.TipReactionBadge) {
        tipReactionOverrides.update { it + (postId to (it[postId].orEmpty() + badge)) }
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
        pollStates.update { it + (post.id to pollStateFor(poll)) }
    }

    fun onPollOptionSelected(postId: String, questionId: String, optionId: String) {
        val current = pollStates.value[postId] ?: return
        val poll = current.poll
        if (!poll.isInteractive) return // closed -> no-op (FR-6)
        if (current is PollCardState.Voting) return // FR-3 double-submit guard
        pollStates.update { it + (postId to PollCardState.Voting(poll, questionId, optionId)) }
        viewModelScope.launch {
            val next: PollCardState = when (val r = polls.vote(postId, questionId, optionId)) {
                // Stay INTERACTIVE while the poll is open so a MULTI question keeps toggling options and a
                // single question can change its vote (allow_vote_change) — full multi-select on newsfeed.
                is ApiResult.Success -> pollStateFor(poll.applyVote(r.data))
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

    /** Submit a voter write-in (sender-enabled polls only); consolidates/appends the option + votes it. */
    fun onPollWriteIn(postId: String, questionId: String, text: String) {
        val current = pollStates.value[postId] ?: return
        val poll = current.poll
        if (!poll.isInteractive || text.isBlank()) return
        viewModelScope.launch {
            val next: PollCardState = when (val r = polls.writeIn(postId, questionId, text.trim())) {
                is ApiResult.Success ->
                    pollStateFor(poll.applyWriteIn(questionId, r.data, _currentUserSub.value))
                is ApiResult.Failure -> PollCardState.Error(poll, questionId, r.error.message)
                is ApiResult.NetworkError -> PollCardState.Error(poll, questionId, OFFLINE_POLL_MESSAGE)
            }
            pollStates.update { it + (postId to next) }
        }
    }

    /** Page the next slice of a write-in question's options (sorted by count desc) into the poll. */
    fun onPollShowMore(postId: String, questionId: String, offset: Int) {
        val current = pollStates.value[postId] ?: return
        val poll = current.poll
        viewModelScope.launch {
            when (val r = polls.pollResults(postId, questionId, offset, POLL_WRITE_IN_PAGE)) {
                is ApiResult.Success ->
                    pollStates.update { it + (postId to pollStateFor(poll.applyResultsPage(r.data))) }
                else -> Unit // best-effort refresh; the card reveals locally from the snapshot it holds
            }
        }
    }

    // ---- ADV-106: sponsored-unit impression / click tracking ----

    // Impression is fired at most once per served unit (keyed on the per-serve ad_click_id, falling back
    // to the creative id) so a scroll-away/return or a recomposition never double-counts.
    private val impressedAds = java.util.Collections.synchronizedSet(mutableSetOf<String>())

    /** Fire an impression the first time a sponsored card becomes visible. Best-effort (never throws). */
    fun onSponsoredImpression(post: FeedPost) {
        val ad = post.sponsored ?: return
        val key = ad.adClickId?.takeIf { it.isNotBlank() } ?: ad.creativeId
        if (!impressedAds.add(key)) return
        viewModelScope.launch { adTracker.track(AdEvent.IMPRESSION, ad) }
    }

    /** Fire a click when the viewer taps the sponsored card / its CTA. Best-effort (never throws). */
    fun onSponsoredClick(post: FeedPost) {
        val ad = post.sponsored ?: return
        // ADV-405: remember this serve as the session last-click so a later subscribe/unlock/checkout
        // attributes the conversion back to it (backend ad_attribution.attribute_conversion).
        adAttribution.record(ad.adClickId)
        viewModelScope.launch { adTracker.track(AdEvent.CLICK, ad) }
    }

    /**
     * ADV2-209 (F2) — a structured CTA tap on a sponsored unit. Money side via the shared [AdCtaClicker]:
     * a NON-tip CTA fires the CPC charge (funds-guarded, idempotent) + stashes the ad_click_id so a
     * resulting purchase/subscribe attributes CPA; a tip fires NO advertiser charge. Routing is the
     * screen's concern (AdCtaRouter).
     */
    fun onCtaTap(post: FeedPost, action: CtaAction) {
        val ad = post.sponsored ?: return
        adCtaClicker.onTap(viewModelScope, ad.adClickId, action)
    }

    private companion object {
        const val PAGE_SIZE = 20
        const val PREFETCH_DISTANCE = 10
        const val INITIAL_LOAD_SIZE = 20
        const val POLL_WRITE_IN_PAGE = 5
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

/**
 * State for a poll snapshot: a CLOSED poll opens read-only (Results); an OPEN poll stays interactive
 * (Idle) even after voting, so multi-select questions can keep toggling options, single questions can
 * change their vote (allow_vote_change) and voters can add write-ins. Per-option interactivity (e.g. a
 * single already-voted question with vote-change disabled) is enforced in the card + by the backend.
 */
internal fun pollStateFor(poll: Poll): PollCardState =
    if (poll.closed) PollCardState.Results(poll) else PollCardState.Idle(poll)

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
