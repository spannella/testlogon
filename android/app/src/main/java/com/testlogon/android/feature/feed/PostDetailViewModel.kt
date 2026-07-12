package com.testlogon.android.feature.feed

import androidx.lifecycle.SavedStateHandle
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.feed.FeedPost
import com.testlogon.android.data.feed.FeedRepository
import com.testlogon.android.data.feed.LikeState
import com.testlogon.android.data.feed.PostEngagementRepository
import com.testlogon.android.data.feed.reactedByMe
import com.testlogon.android.data.feed.toggledReaction
import com.testlogon.android.navigation.PostDetailDest
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Job
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.receiveAsFlow
import kotlinx.coroutines.launch
import javax.inject.Inject

/** Read-only post-detail screen state (AND-100). */
sealed interface PostDetailUiState {
    data object Loading : PostDetailUiState
    data class Content(val post: FeedPost, val isRefreshing: Boolean = false) : PostDetailUiState
    data object NotFound : PostDetailUiState
    data object Forbidden : PostDetailUiState
    data class Error(val message: String, val retryable: Boolean) : PostDetailUiState
}

/**
 * AND-100 — drives [PostDetailUiState] for the post/{postId} screen.
 *
 * Reads `postId` from [SavedStateHandle] (the route/deep-link arg). A blank or malformed id resolves
 * to [PostDetailUiState.NotFound] without a network call (path-injection guard). 404 -> NotFound,
 * 403 -> Forbidden ("subscription required"), other failures -> retryable Error; network/timeout ->
 * retryable Error. Pull-to-refresh / retry re-issue the idempotent GET.
 */
@HiltViewModel
class PostDetailViewModel @Inject constructor(
    private val repository: FeedRepository,
    private val engagement: PostEngagementRepository,
    private val displayNames: com.testlogon.android.data.profile.DisplayNameResolver,
    private val currentUser: com.testlogon.android.data.feed.CurrentUserRepository,
    savedStateHandle: SavedStateHandle,
) : ViewModel() {

    val postId: String = savedStateHandle.get<String>(PostDetailDest.ARG_POST_ID).orEmpty()

    /** #25 — true once we confirm the viewer authored the shown post (hides tipping in the comments). */
    private val _isOwnPost = MutableStateFlow(false)
    val isOwnPost: StateFlow<Boolean> = _isOwnPost.asStateFlow()

    private fun refreshOwnPost(authorId: String) {
        if (authorId.isBlank()) return
        viewModelScope.launch {
            val me = currentUser.currentUserSub()
            if (me is ApiResult.Success) _isOwnPost.value = (me.data == authorId)
        }
    }

    /** author id (email/user_sub) -> display name, resolved lazily for the shown post. */
    val authorNames: StateFlow<Map<String, String>> = displayNames.names

    /** Kick off (cached) resolution of the post author's display name; UI reads it from [authorNames]. */
    fun resolveAuthor(authorId: String) {
        displayNames.resolve(authorId)
    }

    private val _uiState = MutableStateFlow<PostDetailUiState>(PostDetailUiState.Loading)
    val uiState: StateFlow<PostDetailUiState> = _uiState.asStateFlow()

    private val _effects = Channel<PostDetailEffect>(Channel.BUFFERED)
    val effects: Flow<PostDetailEffect> = _effects.receiveAsFlow()

    private var loading = false
    private var likeJob: Job? = null

    init {
        load(force = false)
    }

    /** AND-173 — optimistic like toggle on the detail post; rollback on failure. */
    fun onLikeToggle() {
        val current = _uiState.value as? PostDetailUiState.Content ?: return
        val post = current.post
        val target = !post.likedByMe
        val before = LikeState(post.likedByMe, post.likeCount)
        val optimisticCount = (post.likeCount + if (target) 1 else -1).coerceAtLeast(0)
        updatePost(post.copy(likedByMe = target, likeCount = optimisticCount))

        likeJob?.cancel()
        likeJob = viewModelScope.launch {
            try {
                when (val r = engagement.setLiked(post.id, target, optimisticCount)) {
                    is ApiResult.Success -> updatePost(post.copy(likedByMe = r.data.liked, likeCount = r.data.likeCount))
                    is ApiResult.Failure -> rollbackLike(before, r.error.message)
                    is ApiResult.NetworkError -> rollbackLike(before, OFFLINE_LIKE)
                }
            } catch (e: CancellationException) {
                throw e
            }
        }
    }

    /**
     * #20 — optimistically toggle an emoji reaction on the detail post, then call the server. The
     * endpoints ack only, so we keep our optimistic tally; a later refetch reconciles. On failure the
     * tally rolls back.
     */
    fun onToggleReaction(emoji: String) {
        val current = _uiState.value as? PostDetailUiState.Content ?: return
        val post = current.post
        val before = post.reactions
        val after = before.toggledReaction(emoji)
        val add = after.reactedByMe(emoji)
        updatePost(post.copy(reactions = after))
        viewModelScope.launch {
            try {
                when (val r = engagement.setReaction(post.id, emoji, add)) {
                    is ApiResult.Success -> Unit
                    is ApiResult.Failure -> {
                        updatePost(post.copy(reactions = before))
                        _effects.trySend(PostDetailEffect.ShowError(r.error.message))
                    }
                    is ApiResult.NetworkError -> {
                        updatePost(post.copy(reactions = before))
                        _effects.trySend(PostDetailEffect.ShowError(OFFLINE_LIKE))
                    }
                }
            } catch (e: CancellationException) {
                throw e
            }
        }
    }

    /** AND-174 — optimistically reflect a comment count change from the embedded comments section. */
    fun onCommentCountChanged(delta: Int) {
        val current = _uiState.value as? PostDetailUiState.Content ?: return
        updatePost(current.post.copy(commentCount = (current.post.commentCount + delta).coerceAtLeast(0)))
    }

    private fun rollbackLike(before: LikeState, message: String) {
        val current = _uiState.value as? PostDetailUiState.Content ?: return
        updatePost(current.post.copy(likedByMe = before.liked, likeCount = before.likeCount))
        _effects.trySend(PostDetailEffect.ShowError(message))
    }

    private fun updatePost(post: FeedPost) {
        val current = _uiState.value as? PostDetailUiState.Content ?: return
        _uiState.value = current.copy(post = post)
    }

    fun retry() {
        if (loading) return
        load(force = true)
    }

    fun refresh() {
        val current = _uiState.value
        if (current is PostDetailUiState.Content) {
            _uiState.value = current.copy(isRefreshing = true)
        }
        load(force = true)
    }

    private fun load(force: Boolean) {
        if (!ID_PATTERN.matches(postId)) {
            _uiState.value = PostDetailUiState.NotFound
            return
        }
        loading = true
        if (_uiState.value !is PostDetailUiState.Content) {
            _uiState.value = PostDetailUiState.Loading
        }
        viewModelScope.launch {
            _uiState.value = when (val result = repository.getPost(postId)) {
                is ApiResult.Success -> {
                    refreshOwnPost(result.data.authorId)
                    PostDetailUiState.Content(result.data, isRefreshing = false)
                }
                is ApiResult.Failure -> when (result.error.status) {
                    404 -> PostDetailUiState.NotFound
                    403 -> PostDetailUiState.Forbidden
                    else -> PostDetailUiState.Error(result.error.message, retryable = result.error.status >= 500)
                }
                is ApiResult.NetworkError ->
                    PostDetailUiState.Error(OFFLINE_FALLBACK, retryable = true)
            }
            loading = false
        }
    }

    private companion object {
        const val OFFLINE_FALLBACK = "Couldn't reach the server. Try again."
        const val OFFLINE_LIKE = "Couldn't update like. Try again."
        val ID_PATTERN = Regex("^[A-Za-z0-9_\\-]{1,64}$")
    }
}

/** One-shot post-detail UI effects. */
sealed interface PostDetailEffect {
    data class ShowError(val message: String) : PostDetailEffect
}
