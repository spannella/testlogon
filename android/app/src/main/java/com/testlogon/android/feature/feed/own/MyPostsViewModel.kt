package com.testlogon.android.feature.feed.own

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import androidx.paging.Pager
import androidx.paging.PagingConfig
import androidx.paging.PagingData
import androidx.paging.cachedIn
import androidx.paging.filter
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.feed.CurrentUserRepository
import com.testlogon.android.data.feed.FeedPost
import com.testlogon.android.data.feed.FeedRefreshBus
import com.testlogon.android.data.feed.FeedRepository
import com.testlogon.android.data.feed.PostComposeRepository
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.flow.flatMapLatest
import kotlinx.coroutines.flow.flowOf
import kotlinx.coroutines.flow.receiveAsFlow
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import javax.inject.Inject

/** FD1 — render state for the "Your posts" surface. */
data class MyPostsUiState(
    val resolving: Boolean = true,
    /** Non-null once we know the signed-in user_sub; the pager only starts then. */
    val authorId: String? = null,
    val loadError: String? = null,
)

/** One-shot effects (snackbars) for the "Your posts" screen. */
sealed interface MyPostsEffect {
    data class ShowMessage(val message: String) : MyPostsEffect
}

/**
 * FD1 — drives the "Your posts" list: resolves the signed-in user's id ([CurrentUserRepository]),
 * pages their own posts ([MyPostsPagingSource]), and performs delete (with an optimistic client-side
 * removal overlay so the row disappears immediately) via [PostComposeRepository].
 */
@OptIn(ExperimentalCoroutinesApi::class)
@HiltViewModel
class MyPostsViewModel @Inject constructor(
    private val feedRepository: FeedRepository,
    private val currentUser: CurrentUserRepository,
    private val compose: PostComposeRepository,
    private val displayNames: com.testlogon.android.data.profile.DisplayNameResolver,
    private val feedRefreshBus: FeedRefreshBus,
) : ViewModel() {

    private val _uiState = MutableStateFlow(MyPostsUiState())
    val uiState: StateFlow<MyPostsUiState> = _uiState.asStateFlow()

    private val _effects = Channel<MyPostsEffect>(Channel.BUFFERED)
    val effects: Flow<MyPostsEffect> = _effects.receiveAsFlow()

    /** Author display name (for the post header), resolved lazily + cached. */
    val authorNames: StateFlow<Map<String, String>> = displayNames.names
    fun resolveAuthor(authorId: String) = displayNames.resolve(authorId)

    private val authorIdFlow = MutableStateFlow<String?>(null)
    private val refreshTrigger = MutableStateFlow(0L)

    /** Locally deleted ids — applied as a filter so a deleted row vanishes immediately. */
    private val deletedIds = MutableStateFlow<Set<String>>(emptySet())

    val items: Flow<PagingData<FeedPost>> =
        combine(authorIdFlow, refreshTrigger) { author, _ -> author }
            .flatMapLatest { author ->
                if (author == null) {
                    flowOf(PagingData.empty())
                } else {
                    Pager(
                        config = PagingConfig(pageSize = 20, prefetchDistance = 10, initialLoadSize = 20),
                        pagingSourceFactory = { MyPostsPagingSource(feedRepository, author) },
                    ).flow
                }
            }
            .cachedIn(viewModelScope)
            .combine(deletedIds) { paging, deleted ->
                if (deleted.isEmpty()) paging else paging.filter { it.id !in deleted }
            }
            .stateIn(viewModelScope, SharingStarted.Eagerly, PagingData.empty())

    init {
        resolve()
        // #1 — re-page "Your posts" the moment the composer/edit screen signals a publish/edit landed.
        // ON_RESUME is a backstop; this guarantees a newly published VIDEO post prepends immediately.
        viewModelScope.launch {
            feedRefreshBus.refreshes.collect { refresh() }
        }
    }

    fun resolve() {
        _uiState.update { it.copy(resolving = true, loadError = null) }
        viewModelScope.launch {
            when (val r = currentUser.currentUserSub()) {
                is ApiResult.Success -> {
                    authorIdFlow.value = r.data
                    _uiState.update { it.copy(resolving = false, authorId = r.data, loadError = null) }
                }
                is ApiResult.Failure ->
                    _uiState.update { it.copy(resolving = false, loadError = r.error.message) }
                is ApiResult.NetworkError ->
                    _uiState.update { it.copy(resolving = false, loadError = "You're offline. Try again.") }
            }
        }
    }

    fun refresh() {
        deletedIds.value = emptySet()
        refreshTrigger.update { it + 1 }
    }

    /** FD1 — delete an owned post. Optimistically hides the row, then reconciles. */
    fun deletePost(postId: String) {
        // Optimistic removal.
        deletedIds.update { it + postId }
        viewModelScope.launch {
            when (val r = compose.deletePost(postId)) {
                is ApiResult.Success -> _effects.send(MyPostsEffect.ShowMessage("Post deleted"))
                is ApiResult.Failure -> {
                    deletedIds.update { it - postId } // roll back
                    _effects.send(MyPostsEffect.ShowMessage(r.error.message))
                }
                is ApiResult.NetworkError -> {
                    deletedIds.update { it - postId }
                    _effects.send(MyPostsEffect.ShowMessage("You're offline. Try again."))
                }
            }
        }
    }
}
