package com.testlogon.android.feature.feed

import androidx.lifecycle.SavedStateHandle
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.feed.FeedPost
import com.testlogon.android.data.feed.FeedRepository
import com.testlogon.android.navigation.PostDetailDest
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
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
    savedStateHandle: SavedStateHandle,
) : ViewModel() {

    val postId: String = savedStateHandle.get<String>(PostDetailDest.ARG_POST_ID).orEmpty()

    private val _uiState = MutableStateFlow<PostDetailUiState>(PostDetailUiState.Loading)
    val uiState: StateFlow<PostDetailUiState> = _uiState.asStateFlow()

    private var loading = false

    init {
        load(force = false)
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
                is ApiResult.Success -> PostDetailUiState.Content(result.data, isRefreshing = false)
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
        val ID_PATTERN = Regex("^[A-Za-z0-9_\\-]{1,64}$")
    }
}
