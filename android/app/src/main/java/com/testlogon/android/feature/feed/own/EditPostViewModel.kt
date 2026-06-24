package com.testlogon.android.feature.feed.own

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.feed.FeedRepository
import com.testlogon.android.data.feed.PostComposeRepository
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import javax.inject.Inject

/** FD1 -- edit-an-owned-post screen state. */
data class EditPostUiState(
    val loading: Boolean = true,
    val body: String = "",
    val submitting: Boolean = false,
    val error: String? = null,
    /** Flipped true once the edit is saved so the screen can pop back. */
    val saved: Boolean = false,
) {
    val canSave: Boolean get() = body.isNotBlank() && !submitting && !loading
}

/**
 * FD1 -- loads an owned post's current text ([FeedRepository.getPost]) and saves edits to it
 * ([PostComposeRepository.editPost] -> PATCH /posts/{id}). Text-only edit (the most common case); media
 * re-attachment is out of scope here (documented gap).
 */
@HiltViewModel
class EditPostViewModel @Inject constructor(
    private val feedRepository: FeedRepository,
    private val compose: PostComposeRepository,
) : ViewModel() {

    private val _state = MutableStateFlow(EditPostUiState())
    val state: StateFlow<EditPostUiState> = _state.asStateFlow()

    private var postId: String? = null

    fun load(postId: String) {
        if (this.postId == postId && !_state.value.loading) return
        this.postId = postId
        _state.update { it.copy(loading = true, error = null) }
        viewModelScope.launch {
            when (val r = feedRepository.getPost(postId)) {
                is ApiResult.Success ->
                    _state.update { it.copy(loading = false, body = r.data.body.orEmpty()) }
                is ApiResult.Failure ->
                    _state.update { it.copy(loading = false, error = r.error.message) }
                is ApiResult.NetworkError ->
                    _state.update { it.copy(loading = false, error = "You're offline. Try again.") }
            }
        }
    }

    fun onBodyChange(text: String) = _state.update { it.copy(body = text, error = null) }

    fun save() {
        val id = postId ?: return
        val s = _state.value
        if (!s.canSave) return
        _state.update { it.copy(submitting = true, error = null) }
        viewModelScope.launch {
            when (val r = compose.editPost(id, s.body)) {
                is ApiResult.Success -> _state.update { it.copy(submitting = false, saved = true) }
                is ApiResult.Failure -> _state.update { it.copy(submitting = false, error = r.error.message) }
                is ApiResult.NetworkError -> _state.update { it.copy(submitting = false, error = "You're offline. Try again.") }
            }
        }
    }
}
