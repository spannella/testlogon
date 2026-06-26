package com.testlogon.android.feature.groups

import android.net.Uri
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.model.groups.GroupComment
import com.testlogon.android.data.feed.CommentImageUploader
import com.testlogon.android.feature.groups.data.GroupsRepository
import dagger.assisted.Assisted
import dagger.assisted.AssistedFactory
import dagger.assisted.AssistedInject
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch

/**
 * Batch-9 (#11) - drives the GROUP POST COMMENTS sheet for one (groupId, postId).
 *
 * Loads one page (oldest-first) of comments, supports a cursor "load more", and posts a new comment with
 * optional image (reusing the shared CommentImageUploader = POST /uploads/image, the same uploader the
 * main-feed comments use). On a successful post the new comment is appended and the host is told the new
 * total so the feed row's count bumps. There is NO poll loop.
 *
 * groupId + postId are AssistedInject params (the sheet is created per post, not a nav destination).
 */
@HiltViewModel(assistedFactory = GroupCommentsViewModel.Factory::class)
class GroupCommentsViewModel @AssistedInject constructor(
    private val repository: GroupsRepository,
    private val imageUploader: CommentImageUploader,
    @Assisted("groupId") val groupId: String,
    @Assisted("postId") val postId: String,
) : ViewModel() {

    private val _state = MutableStateFlow(GroupCommentsState())
    val state: StateFlow<GroupCommentsState> = _state.asStateFlow()

    init {
        load(reset = true)
    }

    fun retry() = load(reset = true)

    private fun load(reset: Boolean) {
        val cursor = if (reset) null else _state.value.nextCursor
        if (!reset && cursor == null) return
        _state.update { it.copy(loading = true, error = null) }
        viewModelScope.launch {
            when (val r = repository.listComments(groupId, postId, cursor = cursor)) {
                is ApiResult.Success -> _state.update {
                    val merged = if (reset) r.data.comments else it.comments + r.data.comments
                    it.copy(
                        comments = merged,
                        nextCursor = r.data.nextCursor,
                        loading = false,
                        loaded = true,
                        error = null,
                    )
                }
                is ApiResult.Failure -> _state.update { it.copy(loading = false, error = r.error.message) }
                is ApiResult.NetworkError -> _state.update { it.copy(loading = false, error = OFFLINE) }
            }
        }
    }

    fun loadMore() = load(reset = false)

    fun onDraftChange(value: String) = _state.update { it.copy(draft = value, error = null) }

    fun stageImage(uri: Uri) {
        _state.update { it.copy(uploadingImage = true, error = null) }
        viewModelScope.launch {
            when (val r = imageUploader.uploadImage(uri)) {
                is ApiResult.Success -> _state.update { it.copy(stagedImageUrl = r.data, uploadingImage = false) }
                is ApiResult.Failure -> _state.update { it.copy(uploadingImage = false, error = r.error.message) }
                is ApiResult.NetworkError -> _state.update { it.copy(uploadingImage = false, error = OFFLINE) }
            }
        }
    }

    fun clearStagedImage() = _state.update { it.copy(stagedImageUrl = null) }

    fun submit(onPosted: (Int) -> Unit) {
        val s = _state.value
        val text = s.draft.trim()
        if ((text.isEmpty() && s.stagedImageUrl == null) || s.sending) return
        _state.update { it.copy(sending = true, error = null) }
        viewModelScope.launch {
            when (val r = repository.addComment(groupId, postId, text = text.ifEmpty { null }, imageUrl = s.stagedImageUrl)) {
                is ApiResult.Success -> {
                    _state.update {
                        it.copy(
                            comments = it.comments + r.data,
                            draft = "",
                            stagedImageUrl = null,
                            sending = false,
                            error = null,
                        )
                    }
                    onPosted(_state.value.comments.size)
                }
                is ApiResult.Failure -> _state.update { it.copy(sending = false, error = r.error.message) }
                is ApiResult.NetworkError -> _state.update { it.copy(sending = false, error = OFFLINE) }
            }
        }
    }

    fun delete(comment: GroupComment, onChanged: (Int) -> Unit) {
        viewModelScope.launch {
            when (repository.deleteComment(groupId, postId, comment.commentId)) {
                is ApiResult.Success -> {
                    _state.update { it.copy(comments = it.comments.filterNot { c -> c.commentId == comment.commentId }) }
                    onChanged(_state.value.comments.size)
                }
                else -> _state.update { it.copy(error = OFFLINE) }
            }
        }
    }

    @AssistedFactory
    interface Factory {
        fun create(
            @Assisted("groupId") groupId: String,
            @Assisted("postId") postId: String,
        ): GroupCommentsViewModel
    }

    companion object {
        private const val OFFLINE = "Couldn't reach the server. Please try again."
    }
}

/** Batch-9 (#11) - render-ready state for the group post comments sheet. */
data class GroupCommentsState(
    val comments: List<GroupComment> = emptyList(),
    val nextCursor: String? = null,
    val loading: Boolean = false,
    val loaded: Boolean = false,
    val sending: Boolean = false,
    val uploadingImage: Boolean = false,
    val draft: String = "",
    val stagedImageUrl: String? = null,
    val error: String? = null,
)
