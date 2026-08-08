package com.testlogon.android.feature.stories

import android.net.Uri
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.feed.CommentImageUploader
import com.testlogon.android.data.stories.StoriesRepository
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import javax.inject.Inject

/**
 * PAR-01 — the upload state of the single picked story image.
 *
 * IMAGE-first for v1 (video is out of scope, matching iOS). The picked [Uri] previews immediately while
 * the multipart upload runs; once [Ready] carries the platform media_url the story can be shared.
 */
sealed interface StoryMediaState {
    data object Idle : StoryMediaState
    data class Uploading(val uri: Uri) : StoryMediaState
    data class Ready(val uri: Uri, val mediaUrl: String) : StoryMediaState
    data class Failed(val uri: Uri, val message: String) : StoryMediaState
}

/** PAR-01 — create-a-story screen state (mirrors the newsfeed composer's upload/submit conventions). */
data class CreateStoryUiState(
    val media: StoryMediaState = StoryMediaState.Idle,
    val overlayText: String = "",
    val linkUrl: String = "",
    val linkLabel: String = "",
    val isSubmitting: Boolean = false,
    val errorText: String? = null,
) {
    /** The uploaded platform url, present only once the image finished uploading. */
    val mediaUrl: String? get() = (media as? StoryMediaState.Ready)?.mediaUrl

    val isUploading: Boolean get() = media is StoryMediaState.Uploading

    /** Share is enabled only when an uploaded media_url is ready and nothing is in flight. */
    val canShare: Boolean get() = mediaUrl != null && !isSubmitting && !isUploading
}

@HiltViewModel
class CreateStoryViewModel @Inject constructor(
    private val repository: StoriesRepository,
    private val imageUploader: CommentImageUploader,
) : ViewModel() {

    private val _state = MutableStateFlow(CreateStoryUiState())
    val state: StateFlow<CreateStoryUiState> = _state.asStateFlow()

    /** One-shot: flips true after a successful create so the screen can pop back. */
    private val _posted = MutableStateFlow(false)
    val posted: StateFlow<Boolean> = _posted.asStateFlow()

    fun onOverlayChange(text: String) = _state.update { it.copy(overlayText = text, errorText = null) }
    fun onLinkUrlChange(text: String) = _state.update { it.copy(linkUrl = text, errorText = null) }
    fun onLinkLabelChange(text: String) = _state.update { it.copy(linkLabel = text, errorText = null) }

    /** Clear the picked image (return to the empty picker). */
    fun onClearImage() = _state.update { it.copy(media = StoryMediaState.Idle, errorText = null) }

    /** Pick an image: preview immediately, upload it, then hold its platform url for [share]. */
    fun onImagePicked(uri: Uri?) {
        if (uri == null) return
        _state.update { it.copy(media = StoryMediaState.Uploading(uri), errorText = null) }
        viewModelScope.launch {
            when (val r = imageUploader.uploadImage(uri)) {
                is ApiResult.Success -> _state.update { it.copy(media = StoryMediaState.Ready(uri, r.data)) }
                is ApiResult.Failure -> _state.update {
                    it.copy(media = StoryMediaState.Failed(uri, r.error.message))
                }
                is ApiResult.NetworkError -> _state.update {
                    it.copy(media = StoryMediaState.Failed(uri, "Upload failed. Check your connection."))
                }
            }
        }
    }

    /** Post the story. Maps a 429 (per-day limit) to a friendly message; pops on success. */
    fun share() {
        val s = _state.value
        val url = s.mediaUrl ?: return
        if (!s.canShare) return
        _state.update { it.copy(isSubmitting = true, errorText = null) }
        viewModelScope.launch {
            val result = repository.createStory(
                mediaUrl = url,
                overlay = s.overlayText,
                linkUrl = s.linkUrl,
                linkLabel = s.linkLabel,
            )
            when (result) {
                is ApiResult.Success -> {
                    _state.update { it.copy(isSubmitting = false) }
                    _posted.value = true
                }
                is ApiResult.Failure -> {
                    val msg = if (result.error.status == HTTP_TOO_MANY_REQUESTS) {
                        RATE_LIMIT_MESSAGE
                    } else {
                        result.error.message
                    }
                    _state.update { it.copy(isSubmitting = false, errorText = msg) }
                }
                is ApiResult.NetworkError -> _state.update {
                    it.copy(isSubmitting = false, errorText = "You're offline. Try again.")
                }
            }
        }
    }

    /** Consume the [posted] one-shot after the screen has popped (prevents a re-pop on recomposition). */
    fun onPostedHandled() { _posted.value = false }

    private companion object {
        const val HTTP_TOO_MANY_REQUESTS = 429
        const val RATE_LIMIT_MESSAGE = "You've reached today's story limit. Try again tomorrow."
    }
}
