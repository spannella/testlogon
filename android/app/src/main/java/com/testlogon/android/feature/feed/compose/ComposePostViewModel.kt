package com.testlogon.android.feature.feed.compose

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.feed.PostComposeRepository
import com.testlogon.android.data.feed.PostVisibility
import com.testlogon.android.data.videos.VideoUploadRepository
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import javax.inject.Inject

/** Compose-a-newsfeed-post screen state. */
data class ComposePostUiState(
    val body: String = "",
    val visibility: PostVisibility = PostVisibility.PUBLIC,
    val lockPriceInput: String = "",
    /** Arbitrary future publish time (epoch seconds); null = publish now. */
    val publishAtEpochSeconds: Long? = null,
    /** Uploaded media to attach: image urls (0..n) + an optional video id. */
    val imageUrls: List<String> = emptyList(),
    val videoId: String? = null,
    /** FD20 — the picked video's local content uri, used to show a real frame thumbnail + local
     *  full-screen preview while/after it uploads (independent of the server videoId). */
    val videoLocalUri: String? = null,
    /** True while a picked video is being uploaded to the VOD pipeline (FD8). */
    val uploadingVideo: Boolean = false,
    val uploadingMedia: Boolean = false,
    val submitting: Boolean = false,
    val error: String? = null,
    /** Flipped true on a successful post so the screen can pop back. */
    val posted: Boolean = false,
) {
    val canPost: Boolean
        get() = (body.isNotBlank() || imageUrls.isNotEmpty() || videoId != null) &&
            !submitting && !uploadingMedia && !uploadingVideo
}

@HiltViewModel
class ComposePostViewModel @Inject constructor(
    private val repository: PostComposeRepository,
    private val videoUploads: VideoUploadRepository,
) : ViewModel() {

    private val _state = MutableStateFlow(ComposePostUiState())
    val state: StateFlow<ComposePostUiState> = _state.asStateFlow()

    fun onBodyChange(text: String) = _state.update { it.copy(body = text, error = null) }
    fun onVisibilityChange(v: PostVisibility) = _state.update { it.copy(visibility = v) }
    fun onLockPriceChange(text: String) = _state.update { it.copy(lockPriceInput = text) }
    fun onScheduleChange(epochSeconds: Long?) = _state.update { it.copy(publishAtEpochSeconds = epochSeconds) }
    fun removeImage(url: String) = _state.update { it.copy(imageUrls = it.imageUrls - url) }
    fun removeVideo() = _state.update { it.copy(videoId = null, videoLocalUri = null) }

    /** FD8 — upload a picked video to the VOD pipeline and attach its video_id to the post. */
    fun onVideoPicked(uri: android.net.Uri?) {
        if (uri == null) return
        // FD20 — show the picked clip's real frame + play immediately; the upload runs in parallel.
        _state.update { it.copy(uploadingVideo = true, videoLocalUri = uri.toString(), error = null) }
        viewModelScope.launch {
            when (val r = videoUploads.upload(uri, title = (_state.value.body.trim().take(80)).ifBlank { "Video post" }, description = "")) {
                is ApiResult.Success -> _state.update { it.copy(uploadingVideo = false, videoId = r.data) }
                is ApiResult.Failure -> _state.update { it.copy(uploadingVideo = false, videoLocalUri = null, error = r.error.message) }
                is ApiResult.NetworkError -> _state.update { it.copy(uploadingVideo = false, videoLocalUri = null, error = "Video upload failed.") }
            }
        }
    }

    /** Upload picked images (uris) and add their urls to the post. */
    fun onImagesPicked(uris: List<android.net.Uri>) {
        if (uris.isEmpty()) return
        _state.update { it.copy(uploadingMedia = true, error = null) }
        viewModelScope.launch {
            val urls = mutableListOf<String>()
            for (u in uris) {
                when (val r = repository.uploadImage(u)) {
                    is ApiResult.Success -> urls += r.data
                    is ApiResult.Failure -> _state.update { it.copy(error = r.error.message) }
                    is ApiResult.NetworkError -> _state.update { it.copy(error = "Upload failed.") }
                }
            }
            _state.update { it.copy(uploadingMedia = false, imageUrls = it.imageUrls + urls) }
        }
    }

    fun post() {
        val s = _state.value
        if (!s.canPost) return
        _state.update { it.copy(submitting = true, error = null) }
        viewModelScope.launch {
            val cents = parseDollarsToCents(s.lockPriceInput)
            when (val r = repository.createPost(s.body.trim(), s.visibility, cents, s.publishAtEpochSeconds, s.imageUrls, s.videoId)) {
                is ApiResult.Success -> _state.update { it.copy(submitting = false, posted = true) }
                is ApiResult.Failure -> _state.update { it.copy(submitting = false, error = r.error.message) }
                is ApiResult.NetworkError -> _state.update { it.copy(submitting = false, error = "You're offline. Try again.") }
            }
        }
    }

    private fun parseDollarsToCents(input: String): Long? {
        val t = input.trim()
        if (t.isEmpty()) return null
        val d = t.toDoubleOrNull() ?: return null
        if (d <= 0.0) return null
        return Math.round(d * 100.0)
    }
}
