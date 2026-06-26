package com.testlogon.android.feature.feed.compose

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.feed.FeedRefreshBus
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

/**
 * #2 — one picked video in the composer. [localUri] is shown immediately (real frame + local playback);
 * [videoId] is filled once the VOD upload completes; [uploading] is true while it uploads.
 */
data class PickedVideo(
    val localUri: String,
    val videoId: String? = null,
    val uploading: Boolean = true,
)

/** Compose-a-newsfeed-post screen state. */
data class ComposePostUiState(
    val body: String = "",
    val visibility: PostVisibility = PostVisibility.PUBLIC,
    val lockPriceInput: String = "",
    /** Arbitrary future publish time (epoch seconds); null = publish now. */
    val publishAtEpochSeconds: Long? = null,
    /** #2 — uploaded media to attach: image urls (0..n) + 0..n videos. Images AND videos may coexist. */
    val imageUrls: List<String> = emptyList(),
    /** #2 — the picked videos (each with its local uri + uploaded id + uploading flag). */
    val videos: List<PickedVideo> = emptyList(),
    val uploadingMedia: Boolean = false,
    val submitting: Boolean = false,
    val error: String? = null,
    /** Flipped true on a successful post so the screen can pop back. */
    val posted: Boolean = false,
) {
    /** #2 — video ids of the FULLY-uploaded videos (the ones the post can reference). */
    val uploadedVideoIds: List<String> get() = videos.mapNotNull { it.videoId }

    /** True while ANY picked video is still uploading. */
    val uploadingVideo: Boolean get() = videos.any { it.uploading }

    val canPost: Boolean
        get() = (body.isNotBlank() || imageUrls.isNotEmpty() || videos.isNotEmpty()) &&
            !submitting && !uploadingMedia && !uploadingVideo
}

@HiltViewModel
class ComposePostViewModel @Inject constructor(
    private val repository: PostComposeRepository,
    private val videoUploads: VideoUploadRepository,
    private val feedRefreshBus: FeedRefreshBus,
) : ViewModel() {

    private val _state = MutableStateFlow(ComposePostUiState())
    val state: StateFlow<ComposePostUiState> = _state.asStateFlow()

    fun onBodyChange(text: String) = _state.update { it.copy(body = text, error = null) }
    fun onVisibilityChange(v: PostVisibility) = _state.update { it.copy(visibility = v) }
    fun onLockPriceChange(text: String) = _state.update { it.copy(lockPriceInput = text) }
    fun onScheduleChange(epochSeconds: Long?) = _state.update { it.copy(publishAtEpochSeconds = epochSeconds) }
    fun removeImage(url: String) = _state.update { it.copy(imageUrls = it.imageUrls - url) }

    /** #2 — remove a picked video by its local uri (works whether or not it finished uploading). */
    fun removeVideo(localUri: String) = _state.update {
        it.copy(videos = it.videos.filterNot { v -> v.localUri == localUri })
    }

    /**
     * #2 / FD8 — pick ANOTHER video; upload it to the VOD pipeline and attach its video_id. Multiple
     * videos (and images) can be attached to one post. The local clip previews/plays immediately while
     * the upload runs in parallel.
     */
    fun onVideoPicked(uri: android.net.Uri?) {
        if (uri == null) return
        val key = uri.toString()
        // Ignore an accidental duplicate pick of the same uri.
        if (_state.value.videos.any { it.localUri == key }) return
        _state.update { it.copy(videos = it.videos + PickedVideo(localUri = key), error = null) }
        viewModelScope.launch {
            val title = _state.value.body.trim().take(80).ifBlank { "Video post" }
            when (val r = videoUploads.upload(uri, title = title, description = "")) {
                is ApiResult.Success -> _state.update { s ->
                    s.copy(videos = s.videos.map { v -> if (v.localUri == key) v.copy(videoId = r.data, uploading = false) else v })
                }
                is ApiResult.Failure -> _state.update { s ->
                    s.copy(videos = s.videos.filterNot { v -> v.localUri == key }, error = r.error.message)
                }
                is ApiResult.NetworkError -> _state.update { s ->
                    s.copy(videos = s.videos.filterNot { v -> v.localUri == key }, error = "Video upload failed.")
                }
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
            when (val r = repository.createPost(s.body.trim(), s.visibility, cents, s.publishAtEpochSeconds, s.imageUrls, s.uploadedVideoIds)) {
                is ApiResult.Success -> {
                    // #18a — make the just-published post appear in the main feed immediately.
                    feedRefreshBus.signal()
                    _state.update { it.copy(submitting = false, posted = true) }
                }
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
