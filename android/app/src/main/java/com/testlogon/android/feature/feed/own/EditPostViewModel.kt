package com.testlogon.android.feature.feed.own

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
 * #1 / #2 — one video attached in the editor. An EXISTING (already-published) video has [videoId] set and
 * a [playbackUrl] (so it plays from the server); a JUST-PICKED replacement/addition has [localUri] set and
 * [uploading] true until its VOD upload completes and fills [videoId]. The editor previews [localUri]
 * first (so a fresh pick shows immediately — fixes #1), falling back to [playbackUrl] for existing ones.
 */
data class EditVideo(
    val videoId: String? = null,
    val playbackUrl: String? = null,
    val thumbnailUrl: String? = null,
    val localUri: String? = null,
    val uploading: Boolean = false,
)

/** FD1 / FD-EDIT — edit-an-owned-post screen state (text + photos + videos + audience + paid-lock). */
data class EditPostUiState(
    val loading: Boolean = true,
    val body: String = "",
    /** Edit audience — only PUBLIC / FOLLOWERS are valid for an in-place edit (B-POST contract). */
    val visibility: PostVisibility = PostVisibility.FOLLOWERS,
    /** Currently-attached photo urls (already-uploaded). Empty REMOVES all photos on save. */
    val imageUrls: List<String> = emptyList(),
    /** #2 — the currently-attached videos (existing + newly picked). Images AND videos may coexist. */
    val videos: List<EditVideo> = emptyList(),
    /** #1/#2 — true once the user added/replaced/removed any video this session (so save sends video_ids). */
    val videoChanged: Boolean = false,
    /** Unlock price in dollars as typed; blank = the post is free/unlocked on save. */
    val lockPriceInput: String = "",
    val uploadingMedia: Boolean = false,
    val submitting: Boolean = false,
    val error: String? = null,
    /** Flipped true once the edit is saved so the screen can pop back. */
    val saved: Boolean = false,
) {
    /** True while ANY attached video is still uploading. */
    val uploadingVideo: Boolean get() = videos.any { it.uploading }

    /** #2 — the ids of fully-resolved attached videos, in order, for the PATCH. */
    val attachedVideoIds: List<String> get() = videos.mapNotNull { it.videoId }

    val canSave: Boolean
        get() = (body.isNotBlank() || imageUrls.isNotEmpty() || videos.isNotEmpty()) &&
            !submitting && !loading && !uploadingMedia && !uploadingVideo
}

/**
 * FD1 / FD-EDIT — loads an owned post's current editable fields (un-redacted owner GET via
 * [PostComposeRepository.getEditablePost]) and saves edits to the body, photos, audience (visibility)
 * and paid-lock ([PostComposeRepository.editPost] -> PATCH /posts/{id}). Reuses the compose-screen image
 * picker + visibility/lock controls.
 */
@HiltViewModel
class EditPostViewModel @Inject constructor(
    private val compose: PostComposeRepository,
    private val feedRefreshBus: FeedRefreshBus,
    private val videoUploads: VideoUploadRepository,
) : ViewModel() {

    private val _state = MutableStateFlow(EditPostUiState())
    val state: StateFlow<EditPostUiState> = _state.asStateFlow()

    private var postId: String? = null

    fun load(postId: String) {
        if (this.postId == postId && !_state.value.loading) return
        this.postId = postId
        _state.update { it.copy(loading = true, error = null) }
        viewModelScope.launch {
            when (val r = compose.getEditablePost(postId)) {
                is ApiResult.Success -> {
                    val dto = r.data
                    val priceInput = dto.unlockPriceCents
                        ?.takeIf { dto.locked && it > 0 }
                        ?.let { centsToDollars(it) }
                        .orEmpty()
                    // #2 — merge the legacy single `video` with the full `videos[]` array; de-dup by id.
                    val existingVideos = buildList {
                        dto.video?.let { add(it) }
                        dto.videos.orEmpty().forEach { add(it) }
                    }.distinctBy { it.videoId }.map { v ->
                        EditVideo(
                            videoId = v.videoId,
                            playbackUrl = v.hlsManifestUrl?.let { base ->
                                val tok = v.playbackToken?.takeIf { t -> t.isNotBlank() }
                                if (tok == null) base
                                else base + (if (base.contains('?')) "&" else "?") + "token=" + tok
                            },
                            thumbnailUrl = v.thumbnailUrl,
                        )
                    }
                    _state.update {
                        it.copy(
                            loading = false,
                            body = (dto.bodyPlain ?: dto.body).orEmpty(),
                            visibility = visibilityFromWire(dto.visibility),
                            imageUrls = dto.imageUrls.orEmpty(),
                            lockPriceInput = priceInput,
                            videos = existingVideos,
                            videoChanged = false,
                        )
                    }
                }
                is ApiResult.Failure ->
                    _state.update { it.copy(loading = false, error = r.error.message) }
                is ApiResult.NetworkError ->
                    _state.update { it.copy(loading = false, error = "You're offline. Try again.") }
            }
        }
    }

    fun onBodyChange(text: String) = _state.update { it.copy(body = text, error = null) }
    fun onVisibilityChange(v: PostVisibility) = _state.update { it.copy(visibility = v) }
    fun onLockPriceChange(text: String) = _state.update { it.copy(lockPriceInput = text, error = null) }
    fun removeImage(url: String) = _state.update { it.copy(imageUrls = it.imageUrls - url) }

    /** #2 — remove one attached video (existing or newly-picked) by its stable key. */
    fun removeVideo(key: String) = _state.update {
        it.copy(
            videos = it.videos.filterNot { v -> (v.localUri ?: v.videoId) == key },
            videoChanged = true,
        )
    }

    /**
     * #1 / #2 — pick ANOTHER video; upload it to the VOD pipeline and attach its video_id. Multiple videos
     * (and images) can coexist. The picked clip is added as a LOCAL preview immediately (so it shows +
     * plays right away — fixes #1's "no preview after pick"), then its id fills in once the upload finishes.
     */
    fun onVideoPicked(uri: android.net.Uri?) {
        if (uri == null) return
        val key = uri.toString()
        if (_state.value.videos.any { it.localUri == key }) return
        _state.update {
            it.copy(videos = it.videos + EditVideo(localUri = key, uploading = true), videoChanged = true, error = null)
        }
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

    /** Upload picked images and append their urls (reuses the compose upload path). */
    fun onImagesPicked(uris: List<android.net.Uri>) {
        if (uris.isEmpty()) return
        _state.update { it.copy(uploadingMedia = true, error = null) }
        viewModelScope.launch {
            val urls = mutableListOf<String>()
            for (u in uris) {
                when (val r = compose.uploadImage(u)) {
                    is ApiResult.Success -> urls += r.data
                    is ApiResult.Failure -> _state.update { it.copy(error = r.error.message) }
                    is ApiResult.NetworkError -> _state.update { it.copy(error = "Upload failed.") }
                }
            }
            _state.update { it.copy(uploadingMedia = false, imageUrls = it.imageUrls + urls) }
        }
    }

    fun save() {
        val id = postId ?: return
        val s = _state.value
        if (!s.canSave) return
        _state.update { it.copy(submitting = true, error = null) }
        viewModelScope.launch {
            val cents = parseDollarsToCents(s.lockPriceInput)
            val r = compose.editPost(
                postId = id,
                body = s.body,
                visibility = s.visibility,
                imageUrls = s.imageUrls,
                unlockPriceCents = cents,
                videoChanged = s.videoChanged,
                videoIds = s.attachedVideoIds,
            )
            when (r) {
                is ApiResult.Success -> {
                    // #18b — replace the edited post IN PLACE in the main feed (not just My Posts).
                    feedRefreshBus.signal()
                    _state.update { it.copy(submitting = false, saved = true) }
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

    private fun centsToDollars(cents: Long): String {
        val whole = cents / 100
        val frac = (cents % 100).toInt()
        return if (frac == 0) whole.toString() else String.format(java.util.Locale.US, "%d.%02d", whole, frac)
    }

    /** Map the stored visibility to an edit-valid chip; only public/followers are editable. */
    private fun visibilityFromWire(wire: String?): PostVisibility =
        if (wire?.trim()?.lowercase() == "public") PostVisibility.PUBLIC else PostVisibility.FOLLOWERS
}
