package com.testlogon.android.feature.feed.own

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.feed.PostComposeRepository
import com.testlogon.android.data.feed.PostVisibility
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import javax.inject.Inject

/** FD1 / FD-EDIT — edit-an-owned-post screen state (text + photos + audience + paid-lock). */
data class EditPostUiState(
    val loading: Boolean = true,
    val body: String = "",
    /** Edit audience — only PUBLIC / FOLLOWERS are valid for an in-place edit (B-POST contract). */
    val visibility: PostVisibility = PostVisibility.FOLLOWERS,
    /** Currently-attached photo urls (already-uploaded). Empty REMOVES all photos on save. */
    val imageUrls: List<String> = emptyList(),
    /** Unlock price in dollars as typed; blank = the post is free/unlocked on save. */
    val lockPriceInput: String = "",
    val uploadingMedia: Boolean = false,
    val submitting: Boolean = false,
    val error: String? = null,
    /** Flipped true once the edit is saved so the screen can pop back. */
    val saved: Boolean = false,
) {
    val canSave: Boolean
        get() = (body.isNotBlank() || imageUrls.isNotEmpty()) &&
            !submitting && !loading && !uploadingMedia
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
                    _state.update {
                        it.copy(
                            loading = false,
                            body = (dto.bodyPlain ?: dto.body).orEmpty(),
                            visibility = visibilityFromWire(dto.visibility),
                            imageUrls = dto.imageUrls.orEmpty(),
                            lockPriceInput = priceInput,
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
            )
            when (r) {
                is ApiResult.Success -> _state.update { it.copy(submitting = false, saved = true) }
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
