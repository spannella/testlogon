package com.testlogon.android.feature.settings.emojis

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.ApiResult
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import javax.inject.Inject

/**
 * Drives [CustomEmojiUiState] for the personal custom-emoji manager. Loads the caller's personal emojis, accepts
 * a picked image (bytes held in the VM until submit), uploads a new emoji (multipart), and deletes one. Mirrors
 * the web CustomEmojisPage personal-scope behavior + the 256KB client size guard.
 */
@HiltViewModel
class CustomEmojiViewModel @Inject constructor(
    private val repo: CustomEmojiRepository,
) : ViewModel() {

    private val _uiState = MutableStateFlow<CustomEmojiUiState>(CustomEmojiUiState.Loading)
    val uiState: StateFlow<CustomEmojiUiState> = _uiState.asStateFlow()

    /** Pending picked-image bytes (not in UI state to keep it light/serializable). */
    private var pendingBytes: ByteArray? = null
    private var pendingContentType: String = "image/png"

    init {
        load()
    }

    fun load() {
        _uiState.value = CustomEmojiUiState.Loading
        viewModelScope.launch {
            when (val result = repo.list()) {
                is ApiResult.Success -> _uiState.value = CustomEmojiUiState.Content(
                    emojis = result.data.personal,
                    personalCount = result.data.personalCount,
                )
                is ApiResult.Failure -> _uiState.value = CustomEmojiUiState.Error(result.error.message)
                is ApiResult.NetworkError -> _uiState.value = CustomEmojiUiState.Error(NETWORK_MESSAGE)
            }
        }
    }

    fun onShortcodeChanged(v: String) = editForm { it.copy(shortcode = v.lowercase().trim(), error = null) }
    fun onNameChanged(v: String) = editForm { it.copy(name = v, error = null) }
    fun onCategoryChanged(v: String) = editForm { it.copy(category = v, error = null) }

    /** The Route reads the picked content:// Uri into bytes and forwards them here. */
    fun onImagePicked(bytes: ByteArray, contentType: String, fileName: String) {
        if (bytes.size > MAX_FILE_SIZE) {
            editForm { it.copy(error = "File size exceeds maximum of 256KB.") }
            return
        }
        pendingBytes = bytes
        pendingContentType = contentType.ifBlank { "image/png" }
        editForm { it.copy(pickedFileName = fileName, error = null) }
    }

    private fun editForm(transform: (UploadForm) -> UploadForm) {
        val current = _uiState.value as? CustomEmojiUiState.Content ?: return
        _uiState.value = current.copy(form = transform(current.form), message = null)
    }

    fun upload() {
        val current = _uiState.value as? CustomEmojiUiState.Content ?: return
        val form = current.form
        val bytes = pendingBytes
        if (!form.canSubmit || bytes == null) {
            editForm { it.copy(error = "Choose an image and a shortcode first.") }
            return
        }
        _uiState.value = current.copy(form = form.copy(uploading = true, error = null), message = null)
        viewModelScope.launch {
            val payload = EmojiUpload(
                shortcode = form.shortcode.trim(),
                name = form.name.trim().ifBlank { form.shortcode.trim() },
                altText = form.altText.trim(),
                category = form.category.trim().ifBlank { "Uncategorized" },
                bytes = bytes,
                contentType = pendingContentType,
                fileName = form.pickedFileName ?: "emoji.png",
            )
            when (val result = repo.upload(payload)) {
                is ApiResult.Success -> {
                    pendingBytes = null
                    // Reload so the grid + quota reflect the new emoji.
                    reloadAfter("Emoji uploaded.")
                }
                is ApiResult.Failure -> failUpload(result.error.message)
                is ApiResult.NetworkError -> failUpload(NETWORK_MESSAGE)
            }
        }
    }

    private fun failUpload(message: String) {
        val current = _uiState.value as? CustomEmojiUiState.Content ?: return
        _uiState.value = current.copy(form = current.form.copy(uploading = false, error = message))
    }

    fun delete(emojiId: String) {
        val current = _uiState.value as? CustomEmojiUiState.Content ?: return
        if (current.deletingId != null) return
        _uiState.value = current.copy(deletingId = emojiId, message = null)
        viewModelScope.launch {
            when (val result = repo.delete(emojiId)) {
                is ApiResult.Success -> {
                    val now = _uiState.value as? CustomEmojiUiState.Content ?: return@launch
                    val remaining = now.emojis.filterNot { it.emojiId == emojiId }
                    _uiState.value = now.copy(
                        emojis = remaining,
                        personalCount = (now.personalCount - 1).coerceAtLeast(remaining.size),
                        deletingId = null,
                        message = "Emoji deleted.",
                    )
                }
                is ApiResult.Failure -> failDelete(result.error.message)
                is ApiResult.NetworkError -> failDelete(NETWORK_MESSAGE)
            }
        }
    }

    private fun failDelete(message: String) {
        val current = _uiState.value as? CustomEmojiUiState.Content ?: return
        _uiState.value = current.copy(deletingId = null, message = message)
    }

    private suspend fun reloadAfter(message: String) {
        when (val result = repo.list()) {
            is ApiResult.Success -> _uiState.value = CustomEmojiUiState.Content(
                emojis = result.data.personal,
                personalCount = result.data.personalCount,
                message = message,
            )
            is ApiResult.Failure -> _uiState.value = CustomEmojiUiState.Content(
                emojis = (_uiState.value as? CustomEmojiUiState.Content)?.emojis.orEmpty(),
                personalCount = (_uiState.value as? CustomEmojiUiState.Content)?.personalCount ?: 0,
                message = message,
            )
            is ApiResult.NetworkError -> _uiState.value = CustomEmojiUiState.Content(
                emojis = (_uiState.value as? CustomEmojiUiState.Content)?.emojis.orEmpty(),
                personalCount = (_uiState.value as? CustomEmojiUiState.Content)?.personalCount ?: 0,
                message = message,
            )
        }
    }

    private companion object {
        const val NETWORK_MESSAGE = "Couldn't reach the server. Check your connection and try again."
        const val MAX_FILE_SIZE = 262144 // 256KB, matching the web client guard.
    }
}
