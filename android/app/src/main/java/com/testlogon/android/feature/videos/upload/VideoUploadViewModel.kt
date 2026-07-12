package com.testlogon.android.feature.videos.upload

import android.net.Uri
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.videos.VideoUploadRepository
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import javax.inject.Inject

data class VideoUploadUiState(
    val pickedUri: String? = null,
    val fileName: String? = null,
    val title: String = "",
    val description: String = "",
    val uploading: Boolean = false,
    val error: String? = null,
    /** ADV - creator opts this video into the ad-supported tier (pre-roll ads) on publish. */
    val allowAds: Boolean = false,
    /** Non-null on success = the new video id; the screen pops back. */
    val uploadedVideoId: String? = null,
) {
    val canUpload: Boolean get() = pickedUri != null && title.isNotBlank() && !uploading
}

@HiltViewModel
class VideoUploadViewModel @Inject constructor(
    private val repository: VideoUploadRepository,
) : ViewModel() {

    private val _state = MutableStateFlow(VideoUploadUiState())
    val state: StateFlow<VideoUploadUiState> = _state.asStateFlow()

    fun onVideoPicked(uri: Uri, displayName: String?) =
        _state.update { it.copy(pickedUri = uri.toString(), fileName = displayName ?: uri.lastPathSegment, error = null) }

    fun onTitleChange(text: String) = _state.update { it.copy(title = text, error = null) }
    fun onDescriptionChange(text: String) = _state.update { it.copy(description = text) }

    /** ADV - toggle "Allow ads / Monetize" for this upload. */
    fun onToggleAllowAds(enabled: Boolean) = _state.update { it.copy(allowAds = enabled) }

    fun upload() {
        val s = _state.value
        if (!s.canUpload) return
        val uri = Uri.parse(s.pickedUri)
        _state.update { it.copy(uploading = true, error = null) }
        viewModelScope.launch {
            when (val r = repository.upload(uri, s.title, s.description)) {
                is ApiResult.Success -> {
                    // ADV - if the creator opted in, flip the new video to the ad_supported tier and
                    // enable their ads so it serves a pre-roll (best-effort; upload already succeeded).
                    if (s.allowAds && r.data.isNotBlank()) {
                        repository.enableAds(r.data)
                    }
                    _state.update { it.copy(uploading = false, uploadedVideoId = r.data.ifBlank { "uploaded" }) }
                }
                is ApiResult.Failure -> _state.update { it.copy(uploading = false, error = r.error.message) }
                is ApiResult.NetworkError -> _state.update { it.copy(uploading = false, error = "Upload failed. Check your connection and try again.") }
            }
        }
    }
}
