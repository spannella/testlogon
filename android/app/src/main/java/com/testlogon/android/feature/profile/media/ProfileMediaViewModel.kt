package com.testlogon.android.feature.profile.media

import android.net.Uri
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.R
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.profile.MediaKind
import com.testlogon.android.data.profile.ProfileRepository
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.Job
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.receiveAsFlow
import kotlinx.coroutines.launch
import javax.inject.Inject

/** AND-074 — ephemeral avatar/cover upload state (not persisted across process death). */
sealed interface MediaUploadState {
    data object Idle : MediaUploadState
    data object Preparing : MediaUploadState
    data object Uploading : MediaUploadState
    data class Success(val kind: MediaKind, val url: String?) : MediaUploadState
    data class Error(val message: String) : MediaUploadState
}

/** One-shot effects so the host (own-profile) can refresh its avatar after a successful upload. */
sealed interface MediaUploadEffect {
    data class Uploaded(val kind: MediaKind) : MediaUploadEffect
    data class ShowMessage(val resId: Int) : MediaUploadEffect
}

/**
 * AND-074 — orchestrates pick -> process -> upload. Cancellation aborts the in-flight OkHttp call via
 * coroutine cancellation, leaving the prior media intact. The upload POST is never auto-retried.
 */
@HiltViewModel
class ProfileMediaViewModel @Inject constructor(
    private val repository: ProfileRepository,
    private val imageProcessor: ProfileImageProcessor,
) : ViewModel() {

    private val _state = MutableStateFlow<MediaUploadState>(MediaUploadState.Idle)
    val state: StateFlow<MediaUploadState> = _state.asStateFlow()

    private val _effects = Channel<MediaUploadEffect>(Channel.BUFFERED)
    val effects: Flow<MediaUploadEffect> = _effects.receiveAsFlow()

    private var job: Job? = null

    fun startUpload(kind: MediaKind, source: Uri) {
        if (job?.isActive == true) return
        job = viewModelScope.launch {
            _state.value = MediaUploadState.Preparing
            val prepared = runCatching { imageProcessor.process(source) }.getOrElse {
                _state.value = MediaUploadState.Error("Couldn't prepare the image.")
                _effects.send(MediaUploadEffect.ShowMessage(R.string.profile_media_prepare_failed))
                return@launch
            }
            _state.value = MediaUploadState.Uploading
            when (val result = repository.uploadPhoto(kind, prepared)) {
                is ApiResult.Success -> {
                    _state.value = MediaUploadState.Success(kind, result.data.url)
                    _effects.send(MediaUploadEffect.Uploaded(kind))
                }
                is ApiResult.Failure -> {
                    _state.value = MediaUploadState.Error(result.error.message)
                    _effects.send(MediaUploadEffect.ShowMessage(R.string.profile_media_upload_failed))
                }
                is ApiResult.NetworkError -> {
                    _state.value = MediaUploadState.Error("You're offline. Try again.")
                    _effects.send(MediaUploadEffect.ShowMessage(R.string.profile_media_upload_failed))
                }
            }
        }
    }

    fun cancel() {
        job?.cancel()
        job = null
        _state.value = MediaUploadState.Idle
    }
}
