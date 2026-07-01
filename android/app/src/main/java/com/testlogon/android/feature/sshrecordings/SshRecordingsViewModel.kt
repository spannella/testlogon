package com.testlogon.android.feature.sshrecordings

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.sshrecordings.RecordingDto
import com.testlogon.android.data.sshrecordings.RecordingPlaybackDto
import com.testlogon.android.data.sshrecordings.SshRecordingsRepository
import com.testlogon.android.feature.adminmod.AdminOpsErrorType
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import javax.inject.Inject

/**
 * B7 Remote-Access: SSH-recording management + playback. Lists recordings, opens a recorded-terminal
 * playback (asciicast events -> a real replayable transcript), and deletes. Mirrors SshRecordingsPage.tsx
 * + SshRecordingPlayer.tsx. The surface is behind SSH_SESSION_RECORDING_ENABLED (a 503 -> Disabled). A 403
 * renders Forbidden. Reuses AdminOpsErrorType.
 */
sealed interface RecordingsDataState {
    data object Loading : RecordingsDataState
    data class Content(val recordings: List<RecordingDto>, val isRefreshing: Boolean = false) : RecordingsDataState
    data object Empty : RecordingsDataState
    data object Forbidden : RecordingsDataState
    data object Disabled : RecordingsDataState
    data class Error(val type: AdminOpsErrorType) : RecordingsDataState
}

/** The full recorded transcript rendered from asciicast "o" (output) events, in offset order. */
data class RecordingPlayback(
    val recording: RecordingDto,
    val transcript: String,
    val eventCount: Int,
)

data class RecordingsUiState(
    val data: RecordingsDataState = RecordingsDataState.Loading,
    val actionInFlightId: String? = null,
    val loadingPlaybackId: String? = null,
    val playback: RecordingPlayback? = null,
    val message: String? = null,
    val transientError: AdminOpsErrorType? = null,
)

@HiltViewModel
class SshRecordingsViewModel @Inject constructor(
    private val repo: SshRecordingsRepository,
) : ViewModel() {

    private val _state = MutableStateFlow(RecordingsUiState())
    val state: StateFlow<RecordingsUiState> = _state.asStateFlow()

    init { load() }

    fun retry() = load()

    fun refresh() {
        val cur = _state.value
        if (cur.data is RecordingsDataState.Content) {
            _state.value = cur.copy(data = cur.data.copy(isRefreshing = true), transientError = null)
        }
        fetch(isRefresh = true)
    }

    private fun load() {
        _state.value = _state.value.copy(data = RecordingsDataState.Loading)
        fetch(isRefresh = false)
    }

    private fun fetch(isRefresh: Boolean) {
        viewModelScope.launch {
            when (val r = repo.list()) {
                is ApiResult.Success -> {
                    val items = r.data.recordings
                    _state.value = _state.value.copy(
                        data = if (items.isEmpty()) RecordingsDataState.Empty else RecordingsDataState.Content(items),
                    )
                }
                is ApiResult.Failure -> reduceFailure(isRefresh, r.error.status)
                is ApiResult.NetworkError -> reduceError(isRefresh, AdminOpsErrorType.NETWORK)
            }
        }
    }

    fun openPlayback(recording: RecordingDto) {
        if (_state.value.loadingPlaybackId != null) return
        _state.value = _state.value.copy(loadingPlaybackId = recording.recordingId, transientError = null, message = null)
        viewModelScope.launch {
            when (val r = repo.playback(recording.recordingId)) {
                is ApiResult.Success -> _state.value = _state.value.copy(
                    loadingPlaybackId = null,
                    playback = RecordingPlayback(
                        recording = recording,
                        transcript = renderTranscript(r.data),
                        eventCount = r.data.eventCount,
                    ),
                )
                is ApiResult.Failure -> reducePlaybackError(if (r.error.status == 401) AdminOpsErrorType.AUTH else AdminOpsErrorType.SERVER)
                is ApiResult.NetworkError -> reducePlaybackError(AdminOpsErrorType.NETWORK)
            }
        }
    }

    fun delete(recordingId: String) {
        if (_state.value.actionInFlightId != null) return
        _state.value = _state.value.copy(actionInFlightId = recordingId, transientError = null, message = null)
        viewModelScope.launch {
            when (val r = repo.delete(recordingId)) {
                is ApiResult.Success -> {
                    _state.value = _state.value.copy(actionInFlightId = null, message = "Recording deleted")
                    fetch(isRefresh = true)
                }
                is ApiResult.Failure -> reduceActionError(if (r.error.status == 401) AdminOpsErrorType.AUTH else AdminOpsErrorType.SERVER)
                is ApiResult.NetworkError -> reduceActionError(AdminOpsErrorType.NETWORK)
            }
        }
    }

    fun dismissPlayback() { _state.value = _state.value.copy(playback = null) }

    fun clearMessage() { _state.value = _state.value.copy(message = null, transientError = null) }

    /** Concatenate the recorded "o" (output) events in order into a plain-text transcript. */
    private fun renderTranscript(pb: RecordingPlaybackDto): String {
        val sb = StringBuilder()
        for (ev in pb.events) {
            // event = [offset, type, data]; keep output events only
            val type = ev.getOrNull(1) as? String ?: "o"
            if (type == "o") {
                val data = ev.getOrNull(2) as? String ?: continue
                sb.append(data)
            }
        }
        return sb.toString().ifBlank { "(no output recorded)" }
    }

    private fun reducePlaybackError(type: AdminOpsErrorType) {
        _state.value = _state.value.copy(loadingPlaybackId = null, transientError = type)
    }

    private fun reduceActionError(type: AdminOpsErrorType) {
        _state.value = _state.value.copy(actionInFlightId = null, transientError = type)
    }

    private fun reduceFailure(isRefresh: Boolean, status: Int) = when (status) {
        503 -> _state.value = _state.value.copy(data = RecordingsDataState.Disabled)
        403 -> _state.value = _state.value.copy(data = RecordingsDataState.Forbidden)
        401 -> reduceError(isRefresh, AdminOpsErrorType.AUTH)
        else -> reduceError(isRefresh, AdminOpsErrorType.SERVER)
    }

    private fun reduceError(isRefresh: Boolean, type: AdminOpsErrorType) {
        val cur = _state.value
        val hasData = cur.data is RecordingsDataState.Content
        _state.value = if (isRefresh && hasData) {
            cur.copy(data = (cur.data as RecordingsDataState.Content).copy(isRefreshing = false), transientError = type)
        } else {
            cur.copy(data = RecordingsDataState.Error(type))
        }
    }
}
