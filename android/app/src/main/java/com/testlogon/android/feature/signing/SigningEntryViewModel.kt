package com.testlogon.android.feature.signing

import androidx.lifecycle.SavedStateHandle
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.feature.signing.data.SignatureRepository
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

/**
 * AND-340 - presentation logic for the Signing ENTRY surface.
 *
 * There is NO backend packet-list endpoint, so the entry is NOT a browse list: the user either loads an
 * existing packet by ID or creates a draft from a source path (e.g. a file path handed in from the Files
 * feature via the [ARG_SOURCE_PATH] nav arg). Both land on the packet DETAIL screen. Create is a single
 * write (POST v1 signature-packets) guarded against double-submit.
 */
@HiltViewModel
class SigningEntryViewModel @Inject constructor(
    private val repository: SignatureRepository,
    savedStateHandle: SavedStateHandle,
) : ViewModel() {

    /** An optional source path handed in from the Files feature; gates the "Create draft" affordance. */
    val sourcePath: String? =
        savedStateHandle.get<String>(ARG_SOURCE_PATH)?.takeIf { it.isNotBlank() }

    private val _uiState = MutableStateFlow(SigningEntryUiState(canCreateDraft = sourcePath != null))
    val uiState: StateFlow<SigningEntryUiState> = _uiState.asStateFlow()

    private val _events = Channel<SigningEntryEvent>(Channel.BUFFERED)
    val events: Flow<SigningEntryEvent> = _events.receiveAsFlow()

    /** Single in-flight create guard. */
    private var createJob: Job? = null

    /** Updates the packet-id text field. */
    fun onPacketIdChange(value: String) {
        _uiState.value = _uiState.value.copy(packetId = value)
    }

    /** Loads the entered packet id -> navigate to detail. Blank input is ignored. */
    fun onLoadPacket() {
        val id = _uiState.value.packetId.trim()
        if (id.isEmpty()) return
        viewModelScope.launch { _events.send(SigningEntryEvent.OpenPacket(id)) }
    }

    /**
     * Creates a draft from [sourcePath] -> navigate to the new packet's detail. No-op when there is no
     * source path or a create is already in flight.
     */
    fun onCreateDraft(originChannel: String = DEFAULT_ORIGIN_CHANNEL) {
        val path = sourcePath ?: return
        if (_uiState.value.creating) return
        _uiState.value = _uiState.value.copy(creating = true)

        createJob?.cancel()
        createJob = viewModelScope.launch {
            when (val result = repository.createDraft(sourcePath = path, originChannel = originChannel)) {
                is ApiResult.Success -> {
                    _uiState.value = _uiState.value.copy(creating = false)
                    if (result.data.isNotBlank()) {
                        _events.send(SigningEntryEvent.OpenPacket(result.data))
                    } else {
                        _events.send(SigningEntryEvent.CreateFailed(CREATE_FAILED))
                    }
                }
                is ApiResult.Failure -> {
                    _uiState.value = _uiState.value.copy(creating = false)
                    _events.send(SigningEntryEvent.CreateFailed(result.error.message))
                }
                is ApiResult.NetworkError -> {
                    _uiState.value = _uiState.value.copy(creating = false)
                    _events.send(SigningEntryEvent.CreateFailed(OFFLINE))
                }
            }
        }
    }

    companion object {
        const val ARG_SOURCE_PATH = "sourcePath"

        /** origin_channel for a draft created from a stored file path (per AND-339 contract). */
        const val DEFAULT_ORIGIN_CHANNEL = "share"

        private const val OFFLINE = "Couldn't reach the server. Try again."
        private const val CREATE_FAILED = "Couldn't create the draft."
    }
}

/** UI state for the Signing entry surface (load-by-id + optional create-draft). */
data class SigningEntryUiState(
    val packetId: String = "",
    val canCreateDraft: Boolean = false,
    val creating: Boolean = false,
)

/** One-shot events for the Signing entry surface. */
sealed interface SigningEntryEvent {

    /** Open the packet DETAIL screen for the given id (load-by-id or freshly-created draft). */
    data class OpenPacket(val packetId: String) : SigningEntryEvent

    /** Draft creation failed; carries a user-facing message. */
    data class CreateFailed(val message: String) : SigningEntryEvent
}
