package com.testlogon.android.feature.settings.media

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.model.MediaPreferences
import com.testlogon.android.core.model.VideoResolution
import com.testlogon.android.data.preferences.MediaPreferencesRepository
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.receiveAsFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import javax.inject.Inject

/**
 * AND-079 — call media preferences screen state. Form edits mutate in-memory state only; an explicit
 * Save sends one PUT with the full state (web parity). On load failure with a local mirror, renders
 * a stale form rather than a hard error.
 */
sealed interface MediaPrefsUiState {
    data object Loading : MediaPrefsUiState
    data class Ready(
        val prefs: MediaPreferences,
        val saved: MediaPreferences,
        val isSaving: Boolean = false,
        val isStale: Boolean = false,
    ) : MediaPrefsUiState {
        val isDirty: Boolean get() = prefs != saved
    }

    data class Error(val message: String) : MediaPrefsUiState
}

/** One-shot transient effects (snackbars). */
sealed interface MediaPrefsEffect {
    data class ShowMessage(val message: String) : MediaPrefsEffect
}

@HiltViewModel
class MediaPreferencesViewModel @Inject constructor(
    private val repository: MediaPreferencesRepository,
) : ViewModel() {

    private val _state = MutableStateFlow<MediaPrefsUiState>(MediaPrefsUiState.Loading)
    val state: StateFlow<MediaPrefsUiState> = _state.asStateFlow()

    private val _effects = Channel<MediaPrefsEffect>(Channel.BUFFERED)
    val effects: Flow<MediaPrefsEffect> = _effects.receiveAsFlow()

    init {
        load()
    }

    fun load() {
        _state.value = MediaPrefsUiState.Loading
        viewModelScope.launch {
            when (val result = repository.refresh()) {
                is ApiResult.Success -> _state.value = MediaPrefsUiState.Ready(
                    prefs = result.data,
                    saved = result.data,
                )
                is ApiResult.Failure -> serveStaleOrError(result.error.message)
                is ApiResult.NetworkError -> serveStaleOrError(NETWORK_MESSAGE)
            }
        }
    }

    private fun serveStaleOrError(message: String) {
        val cached = repository.cached()
        _state.value = if (cached != null) {
            MediaPrefsUiState.Ready(prefs = cached, saved = cached, isStale = true)
        } else {
            MediaPrefsUiState.Error(message)
        }
    }

    fun onDefaultMutedChanged(enabled: Boolean) = edit { it.copy(defaultAudioMuted = enabled) }

    fun onDefaultVideoOffChanged(enabled: Boolean) = edit { it.copy(defaultVideoOff = enabled) }

    fun onResolutionSelected(resolution: VideoResolution) =
        edit { it.copy(videoResolution = resolution) }

    private fun edit(transform: (MediaPreferences) -> MediaPreferences) {
        _state.update { current ->
            if (current is MediaPrefsUiState.Ready) {
                current.copy(prefs = transform(current.prefs))
            } else {
                current
            }
        }
    }

    fun save() {
        val ready = _state.value as? MediaPrefsUiState.Ready ?: return
        if (ready.isSaving || !ready.isDirty) return
        _state.value = ready.copy(isSaving = true)
        viewModelScope.launch {
            when (val result = repository.update(ready.prefs)) {
                is ApiResult.Success -> {
                    _state.value = MediaPrefsUiState.Ready(prefs = result.data, saved = result.data)
                    _effects.send(MediaPrefsEffect.ShowMessage(SAVED_MESSAGE))
                }
                is ApiResult.Failure -> failSave(ready, result.error.message)
                is ApiResult.NetworkError -> failSave(ready, NETWORK_MESSAGE)
            }
        }
    }

    private suspend fun failSave(ready: MediaPrefsUiState.Ready, message: String) {
        // Keep the edited form (web parity) and clear the in-flight flag.
        _state.value = ready.copy(isSaving = false)
        _effects.send(MediaPrefsEffect.ShowMessage(message))
    }

    private companion object {
        const val NETWORK_MESSAGE = "Couldn't reach the server. Check your connection and try again."
        const val SAVED_MESSAGE = "Media preferences saved."
    }
}
