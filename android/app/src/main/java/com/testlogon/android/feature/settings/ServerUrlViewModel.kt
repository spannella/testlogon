package com.testlogon.android.feature.settings

import androidx.lifecycle.SavedStateHandle
import androidx.lifecycle.ViewModel
import com.testlogon.android.feature.auth.login.ServerUrlConfig
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import javax.inject.Inject

/** One-shot user message for the server-URL screen (AND-041). */
sealed interface SettingsMessage {
    data object Saved : SettingsMessage
    data object ResetDone : SettingsMessage
    data class Failed(val reason: String) : SettingsMessage
}

data class ServerUrlUiState(
    val input: String = "",
    val persistedUrl: String = "",
    val defaultUrl: String = "",
    val error: UrlError? = null,
    val cleartextWarning: Boolean = false,
    val canSave: Boolean = false,
    val canReset: Boolean = false,
    val saving: Boolean = false,
    val message: SettingsMessage? = null,
)

/**
 * AND-041 — view/edit/reset the runtime base URL via [ServerUrlConfig] (which wraps [SettingsStore]).
 *
 * Validation runs on every keystroke and again at save; only a *valid, changed* URL enables Save and
 * is ever persisted. Persistence is the single source of truth — the host-selection interceptor
 * reads the same store, so a saved URL applies to the next request with no restart.
 */
@HiltViewModel
class ServerUrlViewModel @Inject constructor(
    private val config: ServerUrlConfig,
    savedStateHandle: SavedStateHandle,
) : ViewModel() {

    private val persisted = config.current().normalizeForCompare()
    private val default = config.default().normalizeForCompare()

    private val _state = MutableStateFlow(
        ServerUrlUiState(
            input = savedStateHandle.get<String>(KEY_INPUT) ?: persisted,
            persistedUrl = persisted,
            defaultUrl = default,
            canReset = persisted != default,
        ),
    )
    val state: StateFlow<ServerUrlUiState> = _state.asStateFlow()

    init {
        // Re-validate any restored in-progress input so Save enablement is correct on recreation.
        recomputeFor(_state.value.input)
    }

    fun onInputChange(value: String) {
        recomputeFor(value)
    }

    private fun recomputeFor(value: String) {
        when (val v = BaseUrlValidator.validate(value)) {
            is UrlValidation.Valid -> _state.update {
                it.copy(
                    input = value,
                    error = null,
                    cleartextWarning = v.cleartext,
                    canSave = v.normalized != it.persistedUrl && !it.saving,
                )
            }
            is UrlValidation.Invalid -> _state.update {
                it.copy(input = value, error = v.reason, cleartextWarning = false, canSave = false)
            }
        }
    }

    fun onSave() {
        val s = _state.value
        if (s.saving) return
        val v = BaseUrlValidator.validate(s.input)
        if (v !is UrlValidation.Valid || v.normalized == s.persistedUrl) return
        _state.update { it.copy(saving = true) }
        try {
            config.update(v.normalized)
            val newPersisted = config.current().normalizeForCompare()
            _state.update {
                it.copy(
                    saving = false,
                    persistedUrl = newPersisted,
                    input = newPersisted,
                    canSave = false,
                    canReset = newPersisted != it.defaultUrl,
                    message = SettingsMessage.Saved,
                )
            }
        } catch (e: Exception) {
            _state.update { it.copy(saving = false, message = SettingsMessage.Failed("Could not save server URL")) }
        }
    }

    fun onResetToDefault() {
        val s = _state.value
        if (s.saving || s.persistedUrl == s.defaultUrl) return
        try {
            config.reset()
            val newPersisted = config.current().normalizeForCompare()
            _state.update {
                it.copy(
                    persistedUrl = newPersisted,
                    input = newPersisted,
                    error = null,
                    cleartextWarning = BaseUrlValidator.validate(newPersisted)
                        .let { v -> v is UrlValidation.Valid && v.cleartext },
                    canSave = false,
                    canReset = newPersisted != it.defaultUrl,
                    message = SettingsMessage.ResetDone,
                )
            }
        } catch (e: Exception) {
            _state.update { it.copy(message = SettingsMessage.Failed("Could not reset server URL")) }
        }
    }

    fun onMessageShown() = _state.update { it.copy(message = null) }

    /** Persisted values from SettingsStore always end in '/'; strip it for display/compare parity. */
    private fun String.normalizeForCompare(): String = trimEnd('/')

    private companion object {
        const val KEY_INPUT = "server_url_input"
    }
}
