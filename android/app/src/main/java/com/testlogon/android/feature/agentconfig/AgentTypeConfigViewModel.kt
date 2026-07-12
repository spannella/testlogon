package com.testlogon.android.feature.agentconfig

import androidx.lifecycle.SavedStateHandle
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.agentconfig.AgentConfigType
import com.testlogon.android.data.agentconfig.AgentConfigRepository
import com.testlogon.android.data.agentconfig.ConfigForm
import com.testlogon.android.data.agentconfig.ConfigValidation
import com.testlogon.android.navigation.AgentConfigDest
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
 * B4 web-parity - drives [AgentConfigUiState] for ONE agent-type config surface. The [AgentConfigType] and the
 * runtime typeId come from the nav args ([AgentConfigDest.ARG_TYPE] / [AgentConfigDest.ARG_TYPE_ID]). Loads the
 * config (GET) on first composition, lets the user edit the mirrored field list, validates (POST .../validate),
 * and saves (PUT). A 403 maps to Forbidden (expected for the non-operator test user); a 401 to SessionExpired.
 */
@HiltViewModel
class AgentTypeConfigViewModel @Inject constructor(
    private val repository: AgentConfigRepository,
    savedStateHandle: SavedStateHandle,
) : ViewModel() {

    private val type: AgentConfigType =
        AgentConfigType.from(savedStateHandle[AgentConfigDest.ARG_TYPE]) ?: AgentConfigType.CODER
    private val typeId: String =
        savedStateHandle.get<String>(AgentConfigDest.ARG_TYPE_ID)?.takeIf { it.isNotBlank() } ?: type.typeName

    private val _uiState = MutableStateFlow(AgentConfigUiState(type = type, typeId = typeId))
    val uiState: StateFlow<AgentConfigUiState> = _uiState.asStateFlow()

    private val _effects = Channel<AgentConfigEffect>(Channel.BUFFERED)
    val effects: Flow<AgentConfigEffect> = _effects.receiveAsFlow()

    init {
        load()
    }

    fun onRetry() = load()

    // ---- Field edits ----

    fun onTextChange(key: String, value: String) {
        _uiState.update { s ->
            val form = s.form ?: return@update s
            s.copy(form = form.copy(values = form.values.toMutableMap().apply { put(key, value) }))
        }
    }

    fun onBoolChange(key: String, value: Boolean) {
        _uiState.update { s ->
            val form = s.form ?: return@update s
            s.copy(form = form.copy(bools = form.bools.toMutableMap().apply { put(key, value) }))
        }
    }

    fun onValidate() {
        val form = _uiState.value.form ?: return
        viewModelScope.launch {
            when (val r = repository.validate(type, typeId, form)) {
                is ApiResult.Success -> applyValidation(r.data)
                is ApiResult.Failure -> mapFailure(r.error.status, r.error.message)
                is ApiResult.NetworkError -> _effects.send(AgentConfigEffect.ShowMessage(OFFLINE))
            }
        }
    }

    fun onSave() {
        val form = _uiState.value.form ?: return
        if (_uiState.value.isSaving) return
        _uiState.update { it.copy(isSaving = true, validationErrors = emptyList()) }
        viewModelScope.launch {
            when (val r = repository.save(type, typeId, form)) {
                is ApiResult.Success -> {
                    _uiState.update { it.copy(isSaving = false, validationErrors = emptyList()) }
                    _effects.send(AgentConfigEffect.ShowMessage("Configuration saved"))
                }
                is ApiResult.Failure -> {
                    _uiState.update { it.copy(isSaving = false) }
                    // 422 = invalid config; surface the server message as a validation issue.
                    if (r.error.status == 422) {
                        _uiState.update { it.copy(validationErrors = listOf(r.error.message)) }
                    }
                    mapFailure(r.error.status, r.error.message)
                }
                is ApiResult.NetworkError -> {
                    _uiState.update { it.copy(isSaving = false) }
                    _effects.send(AgentConfigEffect.ShowMessage(OFFLINE))
                }
            }
        }
    }

    private suspend fun applyValidation(v: ConfigValidation) {
        _uiState.update { it.copy(validationErrors = v.errors) }
        val msg = if (v.valid) "Configuration is valid" else "${v.errors.size} validation issue(s)"
        _effects.send(AgentConfigEffect.ShowMessage(msg))
    }

    private suspend fun mapFailure(status: Int, message: String) {
        when (status) {
            403 -> _uiState.update { it.copy(phase = AgentConfigUiState.Phase.Forbidden) }
            401 -> _uiState.update { it.copy(phase = AgentConfigUiState.Phase.SessionExpired) }
            else -> _effects.send(AgentConfigEffect.ShowMessage(message))
        }
    }

    private fun load() {
        _uiState.update { it.copy(phase = AgentConfigUiState.Phase.Loading, errorMessage = null) }
        viewModelScope.launch {
            when (val r = repository.load(type, typeId)) {
                is ApiResult.Success -> _uiState.update {
                    it.copy(phase = AgentConfigUiState.Phase.Content, form = r.data)
                }
                is ApiResult.Failure -> when (r.error.status) {
                    403 -> _uiState.update { it.copy(phase = AgentConfigUiState.Phase.Forbidden) }
                    401 -> _uiState.update { it.copy(phase = AgentConfigUiState.Phase.SessionExpired) }
                    else -> _uiState.update {
                        it.copy(phase = AgentConfigUiState.Phase.Error, errorMessage = r.error.message)
                    }
                }
                is ApiResult.NetworkError -> _uiState.update {
                    it.copy(phase = AgentConfigUiState.Phase.Offline, errorMessage = OFFLINE)
                }
            }
        }
    }

    private companion object {
        private const val OFFLINE = "Could not reach the server. Tap retry."
    }
}
