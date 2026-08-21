package com.testlogon.android.feature.bailout

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.bailout.BailoutRepository
import com.testlogon.android.data.bailout.DistressPosition
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import javax.inject.Inject

data class DistressUiState(
    val phase: Phase = Phase.Loading,
    val positions: List<DistressPosition> = emptyList(),
    val errorMessage: String? = null,
    val actionMessage: String? = null,
    val actionInFlight: Boolean = false,
) {
    enum class Phase { Loading, Content, Error }
}

/**
 * Drives the MARGIN DISTRESS overview: the caller's distressed-but-solvent margin positions with their
 * volatility-scaled health read + an "Open bailout auction" affordance for eligible ones. Every read is
 * SERVER-AUTHORITATIVE and degrades to an honest empty/pending state on 404 — the client never
 * fabricates distress. Opening an auction surfaces a clear result (never a silent success), then
 * refreshes.
 */
@HiltViewModel
class DistressViewModel @Inject constructor(
    private val repository: BailoutRepository,
) : ViewModel() {

    private val _uiState = MutableStateFlow(DistressUiState())
    val uiState: StateFlow<DistressUiState> = _uiState.asStateFlow()

    init {
        load()
    }

    fun onRetry() = load()

    fun consumeActionMessage() = _uiState.update { it.copy(actionMessage = null) }

    fun load() {
        _uiState.update { it.copy(phase = DistressUiState.Phase.Loading, errorMessage = null) }
        viewModelScope.launch {
            when (val r = repository.distress()) {
                is ApiResult.Success -> _uiState.update {
                    it.copy(phase = DistressUiState.Phase.Content, positions = r.data, errorMessage = null)
                }
                is ApiResult.Failure -> _uiState.update {
                    // Repository already degrades 404s to empty; a Failure here is unexpected -> honest empty.
                    it.copy(phase = DistressUiState.Phase.Content, positions = emptyList())
                }
                is ApiResult.NetworkError -> _uiState.update {
                    it.copy(
                        phase = DistressUiState.Phase.Error,
                        errorMessage = "No connection. Check your network and retry.",
                    )
                }
            }
        }
    }

    /** Open a pre-emptive bailout auction on an eligible position, offering up to [maxShareBps]. */
    fun openBailout(symbolId: Int, maxShareBps: Int) {
        if (_uiState.value.actionInFlight) return
        _uiState.update { it.copy(actionInFlight = true) }
        viewModelScope.launch {
            val msg = when (val r = repository.openBailout(symbolId, maxShareBps, closeTs = null)) {
                is ApiResult.Success -> "Bailout auction opened."
                is ApiResult.Failure -> r.error.message.ifBlank { "Couldn't open a bailout auction (backend pending)." }
                is ApiResult.NetworkError -> "No connection. No auction was opened."
            }
            _uiState.update { it.copy(actionInFlight = false, actionMessage = msg) }
            load()
        }
    }
}
