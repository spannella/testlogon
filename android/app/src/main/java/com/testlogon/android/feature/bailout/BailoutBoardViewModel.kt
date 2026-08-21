package com.testlogon.android.feature.bailout

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.bailout.BailoutAuction
import com.testlogon.android.data.bailout.BailoutRepository
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import javax.inject.Inject

data class BailoutBoardUiState(
    val phase: Phase = Phase.Loading,
    val auctions: List<BailoutAuction> = emptyList(),
    val errorMessage: String? = null,
) {
    enum class Phase { Loading, Content, Error }
}

/**
 * Drives the BAILOUTS DISCOVERY board — open pre-emptive bailout auctions a rescuer can inject capital
 * into. Degrades to an honest empty/pending state on 404 (the me/bailouts backend is undeployed) rather
 * than an error, so nothing distress-like is ever fabricated.
 */
@HiltViewModel
class BailoutBoardViewModel @Inject constructor(
    private val repository: BailoutRepository,
) : ViewModel() {

    private val _uiState = MutableStateFlow(BailoutBoardUiState())
    val uiState: StateFlow<BailoutBoardUiState> = _uiState.asStateFlow()

    init {
        load()
    }

    fun onRetry() = load()

    fun load() {
        _uiState.update { it.copy(phase = BailoutBoardUiState.Phase.Loading, errorMessage = null) }
        viewModelScope.launch {
            when (val r = repository.bailouts()) {
                is ApiResult.Success -> _uiState.update {
                    it.copy(phase = BailoutBoardUiState.Phase.Content, auctions = r.data, errorMessage = null)
                }
                is ApiResult.Failure -> _uiState.update {
                    it.copy(phase = BailoutBoardUiState.Phase.Content, auctions = emptyList())
                }
                is ApiResult.NetworkError -> _uiState.update {
                    it.copy(
                        phase = BailoutBoardUiState.Phase.Error,
                        errorMessage = "No connection. Check your network and retry.",
                    )
                }
            }
        }
    }
}
