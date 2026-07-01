package com.testlogon.android.feature.agents.prs.ui

import androidx.lifecycle.SavedStateHandle
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.feature.agents.prs.data.PrsRepository
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.receiveAsFlow
import kotlinx.coroutines.launch
import javax.inject.Inject

/**
 * AGENTS-BASICS (web-parity) - loads a single agent-PR detail (web /agents/prs -> row). Reads the prId nav arg
 * from [SavedStateHandle]. A terminal 401 -> [PrsEffect.NavigateToLogin].
 */
@HiltViewModel
class PrDetailViewModel @Inject constructor(
    savedStateHandle: SavedStateHandle,
    private val repo: PrsRepository,
) : ViewModel() {

    private val prId: String = savedStateHandle.get<String>(ARG_PR_ID).orEmpty()

    private val _uiState = MutableStateFlow<PrDetailUiState>(PrDetailUiState.Loading)
    val uiState: StateFlow<PrDetailUiState> = _uiState.asStateFlow()

    private val _effects = Channel<PrsEffect>(Channel.BUFFERED)
    val effects: Flow<PrsEffect> = _effects.receiveAsFlow()

    init { load() }

    fun load() {
        _uiState.value = PrDetailUiState.Loading
        viewModelScope.launch {
            when (val result = repo.get(prId)) {
                is ApiResult.Success -> _uiState.value = PrDetailUiState.Content(result.data)
                is ApiResult.Failure -> {
                    if (result.error.status == HTTP_UNAUTHORIZED) _effects.send(PrsEffect.NavigateToLogin)
                    _uiState.value = PrDetailUiState.Error(result.error.message)
                }
                is ApiResult.NetworkError -> _uiState.value = PrDetailUiState.Error(OFFLINE)
            }
        }
    }

    fun onRetry() = load()

    companion object {
        const val ARG_PR_ID = "prId"
        private const val HTTP_UNAUTHORIZED = 401
        private const val OFFLINE = "Couldn't reach the server. Tap retry."
    }
}
