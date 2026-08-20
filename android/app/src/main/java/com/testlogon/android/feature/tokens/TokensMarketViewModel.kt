package com.testlogon.android.feature.tokens

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.tokens.Token
import com.testlogon.android.data.tokens.TokensRepository
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import javax.inject.Inject

/** Which slice of the token list is shown. */
enum class TokenListTab { MARKET, ISSUED }

data class TokensMarketUiState(
    val phase: Phase = Phase.Loading,
    val tab: TokenListTab = TokenListTab.MARKET,
    val market: List<Token> = emptyList(),
    val issued: List<Token> = emptyList(),
    val errorMessage: String? = null,
) {
    enum class Phase { Loading, Content, Error }

    val rows: List<Token> get() = if (tab == TokenListTab.MARKET) market else issued
}

/**
 * Drives the token market/browse list. Loads both the LISTED market (browse) and the caller's ISSUED
 * tokens; both degrade to empty on 404 so the screen shows an honest "pending backend" empty state
 * rather than an error when the endpoints are undeployed.
 */
@HiltViewModel
class TokensMarketViewModel @Inject constructor(
    private val repository: TokensRepository,
) : ViewModel() {

    private val _uiState = MutableStateFlow(TokensMarketUiState())
    val uiState: StateFlow<TokensMarketUiState> = _uiState.asStateFlow()

    init {
        load()
    }

    fun onRetry() = load()

    fun selectTab(tab: TokenListTab) = _uiState.update { it.copy(tab = tab) }

    fun load() {
        _uiState.update { it.copy(phase = TokensMarketUiState.Phase.Loading, errorMessage = null) }
        viewModelScope.launch {
            val market = repository.market()
            val issued = repository.issued()
            // A transport failure (offline) on EITHER read -> Error with retry; HTTP 404s already
            // degraded to empty inside the repository.
            val netError = (market as? ApiResult.NetworkError) ?: (issued as? ApiResult.NetworkError)
            if (netError != null) {
                _uiState.update {
                    it.copy(
                        phase = TokensMarketUiState.Phase.Error,
                        errorMessage = "No connection. Check your network and retry.",
                    )
                }
                return@launch
            }
            _uiState.update {
                it.copy(
                    phase = TokensMarketUiState.Phase.Content,
                    market = (market as? ApiResult.Success)?.data.orEmpty(),
                    issued = (issued as? ApiResult.Success)?.data.orEmpty(),
                    errorMessage = null,
                )
            }
        }
    }
}
