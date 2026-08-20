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

data class TokenMintUiState(
    val name: String = "",
    val ticker: String = "",
    val supplyText: String = "1000000",
    val revenueSharePctText: String = "10",
    val submitting: Boolean = false,
    val errorMessage: String? = null,
    val mintedTokenId: String? = null,
) {
    /** Parsed supply, or null when blank/invalid. */
    val supply: Long? get() = supplyText.trim().toLongOrNull()?.takeIf { it > 0 }

    /** Revenue-share basis points parsed from a percent field (e.g. "10" -> 1000 bps). Null when invalid. */
    val revenueShareBps: Int?
        get() {
            val pct = revenueSharePctText.trim().toDoubleOrNull() ?: return null
            if (pct < 0.0 || pct > 100.0) return null
            return (pct * 100.0).toInt()
        }

    val canSubmit: Boolean
        get() = name.isNotBlank() &&
            ticker.isNotBlank() &&
            supply != null &&
            revenueShareBps != null &&
            !submitting
}

/**
 * Drives the Mint form. The creator sets name/ticker/supply/revenue-share %; the SERVER charges the
 * $100 creation fee on [mint] (the UI gates the call behind a money-safety confirm). On success the
 * new token id is emitted so the route can navigate to detail. A 404 (undeployed backend) surfaces as
 * a clear error — never a silent success.
 */
@HiltViewModel
class TokenMintViewModel @Inject constructor(
    private val repository: TokensRepository,
) : ViewModel() {

    private val _uiState = MutableStateFlow(TokenMintUiState())
    val uiState: StateFlow<TokenMintUiState> = _uiState.asStateFlow()

    fun onName(v: String) = _uiState.update { it.copy(name = v, errorMessage = null) }
    fun onTicker(v: String) = _uiState.update { it.copy(ticker = v.uppercase().take(8), errorMessage = null) }
    fun onSupply(v: String) = _uiState.update { it.copy(supplyText = v.filter { c -> c.isDigit() }, errorMessage = null) }
    fun onRevenueShare(v: String) =
        _uiState.update { it.copy(revenueSharePctText = v.filter { c -> c.isDigit() || c == '.' }, errorMessage = null) }

    fun consumeMinted() = _uiState.update { it.copy(mintedTokenId = null) }

    /** Called AFTER the $100 creation-fee confirm is accepted. */
    fun confirmMint() {
        val s = _uiState.value
        val supply = s.supply
        val bps = s.revenueShareBps
        if (supply == null || bps == null || s.name.isBlank() || s.ticker.isBlank()) {
            _uiState.update { it.copy(errorMessage = "Fill in every field with valid values.") }
            return
        }
        _uiState.update { it.copy(submitting = true, errorMessage = null) }
        viewModelScope.launch {
            when (val r = repository.mint(s.name.trim(), s.ticker.trim(), supply, bps)) {
                is ApiResult.Success -> _uiState.update {
                    it.copy(submitting = false, mintedTokenId = r.data.tokenId.ifBlank { null }, errorMessage = null)
                }
                is ApiResult.Failure -> _uiState.update {
                    it.copy(submitting = false, errorMessage = mintError(r.error.message))
                }
                is ApiResult.NetworkError -> _uiState.update {
                    it.copy(submitting = false, errorMessage = "No connection. Your token was not minted.")
                }
            }
        }
    }

    private fun mintError(serverMessage: String): String =
        serverMessage.ifBlank { "Minting isn't available yet (backend pending). Your token was not minted." }
}
