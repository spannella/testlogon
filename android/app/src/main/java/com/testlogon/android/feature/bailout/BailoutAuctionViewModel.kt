package com.testlogon.android.feature.bailout

import androidx.lifecycle.SavedStateHandle
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.bailout.BailoutAuction
import com.testlogon.android.data.bailout.BailoutRepository
import com.testlogon.android.navigation.BailoutAuctionDest
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import javax.inject.Inject

data class BailoutAuctionUiState(
    val symbolId: Int,
    val phase: Phase = Phase.Loading,
    val auction: BailoutAuction? = null,
    val errorMessage: String? = null,
    val actionMessage: String? = null,
    val actionInFlight: Boolean = false,
) {
    enum class Phase { Loading, Content, Error }
}

/**
 * Drives one PRE-EMPTIVE BAILOUT AUCTION (for a position addressed by symbolId): the capital-needed
 * target, rescuer bids, a rescue-bid form behind a money-safety confirm, the indicative clearing share
 * (pure [BailoutMath]), the live "if mark hits liqPrice first -> cancels -> liquidation" warning, and
 * the owner Clear. Reads degrade on 404; mutations surface a clear result then refresh.
 */
@HiltViewModel
class BailoutAuctionViewModel @Inject constructor(
    private val repository: BailoutRepository,
    savedStateHandle: SavedStateHandle,
) : ViewModel() {

    private val symbolId: Int =
        savedStateHandle.get<String>(BailoutAuctionDest.ARG_SYMBOL_ID)?.toIntOrNull() ?: 0

    private val _uiState = MutableStateFlow(BailoutAuctionUiState(symbolId = symbolId))
    val uiState: StateFlow<BailoutAuctionUiState> = _uiState.asStateFlow()

    init {
        load()
    }

    fun onRetry() = load()

    fun consumeActionMessage() = _uiState.update { it.copy(actionMessage = null) }

    fun load() {
        _uiState.update { it.copy(phase = BailoutAuctionUiState.Phase.Loading, errorMessage = null) }
        viewModelScope.launch {
            when (val r = repository.positionBailout(symbolId)) {
                is ApiResult.Success -> _uiState.update {
                    it.copy(phase = BailoutAuctionUiState.Phase.Content, auction = r.data, errorMessage = null)
                }
                is ApiResult.Failure -> _uiState.update {
                    it.copy(phase = BailoutAuctionUiState.Phase.Content, auction = null)
                }
                is ApiResult.NetworkError -> _uiState.update {
                    it.copy(
                        phase = BailoutAuctionUiState.Phase.Error,
                        errorMessage = "No connection. Check your network and retry.",
                    )
                }
            }
        }
    }

    /** Inject rescue capital for a position-share (a sealed rescue bid). */
    fun placeBid(capitalCents: Long, shareBps: Int) = mutate {
        val id = _uiState.value.auction?.auctionId.orEmpty()
        if (id.isBlank()) return@mutate "No open auction to bid on."
        when (val r = repository.placeBid(id, capitalCents, shareBps)) {
            is ApiResult.Success -> if (r.data.accepted) "Rescue bid placed." else (r.data.message ?: "Bid not accepted.")
            is ApiResult.Failure -> r.error.message.ifBlank { "Couldn't place a rescue bid (backend pending)." }
            is ApiResult.NetworkError -> "No connection. Your rescue bid was not placed."
        }
    }

    /** Owner-only: clear the auction at the single least-dilutive clearing share. */
    fun clear() = mutate {
        val id = _uiState.value.auction?.auctionId.orEmpty()
        if (id.isBlank()) return@mutate "No open auction to clear."
        when (val r = repository.clear(id)) {
            is ApiResult.Success -> "Auction cleared at the single clearing share."
            is ApiResult.Failure -> r.error.message.ifBlank { "Couldn't clear the auction (backend pending)." }
            is ApiResult.NetworkError -> "No connection. The auction was not cleared."
        }
    }

    private fun mutate(block: suspend () -> String) {
        if (_uiState.value.actionInFlight) return
        _uiState.update { it.copy(actionInFlight = true) }
        viewModelScope.launch {
            val msg = block()
            _uiState.update { it.copy(actionInFlight = false, actionMessage = msg) }
            load()
        }
    }
}
