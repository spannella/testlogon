package com.testlogon.android.feature.tokens

import androidx.lifecycle.SavedStateHandle
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.tokens.Token
import com.testlogon.android.data.tokens.TokenAuction
import com.testlogon.android.data.tokens.TokenCapTable
import com.testlogon.android.data.tokens.TokenRevenue
import com.testlogon.android.data.tokens.TokenUpkeep
import com.testlogon.android.data.tokens.TokensRepository
import com.testlogon.android.data.exchange.watchlist.WatchKind
import com.testlogon.android.data.exchange.watchlist.WatchlistStore
import com.testlogon.android.data.exchange.watchlist.isWatched as isWatchedIn
import com.testlogon.android.navigation.TokenDetailDest
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import javax.inject.Inject

data class TokenDetailUiState(
    val tokenId: String,
    val phase: Phase = Phase.Loading,
    val token: Token? = null,
    val capTable: TokenCapTable? = null,
    val revenue: TokenRevenue? = null,
    val upkeep: TokenUpkeep? = null,
    val auction: TokenAuction? = null,
    val errorMessage: String? = null,
    /** True when this token is one the CALLER issued (drives issuer-only List/IPO + Clear affordances). */
    val isIssuer: Boolean = false,
    /** A transient one-shot user message (result of a mutation) shown as a snackbar/inline note. */
    val actionMessage: String? = null,
    val actionInFlight: Boolean = false,
) {
    enum class Phase { Loading, Content, Error }
}

/**
 * Drives the token detail surface (cap table + revenue + upkeep + issuer List/IPO + auction panel).
 * Every read degrades to an honest empty/pending state on 404; every mutation surfaces a clear result
 * message (never a silent success), then refreshes the affected reads.
 */
@HiltViewModel
class TokenDetailViewModel @Inject constructor(
    private val repository: TokensRepository,
    private val watchlist: WatchlistStore,
    savedStateHandle: SavedStateHandle,
) : ViewModel() {

    private val tokenId: String = savedStateHandle.get<String>(TokenDetailDest.ARG_TOKEN_ID).orEmpty()

    private val _uiState = MutableStateFlow(TokenDetailUiState(tokenId = tokenId))
    val uiState: StateFlow<TokenDetailUiState> = _uiState.asStateFlow()

    /** Whether this token is on the unified watchlist (drives the detail star). */
    val isWatched: StateFlow<Boolean> = watchlist.items
        .map { items -> isWatchedIn(items, WatchKind.TOKEN, tokenId) }
        .stateIn(
            viewModelScope,
            kotlinx.coroutines.flow.SharingStarted.WhileSubscribed(5_000),
            watchlist.isWatched(WatchKind.TOKEN, tokenId),
        )

    /** Toggle this token on/off the unified watchlist. */
    fun toggleWatch() { watchlist.toggle(WatchKind.TOKEN, tokenId) }

    init {
        load()
    }

    fun onRetry() = load()

    fun consumeActionMessage() = _uiState.update { it.copy(actionMessage = null) }

    fun load() {
        _uiState.update { it.copy(phase = TokenDetailUiState.Phase.Loading, errorMessage = null) }
        viewModelScope.launch {
            val token = repository.token(tokenId)
            val cap = repository.capTable(tokenId)
            val rev = repository.revenue(tokenId)
            val up = repository.upkeep(tokenId)
            val auc = repository.auction(tokenId)
            // Issuer check: is this token among the ones the caller issued? Degrades to false on 404.
            val issued = repository.issued()
            val isIssuer = (issued as? ApiResult.Success)?.data?.any { it.tokenId == tokenId } == true

            val netError = listOf(token, cap, rev, up, auc).firstOrNull { it is ApiResult.NetworkError }
            if (netError != null) {
                _uiState.update {
                    it.copy(
                        phase = TokenDetailUiState.Phase.Error,
                        errorMessage = "No connection. Check your network and retry.",
                    )
                }
                return@launch
            }
            _uiState.update {
                it.copy(
                    phase = TokenDetailUiState.Phase.Content,
                    token = (token as? ApiResult.Success)?.data,
                    capTable = (cap as? ApiResult.Success)?.data,
                    revenue = (rev as? ApiResult.Success)?.data,
                    upkeep = (up as? ApiResult.Success)?.data,
                    auction = (auc as? ApiResult.Success)?.data,
                    isIssuer = isIssuer,
                    errorMessage = null,
                )
            }
        }
    }

    fun listIpo(offeredPctBps: Int, reservePrice: Long, closeTs: Long) = mutate {
        when (val r = repository.list(tokenId, offeredPctBps, reservePrice, closeTs)) {
            is ApiResult.Success -> "IPO listed — auction open." to r.data
            is ApiResult.Failure -> failMsg(r.error.message, "list this token") to null
            is ApiResult.NetworkError -> "No connection. The token was not listed." to null
        }
    }

    fun placeBid(qty: Long, limitPrice: Long) = mutate {
        when (val r = repository.placeBid(tokenId, qty, limitPrice)) {
            is ApiResult.Success ->
                (if (r.data.accepted) "Bid placed." else (r.data.message ?: "Bid not accepted.")) to null
            is ApiResult.Failure -> failMsg(r.error.message, "place a bid") to null
            is ApiResult.NetworkError -> "No connection. Your bid was not placed." to null
        }
    }

    fun clearAuction() = mutate {
        when (val r = repository.clearAuction(tokenId)) {
            is ApiResult.Success -> "Auction cleared." to null
            is ApiResult.Failure -> failMsg(r.error.message, "clear the auction") to null
            is ApiResult.NetworkError -> "No connection. The auction was not cleared." to null
        }
    }

    fun claimRevenue() = mutate {
        when (val r = repository.claimRevenue(tokenId)) {
            is ApiResult.Success ->
                (if (r.data.accepted) "Revenue claimed." else (r.data.message ?: "Nothing to claim.")) to null
            is ApiResult.Failure -> failMsg(r.error.message, "claim revenue") to null
            is ApiResult.NetworkError -> "No connection. Revenue was not claimed." to null
        }
    }

    fun payUpkeep() = mutate {
        when (val r = repository.payUpkeep(tokenId)) {
            is ApiResult.Success ->
                (if (r.data.accepted) "Upkeep paid — book unfrozen." else (r.data.message ?: "Upkeep not paid.")) to null
            is ApiResult.Failure -> failMsg(r.error.message, "pay upkeep") to null
            is ApiResult.NetworkError -> "No connection. Upkeep was not paid." to null
        }
    }

    private fun failMsg(server: String, action: String): String =
        server.ifBlank { "Couldn't $action (backend pending)." }

    /** Runs a mutation [block] that returns (message, ignored); posts the message + refreshes reads. */
    private fun mutate(block: suspend () -> Pair<String, Any?>) {
        if (_uiState.value.actionInFlight) return
        _uiState.update { it.copy(actionInFlight = true) }
        viewModelScope.launch {
            val (msg, _) = block()
            _uiState.update { it.copy(actionInFlight = false, actionMessage = msg) }
            load()
        }
    }
}
