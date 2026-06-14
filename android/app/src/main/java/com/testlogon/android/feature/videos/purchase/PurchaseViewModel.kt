package com.testlogon.android.feature.videos.purchase

import androidx.lifecycle.SavedStateHandle
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.vod.purchase.Entitlement
import com.testlogon.android.data.vod.purchase.PurchaseOutcome
import com.testlogon.android.data.vod.purchase.PurchaseTier
import com.testlogon.android.data.vod.purchase.VodPurchaseRepository
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
 * AND-193 — purchase-sheet UI state (tier list / confirm / processing / success / error).
 */
data class PurchaseUiState(
    val isLoadingTiers: Boolean = false,
    val tiers: List<PurchaseTier> = emptyList(),
    val selectedType: String? = null,
    val isSubmitting: Boolean = false,
    val isPurchased: Boolean = false,
    val tiersError: String? = null,
    val purchaseError: String? = null,
) {
    val canConfirm: Boolean get() = selectedType != null && !isSubmitting && !isPurchased
}

/** One-shot effects (Channel + receiveAsFlow — never replayed on recomposition). */
sealed interface PurchaseEvent {
    data class Unlocked(val entitlement: Entitlement) : PurchaseEvent
    data object RequireReauth : PurchaseEvent
    data object PaymentsUnavailable : PurchaseEvent
}

@HiltViewModel
class PurchaseViewModel @Inject constructor(
    private val repository: VodPurchaseRepository,
    savedStateHandle: SavedStateHandle,
) : ViewModel() {

    private val videoId: String = checkNotNull(savedStateHandle[ARG_VIDEO_ID]) { "missing videoId arg" }

    private val _uiState = MutableStateFlow(PurchaseUiState())
    val uiState: StateFlow<PurchaseUiState> = _uiState.asStateFlow()

    private val _events = Channel<PurchaseEvent>(Channel.BUFFERED)
    val events: Flow<PurchaseEvent> = _events.receiveAsFlow()

    /** Loads the offer (GET access) -> tiers; default-selects the offer's default purchase type. */
    fun loadTiers() {
        _uiState.update { it.copy(isLoadingTiers = true, tiersError = null) }
        viewModelScope.launch {
            when (val r = repository.getOffer(videoId)) {
                is ApiResult.Success -> {
                    val offer = r.data
                    val tiers = offer.tiers()
                    _uiState.update {
                        it.copy(
                            isLoadingTiers = false,
                            tiers = tiers,
                            selectedType = it.selectedType ?: tiers.firstOrNull()?.type?.wire,
                            tiersError = null,
                        )
                    }
                }
                is ApiResult.Failure -> _uiState.update {
                    it.copy(isLoadingTiers = false, tiersError = r.error.message)
                }
                is ApiResult.NetworkError -> _uiState.update {
                    it.copy(isLoadingTiers = false, tiersError = MSG_OFFLINE)
                }
            }
        }
    }

    fun onTierSelected(type: String) {
        _uiState.update { it.copy(selectedType = type, purchaseError = null) }
    }

    fun onConfirm() {
        val type = _uiState.value.selectedType ?: return
        if (_uiState.value.isSubmitting || _uiState.value.isPurchased) return
        _uiState.update { it.copy(isSubmitting = true, purchaseError = null) }
        viewModelScope.launch {
            when (val r = repository.purchase(videoId, type)) {
                is PurchaseOutcome.Unlocked -> {
                    _uiState.update { it.copy(isSubmitting = false, isPurchased = true) }
                    _events.send(PurchaseEvent.Unlocked(r.entitlement))
                }
                PurchaseOutcome.RequireReauth -> {
                    _uiState.update { it.copy(isSubmitting = false) }
                    _events.send(PurchaseEvent.RequireReauth)
                }
                PurchaseOutcome.PaymentsUnavailable -> {
                    _uiState.update { it.copy(isSubmitting = false) }
                    _events.send(PurchaseEvent.PaymentsUnavailable)
                }
                is PurchaseOutcome.Cancelled ->
                    _uiState.update { it.copy(isSubmitting = false) }
                is PurchaseOutcome.Failure ->
                    _uiState.update { it.copy(isSubmitting = false, purchaseError = r.message) }
            }
        }
    }

    fun retry() = loadTiers()

    companion object {
        const val ARG_VIDEO_ID = "videoId"
        private const val MSG_OFFLINE = "You're offline. Try again."
    }
}
