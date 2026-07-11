package com.testlogon.android.feature.subscriptions

import androidx.lifecycle.SavedStateHandle
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.ui.i18n.UiText
import com.testlogon.android.data.messaging.BillingAuthorizer
import com.testlogon.android.data.messaging.BillingResult
import com.testlogon.android.data.subscriptions.CreatorSubscription
import com.testlogon.android.data.subscriptions.GiftSubscriptionReqDto
import com.testlogon.android.data.subscriptions.SubscriptionFeatureFlags
import com.testlogon.android.data.subscriptions.SubscriptionTier
import com.testlogon.android.data.subscriptions.SubscriptionsRepository
import com.testlogon.android.feature.billing.error.BillingErrorMapper
import com.testlogon.android.feature.billing.error.Recoverability
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
 * SUB-E2 PART 2 (SUB-23) - gift-a-subscription flow state. The GIFTER picks a recipient + a tier and
 * pays for ONE cycle; the recipient gets a no-renew subscription that lapses at period end (they are
 * never charged). Money routes through the [BillingAuthorizer] payment seam, gated by
 * [SubscriptionFeatureFlags.checkoutEnabled], then POSTs api/plans/{planId}/gift exactly once.
 */
data class GiftSubscriptionUiState(
    val creatorDisplayName: String?,
    val status: Status = Status.Loading,
    val tiers: List<SubscriptionTier> = emptyList(),
    val selectedPlanId: String? = null,
    val recipient: String = "",
    val message: String = "",
    val errorMessage: UiText? = null,
    /** True when the failure was a real decline / no-PM (HTTP 402): show an add-a-card affordance. */
    val requiresPaymentMethod: Boolean = false,
    val gift: CreatorSubscription? = null,
) {
    enum class Status { Loading, Reviewing, Empty, Authorizing, Gifting, Success, PaymentsUnavailable, Error }

    val isWorking: Boolean get() = status == Status.Authorizing || status == Status.Gifting

    val selectedTier: SubscriptionTier? get() = tiers.firstOrNull { it.planId == selectedPlanId }

    /** Confirm is enabled once a recipient is entered and a tier is chosen. */
    val canConfirm: Boolean
        get() = recipient.isNotBlank() && selectedTier != null && !isWorking
}

/** SUB-E2 - one-shot gift effects. */
sealed interface GiftSubscriptionEvent {
    data class Gifted(val subscriptionId: String) : GiftSubscriptionEvent
    data class ShowMessage(val message: UiText) : GiftSubscriptionEvent
}

@HiltViewModel
class GiftSubscriptionViewModel @Inject constructor(
    savedStateHandle: SavedStateHandle,
    private val repository: SubscriptionsRepository,
    private val billingAuthorizer: BillingAuthorizer,
    private val featureFlags: SubscriptionFeatureFlags,
    private val errorMapper: BillingErrorMapper,
) : ViewModel() {

    private val creatorId: String = checkNotNull(savedStateHandle[ARG_CREATOR_ID]) {
        "GiftSubscriptionViewModel requires a '$ARG_CREATOR_ID' nav argument"
    }

    private val clientRequestId: String = java.util.UUID.randomUUID().toString()

    private val _uiState = MutableStateFlow(
        GiftSubscriptionUiState(creatorDisplayName = savedStateHandle.get<String>(ARG_DISPLAY_NAME)),
    )
    val uiState: StateFlow<GiftSubscriptionUiState> = _uiState.asStateFlow()

    private val _events = Channel<GiftSubscriptionEvent>(Channel.BUFFERED)
    val events: Flow<GiftSubscriptionEvent> = _events.receiveAsFlow()

    init {
        loadTiers()
    }

    fun loadTiers() {
        _uiState.update { it.copy(status = GiftSubscriptionUiState.Status.Loading) }
        viewModelScope.launch {
            when (val result = repository.getCreatorTiers(creatorId)) {
                is ApiResult.Success -> {
                    val active = result.data.filter { it.isActive && it.priceCents > 0L }
                    _uiState.update {
                        it.copy(
                            tiers = active,
                            selectedPlanId = it.selectedPlanId ?: active.firstOrNull()?.planId,
                            status = if (active.isEmpty()) {
                                GiftSubscriptionUiState.Status.Empty
                            } else {
                                GiftSubscriptionUiState.Status.Reviewing
                            },
                        )
                    }
                }
                else -> {
                    val error = errorMapper.map(result)
                    _uiState.update {
                        it.copy(status = GiftSubscriptionUiState.Status.Error, errorMessage = error.message)
                    }
                }
            }
        }
    }

    fun onRecipientChanged(value: String) {
        _uiState.update { it.copy(recipient = value) }
    }

    fun onMessageChanged(value: String) {
        _uiState.update { it.copy(message = value) }
    }

    fun onSelectTier(planId: String) {
        _uiState.update { it.copy(selectedPlanId = planId) }
    }

    /** Confirm the gift: authorize a PM for one cycle, then POST the gift once. */
    fun confirm() {
        val current = _uiState.value
        if (current.isWorking) return
        val tier = current.selectedTier ?: return
        val recipient = current.recipient.trim()
        if (recipient.isEmpty()) return

        if (!featureFlags.checkoutEnabled) {
            _uiState.update { it.copy(status = GiftSubscriptionUiState.Status.PaymentsUnavailable) }
            return
        }

        _uiState.update { it.copy(status = GiftSubscriptionUiState.Status.Authorizing, errorMessage = null) }
        viewModelScope.launch {
            when (val auth = billingAuthorizer.authorize(tier.priceCents, tier.currency, memo = tier.name)) {
                is BillingResult.Authorized -> runGift(tier, recipient, auth.paymentMethodId)
                is BillingResult.Cancelled ->
                    _uiState.update { it.copy(status = GiftSubscriptionUiState.Status.Reviewing) }
                is BillingResult.NotConfigured,
                is BillingResult.Declined,
                is BillingResult.Failed,
                ->
                    _uiState.update { it.copy(status = GiftSubscriptionUiState.Status.PaymentsUnavailable) }
            }
        }
    }

    private suspend fun runGift(tier: SubscriptionTier, recipient: String, paymentMethodId: String) {
        _uiState.update { it.copy(status = GiftSubscriptionUiState.Status.Gifting) }
        val body = GiftSubscriptionReqDto(
            recipientId = recipient,
            paymentMethodId = paymentMethodId.takeIf { it.isNotBlank() },
            message = _uiState.value.message.trim().takeIf { it.isNotBlank() },
            clientRequestId = clientRequestId,
        )
        when (val result = repository.gift(tier.planId, body)) {
            is ApiResult.Success -> {
                _uiState.update {
                    it.copy(
                        status = GiftSubscriptionUiState.Status.Success,
                        gift = result.data,
                        errorMessage = null,
                        requiresPaymentMethod = false,
                    )
                }
                _events.send(GiftSubscriptionEvent.Gifted(result.data.subscriptionId))
            }
            else -> {
                val error = errorMapper.map(result)
                val needsCard = error.httpStatus == HTTP_PAYMENT_REQUIRED ||
                    error.recoverability == Recoverability.REQUIRES_NEW_METHOD
                _uiState.update {
                    it.copy(
                        status = GiftSubscriptionUiState.Status.Error,
                        errorMessage = error.message,
                        requiresPaymentMethod = needsCard,
                    )
                }
                _events.send(GiftSubscriptionEvent.ShowMessage(error.message))
            }
        }
    }

    fun retry() {
        if (_uiState.value.isWorking) return
        _uiState.update {
            it.copy(
                status = GiftSubscriptionUiState.Status.Reviewing,
                errorMessage = null,
                requiresPaymentMethod = false,
            )
        }
    }

    companion object {
        const val ARG_CREATOR_ID = "creatorId"
        const val ARG_DISPLAY_NAME = "creatorDisplayName"
        private const val HTTP_PAYMENT_REQUIRED = 402
    }
}
