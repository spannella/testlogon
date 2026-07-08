package com.testlogon.android.feature.subscriptions

import androidx.lifecycle.SavedStateHandle
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.ui.i18n.UiText
import com.testlogon.android.data.ads.AdClickAttributionStore
import com.testlogon.android.data.messaging.BillingAuthorizer
import com.testlogon.android.data.messaging.BillingResult
import com.testlogon.android.data.subscriptions.CreatorSubscription
import com.testlogon.android.data.subscriptions.SubscribeReqDto
import com.testlogon.android.data.subscriptions.SubscriptionFeatureFlags
import com.testlogon.android.data.subscriptions.SubscriptionTier
import com.testlogon.android.data.subscriptions.SubscriptionsRepository
import com.testlogon.android.feature.billing.error.BillingErrorMapper
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
 * AND-236 — subscribe confirmation flow state. The user reviews the selected tier (name + recurring
 * price/interval), confirms, and the pay step is routed through the [BillingAuthorizer] stub gated by
 * [SubscriptionFeatureFlags.checkoutEnabled]. When payments are unavailable (flag off or stub
 * NotConfigured) the flow surfaces [Status.PaymentsUnavailable] and NEVER calls the subscribe endpoint
 * or fakes a charge. On the Authorized path it POSTs `api/plans/{planId}/subscribe` exactly once and
 * reflects the active subscription.
 */
data class SubscribeUiState(
    val tier: SubscriptionTier,
    val status: Status = Status.Reviewing,
    /** Screen-ready error copy (mapped via [BillingErrorMapper]) for the Error status. */
    val errorMessage: UiText? = null,
    /** The activated subscription, present once [Status.Success]. */
    val subscription: CreatorSubscription? = null,
) {
    enum class Status { Reviewing, Authorizing, Subscribing, Success, PaymentsUnavailable, Error }

    val isWorking: Boolean get() = status == Status.Authorizing || status == Status.Subscribing
}

/** AND-236 — one-shot effects (Channel-backed so rotation never replays them). */
sealed interface SubscribeEvent {
    /** Subscription activated; carries the new id + plan so the originating screen can reflect entitlement. */
    data class Activated(val subscriptionId: String, val planId: String) : SubscribeEvent

    /** Transient snackbar copy (e.g. a mapped error to show on top of the confirm sheet). */
    data class ShowMessage(val message: UiText) : SubscribeEvent
}

/**
 * AND-236 — subscribe confirmation presentation logic.
 *
 * Reuses the AND-234 [SubscriptionsRepository] (real `api/plans/{planId}/subscribe`), the
 * [BillingAuthorizer] payment seam (AND-139 stub: NotConfigured -> never charges), the
 * [SubscriptionFeatureFlags] checkout gate (AND-235, default-off), and [BillingErrorMapper] (AND-232)
 * for failures. The tier under review is supplied by the navigation args resolved from the browse
 * list (the tier's `plan_id` is the subscribe PATH param).
 */
@HiltViewModel
class SubscribeViewModel @Inject constructor(
    savedStateHandle: SavedStateHandle,
    private val repository: SubscriptionsRepository,
    private val adAttribution: AdClickAttributionStore,
    private val billingAuthorizer: BillingAuthorizer,
    private val featureFlags: SubscriptionFeatureFlags,
    private val errorMapper: BillingErrorMapper,
) : ViewModel() {

    private val planId: String = checkNotNull(savedStateHandle[ARG_PLAN_ID]) {
        "SubscribeViewModel requires a '$ARG_PLAN_ID' nav argument"
    }
    private val creatorId: String = checkNotNull(savedStateHandle[ARG_CREATOR_ID]) {
        "SubscribeViewModel requires a '$ARG_CREATOR_ID' nav argument"
    }
    private val priceCents: Long = savedStateHandle.get<Long>(ARG_PRICE_CENTS) ?: 0L

    private val _uiState = MutableStateFlow(
        SubscribeUiState(tier = buildTierFromArgs(savedStateHandle)),
    )
    val uiState: StateFlow<SubscribeUiState> = _uiState.asStateFlow()

    private val _events = Channel<SubscribeEvent>(Channel.BUFFERED)
    val events: Flow<SubscribeEvent> = _events.receiveAsFlow()

    /**
     * AND-236 — confirm the subscription. Routes the pay step through the BillingAuthorizer stub gated
     * by the checkout flag. NotConfigured / flag-off / decline -> PaymentsUnavailable, and the subscribe
     * endpoint is NEVER called. Only the Authorized path POSTs subscribe.
     */
    fun confirm() {
        val current = _uiState.value
        if (current.isWorking) return // guard against concurrent confirms

        if (!featureFlags.checkoutEnabled) {
            _uiState.update { it.copy(status = SubscribeUiState.Status.PaymentsUnavailable) }
            return
        }

        _uiState.update { it.copy(status = SubscribeUiState.Status.Authorizing, errorMessage = null) }
        viewModelScope.launch {
            when (billingAuthorizer.authorize(priceCents, current.tier.currency, memo = current.tier.name)) {
                is BillingResult.Authorized -> runSubscribe()
                is BillingResult.NotConfigured ->
                    _uiState.update { it.copy(status = SubscribeUiState.Status.PaymentsUnavailable) }
                is BillingResult.Cancelled ->
                    // User dismissed the payment sheet: return to review, no error, no charge.
                    _uiState.update { it.copy(status = SubscribeUiState.Status.Reviewing) }
                is BillingResult.Declined,
                is BillingResult.Failed,
                ->
                    _uiState.update { it.copy(status = SubscribeUiState.Status.PaymentsUnavailable) }
            }
        }
    }

    /** Re-attempt after a recoverable error: back to Reviewing so the user can confirm again. */
    fun retry() {
        if (_uiState.value.isWorking) return
        _uiState.update { it.copy(status = SubscribeUiState.Status.Reviewing, errorMessage = null) }
    }

    private suspend fun runSubscribe() {
        _uiState.update { it.copy(status = SubscribeUiState.Status.Subscribing) }
        // ADV-405: attach the session last-click ad_click_id so a subscribe converts the ad (ADV-402).
        when (val result = repository.subscribe(planId, SubscribeReqDto(adClickId = adAttribution.peek()))) {
            is ApiResult.Success -> {
                val sub = result.data
                _uiState.update {
                    it.copy(status = SubscribeUiState.Status.Success, subscription = sub, errorMessage = null)
                }
                _events.send(SubscribeEvent.Activated(sub.subscriptionId, sub.planId))
            }
            else -> {
                val error = errorMapper.map(result)
                _uiState.update {
                    it.copy(status = SubscribeUiState.Status.Error, errorMessage = error.message)
                }
                _events.send(SubscribeEvent.ShowMessage(error.message))
            }
        }
    }

    private fun buildTierFromArgs(handle: SavedStateHandle): SubscriptionTier = SubscriptionTier(
        planId = planId,
        creatorId = creatorId,
        name = handle.get<String>(ARG_TIER_NAME).orEmpty(),
        description = handle.get<String>(ARG_DESCRIPTION),
        priceCents = priceCents,
        currency = handle.get<String>(ARG_CURRENCY) ?: DEFAULT_CURRENCY,
        interval = com.testlogon.android.data.subscriptions.BillingInterval.fromWire(
            handle.get<String>(ARG_INTERVAL),
        ),
        annualPriceCents = null,
        status = "active",
        perks = emptyList(),
        createdAtEpochSeconds = null,
        updatedAtEpochSeconds = null,
    )

    companion object {
        const val ARG_PLAN_ID = "planId"
        const val ARG_CREATOR_ID = "creatorId"
        const val ARG_TIER_NAME = "tierName"
        const val ARG_PRICE_CENTS = "priceCents"
        const val ARG_CURRENCY = "currency"
        const val ARG_INTERVAL = "interval"
        const val ARG_DESCRIPTION = "description"

        private const val DEFAULT_CURRENCY = "USD"
    }
}
