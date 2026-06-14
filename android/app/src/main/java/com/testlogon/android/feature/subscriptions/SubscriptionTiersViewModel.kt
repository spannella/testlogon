package com.testlogon.android.feature.subscriptions

import androidx.lifecycle.SavedStateHandle
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.auth.AuthStateStore
import com.testlogon.android.data.messaging.BillingAuthorizer
import com.testlogon.android.data.messaging.BillingResult
import com.testlogon.android.data.subscriptions.BillingInterval
import com.testlogon.android.data.subscriptions.CreatorSubscription
import com.testlogon.android.data.subscriptions.SubscriptionFeatureFlags
import com.testlogon.android.data.subscriptions.SubscriptionState
import com.testlogon.android.data.subscriptions.SubscriptionTier
import com.testlogon.android.data.subscriptions.SubscriptionsRepository
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.receiveAsFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import javax.inject.Inject

/** AND-235 — a single tier card, fully derived for the UI (price text resolved at render time). */
data class TierUiModel(
    val id: String,
    val name: String,
    val description: String?,
    val priceCents: Long,
    val currency: String,
    val interval: BillingInterval,
    val perks: List<String>,
    val isCurrent: Boolean,
)

/** AND-235 — subscription tiers browse screen state. */
data class SubscriptionTiersUiState(
    val isLoading: Boolean = false,
    val isRefreshing: Boolean = false,
    val creatorDisplayName: String? = null,
    val tiers: List<TierUiModel> = emptyList(),
    val currentTierId: String? = null,
    val error: String? = null,
) {
    /** Empty only when a successful load returned zero active tiers. */
    val isEmpty: Boolean get() = !isLoading && error == null && tiers.isEmpty()
}

/** AND-235 — one-shot effects. Delivered over a Channel so rotation cannot replay them. */
sealed interface SubscriptionsEvent {
    /**
     * Checkout enabled — navigate to the AND-236 subscribe confirmation flow for [tierId] (the plan
     * id). Carries the tier display fields so the confirm sheet can render without a re-fetch.
     */
    data class NavigateToCheckout(
        val tierId: String,
        val creatorId: String,
        val name: String,
        val priceCents: Long,
        val currency: String,
        val interval: BillingInterval,
        val description: String?,
    ) : SubscriptionsEvent

    /** FLAGGED: payments unavailable (BillingAuthorizer stub NotConfigured / checkout flag off). */
    data object PaymentsUnavailable : SubscriptionsEvent

    /** AND-237 — open the manage / cancel screen for the current subscription. */
    data object NavigateToManage : SubscriptionsEvent

    /** Generic transient snackbar (e.g. refresh failed). */
    data class ShowMessage(val message: String) : SubscriptionsEvent
}

/**
 * AND-235 — subscription tiers browse presentation logic.
 *
 * Loads a creator's active plans ("tiers") plus the viewer's subscriptions in a single combined load,
 * sorts tiers ascending by price (name tie-break), marks the viewer's current tier, and degrades to
 * loading/empty/error. The Subscribe CTA routes the purchase through the [BillingAuthorizer] stub:
 * when checkout is disabled (default) or the stub returns NotConfigured, it surfaces a
 * payments-unavailable effect and NEVER fakes a charge or hits a subscribe endpoint.
 */
@HiltViewModel
class SubscriptionTiersViewModel @Inject constructor(
    savedStateHandle: SavedStateHandle,
    private val repository: SubscriptionsRepository,
    private val billingAuthorizer: BillingAuthorizer,
    private val featureFlags: SubscriptionFeatureFlags,
    private val authStateStore: AuthStateStore,
) : ViewModel() {

    private val creatorIdArg: String = checkNotNull(savedStateHandle[ARG_CREATOR_ID]) {
        "SubscriptionTiersViewModel requires a '$ARG_CREATOR_ID' nav argument"
    }

    /** Resolved creator id (the [SELF] sentinel from the More hub maps to the current user). */
    @Volatile
    private var creatorId: String = creatorIdArg

    private val _uiState = MutableStateFlow(
        SubscriptionTiersUiState(
            isLoading = true,
            creatorDisplayName = savedStateHandle.get<String?>(ARG_DISPLAY_NAME),
        ),
    )
    val uiState: StateFlow<SubscriptionTiersUiState> = _uiState.asStateFlow()

    private val _events = Channel<SubscriptionsEvent>(Channel.BUFFERED)
    val events: Flow<SubscriptionsEvent> = _events.receiveAsFlow()

    init {
        load(isRefresh = false)
    }

    fun onRetry() = load(isRefresh = false)

    fun onRefresh() {
        if (_uiState.value.isRefreshing) return
        load(isRefresh = true)
    }

    private fun load(isRefresh: Boolean) {
        _uiState.update {
            if (isRefresh) it.copy(isRefreshing = true) else it.copy(isLoading = true, error = null)
        }
        viewModelScope.launch {
            // Resolve the SELF sentinel (More-hub self-browse) to the current principal once.
            if (creatorId == SELF) {
                authStateStore.userSub.first()?.takeIf { it.isNotBlank() }?.let { creatorId = it }
            }
            val tiersResult = repository.getCreatorTiers(creatorId)
            // Partial-failure tolerance: a subs read failure is non-fatal — render tiers, no badge.
            val currentTierId = currentTierIdOrNull()

            when (tiersResult) {
                is ApiResult.Success -> {
                    val tiers = tiersResult.data
                        .filter { it.isActive }
                        .sortedWith(compareBy<SubscriptionTier> { it.priceCents }.thenBy { it.name })
                        .map { it.toUiModel(currentTierId) }
                    _uiState.update {
                        it.copy(
                            isLoading = false,
                            isRefreshing = false,
                            tiers = tiers,
                            currentTierId = currentTierId,
                            error = null,
                        )
                    }
                }
                else -> {
                    val message = tiersResult.messageOrOffline()
                    if (isRefresh && _uiState.value.tiers.isNotEmpty()) {
                        // Keep existing content on a refresh failure; surface a snackbar only.
                        _uiState.update { it.copy(isRefreshing = false) }
                        _events.send(SubscriptionsEvent.ShowMessage(message))
                    } else {
                        _uiState.update {
                            it.copy(isLoading = false, isRefreshing = false, error = message)
                        }
                    }
                }
            }
        }
    }

    /** AND-235 — Subscribe CTA. Gated by the checkout flag + BillingAuthorizer stub (no charge). */
    fun onSubscribeClick(tierId: String) {
        if (!featureFlags.checkoutEnabled) {
            viewModelScope.launch { _events.send(SubscriptionsEvent.PaymentsUnavailable) }
            return
        }
        val tier = _uiState.value.tiers.firstOrNull { it.id == tierId } ?: return
        viewModelScope.launch {
            // Route through the billing authorizer stub: NotConfigured -> payments unavailable, NEVER
            // a faked charge and NEVER a subscribe call.
            when (billingAuthorizer.authorize(tier.priceCents, tier.currency, memo = tier.name)) {
                is BillingResult.Authorized -> _events.send(
                    SubscriptionsEvent.NavigateToCheckout(
                        tierId = tierId,
                        creatorId = creatorId,
                        name = tier.name,
                        priceCents = tier.priceCents,
                        currency = tier.currency,
                        interval = tier.interval,
                        description = tier.description,
                    ),
                )
                is BillingResult.NotConfigured -> _events.send(SubscriptionsEvent.PaymentsUnavailable)
                is BillingResult.Cancelled -> Unit
                is BillingResult.Declined,
                is BillingResult.Failed,
                -> _events.send(SubscriptionsEvent.PaymentsUnavailable)
            }
        }
    }

    /** AND-237 — open the manage / cancel screen for the viewer's current subscription. */
    fun onManageClick() {
        viewModelScope.launch { _events.send(SubscriptionsEvent.NavigateToManage) }
    }

    private suspend fun currentTierIdOrNull(): String? =
        when (val subs = repository.getMySubscriptions()) {
            is ApiResult.Success -> subs.data
                .filter { it.creatorId == creatorId && it.isCurrentlyActive() }
                .maxByOrNull { it.currentPeriodEndEpochSeconds ?: 0L }
                ?.planId
            else -> null
        }

    private fun CreatorSubscription.isCurrentlyActive(): Boolean =
        status == SubscriptionState.ACTIVE || status == SubscriptionState.TRIALING

    private fun SubscriptionTier.toUiModel(currentTierId: String?): TierUiModel = TierUiModel(
        id = planId,
        name = name,
        description = description,
        priceCents = priceCents,
        currency = currency,
        interval = interval,
        perks = perks,
        isCurrent = planId == currentTierId,
    )

    private fun ApiResult<*>.messageOrOffline(): String = when (this) {
        is ApiResult.Failure -> error.message
        is ApiResult.NetworkError -> OFFLINE_MESSAGE
        is ApiResult.Success -> ""
    }

    companion object {
        const val ARG_CREATOR_ID = "creatorId"
        const val ARG_DISPLAY_NAME = "creatorDisplayName"

        /** Sentinel creator id used by the More-hub self-browse; resolves to the current user. */
        const val SELF = "me"
        private const val OFFLINE_MESSAGE = "You're offline"
    }
}
