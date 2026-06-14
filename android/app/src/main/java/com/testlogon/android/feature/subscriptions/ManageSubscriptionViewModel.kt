package com.testlogon.android.feature.subscriptions

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.ui.i18n.UiText
import com.testlogon.android.data.subscriptions.CancelSubscriptionReqDto
import com.testlogon.android.data.subscriptions.CreatorSubscription
import com.testlogon.android.data.subscriptions.RenewalReqDto
import com.testlogon.android.data.subscriptions.ResumeSubscriptionReqDto
import com.testlogon.android.data.subscriptions.SubscriptionState
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

/** AND-237 — in-flight mutation status for the manage screen. */
sealed interface MutationStatus {
    data object Idle : MutationStatus
    data object Canceling : MutationStatus
    data object Renewing : MutationStatus
    data class Failed(val message: UiText) : MutationStatus
}

/** AND-237 — manage / cancel subscription screen state. */
sealed interface ManageSubscriptionUiState {
    data object Loading : ManageSubscriptionUiState

    /** Empty: the viewer has no current subscription -> CTA to subscribe. */
    data object NoSubscription : ManageSubscriptionUiState

    data class Content(
        val subscription: CreatorSubscription,
        val mutation: MutationStatus = MutationStatus.Idle,
        val confirmCancelVisible: Boolean = false,
    ) : ManageSubscriptionUiState {
        /** Active and not scheduled to end -> show "Cancel subscription". */
        val canCancel: Boolean
            get() = subscription.status == SubscriptionState.ACTIVE && !subscription.cancelAtPeriodEnd

        /** Active but scheduled to cancel -> show "Keep subscription" (clears the scheduled cancel). */
        val isScheduledToCancel: Boolean
            get() = (subscription.status == SubscriptionState.ACTIVE ||
                subscription.status == SubscriptionState.TRIALING) && subscription.cancelAtPeriodEnd

        /** Fully canceled / expired -> show "Reactivate" (resume, no new payment). */
        val isReactivatable: Boolean
            get() = subscription.status == SubscriptionState.CANCELED ||
                subscription.status == SubscriptionState.EXPIRED
    }

    data class Error(val message: UiText, val retryable: Boolean) : ManageSubscriptionUiState
}

/** AND-237 — one-shot effects (Channel-backed). */
sealed interface ManageSubscriptionEvent {
    /** A reactivation needs a fresh payment authorization -> route to the AND-236 subscribe flow. */
    data class NavigateToSubscribe(val planId: String, val creatorId: String) : ManageSubscriptionEvent
}

/**
 * AND-237 — manage / cancel subscription presentation logic.
 *
 * Reuses the AND-234 [SubscriptionsRepository] (real `api/subscriptions` list + the
 * `.../{id}/cancel|renewal|resume` mutations) and [BillingErrorMapper] (AND-232) for failures. The
 * "current" subscription is the most-recent active/trialing entry, else the most-recently-ending one.
 *
 * Cancel uses cancel-at-period-end (the verified SubscriptionCancelIn default) behind a Material3
 * confirm dialog; on success the screen reflects the server-returned cancel-at-period-end / canceled
 * state. Renew clears a scheduled cancel via `renewal{auto_renew:true}`; reactivating a fully
 * canceled/expired sub uses `resume`. A billing-class mapper error on resume routes to AND-236.
 */
@HiltViewModel
class ManageSubscriptionViewModel @Inject constructor(
    private val repository: SubscriptionsRepository,
    private val errorMapper: BillingErrorMapper,
) : ViewModel() {

    private val _uiState = MutableStateFlow<ManageSubscriptionUiState>(ManageSubscriptionUiState.Loading)
    val uiState: StateFlow<ManageSubscriptionUiState> = _uiState.asStateFlow()

    private val _events = Channel<ManageSubscriptionEvent>(Channel.BUFFERED)
    val events: Flow<ManageSubscriptionEvent> = _events.receiveAsFlow()

    init {
        refresh()
    }

    fun refresh() {
        // Preserve a transient confirm-dialog flag across an explicit refresh only when content exists.
        _uiState.update {
            when (it) {
                is ManageSubscriptionUiState.Content -> it.copy(mutation = MutationStatus.Idle)
                else -> ManageSubscriptionUiState.Loading
            }
        }
        viewModelScope.launch {
            when (val result = repository.getMySubscriptions()) {
                is ApiResult.Success -> {
                    val current = result.data.pickCurrent()
                    _uiState.value = if (current == null) {
                        ManageSubscriptionUiState.NoSubscription
                    } else {
                        ManageSubscriptionUiState.Content(subscription = current)
                    }
                }
                else -> {
                    val error = errorMapper.map(result)
                    _uiState.value = ManageSubscriptionUiState.Error(
                        message = error.message,
                        retryable = error.recoverability == Recoverability.RETRYABLE,
                    )
                }
            }
        }
    }

    fun onCancelClicked() {
        val content = currentContent() ?: return
        if (content.mutation != MutationStatus.Idle) return
        _uiState.value = content.copy(confirmCancelVisible = true)
    }

    fun onCancelDismissed() {
        val content = currentContent() ?: return
        _uiState.value = content.copy(confirmCancelVisible = false)
    }

    fun onCancelConfirmed() {
        val content = currentContent() ?: return
        if (content.mutation != MutationStatus.Idle) return // concurrent-mutation guard
        _uiState.value = content.copy(confirmCancelVisible = false, mutation = MutationStatus.Canceling)
        viewModelScope.launch {
            val result = repository.cancel(
                content.subscription.subscriptionId,
                CancelSubscriptionReqDto(cancelAtPeriodEnd = true),
            )
            applyMutationResult(result)
        }
    }

    /**
     * AND-237 — "Keep subscription" / "Reactivate". For a scheduled-cancel active sub, clears the
     * cancel via renewal(auto_renew=true). For a fully canceled/expired sub, calls resume; if the
     * mapper classifies the resume failure as a billing/payment error, routes to AND-236 instead.
     */
    fun onRenewClicked() {
        val content = currentContent() ?: return
        if (content.mutation != MutationStatus.Idle) return // concurrent-mutation guard
        _uiState.value = content.copy(mutation = MutationStatus.Renewing)
        viewModelScope.launch {
            val sub = content.subscription
            val result = if (content.isReactivatable) {
                repository.resume(sub.subscriptionId, ResumeSubscriptionReqDto())
            } else {
                repository.renew(sub.subscriptionId, RenewalReqDto(autoRenew = true))
            }
            if (result !is ApiResult.Success && content.isReactivatable) {
                val error = errorMapper.map(result)
                // Reactivation that needs a fresh payment -> route to the subscribe flow (defensive:
                // classified by recoverability, NOT a hard-coded 402 per AND-237 §5).
                if (error.recoverability == Recoverability.REQUIRES_NEW_METHOD ||
                    error.recoverability == Recoverability.REQUIRES_ACTION
                ) {
                    _uiState.value = content.copy(mutation = MutationStatus.Idle)
                    _events.send(ManageSubscriptionEvent.NavigateToSubscribe(sub.planId, sub.creatorId))
                    return@launch
                }
            }
            applyMutationResult(result)
        }
    }

    fun onErrorRetry() = refresh()

    private suspend fun applyMutationResult(result: ApiResult<CreatorSubscription>) {
        val content = currentContent() ?: return
        when (result) {
            is ApiResult.Success ->
                // Single source of truth: reflect the server-returned subscription verbatim.
                _uiState.value = content.copy(subscription = result.data, mutation = MutationStatus.Idle)
            else -> {
                val error = errorMapper.map(result)
                _uiState.value = content.copy(mutation = MutationStatus.Failed(error.message))
            }
        }
    }

    private fun currentContent(): ManageSubscriptionUiState.Content? =
        _uiState.value as? ManageSubscriptionUiState.Content

    private fun List<CreatorSubscription>.pickCurrent(): CreatorSubscription? {
        if (isEmpty()) return null
        val activeLike = filter {
            it.status == SubscriptionState.ACTIVE ||
                it.status == SubscriptionState.TRIALING ||
                it.status == SubscriptionState.PAST_DUE
        }
        val pool = activeLike.ifEmpty { this }
        return pool.maxByOrNull { it.currentPeriodEndEpochSeconds ?: it.startAtEpochSeconds ?: 0L }
    }

    companion object {
        const val ROUTE = "subscriptions/manage"
    }
}
