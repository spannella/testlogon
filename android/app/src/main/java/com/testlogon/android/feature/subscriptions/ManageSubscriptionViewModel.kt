package com.testlogon.android.feature.subscriptions

import androidx.lifecycle.SavedStateHandle
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.ui.i18n.UiText
import com.testlogon.android.data.messaging.BillingAuthorizer
import com.testlogon.android.data.messaging.BillingResult
import com.testlogon.android.data.subscriptions.CancelSubscriptionReqDto
import com.testlogon.android.data.subscriptions.ChangePlanReqDto
import com.testlogon.android.data.subscriptions.CreatorSubscription
import com.testlogon.android.data.subscriptions.RenewalReqDto
import com.testlogon.android.data.subscriptions.ResumeSubscriptionReqDto
import com.testlogon.android.data.subscriptions.RetryPaymentReqDto
import com.testlogon.android.data.subscriptions.SubscriptionState
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

/** AND-237 / SUB-E2 - in-flight mutation status for the manage screen. */
sealed interface MutationStatus {
    data object Idle : MutationStatus
    data object Canceling : MutationStatus
    data object Renewing : MutationStatus
    data object Changing : MutationStatus

    /** SUBX-22 - retrying a PAST_DUE renewal charge (dunning recovery). */
    data object RetryingPayment : MutationStatus

    /** SUBX-52 - converting a TRIALING sub to paid early (charge now). */
    data object ConvertingTrial : MutationStatus
    data class Failed(val message: UiText) : MutationStatus
}

/** SUB-E2 - the cancel choice presented in the cancel dialog. */
enum class CancelChoice { AT_PERIOD_END, IMMEDIATE_REFUND }

/** AND-237 / SUB-E2 - manage / cancel subscription screen state. */
sealed interface ManageSubscriptionUiState {
    data object Loading : ManageSubscriptionUiState

    /** Empty: the viewer has no current subscription -> CTA to subscribe. */
    data object NoSubscription : ManageSubscriptionUiState

    data class Content(
        val subscription: CreatorSubscription,
        val mutation: MutationStatus = MutationStatus.Idle,
        val confirmCancelVisible: Boolean = false,
        /** SUB-E2 - other active tiers from the same creator, for upgrade/downgrade. */
        val availableTiers: List<SubscriptionTier> = emptyList(),
        /** SUB-E2 - the tier chosen for a change-plan confirm (null = no dialog). */
        val changeTarget: SubscriptionTier? = null,
        /** SUBX-21 - the sub's human tier name (joined from the plan) instead of the raw plan id. */
        val planName: String? = null,
        /** SUBX-21 - the creator's display name (from the nav arg), for "Tier - Creator" headline. */
        val creatorName: String? = null,
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

        /** SUBX-22 - PAST_DUE (dunning) -> expose update-card + retry-payment recovery actions. */
        val isPastDue: Boolean
            get() = subscription.status == SubscriptionState.PAST_DUE

        /**
         * SUBX-52 - a TRIALING sub not scheduled to cancel may be converted to paid EARLY (charge now).
         * Delegates to the pure [TrialConvertMath.canConvert] so the rule stays JVM-tested + single-sourced.
         */
        val canConvertTrial: Boolean
            get() = TrialConvertMath.canConvert(subscription)

        /** SUB-E2 - upgrade/downgrade is offered while the sub is active/trialing and not ending. */
        val canChangePlan: Boolean
            get() = (subscription.status == SubscriptionState.ACTIVE ||
                subscription.status == SubscriptionState.TRIALING) &&
                !subscription.cancelAtPeriodEnd && availableTiers.isNotEmpty()

        /** SUB-E2 - true when [changeTarget] costs more than the current plan (immediate prorated charge). */
        val changeTargetIsUpgrade: Boolean
            get() {
                val t = changeTarget ?: return false
                // SUBX-24: classify by MONTHLY-EQUIVALENT price so a $50/yr vs an $8/mo plan is not
                // mislabelled an "upgrade" by raw price (matches the backend M5 fix).
                return monthlyEquivCents(t.priceCents, t.interval) >
                    monthlyEquivCents(subscription.priceCents ?: 0L, subscription.interval)
            }
    }

    data class Error(val message: UiText, val retryable: Boolean) : ManageSubscriptionUiState
}

/** AND-237 - one-shot effects (Channel-backed). */
sealed interface ManageSubscriptionEvent {
    /** A reactivation needs a fresh payment authorization -> route to the AND-236 subscribe flow. */
    data class NavigateToSubscribe(val planId: String, val creatorId: String) : ManageSubscriptionEvent

    /** SUBX-22 - route to add/select a payment method (card-less user / PAST_DUE card update). */
    data object NavigateToAddCard : ManageSubscriptionEvent
}

/**
 * AND-237 / SUB-E2 - manage / cancel / change-plan presentation logic.
 *
 * Loads the current subscription (most-recent active/trialing entry) plus the creator's other active
 * plans so the subscriber can UPGRADE (immediate prorated delta charge) or DOWNGRADE (scheduled at
 * period end). Cancel offers the locked-decision choice: at-period-end (default, keeps access, no
 * refund) or immediate + refund of the unused prorated portion. Reuses the AND-234
 * [SubscriptionsRepository], the [BillingAuthorizer] payment seam (for an upgrade PM), and
 * [BillingErrorMapper].
 */
@HiltViewModel
class ManageSubscriptionViewModel @Inject constructor(
    savedStateHandle: SavedStateHandle,
    private val repository: SubscriptionsRepository,
    private val billingAuthorizer: BillingAuthorizer,
    private val errorMapper: BillingErrorMapper,
) : ViewModel() {

    // SUBX-21 - the SPECIFIC sub to manage (from My-subscriptions / a creator's tier page). Absent for
    // the legacy arg-less More-hub entry, which falls back to the viewer's most-recent active sub.
    private val targetSubscriptionId: String? =
        savedStateHandle.get<String>(ARG_SUBSCRIPTION_ID)?.takeIf { it.isNotBlank() }
    private val targetCreatorId: String? =
        savedStateHandle.get<String>(ARG_CREATOR_ID)?.takeIf { it.isNotBlank() }
    private val targetCreatorName: String? =
        savedStateHandle.get<String>(ARG_CREATOR_NAME)?.takeIf { it.isNotBlank() }

    private val _uiState = MutableStateFlow<ManageSubscriptionUiState>(ManageSubscriptionUiState.Loading)
    val uiState: StateFlow<ManageSubscriptionUiState> = _uiState.asStateFlow()

    private val _events = Channel<ManageSubscriptionEvent>(Channel.BUFFERED)
    val events: Flow<ManageSubscriptionEvent> = _events.receiveAsFlow()

    init {
        refresh()
    }

    fun refresh() {
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
                    if (current == null) {
                        _uiState.value = ManageSubscriptionUiState.NoSubscription
                    } else {
                        _uiState.value = ManageSubscriptionUiState.Content(
                            subscription = current,
                            creatorName = targetCreatorName,
                        )
                        loadTiers(current)
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

    /** SUB-E2 - fetch the creator's other active plans to power upgrade/downgrade. */
    private fun loadTiers(sub: CreatorSubscription) {
        viewModelScope.launch {
            when (val result = repository.getCreatorTiers(sub.creatorId)) {
                is ApiResult.Success -> {
                    val others = result.data.filter { it.isActive && it.planId != sub.planId }
                    // SUBX-21 - join the sub to its plan for a human tier name (was: raw plan id).
                    val planName = result.data.firstOrNull { it.planId == sub.planId }?.name
                    val content = currentContent() ?: return@launch
                    if (content.subscription.subscriptionId == sub.subscriptionId) {
                        _uiState.value = content.copy(availableTiers = others, planName = planName)
                    }
                }
                else -> Unit // best-effort: change-plan section stays hidden on failure
            }
        }
    }

    // ---- Cancel ----

    fun onCancelClicked() {
        val content = currentContent() ?: return
        if (content.mutation != MutationStatus.Idle) return
        _uiState.value = content.copy(confirmCancelVisible = true)
    }

    fun onCancelDismissed() {
        val content = currentContent() ?: return
        _uiState.value = content.copy(confirmCancelVisible = false)
    }

    /** SUB-E2 - confirm cancel with the chosen mode (at-period-end vs immediate+refund). */
    fun onCancelConfirmed(choice: CancelChoice = CancelChoice.AT_PERIOD_END) {
        val content = currentContent() ?: return
        if (content.mutation != MutationStatus.Idle) return
        _uiState.value = content.copy(confirmCancelVisible = false, mutation = MutationStatus.Canceling)
        viewModelScope.launch {
            val body = when (choice) {
                CancelChoice.AT_PERIOD_END -> CancelSubscriptionReqDto(cancelAtPeriodEnd = true)
                CancelChoice.IMMEDIATE_REFUND ->
                    CancelSubscriptionReqDto(cancelAtPeriodEnd = false, refund = true)
            }
            val result = repository.cancel(content.subscription.subscriptionId, body)
            applyMutationResult(result)
        }
    }

    // ---- Change plan (upgrade / downgrade) ----

    fun onChangePlanClicked(tier: SubscriptionTier) {
        val content = currentContent() ?: return
        if (content.mutation != MutationStatus.Idle) return
        _uiState.value = content.copy(changeTarget = tier)
    }

    fun onChangePlanDismissed() {
        val content = currentContent() ?: return
        _uiState.value = content.copy(changeTarget = null)
    }

    /**
     * SUB-E2 - confirm the plan change. An UPGRADE authorizes a PM for the prorated delta (the backend
     * charges it immediately + credits the creator NET); a DOWNGRADE takes no payment (scheduled at
     * period end). The backend routes by price, so effective is omitted here.
     */
    fun onChangePlanConfirmed() {
        val content = currentContent() ?: return
        val target = content.changeTarget ?: return
        if (content.mutation != MutationStatus.Idle) return
        val isUpgrade = content.changeTargetIsUpgrade
        _uiState.value = content.copy(changeTarget = null, mutation = MutationStatus.Changing)
        viewModelScope.launch {
            var pm: String? = null
            if (isUpgrade) {
                when (val auth = billingAuthorizer.authorize(target.priceCents, target.currency, memo = target.name)) {
                    is BillingResult.Authorized -> pm = auth.paymentMethodId
                    is BillingResult.Cancelled -> {
                        _uiState.value = content.copy(mutation = MutationStatus.Idle)
                        return@launch
                    }
                    else -> {
                        // No configured PM -> surface a payment error (add a card, then retry).
                        _uiState.value = content.copy(
                            mutation = MutationStatus.Failed(
                                UiText.Res(com.testlogon.android.R.string.manage_sub_change_needs_payment),
                            ),
                        )
                        return@launch
                    }
                }
            }
            val result = repository.changePlan(
                content.subscription.subscriptionId,
                ChangePlanReqDto(
                    planId = target.planId,
                    paymentMethodId = pm?.takeIf { it.isNotBlank() },
                    reason = if (isUpgrade) "upgrade" else "downgrade",
                ),
            )
            applyMutationResult(result, reloadTiers = true)
        }
    }

    // ---- Keep / reactivate ----

    fun onRenewClicked() {
        val content = currentContent() ?: return
        if (content.mutation != MutationStatus.Idle) return
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
                // SUBX-23 - honest reactivate: a lapsed sub (backend 409) or a card/action-required
                // failure can't be resumed for free -> route to the paid subscribe flow instead of
                // ever showing a false "active" (never active-but-locked).
                if (error.httpStatus == HTTP_CONFLICT ||
                    error.recoverability == Recoverability.REQUIRES_NEW_METHOD ||
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

    // ---- SUBX-22: PAST_DUE dunning recovery ----

    /** SUBX-22 - route to add/select a card; the user returns and taps Retry payment. */
    fun onUpdateCardClicked() {
        val content = currentContent() ?: return
        if (content.mutation != MutationStatus.Idle) return
        viewModelScope.launch { _events.send(ManageSubscriptionEvent.NavigateToAddCard) }
    }

    /**
     * SUBX-22 - retry the failed renewal charge on a PAST_DUE sub via the backend recovery endpoint
     * (same funds-guarded rail as the sweeper). A real collected charge clears past_due -> active; a
     * decline (402) surfaces an error prompting a card update.
     */
    fun onRetryPaymentClicked() {
        val content = currentContent() ?: return
        if (content.mutation != MutationStatus.Idle) return
        _uiState.value = content.copy(mutation = MutationStatus.RetryingPayment)
        viewModelScope.launch {
            val result = repository.retryPayment(content.subscription.subscriptionId, RetryPaymentReqDto())
            applyMutationResult(result)
        }
    }

    /**
     * SUBX-52 - convert the TRIALING sub to paid EARLY via the backend convert endpoint (same
     * funds-guarded rail as the trial-end sweeper). A real collected charge flips trialing -> active; a
     * decline / missing PM (402) or a non-trial state (400) surfaces a mutation error.
     */
    fun onConvertTrialClicked() {
        val content = currentContent() ?: return
        if (content.mutation != MutationStatus.Idle) return
        if (!content.canConvertTrial) return
        _uiState.value = content.copy(mutation = MutationStatus.ConvertingTrial)
        viewModelScope.launch {
            val result = repository.convertTrial(content.subscription.subscriptionId)
            applyMutationResult(result)
        }
    }

    fun onErrorRetry() = refresh()

    private suspend fun applyMutationResult(
        result: ApiResult<CreatorSubscription>,
        reloadTiers: Boolean = false,
    ) {
        val content = currentContent() ?: return
        when (result) {
            is ApiResult.Success -> {
                _uiState.value = content.copy(subscription = result.data, mutation = MutationStatus.Idle)
                if (reloadTiers) loadTiers(result.data)
            }
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
        // SUBX-21 - resolve the SPECIFIC sub the caller asked for (by id, then by creator) so a
        // multi-creator subscriber lands on the RIGHT sub, not the global most-recent one.
        targetSubscriptionId?.let { id -> firstOrNull { it.subscriptionId == id }?.let { return it } }
        val scoped = targetCreatorId?.let { cid -> filter { it.creatorId == cid } } ?: this
        val fromScope = scoped.ifEmpty { this }
        val activeLike = fromScope.filter {
            it.status == SubscriptionState.ACTIVE ||
                it.status == SubscriptionState.TRIALING ||
                it.status == SubscriptionState.PAST_DUE
        }
        val pool = activeLike.ifEmpty { fromScope }
        return pool.maxByOrNull { it.currentPeriodEndEpochSeconds ?: it.startAtEpochSeconds ?: 0L }
    }

    companion object {
        const val ROUTE = "subscriptions/manage"
        const val ARG_SUBSCRIPTION_ID = "subscriptionId"
        const val ARG_CREATOR_ID = "creatorId"
        const val ARG_CREATOR_NAME = "creatorName"
        private const val HTTP_CONFLICT = 409
    }
}
