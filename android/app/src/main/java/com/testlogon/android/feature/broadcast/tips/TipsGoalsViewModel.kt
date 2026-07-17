package com.testlogon.android.feature.broadcast.tips

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.broadcast.chat.BroadcastChatRepository
import com.testlogon.android.data.broadcast.chat.ChatStreamEvent
import com.testlogon.android.data.broadcast.chat.ChatStreamSignal
import com.testlogon.android.data.broadcast.tips.Goal
import com.testlogon.android.data.broadcast.tips.TipsRepository
import com.testlogon.android.data.broadcast.tips.TipsSummary
import com.testlogon.android.data.messaging.BillingAuthorizer
import com.testlogon.android.data.messaging.BillingResult
import com.testlogon.android.feature.common.tip.TipVisibility
import dagger.assisted.Assisted
import dagger.assisted.AssistedFactory
import dagger.assisted.AssistedInject
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.flow.receiveAsFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch

/** AND-282 — the tip composer + goals view-state. Money is integer cents throughout. */
data class TipsGoalsUiState(
    val summary: TipsSummary? = null,
    val goals: List<Goal> = emptyList(),
    val loading: Boolean = true,
    val error: Boolean = false,
    val tipInFlight: Boolean = false,
)

/** AND-282 — one-shot effects (snackbars / sheet dismissal) consumed exactly once by the screen. */
sealed interface TipsEffect {
    data object TipSent : TipsEffect
    data object TipSentPrivate : TipsEffect
    data object PaymentsUnavailable : TipsEffect
    data class TipFailed(val message: String?) : TipsEffect
}

/**
 * AND-282 — tips + goals presentation logic for a single broadcast session.
 *
 * Combines the [TipsRepository] summary + goals flows into [uiState]; triggers a goals/summary
 * [TipsRepository.refresh] on entry, on a successful local tip, and on a tip-bearing chat:message
 * arriving over the AND-281 broadcast SSE stream (there is NO goal_update event in the contract).
 *
 * Tip charge routes through [BillingAuthorizer]: when the stub returns [BillingResult.NotConfigured] the
 * POST is NEVER made (no charge, no fake) and a "payments unavailable" effect is surfaced. The POST is
 * not auto-retried. Built with AssistedInject so the sessionId is supplied at the call site.
 */
@HiltViewModel(assistedFactory = TipsGoalsViewModel.Factory::class)
class TipsGoalsViewModel @AssistedInject constructor(
    @Assisted private val sessionId: String,
    private val repo: TipsRepository,
    private val chatRepo: BroadcastChatRepository,
    private val billing: BillingAuthorizer,
) : ViewModel() {

    @AssistedFactory
    interface Factory {
        fun create(sessionId: String): TipsGoalsViewModel
    }

    private val loading = MutableStateFlow(true)
    private val error = MutableStateFlow(false)
    private val tipInFlight = MutableStateFlow(false)

    private val _effects = Channel<TipsEffect>(Channel.BUFFERED)
    val effects = _effects.receiveAsFlow()

    private val _uiState = MutableStateFlow(TipsGoalsUiState())
    val uiState: StateFlow<TipsGoalsUiState> = _uiState.asStateFlow()

    init {
        viewModelScope.launch {
            combine(
                repo.observeTipsSummary(),
                repo.observeGoals(),
                loading,
                error,
                tipInFlight,
            ) { summary, goals, isLoading, isError, inFlight ->
                TipsGoalsUiState(
                    summary = summary,
                    goals = goals,
                    loading = isLoading,
                    error = isError,
                    tipInFlight = inFlight,
                )
            }.collect { state -> _uiState.value = state }
        }
        observeTipEvents()
        refresh()
    }

    /** Loads goals + summary once (idempotent GETs). */
    fun refresh() {
        loading.value = true
        viewModelScope.launch {
            error.value = repo.refresh(sessionId) !is ApiResult.Success
            loading.value = false
        }
    }

    fun retry() = refresh()

    /**
     * Authorizes the tip via [BillingAuthorizer], then (only if Authorized) POSTs it and refreshes
     * summary/goals. Validates the amount against [MIN_TIP_CENTS]..[MAX_TIP_CENTS] and a non-empty
     * payment method. NotConfigured surfaces a payments-unavailable effect and NEVER charges/POSTs.
     */
    fun submitTip(
        amountCents: Long,
        text: String?,
        currency: String = DEFAULT_CURRENCY,
        visibility: TipVisibility = TipVisibility.Default,
    ) {
        if (amountCents !in MIN_TIP_CENTS..MAX_TIP_CENTS) {
            _effects.trySend(TipsEffect.TipFailed(null))
            return
        }
        if (tipInFlight.value) return
        tipInFlight.value = true
        viewModelScope.launch {
            try {
                when (val auth = billing.authorize(amountCents, currency, memo = TIP_MEMO)) {
                    is BillingResult.Authorized -> {
                        // TIPX-B1 (F1) - a BLANK payment-method id is the DEBUG/dev-demo path
                        // (RealBillingAuthorizer authorizes blank; the dev backend mock-completes the
                        // charge + falls back to the tip-default PM). Only a RELEASE build treats blank
                        // as "no instrument -> payments unavailable"; in DEBUG we proceed so live-
                        // broadcast tipping works end-to-end in the demo/test build.
                        if (auth.paymentMethodId.isBlank() && !com.testlogon.android.BuildConfig.DEBUG) {
                            _effects.trySend(TipsEffect.PaymentsUnavailable)
                            return@launch
                        }
                        val result = repo.submitTip(
                            sessionId = sessionId,
                            amountCents = amountCents,
                            paymentMethodId = auth.paymentMethodId,
                            text = text?.takeIf { it.isNotBlank() },
                            currency = currency,
                        )
                        when (result) {
                            is ApiResult.Success -> {
                                _effects.trySend(
                                    if (visibility.isPrivate) TipsEffect.TipSentPrivate else TipsEffect.TipSent,
                                )
                                repo.refresh(sessionId)
                            }
                            is ApiResult.Failure -> _effects.trySend(TipsEffect.TipFailed(result.error.message))
                            is ApiResult.NetworkError -> _effects.trySend(TipsEffect.TipFailed(null))
                        }
                    }
                    // NotConfigured / Cancelled / Declined / Failed: NEVER POST a tip (no charge).
                    BillingResult.NotConfigured -> _effects.trySend(TipsEffect.PaymentsUnavailable)
                    BillingResult.Cancelled -> Unit
                    is BillingResult.Declined -> _effects.trySend(TipsEffect.TipFailed(auth.reason))
                    is BillingResult.Failed -> _effects.trySend(TipsEffect.TipFailed(null))
                }
            } finally {
                tipInFlight.update { false }
            }
        }
    }

    /**
     * Subscribes to the AND-281 broadcast SSE stream and triggers a goals/summary refresh whenever a
     * tip-bearing chat:message arrives (kind == "tip"); goal progress is not pushed over SSE, so a
     * re-GET is the reconciliation mechanism (FR-6).
     */
    private fun observeTipEvents() {
        viewModelScope.launch {
            chatRepo.chatEvents(sessionId).collect { signal ->
                if (signal is ChatStreamSignal.Decoded) {
                    val event = signal.event
                    if (event is ChatStreamEvent.MessageReceived && event.message.kind == TIP_KIND) {
                        repo.refresh(sessionId)
                    }
                }
            }
        }
    }

    companion object {
        const val DEFAULT_CURRENCY = "USD"
        const val TIP_MEMO = "Broadcast tip"
        const val TIP_KIND = "tip"

        /** Backend hard bounds on BroadcastChatTipIn.amount_cents. */
        const val MIN_TIP_CENTS = 100L
        const val MAX_TIP_CENTS = 100_000L

        /** Web preset chips, in cents ($1 / $5 / $10 / $25). */
        val PRESET_CENTS: List<Long> = listOf(100L, 500L, 1_000L, 2_500L)
    }
}
