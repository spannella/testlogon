package com.testlogon.android.feature.call.ui

import androidx.lifecycle.SavedStateHandle
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.data.call.CallMode
import com.testlogon.android.data.messaging.BillingAuthorizer
import com.testlogon.android.feature.call.billing.CallBillingDelegate
import com.testlogon.android.feature.call.billing.CallBillingUiState
import com.testlogon.android.feature.call.billing.PaidCallConfirmState
import com.testlogon.android.feature.call.domain.CallEndReason
import com.testlogon.android.feature.call.domain.CallManager
import com.testlogon.android.feature.call.domain.CallPhase
import com.testlogon.android.feature.call.domain.CallSessionState
import com.testlogon.android.feature.call.telecom.TelecomCallController
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.flow.receiveAsFlow
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.launch
import javax.inject.Inject

/** AND-296 — per-phase UI label key + duration the outgoing-call screen renders. */
data class CallUiState(
    val peerName: String?,
    val phase: CallUiPhase,
    val elapsedSeconds: Long,
    val mediaUnavailable: Boolean,
    val canRetry: Boolean,
)

/** Coarse UI phase derived from the domain [CallPhase]. */
enum class CallUiPhase { CALLING, RINGING, CONNECTING, CONNECTED, ENDING, ENDED, FAILED }

/** One-shot effects (close the screen). Channel + receiveAsFlow (never distinctUntilChanged). */
sealed interface OutgoingCallEffect {
    data object Finish : OutgoingCallEffect
}

/**
 * AND-296 — thin adapter mapping [CallManager.state] -> [CallUiState]. The CallManager owns the lifecycle
 * (app-scoped) so this VM is stateless beyond the mapping; placing the call is driven from the entry point
 * via [start] (single-active guarded by the manager).
 */
@HiltViewModel
class OutgoingCallViewModel @Inject constructor(
    private val callManager: CallManager,
    // AND-301: the FLAGGED wallet-balance seam (AND-031). It returns NotConfigured, so the pre-start
    // balance is unknown -> the confirm dialog shows the rate, flags the balance as unavailable, and still
    // allows Start (do NOT block start on an unknown balance; no payment SDK is invoked).
    private val billingAuthorizer: BillingAuthorizer,
    // AND-304: best-effort self-managed Telecom modeling, UNDER the AND-296 flow. Optional/guarded — a
    // Telecom failure never affects placing the call (the control-plane invite below is authoritative).
    private val telecomCallController: TelecomCallController,
    // #18 — resolve the callee's real display name when the launching screen didn't pass a peerName
    // (the thread header title may not have resolved yet), so the call never shows "Unknown caller".
    private val displayNames: com.testlogon.android.data.profile.DisplayNameResolver,
    savedState: SavedStateHandle,
) : ViewModel() {

    private val conversationId: String = savedState.get<String>(ARG_CONVERSATION_ID).orEmpty()
    private val calleeUserId: String = savedState.get<String>(ARG_CALLEE_USER_ID).orEmpty()
    private val mode: CallMode = CallMode.fromWire(savedState.get<String>(ARG_MODE))
    private val peerName: String? = savedState.get<String>(ARG_PEER_NAME)
    // #18 — best display name known so far for the peer: the nav-arg name, else the resolved name,
    // else the callee id itself (we always KNOW the peer, so never show "Unknown caller").
    private val resolvedPeerName = MutableStateFlow(
        peerName?.takeIf { it.isNotBlank() } ?: calleeUserId.takeIf { it.isNotBlank() },
    )
    private val paid: Boolean = savedState[ARG_PAID] ?: false
    private val rateCentsPerMin: Int? = savedState.get<Int>(ARG_RATE_CENTS_PER_MIN)

    private val effects = Channel<OutgoingCallEffect>(Channel.BUFFERED)
    val effect = effects.receiveAsFlow()

    // AND-301: the billing layer is a separate StateFlow so the call-flow CallUiState mapping is untouched.
    private val billingDelegate = CallBillingDelegate()
    private val _billing = MutableStateFlow(CallBillingUiState.free())
    val billing: StateFlow<CallBillingUiState> = _billing.asStateFlow()

    val uiState: StateFlow<CallUiState> =
        kotlinx.coroutines.flow.combine(callManager.state, resolvedPeerName) { session, name ->
            session.toUi(name)
        }.stateIn(
            scope = viewModelScope,
            started = SharingStarted.WhileSubscribed(5_000),
            initialValue = CallSessionState().toUi(resolvedPeerName.value),
        )

    init {
        // #18 — when the launching screen didn't pass a real display name, resolve the callee's name
        // (the id is shown meanwhile) and upgrade in place once it arrives.
        if (peerName.isNullOrBlank() && calleeUserId.isNotBlank()) {
            displayNames.resolve(calleeUserId)?.let { resolvedPeerName.value = it }
            viewModelScope.launch {
                displayNames.names.collect { names ->
                    val n = names[calleeUserId]
                    if (!n.isNullOrBlank()) resolvedPeerName.value = n
                }
            }
        }
        // AND-301: seed the paid-call confirm BEFORE placing the call. The wallet balance comes from the
        // FLAGGED seam (NotConfigured -> null balance), so the dialog allows Start.
        if (paid && rateCentsPerMin != null) {
            viewModelScope.launch { seedBilling() }
        } else {
            // Place the call once if the manager is idle (re-entering the screen after a config change must
            // not re-invite — the manager guards via isBusy()).
            start()
        }
    }

    /** AND-301: route the pre-start balance check through the FLAGGED seam, then arm the confirm gate. */
    private suspend fun seedBilling() {
        val rate = rateCentsPerMin ?: return
        // The seam returns NotConfigured -> we treat the wallet balance as UNKNOWN (null) and allow start.
        billingAuthorizer.authorize(amountMinorUnits = rate.toLong(), currency = "USD")
        _billing.value = billingDelegate.onInvite(
            paid = true,
            rateCentsPerMinute = rate,
            balanceRemainingCents = null,
        )
    }

    /** AND-301: user confirmed the paid call — open the gate and place the call. */
    fun onConfirmPaidCall() {
        _billing.value = billingDelegate.confirmPaidCall(_billing.value)
        start()
    }

    /** AND-301: user cancelled the paid call before start — record it and finish the screen. */
    fun onCancelPaidCall() {
        _billing.value = billingDelegate.cancel(_billing.value)
        callManager.endCall(CallEndReason.HANGUP)
        callManager.reset()
        viewModelScope.launch { effects.send(OutgoingCallEffect.Finish) }
    }

    fun start() {
        if (conversationId.isBlank() || calleeUserId.isBlank()) return
        // AND-301: a paid call only starts once the user has confirmed the gate (Confirmed); a free call
        // starts immediately. This guard makes start() safe to call from both init and onConfirmPaidCall.
        if (paid && _billing.value.confirm !is PaidCallConfirmState.Confirmed) return
        // AND-304: model the call to the OS via self-managed Telecom (audio focus / DND / headset). This is
        // additive and fully guarded: placeOutgoing() returns false (and no-ops) on unsupported devices or
        // any OEM failure, so the AND-296 placeCall() below ALWAYS runs and remains the source of truth.
        val effectivePeerName = resolvedPeerName.value ?: peerName
        runCatching {
            telecomCallController.placeOutgoing(
                callId = com.testlogon.android.data.call.CallId.new(),
                displayName = effectivePeerName,
                video = mode == CallMode.VIDEO,
            )
        }
        callManager.placeCall(
            conversationId = conversationId,
            calleeUserId = calleeUserId,
            mode = mode,
            peerName = effectivePeerName,
            paid = paid,
            rateCentsPerMin = rateCentsPerMin,
        )
    }

    fun onHangUp() = callManager.endCall(CallEndReason.HANGUP)

    /** User dismissed a terminal/failed call: reset the manager and ask the screen to finish. */
    fun onClose() {
        callManager.reset()
        viewModelScope.launch { effects.send(OutgoingCallEffect.Finish) }
    }

    private fun CallSessionState.toUi(name: String? = resolvedPeerName.value): CallUiState = CallUiState(
        peerName = name ?: peerName,
        phase = phase.toUiPhase(),
        elapsedSeconds = elapsedSeconds,
        mediaUnavailable = mediaUnavailable,
        canRetry = phase is CallPhase.Failed,
    )

    private fun CallPhase.toUiPhase(): CallUiPhase = when (this) {
        CallPhase.Idle, CallPhase.Inviting -> CallUiPhase.CALLING
        CallPhase.Ringing -> CallUiPhase.RINGING
        CallPhase.Connecting -> CallUiPhase.CONNECTING
        is CallPhase.Connected -> CallUiPhase.CONNECTED
        CallPhase.Ending -> CallUiPhase.ENDING
        is CallPhase.Ended -> CallUiPhase.ENDED
        is CallPhase.Failed -> CallUiPhase.FAILED
    }

    companion object {
        const val ARG_CONVERSATION_ID = "conversationId"
        const val ARG_CALLEE_USER_ID = "calleeUserId"
        const val ARG_MODE = "mode"
        const val ARG_PEER_NAME = "peerName"

        /** AND-301 — outgoing-call nav args carrying the paid/rate intent for a paid call. */
        const val ARG_PAID = "paid"
        const val ARG_RATE_CENTS_PER_MIN = "rateCentsPerMin"
    }
}
