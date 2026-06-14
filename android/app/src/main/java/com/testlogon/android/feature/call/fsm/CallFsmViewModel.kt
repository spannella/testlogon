package com.testlogon.android.feature.call.fsm

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.data.cache.Clock
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.SharedFlow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.flow.flow
import kotlinx.coroutines.flow.stateIn
import javax.inject.Inject

/**
 * AND-305 — thin, ADDITIVE ViewModel over the canonical [CallStateMachine].
 *
 * Named CallFsmViewModel to avoid clashing with the existing
 * [com.testlogon.android.feature.call.ui.OutgoingCallViewModel] /
 * [com.testlogon.android.feature.call.incall.InCallViewModel] (AND-296/298), which keep their current VMs
 * and screens. This VM is NOT wired into navigation yet — migrating the screens to it is a FOLLOW-UP.
 *
 * It owns NO state: it projects [CallStateMachine.state] into [CallUiState] (1Hz duration driven by a
 * bounded ticker that lives inside the WhileSubscribed stateIn — it stops when nothing collects) and
 * forwards [CallIntent] to the machine. The one-shot [effects] flow is re-exposed for transient UI.
 */
@HiltViewModel
class CallFsmViewModel @Inject constructor(
    private val stateMachine: CallStateMachine,
    private val clock: Clock,
) : ViewModel() {

    /** Re-exposed one-shot effects (PlayRingback / StopAudio / Error / CallBusy). */
    val effects: SharedFlow<CallEffect> = stateMachine.effects

    // Bounded 1Hz ticker; lives inside the WhileSubscribed stateIn below so it never runs unbounded.
    private val ticker = flow {
        while (true) {
            emit(Unit)
            delay(1_000L)
        }
    }

    val uiState: StateFlow<CallUiState> = combine(stateMachine.state, ticker) { state, _ ->
        CallUiState.project(state, clock.now())
    }.stateIn(
        scope = viewModelScope,
        started = SharingStarted.WhileSubscribed(5_000L),
        initialValue = CallUiState.project(stateMachine.state.value, clock.now()),
    )

    fun onIntent(intent: CallIntent) = stateMachine.dispatch(intent.toEvent())
}
