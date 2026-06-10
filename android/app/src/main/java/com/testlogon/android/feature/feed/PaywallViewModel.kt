package com.testlogon.android.feature.feed

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.data.paywall.PaywallRepository
import com.testlogon.android.data.paywall.UnlockOutcome
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import javax.inject.Inject

/**
 * AND-177 — drives the unlock flow behind the AND-101 paywall CTA. Per-post state machine
 * Idle -> InProgress -> (Unlocked | AlreadyEntitled | SoldOut | PaymentsUnavailable | Failed).
 *
 * The reveal is cache-driven: on Success/AlreadyEntitled the repository writes the entitlement row and
 * the feed's [PaywallRepository.entitledPostIds] flow recomposes the post to its unlocked branch
 * (no navigation). A second tap while InProgress is a no-op (idempotent re-entry guard, FR-5).
 */
@HiltViewModel
class PaywallViewModel @Inject constructor(
    private val repo: PaywallRepository,
) : ViewModel() {

    private val _states = MutableStateFlow<Map<String, UnlockState>>(emptyMap())
    val states: StateFlow<Map<String, UnlockState>> = _states.asStateFlow()

    fun unlock(postId: String) {
        if (_states.value[postId] is UnlockState.InProgress) return // FR-5 double-tap no-op
        _states.update { it + (postId to UnlockState.InProgress) }
        viewModelScope.launch {
            val next = when (val outcome = repo.unlock(postId)) {
                is UnlockOutcome.Success -> UnlockState.Unlocked
                UnlockOutcome.AlreadyEntitled -> UnlockState.Unlocked
                UnlockOutcome.PaymentsUnavailable -> UnlockState.PaymentsUnavailable
                UnlockOutcome.SoldOut -> UnlockState.SoldOut
                is UnlockOutcome.Cancelled -> UnlockState.Idle
                is UnlockOutcome.Failure -> UnlockState.Failed(outcome.message, outcome.retryable)
            }
            _states.update { it + (postId to next) }
        }
    }

    fun retry(postId: String) {
        _states.update { it - postId }
        unlock(postId)
    }

    fun dismiss(postId: String) {
        _states.update { it - postId }
    }
}

/** AND-177 — observable unlock state for a single locked post. */
sealed interface UnlockState {
    data object Idle : UnlockState
    data object InProgress : UnlockState
    data object Unlocked : UnlockState
    data object SoldOut : UnlockState

    /** STOP-AND-FLAG (payments): no billing provider wired; CTA shows "payments unavailable". */
    data object PaymentsUnavailable : UnlockState
    data class Failed(val message: String, val retryable: Boolean) : UnlockState
}
