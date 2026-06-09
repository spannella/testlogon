package com.testlogon.android.feature.auth.recovery

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.auth.PasswordRecoveryRepository
import com.testlogon.android.data.auth.RecoveryStartOutcome
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.channels.BufferOverflow
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharedFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asSharedFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import javax.inject.Inject

/** Masked delivery summary rendered on the recovery screens (AND-057/058). */
data class DeliverySummary(val medium: String, val destinationMasked: String?)

/** One-shot navigation effects from the recovery-start screen (AND-057). */
sealed interface RecoveryStartEffect {
    /** A challenge was issued → advance to the challenge/verify step (AND-058). */
    data class ProceedToChallenge(
        val username: String,
        val challengeId: String,
        val requiredFactors: List<String>,
        val delivery: DeliverySummary?,
    ) : RecoveryStartEffect
}

/**
 * Hoisted recovery-start screen state (AND-057). The [username] is PII (not a secret) and is excluded
 * from [toString] so it is never accidentally logged.
 */
data class RecoveryStartUiState(
    val username: String = "",
    val isSubmitting: Boolean = false,
    val sentConfirmation: DeliverySummary? = null,
    val error: String? = null,
) {
    val canContinue: Boolean get() = username.isNotBlank() && !isSubmitting

    override fun toString(): String =
        "RecoveryStartUiState(username=***, isSubmitting=$isSubmitting, " +
            "sentConfirmation=$sentConfirmation, error=$error)"
}

/**
 * Drives the password-recovery start step (AND-057).
 *
 * [onContinue] trims the username and calls `POST /ui/password-recovery/start`.
 *
 * CONTRACT:
 *  - POST → never auto-retried (it may send an SMS/email); retry is user-driven.
 *  - Account-enumeration safe: the UI behaves identically for known/unknown usernames — the screen
 *    never branches on "user not found"; any distinguishing error maps to the generic message.
 *  - PII/logging: the raw username, masked destination, and challenge_id are never logged here.
 *  - On a 200 carrying a challenge → emit [RecoveryStartEffect.ProceedToChallenge] (hand-off to
 *    AND-058). On the no-challenge variant → render a terminal "check your <medium>" state.
 */
@HiltViewModel
class RecoveryStartViewModel @Inject constructor(
    private val repository: PasswordRecoveryRepository,
) : ViewModel() {

    private val _uiState = MutableStateFlow(RecoveryStartUiState())
    val uiState: StateFlow<RecoveryStartUiState> = _uiState.asStateFlow()

    private val _effects = MutableSharedFlow<RecoveryStartEffect>(
        replay = 0,
        extraBufferCapacity = 1,
        onBufferOverflow = BufferOverflow.DROP_OLDEST,
    )
    val effects: SharedFlow<RecoveryStartEffect> = _effects.asSharedFlow()

    fun onUsernameChange(value: String) =
        _uiState.update { it.copy(username = value, error = null, sentConfirmation = null) }

    fun onContinue() {
        val s = _uiState.value
        if (!s.canContinue) return
        _uiState.update { it.copy(isSubmitting = true, error = null) }
        viewModelScope.launch {
            when (val result = repository.start(s.username)) {
                is ApiResult.Success -> handleSuccess(result.data, s.username.trim())
                is ApiResult.Failure ->
                    _uiState.update { it.copy(isSubmitting = false, error = result.error.message) }
                is ApiResult.NetworkError ->
                    _uiState.update {
                        it.copy(
                            isSubmitting = false,
                            error = "Couldn't reach the server. Check your connection and try again.",
                        )
                    }
            }
        }
    }

    private fun handleSuccess(outcome: RecoveryStartOutcome, username: String) =
        when (outcome) {
            is RecoveryStartOutcome.Challenge -> {
                _uiState.update { it.copy(isSubmitting = false) }
                _effects.tryEmit(
                    RecoveryStartEffect.ProceedToChallenge(
                        username = username,
                        challengeId = outcome.challengeId,
                        requiredFactors = outcome.requiredFactors.map { it.wire },
                        delivery = outcome.deliveryMedium?.let {
                            DeliverySummary(it, outcome.deliveryDestination)
                        },
                    ),
                )
                Unit
            }
            is RecoveryStartOutcome.Sent ->
                _uiState.update {
                    it.copy(
                        isSubmitting = false,
                        sentConfirmation = DeliverySummary(
                            outcome.deliveryMedium ?: "email",
                            outcome.deliveryDestination,
                        ),
                    )
                }
        }
}
