package com.testlogon.android.feature.auth.passwordless

import androidx.compose.runtime.Immutable
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.auth.PasswordlessRepository
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import javax.inject.Inject

/** Two-phase magic-link start screen (AND-060). */
enum class MagicLinkPhase { Entry, Sending, Confirmation }

/**
 * Hoisted magic-link-start screen state (AND-060). The [identifier] is PII (not a secret) and is
 * excluded from [toString] so it is never accidentally logged.
 */
@Immutable
data class MagicLinkStartUiState(
    val phase: MagicLinkPhase = MagicLinkPhase.Entry,
    val identifier: String = "",
    val sentTo: List<String> = emptyList(),
    val resendSecondsLeft: Int = 0,
    val error: String? = null,
) {
    val isSubmitEnabled: Boolean
        get() = phase != MagicLinkPhase.Sending && identifier.isNotBlank()

    val canResend: Boolean
        get() = phase == MagicLinkPhase.Confirmation && resendSecondsLeft == 0

    override fun toString(): String =
        "MagicLinkStartUiState(phase=$phase, identifier=***, sentTo=***, " +
            "resendSecondsLeft=$resendSecondsLeft, error=$error)"
}

/**
 * Drives the passwordless / magic-link start step (AND-060).
 *
 * [onSubmit] trims the identifier (username OR email) and calls `POST /ui/passwordless/start`. On a
 * 2xx the screen switches to a "check your email" confirmation phase and a client-side resend cooldown
 * begins. The dispatch is gated on a non-blank identifier (a bare username is accepted — no email
 * hard-block, matching the web client); a blank identifier never reaches the network.
 *
 * CONTRACT:
 *  - POST → never auto-retried (it sends an email); retry is user-driven only.
 *  - Cooldown is purely client-side ([RESEND_COOLDOWN_SECONDS]) — the server returns no cooldown hint.
 *  - PII/logging: the raw identifier and sent_to are never logged here.
 */
@HiltViewModel
class MagicLinkStartViewModel @Inject constructor(
    private val repository: PasswordlessRepository,
) : ViewModel() {

    private val _uiState = MutableStateFlow(MagicLinkStartUiState())
    val uiState: StateFlow<MagicLinkStartUiState> = _uiState.asStateFlow()

    private var cooldownJob: Job? = null

    fun onIdentifierChange(value: String) =
        _uiState.update { it.copy(identifier = value, error = null) }

    fun onSubmit() = dispatch(isResend = false)

    fun onResend() {
        if (_uiState.value.canResend) dispatch(isResend = true)
    }

    /** Return to the entry phase, preserving the typed identifier so the user can fix a typo. */
    fun onChangeEmail() {
        cooldownJob?.cancel()
        _uiState.update {
            it.copy(phase = MagicLinkPhase.Entry, resendSecondsLeft = 0, error = null)
        }
    }

    fun onDismissError() = _uiState.update { it.copy(error = null) }

    private fun dispatch(isResend: Boolean) {
        val s = _uiState.value
        if (s.identifier.isBlank()) return
        if (s.phase == MagicLinkPhase.Sending) return
        if (isResend && !s.canResend) return

        _uiState.update { it.copy(phase = MagicLinkPhase.Sending, error = null) }
        viewModelScope.launch {
            when (val result = repository.start(s.identifier)) {
                is ApiResult.Success -> {
                    _uiState.update {
                        it.copy(phase = MagicLinkPhase.Confirmation, sentTo = result.data.sentTo)
                    }
                    startCooldown()
                }
                is ApiResult.Failure ->
                    _uiState.update {
                        it.copy(
                            // Resend keeps the user on the confirmation phase; an initial failure
                            // returns them to entry so they can correct/retry.
                            phase = if (isResend) MagicLinkPhase.Confirmation else MagicLinkPhase.Entry,
                            error = result.error.message,
                        )
                    }
                is ApiResult.NetworkError ->
                    _uiState.update {
                        it.copy(
                            phase = if (isResend) MagicLinkPhase.Confirmation else MagicLinkPhase.Entry,
                            error = "Couldn't reach the server. Check your connection and try again.",
                        )
                    }
            }
        }
    }

    private fun startCooldown() {
        cooldownJob?.cancel()
        cooldownJob = viewModelScope.launch {
            _uiState.update { it.copy(resendSecondsLeft = RESEND_COOLDOWN_SECONDS) }
            while (isActive && _uiState.value.resendSecondsLeft > 0) {
                delay(1_000)
                _uiState.update { it.copy(resendSecondsLeft = (it.resendSecondsLeft - 1).coerceAtLeast(0)) }
            }
        }
    }

    companion object {
        const val RESEND_COOLDOWN_SECONDS = 30
    }
}
