package com.testlogon.android.feature.auth.register

import androidx.lifecycle.SavedStateHandle
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.auth.MfaSetupHandoff
import com.testlogon.android.data.auth.RegisterConfirmOutcome
import com.testlogon.android.data.auth.RegisterConfirmReq
import com.testlogon.android.data.auth.RegisterRepository
import com.testlogon.android.data.auth.RegisterResendReq
import com.testlogon.android.navigation.AuthDest
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.channels.BufferOverflow
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharedFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asSharedFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import javax.inject.Inject

/** One-shot navigation effects from the confirm screen (AND-054/056). */
sealed interface RegisterConfirmEffect {
    /** No session established → route to Login with the email prefilled (web parity). */
    data class GoToLogin(val email: String) : RegisterConfirmEffect

    /** Session established, no pending MFA → into the app (auth gate swaps graphs). */
    data object GoToApp : RegisterConfirmEffect

    /** Session established + pending MFA enrollment → MFA-setup handoff (AND-056). */
    data class GoToMfaSetup(val handoff: MfaSetupHandoff) : RegisterConfirmEffect
}

/**
 * Hoisted confirm screen state (AND-054). The OTP [code] is excluded from [toString] (secret).
 */
data class RegisterConfirmUiState(
    val email: String = "",
    val deliveryMedium: String? = null,
    val deliveryDestination: String? = null,
    val code: String = "",
    val codeLength: Int = 6,
    val isSubmitting: Boolean = false,
    val isResending: Boolean = false,
    val resendCountdownSeconds: Int = 0,
    val error: String? = null,
    val transientMessage: String? = null,
) {
    val canConfirm: Boolean get() = code.length == codeLength && !isSubmitting
    val canResend: Boolean get() = resendCountdownSeconds == 0 && !isResending && !isSubmitting

    override fun toString(): String =
        "RegisterConfirmUiState(email=***, deliveryMedium=$deliveryMedium, " +
            "deliveryDestination=***, code=***, codeLength=$codeLength, isSubmitting=$isSubmitting, " +
            "isResending=$isResending, resendCountdownSeconds=$resendCountdownSeconds, " +
            "error=$error, transientMessage=$transientMessage)"
}

/**
 * Drives the registration confirm step (AND-054) and the post-confirm MFA-setup handoff (AND-056).
 *
 * Seeded from typed nav args (email + delivery hints + MFA opt-in flags/phone). Confirm calls
 * `register/confirm`; on success it routes per the typed [RegisterConfirmOutcome] (login vs app vs
 * MFA-setup). Resend calls `register/resend` and starts a client-side cooldown (the backend returns
 * no cooldown field). A wrong-code (server-rejected) clears the OTP; a pure network failure does not.
 */
@HiltViewModel
class RegisterConfirmViewModel @Inject constructor(
    private val repository: RegisterRepository,
    savedStateHandle: SavedStateHandle,
) : ViewModel() {

    private val argEmail: String =
        savedStateHandle.get<String>(AuthDest.RegisterConfirm.ARG_EMAIL).orEmpty()
    private val argMedium: String? =
        savedStateHandle.get<String>(AuthDest.RegisterConfirm.ARG_MEDIUM)?.takeIf { it.isNotBlank() }
    private val argDestination: String? =
        savedStateHandle.get<String>(AuthDest.RegisterConfirm.ARG_DESTINATION)?.takeIf { it.isNotBlank() }
    private val argSmsMfa: Boolean =
        savedStateHandle.get<String>(AuthDest.RegisterConfirm.ARG_SMS_MFA).toBoolean()
    private val argTotpMfa: Boolean =
        savedStateHandle.get<String>(AuthDest.RegisterConfirm.ARG_TOTP_MFA).toBoolean()
    private val argPhone: String? =
        savedStateHandle.get<String>(AuthDest.RegisterConfirm.ARG_PHONE)?.takeIf { it.isNotBlank() }

    private val _uiState = MutableStateFlow(
        RegisterConfirmUiState(
            email = argEmail,
            deliveryMedium = argMedium,
            deliveryDestination = argDestination,
        ),
    )
    val uiState: StateFlow<RegisterConfirmUiState> = _uiState.asStateFlow()

    private val _effects = MutableSharedFlow<RegisterConfirmEffect>(
        replay = 0,
        extraBufferCapacity = 1,
        onBufferOverflow = BufferOverflow.DROP_OLDEST,
    )
    val effects: SharedFlow<RegisterConfirmEffect> = _effects.asSharedFlow()

    fun onCodeChange(value: String) = _uiState.update { it.copy(code = value, error = null) }

    fun onDismissTransient() = _uiState.update { it.copy(transientMessage = null) }

    fun onConfirm() {
        val s = _uiState.value
        if (s.isSubmitting || !s.canConfirm) return
        _uiState.update { it.copy(isSubmitting = true, error = null, transientMessage = null) }
        viewModelScope.launch {
            val result = repository.confirm(RegisterConfirmReq(s.email, s.code))
            handleConfirm(result)
        }
    }

    private fun handleConfirm(result: ApiResult<RegisterConfirmOutcome>) = when (result) {
        is ApiResult.Success -> when (val outcome = result.data) {
            is RegisterConfirmOutcome.Authenticated -> {
                _uiState.update { it.copy(isSubmitting = false) }
                if (outcome.handoff.isRequired) {
                    _effects.tryEmit(RegisterConfirmEffect.GoToMfaSetup(outcome.handoff))
                } else {
                    // Enrollment is offered by the authenticated shell from the buffer (post-swap).
                    _effects.tryEmit(RegisterConfirmEffect.GoToApp)
                }
                Unit
            }
            is RegisterConfirmOutcome.VerifiedSignIn -> {
                _uiState.update { it.copy(isSubmitting = false) }
                _effects.tryEmit(RegisterConfirmEffect.GoToLogin(outcome.email))
                Unit
            }
        }
        is ApiResult.Failure -> {
            // Server-rejected code: clear the OTP and stay on screen (FR-4).
            _uiState.update { it.copy(isSubmitting = false, code = "", error = result.error.message) }
        }
        is ApiResult.NetworkError -> {
            // Pure network/timeout: keep the entered code (FR-7).
            _uiState.update {
                it.copy(
                    isSubmitting = false,
                    error = "Couldn't reach the server. Check your connection and try again.",
                )
            }
        }
    }

    fun onResend() {
        val s = _uiState.value
        if (!s.canResend) return
        _uiState.update { it.copy(isResending = true, error = null, transientMessage = null) }
        viewModelScope.launch {
            val req = RegisterResendReq(
                email = s.email,
                deliveryMethod = s.deliveryMedium ?: "email",
                phone = argPhone,
                enableSmsMfa = argSmsMfa,
                enableTotpMfa = argTotpMfa,
            )
            when (val result = repository.resend(req)) {
                is ApiResult.Success -> {
                    _uiState.update {
                        it.copy(
                            isResending = false,
                            transientMessage = "New code sent",
                            deliveryMedium = result.data.deliveryMedium ?: it.deliveryMedium,
                            deliveryDestination = result.data.deliveryDestination ?: it.deliveryDestination,
                        )
                    }
                    startCooldown()
                }
                is ApiResult.Failure ->
                    _uiState.update { it.copy(isResending = false, error = result.error.message) }
                is ApiResult.NetworkError ->
                    _uiState.update {
                        it.copy(
                            isResending = false,
                            error = "Couldn't reach the server. Check your connection and try again.",
                        )
                    }
            }
        }
    }

    private fun startCooldown() {
        _uiState.update { it.copy(resendCountdownSeconds = RESEND_COOLDOWN_SECONDS) }
        viewModelScope.launch {
            while (isActive && _uiState.value.resendCountdownSeconds > 0) {
                delay(1_000)
                _uiState.update { it.copy(resendCountdownSeconds = (it.resendCountdownSeconds - 1).coerceAtLeast(0)) }
            }
        }
    }

    companion object {
        const val RESEND_COOLDOWN_SECONDS = 30
    }
}
