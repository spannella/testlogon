package com.testlogon.android.feature.auth.mfa

import androidx.lifecycle.SavedStateHandle
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.data.telemetry.AuthEvent
import com.testlogon.android.core.data.telemetry.AuthFactor
import com.testlogon.android.core.data.telemetry.AuthStage
import com.testlogon.android.core.data.telemetry.AuthTelemetry
import com.testlogon.android.core.data.telemetry.NoopAuthTelemetry
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.auth.AuthRepository
import com.testlogon.android.data.auth.MfaFactor
import com.testlogon.android.data.auth.MfaVerifyOutcome
import com.testlogon.android.data.auth.toAuthReason
import com.testlogon.android.data.auth.toTelemetry
import com.testlogon.android.navigation.AuthDest
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

/** Whether the active factor needs a code-entry surface (all current factors do). */
enum class MfaMode { SELECTING, ENTERING }

/** One-shot navigation effects for the MFA screen (AND-040). */
sealed interface MfaEffect {
    data object NavigateHome : MfaEffect
    data object NavigateToLogin : MfaEffect
}

/**
 * Hoisted MFA screen state. [code] is excluded from [toString] (secret).
 */
data class MfaUiState(
    val challengeId: String = "",
    val remainingFactors: List<MfaFactor> = emptyList(),
    val activeFactor: MfaFactor? = null,
    val mode: MfaMode = MfaMode.ENTERING,
    val code: String = "",
    val codeLength: Int = 6,
    val sentTo: List<String> = emptyList(),
    val isVerifying: Boolean = false,
    val isSending: Boolean = false,
    val error: String? = null,
    val recoveryMode: Boolean = false,
    val recoveryCode: String = "",
) {
    val canSwitchFactor: Boolean get() = remainingFactors.size > 1
    val needsBegin: Boolean get() = activeFactor == MfaFactor.Sms || activeFactor == MfaFactor.Email
    val canSubmit: Boolean
        get() = !isVerifying &&
            if (recoveryMode) recoveryCode.isNotBlank() else code.length == codeLength

    override fun toString(): String =
        "MfaUiState(challengeId=$challengeId, remainingFactors=$remainingFactors, " +
            "activeFactor=$activeFactor, mode=$mode, code=***, codeLength=$codeLength, " +
            "sentTo=$sentTo, isVerifying=$isVerifying, isSending=$isSending, error=$error, " +
            "recoveryMode=$recoveryMode, recoveryCode=***)"
}

/**
 * MFA challenge state machine (AND-038/040). Seeded from nav args (`challengeId` + factors),
 * it selects the active factor from `remaining_factors`, runs `begin` for SMS/email, drives verify
 * via [AuthRepository], and advances until the repository reports [MfaVerifyOutcome.Authenticated]
 * (which it reaches by finalizing + getMe internally). Wrong codes keep the user on the factor;
 * a definitive session loss routes back to login.
 */
@HiltViewModel
class MfaViewModel @Inject constructor(
    private val authRepository: AuthRepository,
    savedStateHandle: SavedStateHandle,
    // AND-052: defaulted to no-op so direct-construction unit tests are unaffected; Hilt injects real.
    private val telemetry: AuthTelemetry = NoopAuthTelemetry,
) : ViewModel() {

    private val challengeId: String =
        savedStateHandle.get<String>(AuthDest.Mfa.ARG_CHALLENGE_ID).orEmpty()
    private val seedFactors: List<MfaFactor> =
        savedStateHandle.get<String>(AuthDest.Mfa.ARG_FACTORS)
            .orEmpty()
            .split(",")
            .filter { it.isNotBlank() }
            .map(MfaFactor::fromWire)

    private val _uiState = MutableStateFlow(
        MfaUiState(
            challengeId = challengeId,
            remainingFactors = seedFactors,
            activeFactor = seedFactors.firstOrNull() ?: MfaFactor.Totp,
        ),
    )
    val uiState: StateFlow<MfaUiState> = _uiState.asStateFlow()

    private val _effects = MutableSharedFlow<MfaEffect>(
        replay = 0,
        extraBufferCapacity = 1,
        onBufferOverflow = BufferOverflow.DROP_OLDEST,
    )
    val effects: SharedFlow<MfaEffect> = _effects.asSharedFlow()

    init {
        if (challengeId.isBlank()) {
            _effects.tryEmit(MfaEffect.NavigateToLogin)
        } else {
            beginActiveIfNeeded()
        }
    }

    fun onCodeChange(value: String) = _uiState.update { it.copy(code = value, error = null) }

    fun onRecoveryCodeChange(value: String) =
        _uiState.update { it.copy(recoveryCode = value, error = null) }

    /** Switch to another remaining factor (must be present in `remaining`). */
    fun onSwitchFactor(factor: MfaFactor) {
        val s = _uiState.value
        if (factor !in s.remainingFactors || s.isVerifying) return
        _uiState.update {
            it.copy(activeFactor = factor, code = "", error = null, sentTo = emptyList(), recoveryMode = false)
        }
        beginActiveIfNeeded()
    }

    fun onOpenRecovery() = _uiState.update { it.copy(recoveryMode = true, error = null, recoveryCode = "") }

    fun onCloseRecovery() = _uiState.update { it.copy(recoveryMode = false, error = null) }

    /** Re-issue the begin challenge for the active SMS/email factor. */
    fun onResend() {
        if (_uiState.value.needsBegin) beginActiveIfNeeded(force = true)
    }

    fun onSubmit() {
        val s = _uiState.value
        if (s.isVerifying || !s.canSubmit) return
        _uiState.update { it.copy(isVerifying = true, error = null) }
        val verifyFactor =
            if (s.recoveryMode) AuthFactor.RECOVERY else (s.activeFactor ?: MfaFactor.Totp).toTelemetry()
        telemetry.log(AuthEvent.MfaVerifyAttempt(factor = verifyFactor, challengeId = s.challengeId))
        viewModelScope.launch {
            val result = when {
                s.recoveryMode -> authRepository.useRecovery(s.challengeId, s.recoveryCode)
                s.activeFactor == MfaFactor.Totp -> authRepository.verifyTotp(s.challengeId, s.code)
                s.activeFactor == MfaFactor.Sms -> authRepository.verifySms(s.challengeId, s.code)
                s.activeFactor == MfaFactor.Email -> authRepository.verifyEmail(s.challengeId, s.code)
                else -> authRepository.verifyTotp(s.challengeId, s.code)
            }
            handleVerify(result, verifyFactor, s.challengeId)
        }
    }

    private fun handleVerify(
        result: ApiResult<MfaVerifyOutcome>,
        verifyFactor: AuthFactor,
        challengeId: String,
    ) = when (result) {
        is ApiResult.Success -> when (val outcome = result.data) {
            is MfaVerifyOutcome.Authenticated -> {
                telemetry.log(AuthEvent.MfaSuccess(factor = verifyFactor, challengeId = challengeId))
                _uiState.update { it.copy(isVerifying = false) }
                _effects.tryEmit(MfaEffect.NavigateHome)
                Unit
            }
            is MfaVerifyOutcome.FactorsRemaining -> {
                telemetry.log(AuthEvent.MfaSuccess(factor = verifyFactor, challengeId = challengeId))
                val next = outcome.factors.firstOrNull() ?: MfaFactor.Totp
                _uiState.update {
                    it.copy(
                        isVerifying = false,
                        remainingFactors = outcome.factors,
                        activeFactor = next,
                        code = "",
                        recoveryMode = false,
                        recoveryCode = "",
                        sentTo = emptyList(),
                        error = null,
                    )
                }
                beginActiveIfNeeded()
            }
        }
        is ApiResult.Failure -> {
            telemetry.log(
                AuthEvent.MfaFailure(
                    factor = verifyFactor,
                    reason = result.toAuthReason(AuthStage.MFA_VERIFY),
                    remainingFactors = _uiState.value.remainingFactors.size,
                    httpStatus = result.error.status,
                ),
            )
            val sessionLost = result.error.status == 401 || result.error.status == 410
            if (sessionLost) {
                _uiState.update { it.copy(isVerifying = false) }
                _effects.tryEmit(MfaEffect.NavigateToLogin)
                Unit
            } else {
                _uiState.update { it.copy(isVerifying = false, code = "", error = result.error.message) }
            }
        }
        is ApiResult.NetworkError -> {
            telemetry.log(
                AuthEvent.MfaFailure(
                    factor = verifyFactor,
                    reason = result.toAuthReason(AuthStage.MFA_VERIFY),
                    remainingFactors = _uiState.value.remainingFactors.size,
                ),
            )
            _uiState.update {
                it.copy(
                    isVerifying = false,
                    error = "Couldn't reach the server. Check your connection and try again.",
                )
            }
        }
    }

    private var begunFor: MfaFactor? = null

    private fun beginActiveIfNeeded(force: Boolean = false) {
        val s = _uiState.value
        val factor = s.activeFactor
        if (factor != MfaFactor.Sms && factor != MfaFactor.Email) return
        if (!force && begunFor == factor) return
        begunFor = factor
        telemetry.log(AuthEvent.MfaBegin(factor = factor.toTelemetry(), challengeId = s.challengeId))
        _uiState.update { it.copy(isSending = true, error = null) }
        viewModelScope.launch {
            val result: ApiResult<List<String>> = when (factor) {
                MfaFactor.Sms -> authRepository.beginSms(s.challengeId)
                MfaFactor.Email -> authRepository.beginEmail(s.challengeId)
                else -> ApiResult.Success(emptyList())
            }
            when (result) {
                is ApiResult.Success -> _uiState.update { it.copy(isSending = false, sentTo = result.data) }
                is ApiResult.Failure ->
                    _uiState.update { it.copy(isSending = false, error = result.error.message) }
                is ApiResult.NetworkError ->
                    _uiState.update {
                        it.copy(isSending = false, error = "Couldn't send the code. Try again.")
                    }
            }
        }
    }
}
