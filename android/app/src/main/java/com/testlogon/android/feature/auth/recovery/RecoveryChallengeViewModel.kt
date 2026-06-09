package com.testlogon.android.feature.auth.recovery

import androidx.lifecycle.SavedStateHandle
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.auth.PasswordRecoveryRepository
import com.testlogon.android.data.auth.RecoveryFactor
import com.testlogon.android.navigation.AuthDest
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

/** One-shot navigation effects from the recovery-challenge screen (AND-058). */
sealed interface RecoveryChallengeEffect {
    /**
     * The challenge passed → advance to the confirm step (AND-059), forwarding the verified
     * [challengeId] and the entered [code] (the latter rides the confirm entry's SavedStateHandle,
     * never a route arg).
     */
    data class Verified(
        val username: String,
        val challengeId: String,
        val code: String,
    ) : RecoveryChallengeEffect

    /** The challenge expired / is unusable → restart from the start step (AND-057). */
    data object RestartRequired : RecoveryChallengeEffect
}

/**
 * Hoisted recovery-challenge screen state (AND-058). The entered [code] is excluded from [toString]
 * (capability secret), as is the [username] (PII).
 */
data class RecoveryChallengeUiState(
    val username: String = "",
    val challengeId: String = "",
    val factors: List<RecoveryFactor> = emptyList(),
    val activeFactor: RecoveryFactor = RecoveryFactor.Email,
    val maskedDestination: String? = null,
    val sentTo: List<String> = emptyList(),
    val code: String = "",
    val codeLength: Int = 6,
    val isSending: Boolean = false,
    val isVerifying: Boolean = false,
    val error: String? = null,
) {
    /** Numeric factors (email/sms/totp) want a fixed-length OTP; recovery accepts a longer code. */
    val isNumericFactor: Boolean
        get() = activeFactor == RecoveryFactor.Email ||
            activeFactor == RecoveryFactor.Sms ||
            activeFactor == RecoveryFactor.Totp

    val canSwitchFactor: Boolean get() = factors.size > 1

    val canSubmit: Boolean
        get() = !isVerifying &&
            if (isNumericFactor) code.length == codeLength else code.trim().length >= MIN_RECOVERY_CODE

    override fun toString(): String =
        "RecoveryChallengeUiState(username=***, challengeId=$challengeId, factors=$factors, " +
            "activeFactor=$activeFactor, maskedDestination=***, sentTo=***, code=***, " +
            "codeLength=$codeLength, isSending=$isSending, isVerifying=$isVerifying, error=$error)"

    companion object {
        const val MIN_RECOVERY_CODE = 8
    }
}

/**
 * Password-recovery challenge state machine (AND-058). Seeded from nav args (username, challengeId,
 * required factors, delivery descriptor), it begins the active email/sms factor, drives verify per
 * factor via [PasswordRecoveryRepository], and on a passing verification emits
 * [RecoveryChallengeEffect.Verified] (hand-off to AND-059).
 *
 * CONTRACT:
 *  - begin/verify are non-idempotent POSTs and are NEVER auto-retried; a double-tap is guarded.
 *  - A wrong code clears the field and stays on the screen; an expired challenge (401/404/410) routes
 *    back to start. The entered code / recovery_token are never logged.
 */
@HiltViewModel
class RecoveryChallengeViewModel @Inject constructor(
    private val repository: PasswordRecoveryRepository,
    savedStateHandle: SavedStateHandle,
) : ViewModel() {

    private val argUsername: String =
        savedStateHandle.get<String>(AuthDest.RecoveryChallenge.ARG_USERNAME).orEmpty()
    private val argChallengeId: String =
        savedStateHandle.get<String>(AuthDest.RecoveryChallenge.ARG_CHALLENGE_ID).orEmpty()
    private val seedFactors: List<RecoveryFactor> =
        savedStateHandle.get<String>(AuthDest.RecoveryChallenge.ARG_FACTORS)
            .orEmpty()
            .split(",")
            .filter { it.isNotBlank() }
            .map(RecoveryFactor::fromWire)
    private val argMedium: String? =
        savedStateHandle.get<String>(AuthDest.RecoveryChallenge.ARG_MEDIUM)?.takeIf { it.isNotBlank() }
    private val argDestination: String? =
        savedStateHandle.get<String>(AuthDest.RecoveryChallenge.ARG_DESTINATION)?.takeIf { it.isNotBlank() }

    private val _uiState = MutableStateFlow(
        RecoveryChallengeUiState(
            username = argUsername,
            challengeId = argChallengeId,
            factors = seedFactors,
            activeFactor = seedFactors.firstOrNull() ?: RecoveryFactor.fromWire(argMedium ?: "email"),
            maskedDestination = argDestination,
        ),
    )
    val uiState: StateFlow<RecoveryChallengeUiState> = _uiState.asStateFlow()

    // Channel-backed one-shot effects: buffers events emitted before a collector subscribes
    // (e.g. the blank-challengeId RestartRequired emitted in init), unlike a replay=0 SharedFlow.
    private val _effects = Channel<RecoveryChallengeEffect>(Channel.BUFFERED)
    val effects: Flow<RecoveryChallengeEffect> = _effects.receiveAsFlow()

    init {
        if (argChallengeId.isBlank()) {
            _effects.trySend(RecoveryChallengeEffect.RestartRequired)
        } else {
            beginActiveIfNeeded()
        }
    }

    fun onCodeChange(value: String) = _uiState.update { it.copy(code = value, error = null) }

    fun onSwitchFactor(factor: RecoveryFactor) {
        val s = _uiState.value
        if (factor !in s.factors || s.isVerifying) return
        _uiState.update {
            it.copy(activeFactor = factor, code = "", error = null, sentTo = emptyList())
        }
        beginActiveIfNeeded()
    }

    /** Re-issue the begin for the active email/sms factor (FR-4). */
    fun onResend() {
        if (_uiState.value.activeFactor.requiresBegin) beginActiveIfNeeded(force = true)
    }

    fun onSubmit() {
        val s = _uiState.value
        if (s.isVerifying || !s.canSubmit) return
        val code = s.code.trim()
        _uiState.update { it.copy(isVerifying = true, error = null) }
        viewModelScope.launch {
            val result = repository.verifyChallenge(s.activeFactor, s.username, s.challengeId, code)
            handleVerify(result, code)
        }
    }

    private fun handleVerify(result: ApiResult<*>, code: String) = when (result) {
        is ApiResult.Success -> {
            _uiState.update { it.copy(isVerifying = false) }
            val s = _uiState.value
            _effects.trySend(RecoveryChallengeEffect.Verified(s.username, s.challengeId, code))
            Unit
        }
        is ApiResult.Failure -> {
            val expired = result.error.status == 401 || result.error.status == 404 || result.error.status == 410
            if (expired) {
                _uiState.update { it.copy(isVerifying = false) }
                _effects.trySend(RecoveryChallengeEffect.RestartRequired)
                Unit
            } else {
                _uiState.update { it.copy(isVerifying = false, code = "", error = result.error.message) }
            }
        }
        is ApiResult.NetworkError ->
            _uiState.update {
                it.copy(
                    isVerifying = false,
                    error = "Couldn't reach the server. Check your connection and try again.",
                )
            }
    }

    private var begunFor: RecoveryFactor? = null

    private fun beginActiveIfNeeded(force: Boolean = false) {
        val s = _uiState.value
        val factor = s.activeFactor
        if (!factor.requiresBegin) return
        if (!force && begunFor == factor) return
        begunFor = factor
        _uiState.update { it.copy(isSending = true, error = null) }
        viewModelScope.launch {
            when (val result = repository.beginChallenge(factor, s.username, s.challengeId)) {
                is ApiResult.Success ->
                    _uiState.update {
                        it.copy(
                            isSending = false,
                            sentTo = result.data.maskedDestinations,
                        )
                    }
                is ApiResult.Failure ->
                    _uiState.update { it.copy(isSending = false, error = result.error.message) }
                is ApiResult.NetworkError ->
                    _uiState.update { it.copy(isSending = false, error = "Couldn't send the code. Try again.") }
            }
        }
    }
}
