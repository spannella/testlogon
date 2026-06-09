package com.testlogon.android.feature.auth.recovery

import androidx.lifecycle.SavedStateHandle
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.auth.PasswordRecoveryRepository
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

/** Fatal (no-network) states for the confirm screen (AND-059). */
enum class ConfirmFatal { MISSING_CONTEXT, CHALLENGE_EXPIRED }

/** One-shot navigation effects from the recovery-confirm screen (AND-059). */
sealed interface RecoveryConfirmEffect {
    /** Password set → go to Login with the username prefilled; the recovery graph is popped. */
    data class Success(val username: String) : RecoveryConfirmEffect

    /** Missing context / expired challenge → restart from the start step (AND-057). */
    data object StartOver : RecoveryConfirmEffect
}

/**
 * Hoisted recovery-confirm screen state (AND-059). Passwords are excluded from [toString] (secret),
 * as is the [username] (PII).
 */
data class RecoveryConfirmUiState(
    val newPassword: String = "",
    val confirmPassword: String = "",
    val rules: PasswordRuleResults = PasswordRuleResults(),
    val isSubmitting: Boolean = false,
    val error: String? = null,
    val fatal: ConfirmFatal? = null,
) {
    val passwordsMatch: Boolean get() = newPassword.isNotEmpty() && newPassword == confirmPassword

    val isSubmitEnabled: Boolean get() = rules.allPass && passwordsMatch && !isSubmitting && fatal == null

    override fun toString(): String =
        "RecoveryConfirmUiState(newPassword=***, confirmPassword=***, rules=$rules, " +
            "isSubmitting=$isSubmitting, error=$error, fatal=$fatal)"
}

/**
 * Drives the final recovery confirm step (AND-059): collect + validate a new password and POST it to
 * `/ui/password-recovery/confirm`.
 *
 * CONTRACT:
 *  - Seeded from nav args (username, challengeId) plus the verified confirmation code carried on this
 *    entry's SavedStateHandle (key [AuthDest.RecoveryConfirm.KEY_CODE]). Missing context → fatal
 *    [ConfirmFatal.MISSING_CONTEXT] with no network call.
 *  - confirm is a non-idempotent POST and is never auto-retried; double-submit is guarded.
 *  - On a 200 the screen emits [RecoveryConfirmEffect.Success] (route to Login, username prefilled);
 *    recovery NEVER auto-logs-in. Passwords are cleared from state before navigation and never logged.
 */
@HiltViewModel
class RecoveryConfirmViewModel @Inject constructor(
    private val repository: PasswordRecoveryRepository,
    savedStateHandle: SavedStateHandle,
) : ViewModel() {

    private val username: String =
        savedStateHandle.get<String>(AuthDest.RecoveryConfirm.ARG_USERNAME).orEmpty()
    private val challengeId: String? =
        savedStateHandle.get<String>(AuthDest.RecoveryConfirm.ARG_CHALLENGE_ID)?.takeIf { it.isNotBlank() }
    private val confirmationCode: String? =
        savedStateHandle.get<String>(AuthDest.RecoveryConfirm.KEY_CODE)?.takeIf { it.isNotBlank() }

    private val hasContext: Boolean = username.isNotBlank() && !confirmationCode.isNullOrBlank()

    private val _uiState = MutableStateFlow(
        RecoveryConfirmUiState(fatal = if (hasContext) null else ConfirmFatal.MISSING_CONTEXT),
    )
    val uiState: StateFlow<RecoveryConfirmUiState> = _uiState.asStateFlow()

    private val _effects = MutableSharedFlow<RecoveryConfirmEffect>(
        replay = 0,
        extraBufferCapacity = 1,
        onBufferOverflow = BufferOverflow.DROP_OLDEST,
    )
    val effects: SharedFlow<RecoveryConfirmEffect> = _effects.asSharedFlow()

    fun onNewPasswordChange(value: String) = _uiState.update {
        it.copy(newPassword = value, rules = RecoveryPasswordValidator.evaluate(value), error = null)
    }

    fun onConfirmPasswordChange(value: String) =
        _uiState.update { it.copy(confirmPassword = value, error = null) }

    fun onStartOver() = _effects.tryEmit(RecoveryConfirmEffect.StartOver)

    fun onSubmit() {
        val s = _uiState.value
        if (!s.isSubmitEnabled || !hasContext) return
        _uiState.update { it.copy(isSubmitting = true, error = null) }
        val password = s.newPassword
        viewModelScope.launch {
            val result = repository.confirmNewPassword(
                username = username,
                confirmationCode = confirmationCode.orEmpty(),
                newPassword = password,
                challengeId = challengeId,
            )
            handleConfirm(result)
        }
    }

    private fun handleConfirm(result: ApiResult<Unit>) = when (result) {
        is ApiResult.Success -> {
            // Clear secrets from state before navigating.
            _uiState.update {
                it.copy(newPassword = "", confirmPassword = "", isSubmitting = false)
            }
            _effects.tryEmit(RecoveryConfirmEffect.Success(username))
            Unit
        }
        is ApiResult.Failure -> {
            val expired = result.error.status == 404 ||
                result.error.status == 410 ||
                result.error.code == "challenge_expired"
            if (expired) {
                _uiState.update { it.copy(isSubmitting = false, fatal = ConfirmFatal.CHALLENGE_EXPIRED) }
            } else {
                _uiState.update { it.copy(isSubmitting = false, error = result.error.message) }
            }
        }
        is ApiResult.NetworkError ->
            _uiState.update {
                it.copy(
                    isSubmitting = false,
                    error = "Couldn't reach the server. Check your connection and try again.",
                )
            }
    }
}
