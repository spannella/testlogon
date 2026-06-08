package com.testlogon.android.feature.auth.login

import androidx.lifecycle.SavedStateHandle
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.ApiError
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.model.LogoutReason
import com.testlogon.android.data.auth.AuthRepository
import com.testlogon.android.data.auth.AuthStateStore
import com.testlogon.android.data.auth.LoginOutcome
import com.testlogon.android.data.auth.MfaFactor
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

/** One-shot navigation effects from the login screen (AND-031). */
sealed interface LoginEffect {
    data class NavigateToMfa(val challengeId: String, val factors: List<MfaFactor>) : LoginEffect
    data object NavigateHome : LoginEffect
}

enum class LoginStatus { Idle, Submitting }

/**
 * Hoisted login screen state. [password] is excluded from [toString] so accidental state logging
 * cannot leak the credential.
 */
data class LoginUiState(
    val email: String = "",
    val password: String = "",
    val passwordVisible: Boolean = false,
    val status: LoginStatus = LoginStatus.Idle,
    val error: String? = null,
    val serverUrl: String = "",
    val expiryReason: LogoutReason? = null,
) {
    val isSubmitting: Boolean get() = status == LoginStatus.Submitting
    val submitEnabled: Boolean
        get() = status != LoginStatus.Submitting &&
            LoginValidator.validateEmail(email) == null &&
            password.isNotBlank()

    override fun toString(): String =
        "LoginUiState(email=$email, password=***, passwordVisible=$passwordVisible, " +
            "status=$status, error=$error, serverUrl=$serverUrl, expiryReason=$expiryReason)"
}

/**
 * Orchestrates the email/password login (AND-031). Drives [AuthRepository.login], maps the typed
 * outcome to a one-shot navigation effect (MFA vs. home), and surfaces user-facing errors without
 * leaking transport details. Navigation is delivered as effects (never state) so rotation cannot
 * replay it.
 */
@HiltViewModel
class LoginViewModel @Inject constructor(
    private val authRepository: AuthRepository,
    private val serverUrlConfig: ServerUrlConfig,
    private val authStateStore: AuthStateStore,
    savedStateHandle: SavedStateHandle,
) : ViewModel() {

    private val _uiState = MutableStateFlow(LoginUiState(serverUrl = serverUrlConfig.current()))
    val uiState: StateFlow<LoginUiState> = _uiState.asStateFlow()

    init {
        // Expiry reason (AND-044): prefer the nav arg; fall back to the persisted reason so a cold
        // launch after process death still shows the banner. USER_INITIATED/UNKNOWN render no banner.
        val navReason = savedStateHandle.get<String>(AuthDest.Login.ARG_REASON)
            ?.let(LogoutReason::fromName)
        viewModelScope.launch {
            val reason = navReason ?: authStateStore.lastLogoutReason()
            if (reason == LogoutReason.SESSION_EXPIRED || reason == LogoutReason.SESSION_REVOKED) {
                _uiState.update { it.copy(expiryReason = reason) }
            }
        }
    }

    private val _effects = MutableSharedFlow<LoginEffect>(
        replay = 0,
        extraBufferCapacity = 1,
        onBufferOverflow = BufferOverflow.DROP_OLDEST,
    )
    val effects: SharedFlow<LoginEffect> = _effects.asSharedFlow()

    fun onEmailChange(value: String) = _uiState.update { it.copy(email = value, error = null) }

    fun onPasswordChange(value: String) = _uiState.update { it.copy(password = value, error = null) }

    fun onTogglePasswordVisibility() =
        _uiState.update { it.copy(passwordVisible = !it.passwordVisible) }

    fun onDismissError() = _uiState.update { it.copy(error = null) }

    /** Dismiss the expiry banner (web parity: the session-expired banner is dismissable). */
    fun onDismissExpiry() {
        _uiState.update { it.copy(expiryReason = null) }
        viewModelScope.launch { authStateStore.clearLogoutReason() }
    }

    fun onSubmit() {
        val snapshot = _uiState.value
        if (snapshot.isSubmitting || !snapshot.submitEnabled) return
        _uiState.update { it.copy(status = LoginStatus.Submitting, error = null) }
        viewModelScope.launch {
            when (val result = authRepository.login(snapshot.email.trim(), snapshot.password)) {
                is ApiResult.Success -> handleSuccess(result.data)
                is ApiResult.Failure ->
                    _uiState.update { it.copy(status = LoginStatus.Idle, error = result.error.toMessage()) }
                is ApiResult.NetworkError ->
                    _uiState.update {
                        it.copy(
                            status = LoginStatus.Idle,
                            error = "Couldn't reach the server. Check your connection and try again.",
                        )
                    }
            }
        }
    }

    private fun handleSuccess(outcome: LoginOutcome) {
        // FR-8: a successful (re)login consumes the stale expiry reason so it can't reappear.
        _uiState.update { it.copy(expiryReason = null) }
        viewModelScope.launch { authStateStore.clearLogoutReason() }
        handleOutcome(outcome)
    }

    private fun handleOutcome(outcome: LoginOutcome) = when (outcome) {
        is LoginOutcome.MfaRequired -> {
            _uiState.update { it.copy(status = LoginStatus.Idle) }
            _effects.tryEmit(LoginEffect.NavigateToMfa(outcome.challengeId, outcome.factors))
            Unit
        }
        is LoginOutcome.Authenticated -> {
            // Keep Submitting through the nav transition so the button doesn't flash re-enabled.
            _effects.tryEmit(LoginEffect.NavigateHome)
            Unit
        }
    }

    private fun ApiError.toMessage(): String = when {
        status == 401 -> "Invalid email or password."
        else -> message
    }
}
