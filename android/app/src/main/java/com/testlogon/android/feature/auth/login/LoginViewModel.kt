package com.testlogon.android.feature.auth.login

import android.app.Activity
import android.content.Context
import android.net.Uri
import androidx.lifecycle.SavedStateHandle
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.data.telemetry.AuthEvent
import com.testlogon.android.core.data.telemetry.AuthStage
import com.testlogon.android.core.data.telemetry.AuthTelemetry
import com.testlogon.android.core.data.telemetry.NoopAuthTelemetry
import com.testlogon.android.core.model.ApiError
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.model.LogoutReason
import com.testlogon.android.data.auth.AuthRepository
import com.testlogon.android.data.auth.AuthStateStore
import com.testlogon.android.data.auth.LoginOutcome
import com.testlogon.android.data.auth.MfaFactor
import com.testlogon.android.data.auth.PasskeyAuthResult
import com.testlogon.android.data.auth.PasskeyRepository
import com.testlogon.android.data.auth.SsoInfo
import com.testlogon.android.data.auth.SsoRepository
import com.testlogon.android.data.auth.SsoStateStore
import com.testlogon.android.data.auth.toAuthReason
import com.testlogon.android.data.auth.toTelemetry
import com.testlogon.android.feature.auth.sso.SsoTabLauncher
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
import java.security.SecureRandom
import javax.inject.Inject

/** One-shot navigation effects from the login screen (AND-031/062/063). */
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
    // AND-063 SSO
    val ssoInfo: SsoInfo? = null,
    val ssoBusy: Boolean = false,
    // AND-062 passkeys
    val passkeySupported: Boolean = false,
    val passkeyBusy: Boolean = false,
) {
    val isSubmitting: Boolean get() = status == LoginStatus.Submitting

    /** SSO-only tenants hide the password form (web parity: sso_only). */
    val ssoOnly: Boolean get() = ssoInfo?.ssoOnly == true
    val ssoAvailable: Boolean get() = ssoInfo?.ssoAvailable == true
    val ssoProviderName: String get() = ssoInfo?.providerDisplayName ?: "SSO"

    val submitEnabled: Boolean
        get() = status != LoginStatus.Submitting &&
            !ssoOnly &&
            LoginValidator.validateEmail(email) == null &&
            password.isNotBlank()

    /** Passkey sign-in requires a non-blank username (no usernameless flow in the contract). */
    val passkeySignInEnabled: Boolean
        get() = !isSubmitting && !passkeyBusy && email.isNotBlank()

    override fun toString(): String =
        "LoginUiState(email=$email, password=***, passwordVisible=$passwordVisible, " +
            "status=$status, error=$error, serverUrl=$serverUrl, expiryReason=$expiryReason, " +
            "ssoOnly=$ssoOnly, ssoBusy=$ssoBusy, passkeySupported=$passkeySupported, passkeyBusy=$passkeyBusy)"
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
    // AND-052: redacted auth telemetry. Defaulted to no-op so unit tests that construct the
    // ViewModel directly need no change; Hilt injects DefaultAuthTelemetry in the app.
    private val telemetry: AuthTelemetry = NoopAuthTelemetry,
    // AND-062/063: defaulted to no-ops so existing unit tests that construct the VM directly are
    // unaffected; Hilt ignores the defaults and injects the real bound collaborators.
    private val ssoRepository: SsoRepository = NoopSsoRepository,
    private val ssoStateStore: SsoStateStore = NoopSsoStateStore,
    private val ssoTabLauncher: SsoTabLauncher = SsoTabLauncher { _, _ -> false },
    private val passkeyRepository: PasskeyRepository = NoopPasskeyRepository,
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
        // AND-062: capability gate for the passkey sign-in button.
        viewModelScope.launch {
            _uiState.update { it.copy(passkeySupported = passkeyRepository.isSupported()) }
        }
        // AND-063: tenant SSO discovery on mount (web parity: getSsoInfo("default")).
        probeSso()
    }

    // ── AND-063 SSO ──

    /** Tenant-scoped SSO discovery; degrades silently to the password form on failure. */
    fun probeSso(tenant: String = "default") {
        viewModelScope.launch {
            when (val r = ssoRepository.getSsoInfo(tenant)) {
                is ApiResult.Success -> _uiState.update { it.copy(ssoInfo = r.data) }
                is ApiResult.Failure -> Unit // fall back to the password form
                is ApiResult.NetworkError -> Unit
            }
        }
    }

    /** Opens the SSO/SAML authorization URL in a Custom Tab; persists a local-only correlation state. */
    fun startSso(context: Context) {
        if (_uiState.value.ssoBusy) return
        _uiState.update { it.copy(ssoBusy = true, error = null) }
        viewModelScope.launch {
            val state = newStateToken()
            ssoStateStore.save(state)
            val url = ssoRepository.authorizeUrl(_uiState.value.ssoInfo, tenant = "default")
            val launched = ssoTabLauncher.launch(context, url)
            if (!launched) {
                _uiState.update { it.copy(ssoBusy = false, error = "No browser available to complete sign-in.") }
                ssoStateStore.clear()
            }
        }
    }

    /** Handle the ACS deep-link callback: map ?error= codes, else finalize via getMe (source of truth). */
    fun onSsoRedirect(uri: Uri) {
        val errorCode = uri.getQueryParameter("error")
        if (errorCode != null) {
            _uiState.update { it.copy(ssoBusy = false, error = mapSsoError(errorCode)) }
            viewModelScope.launch { ssoStateStore.clear() }
            return
        }
        _uiState.update { it.copy(ssoBusy = true) }
        viewModelScope.launch {
            // state is a local-only guard; absence on a legitimate ACS redirect must not block — gate
            // finalization on getMe instead.
            ssoStateStore.clear()
            when (ssoRepository.finalizeAfterCallback()) {
                is ApiResult.Success -> {
                    _uiState.update { it.copy(ssoBusy = false) }
                    _effects.tryEmit(LoginEffect.NavigateHome)
                }
                is ApiResult.Failure ->
                    _uiState.update { it.copy(ssoBusy = false, error = "Sign-in could not be completed. Please try again.") }
                is ApiResult.NetworkError ->
                    _uiState.update {
                        it.copy(ssoBusy = false, error = "Couldn't reach the server. Check your connection and try again.")
                    }
            }
        }
    }

    private fun mapSsoError(code: String): String = when (code) {
        "sso_validation_failed" -> "We couldn't validate your sign-in. Please try again."
        "sso_not_authenticated" -> "Sign-in was not completed."
        "sso_replay_detected" -> "This sign-in link was already used. Please try again."
        "sso_no_email" -> "Your account has no email on file with the provider."
        "sso_domain_not_allowed" -> "Your email domain isn't allowed for SSO."
        "sso_user_not_found" -> "No matching account was found."
        "account_banned" -> "This account has been disabled."
        else -> "SSO error: $code"
    }

    private fun newStateToken(): String {
        val bytes = ByteArray(16)
        SecureRandom().nextBytes(bytes)
        // Hex, not android.util.Base64 (unavailable in JVM unit tests) and not java.util.Base64
        // (needs API 26 > minSdk 24); a 32-char random token is ample for a local CSRF-style state.
        return bytes.joinToString("") { "%02x".format(it) }
    }

    // ── AND-062 passkey sign-in ──

    /** Authenticate with a platform passkey using the entered username (required by the contract). */
    fun signInWithPasskey(activity: Activity) {
        val username = _uiState.value.email.trim()
        if (username.isEmpty() || _uiState.value.passkeyBusy) return
        _uiState.update { it.copy(passkeyBusy = true, error = null) }
        viewModelScope.launch {
            when (val r = passkeyRepository.authenticateWithPasskey(activity, username)) {
                is ApiResult.Success -> {
                    _uiState.update { it.copy(passkeyBusy = false) }
                    if (r.data is PasskeyAuthResult.Authenticated) {
                        _effects.tryEmit(LoginEffect.NavigateHome)
                    }
                    // Cancelled: silent return, no error.
                }
                is ApiResult.Failure -> _uiState.update { it.copy(passkeyBusy = false, error = r.error.message) }
                is ApiResult.NetworkError ->
                    _uiState.update {
                        it.copy(passkeyBusy = false, error = "Couldn't reach the server. Check your connection and try again.")
                    }
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
        telemetry.log(AuthEvent.LoginAttempt(userPresent = snapshot.email.isNotBlank()))
        viewModelScope.launch {
            when (val result = authRepository.login(snapshot.email.trim(), snapshot.password)) {
                is ApiResult.Success -> {
                    telemetry.log(AuthEvent.LoginSuccess(requiredFactors = result.data.telemetryFactors()))
                    handleSuccess(result.data)
                }
                is ApiResult.Failure -> {
                    telemetry.log(
                        AuthEvent.LoginFailure(
                            reason = result.toAuthReason(AuthStage.LOGIN),
                            httpStatus = result.error.status,
                        ),
                    )
                    _uiState.update { it.copy(status = LoginStatus.Idle, error = result.error.toMessage()) }
                }
                is ApiResult.NetworkError -> {
                    telemetry.log(AuthEvent.LoginFailure(reason = result.toAuthReason(AuthStage.LOGIN)))
                    _uiState.update {
                        it.copy(
                            status = LoginStatus.Idle,
                            error = "Couldn't reach the server. Check your connection and try again.",
                        )
                    }
                }
            }
        }
    }

    private fun LoginOutcome.telemetryFactors() = when (this) {
        is LoginOutcome.MfaRequired -> factors.map { it.toTelemetry() }
        is LoginOutcome.Authenticated -> emptyList()
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

/**
 * No-op defaults for the AND-062/063 collaborators so the [LoginViewModel] can be constructed without
 * them in pure-JVM tests (Hilt ignores these and injects the real bound implementations). They render
 * SSO/passkey affordances inert (no discovery, unsupported device, no-op store).
 */
private object NoopSsoRepository : SsoRepository {
    override suspend fun getSsoInfo(tenant: String): ApiResult<SsoInfo> =
        ApiResult.Failure(ApiError(0, "sso disabled"))
    override fun authorizeUrl(info: SsoInfo?, tenant: String): String = ""
    override suspend fun finalizeAfterCallback(): ApiResult<com.testlogon.android.data.auth.SsoFinalizeResult> =
        ApiResult.Failure(ApiError(0, "sso disabled"))
}

private object NoopSsoStateStore : SsoStateStore {
    override suspend fun save(state: String, ttlMillis: Long) = Unit
    override suspend fun peek(): com.testlogon.android.data.auth.PendingSso? = null
    override suspend fun clear() = Unit
}

private object NoopPasskeyRepository : PasskeyRepository {
    override suspend fun isSupported(): Boolean = false
    override suspend fun registerPasskey(
        activity: Context,
        label: String?,
    ): ApiResult<com.testlogon.android.data.auth.RegisteredPasskey> =
        ApiResult.Failure(ApiError(0, "passkeys disabled"))
    override suspend fun authenticateWithPasskey(
        activity: Context,
        username: String,
    ): ApiResult<PasskeyAuthResult> = ApiResult.Failure(ApiError(0, "passkeys disabled"))
}
