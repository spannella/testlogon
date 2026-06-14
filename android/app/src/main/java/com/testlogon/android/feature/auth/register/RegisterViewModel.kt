package com.testlogon.android.feature.auth.register

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.auth.EmailAvailability
import com.testlogon.android.data.auth.RegisterRepository
import com.testlogon.android.data.auth.RegisterStartOutcome
import com.testlogon.android.data.auth.RegisterStartReq
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.FlowPreview
import kotlinx.coroutines.channels.BufferOverflow
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharedFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asSharedFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.debounce
import kotlinx.coroutines.flow.distinctUntilChanged
import kotlinx.coroutines.flow.flatMapLatest
import kotlinx.coroutines.flow.flow
import kotlinx.coroutines.flow.flowOf
import kotlinx.coroutines.flow.launchIn
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.flow.onEach
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import javax.inject.Inject

/** One-shot navigation effects from the register-start screen (AND-053/056). */
sealed interface RegisterEffect {
    /** verification_required = true → confirm step (AND-054) keyed on email + delivery hints. */
    data class GoToConfirm(
        val email: String,
        val deliveryMedium: String?,
        val deliveryDestination: String?,
        val enableSmsMfa: Boolean,
        val enableTotpMfa: Boolean,
        val phone: String?,
    ) : RegisterEffect

    /** verification_required = false + no session → show success and route to sign in. */
    data object GoToLoginSuccess : RegisterEffect

    /** verification_required = false + session established → app (auth gate swaps graphs). */
    data object GoToAppAuthenticated : RegisterEffect
}

enum class RegisterStatus { Idle, Submitting }

/**
 * Hoisted register-start screen state (AND-053 + AND-055 availability fields). Credential fields
 * are excluded from [toString] so accidental state logging cannot leak them.
 */
data class RegisterUiState(
    val fullName: String = "",
    val email: String = "",
    val password: String = "",
    val confirm: String = "",
    val phone: String = "",
    val enableSmsMfa: Boolean = false,
    val enableTotpMfa: Boolean = false,
    val passwordVisible: Boolean = false,
    val fullNameError: RegisterFieldError? = null,
    val emailError: RegisterFieldError? = null,
    val passwordError: RegisterFieldError? = null,
    val confirmError: RegisterFieldError? = null,
    val phoneError: RegisterFieldError? = null,
    val emailAvailability: EmailAvailability = EmailAvailability.Unknown,
    val formError: String? = null,
    val status: RegisterStatus = RegisterStatus.Idle,
) {
    val isSubmitting: Boolean get() = status == RegisterStatus.Submitting

    /** Phone is required iff the SMS-MFA opt-in is on (web rule). */
    val isPhoneRequired: Boolean get() = enableSmsMfa

    val emailChecking: Boolean get() = emailAvailability == EmailAvailability.Checking
    val emailTaken: Boolean get() = emailAvailability == EmailAvailability.Taken

    val submitEnabled: Boolean
        get() = !isSubmitting && !emailTaken &&
            RegisterValidator.validateFullName(fullName) == null &&
            RegisterValidator.validateEmail(email) == null &&
            RegisterValidator.validatePassword(password) == null &&
            RegisterValidator.validateConfirm(password, confirm) == null &&
            RegisterValidator.validatePhone(phone, isPhoneRequired) == null

    override fun toString(): String =
        "RegisterUiState(fullName=***, email=***, password=***, confirm=***, phone=***, " +
            "enableSmsMfa=$enableSmsMfa, enableTotpMfa=$enableTotpMfa, " +
            "passwordVisible=$passwordVisible, fullNameError=$fullNameError, " +
            "emailError=$emailError, passwordError=$passwordError, confirmError=$confirmError, " +
            "phoneError=$phoneError, emailAvailability=$emailAvailability, formError=$formError, " +
            "status=$status)"
}

/**
 * Drives the registration start form (AND-053): local validation, a debounced email-availability
 * check (AND-055), and the `register/start` submit that branches into a one-shot [RegisterEffect].
 * Navigation is delivered as effects (never state) so rotation cannot replay it.
 */
@OptIn(FlowPreview::class, ExperimentalCoroutinesApi::class)
@HiltViewModel
class RegisterViewModel @Inject constructor(
    private val repository: RegisterRepository,
) : ViewModel() {

    private val _uiState = MutableStateFlow(RegisterUiState())
    val uiState: StateFlow<RegisterUiState> = _uiState.asStateFlow()

    private val _effects = MutableSharedFlow<RegisterEffect>(
        replay = 0,
        extraBufferCapacity = 1,
        onBufferOverflow = BufferOverflow.DROP_OLDEST,
    )
    val effects: SharedFlow<RegisterEffect> = _effects.asSharedFlow()

    /** Raw email keystrokes; drives the AND-055 debounced availability pipeline. */
    private val emailQuery = MutableStateFlow("")

    init {
        emailQuery
            .map { it.trim() }
            .debounce(EMAIL_DEBOUNCE_MS)
            .distinctUntilChanged()
            .flatMapLatest { email ->
                if (!RegisterValidator.isPlausibleEmail(email)) {
                    flowOf(CheckOutcome(email, EmailAvailability.Unknown))
                } else {
                    flow {
                        emit(CheckOutcome(email, EmailAvailability.Checking))
                        emit(CheckOutcome(email, repository.checkEmail(email).toAvailability()))
                    }
                }
            }
            .onEach { (checkedEmail, availability) ->
                // FR-6 stale guard: ignore a result for an email the field has since moved past.
                if (_uiState.value.email.trim() == checkedEmail) {
                    _uiState.update { it.copy(emailAvailability = availability) }
                }
            }
            .launchIn(viewModelScope)
    }

    fun onFullNameChange(value: String) =
        _uiState.update { it.copy(fullName = value, fullNameError = null, formError = null) }

    fun onEmailChange(value: String) {
        // FR-2: reset availability + clear field error on every keystroke; re-trigger the pipeline.
        _uiState.update {
            it.copy(
                email = value,
                emailError = null,
                emailAvailability = EmailAvailability.Unknown,
                formError = null,
            )
        }
        emailQuery.value = value
    }

    fun onPasswordChange(value: String) = _uiState.update {
        // Cross-field confirm re-validates when password changes (re-derived on submit/blur anyway).
        it.copy(password = value, passwordError = null, confirmError = null, formError = null)
    }

    fun onConfirmChange(value: String) =
        _uiState.update { it.copy(confirm = value, confirmError = null, formError = null) }

    fun onPhoneChange(value: String) =
        _uiState.update { it.copy(phone = value, phoneError = null, formError = null) }

    fun onToggleSmsMfa(enabled: Boolean) = _uiState.update {
        // Disabling SMS-MFA drops the phone requirement (and any stale phone error).
        it.copy(enableSmsMfa = enabled, phoneError = if (enabled) it.phoneError else null)
    }

    fun onToggleTotpMfa(enabled: Boolean) = _uiState.update { it.copy(enableTotpMfa = enabled) }

    fun onTogglePasswordVisibility() =
        _uiState.update { it.copy(passwordVisible = !it.passwordVisible) }

    fun onDismissError() = _uiState.update { it.copy(formError = null) }

    fun onSubmit() {
        val s = _uiState.value
        // Re-derive all field errors so submit surfaces them even if no blur occurred.
        val validated = s.copy(
            fullNameError = RegisterValidator.validateFullName(s.fullName),
            emailError = RegisterValidator.validateEmail(s.email),
            passwordError = RegisterValidator.validatePassword(s.password),
            confirmError = RegisterValidator.validateConfirm(s.password, s.confirm),
            phoneError = RegisterValidator.validatePhone(s.phone, s.isPhoneRequired),
        )
        _uiState.value = validated
        if (validated.isSubmitting || !validated.submitEnabled) return

        _uiState.update { it.copy(status = RegisterStatus.Submitting, formError = null) }
        val req = RegisterStartReq(
            fullName = s.fullName.trim(),
            email = s.email.trim(),
            password = s.password,
            confirmPassword = s.confirm,
            // Web omits delivery_method (server default "email").
            deliveryMethod = null,
            // Phone is sent only when SMS-MFA is opted in.
            phone = if (s.enableSmsMfa) s.phone.trim() else null,
            enableSmsMfa = s.enableSmsMfa,
            enableTotpMfa = s.enableTotpMfa,
        )
        viewModelScope.launch {
            when (val result = repository.registerStart(req)) {
                is ApiResult.Success -> handleOutcome(result.data)
                is ApiResult.Failure ->
                    _uiState.update { it.copy(status = RegisterStatus.Idle, formError = result.error.message) }
                is ApiResult.NetworkError ->
                    _uiState.update {
                        it.copy(
                            status = RegisterStatus.Idle,
                            formError = "Couldn't reach the server. Check your connection and try again.",
                        )
                    }
            }
        }
    }

    private fun handleOutcome(outcome: RegisterStartOutcome) = when (outcome) {
        is RegisterStartOutcome.VerificationRequired -> {
            _uiState.update { it.copy(status = RegisterStatus.Idle) }
            val s = _uiState.value
            _effects.tryEmit(
                RegisterEffect.GoToConfirm(
                    email = outcome.email,
                    deliveryMedium = outcome.deliveryMedium,
                    deliveryDestination = outcome.deliveryDestination,
                    enableSmsMfa = s.enableSmsMfa,
                    enableTotpMfa = s.enableTotpMfa,
                    phone = if (s.enableSmsMfa) s.phone.trim() else null,
                ),
            )
            Unit
        }
        is RegisterStartOutcome.Authenticated -> {
            // Keep Submitting through the graph swap so the button doesn't flash re-enabled.
            _effects.tryEmit(RegisterEffect.GoToAppAuthenticated)
            Unit
        }
        RegisterStartOutcome.VerifiedSignIn -> {
            _uiState.update { it.copy(status = RegisterStatus.Idle) }
            _effects.tryEmit(RegisterEffect.GoToLoginSuccess)
            Unit
        }
    }

    private fun ApiResult<Boolean>.toAvailability(): EmailAvailability = when (this) {
        is ApiResult.Success -> if (data) EmailAvailability.Available else EmailAvailability.Taken
        is ApiResult.Failure -> EmailAvailability.Error
        is ApiResult.NetworkError -> EmailAvailability.Error
    }

    private data class CheckOutcome(val email: String, val availability: EmailAvailability)

    companion object {
        const val EMAIL_DEBOUNCE_MS = 400L
    }
}
