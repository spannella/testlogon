package com.testlogon.android.feature.kyc.wizard

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.feature.kyc.data.KycTierRepository
import com.testlogon.android.feature.kyc.wizard.data.KycWizardRepository
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.Job
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import javax.inject.Inject

/**
 * Batch-9 (#18) - presentation logic for the guided KYC verification wizard.
 *
 * On init it refreshes the tier status ONCE to learn which steps are already satisfied (email_verified /
 * phone_verified met) so the wizard starts on the first INCOMPLETE step and shows the others as done. Each
 * channel runs a simple start -> confirm flow; the ID step creates a draft case then hands off to the proven
 * ID-scanner screen (the screen reports back via [onIdSubmitted]).
 *
 * A plain MutableStateFlow drives the UI; there is NO poll/delay loop. In-flight work is single-tracked per
 * concern via [work] guards so a double-tap cannot fire two requests.
 */
@HiltViewModel
class KycWizardViewModel @Inject constructor(
    private val repository: KycWizardRepository,
    private val tierRepository: KycTierRepository,
) : ViewModel() {

    private val _uiState = MutableStateFlow(KycWizardUiState())
    val uiState: StateFlow<KycWizardUiState> = _uiState.asStateFlow()

    private var work: Job? = null

    init {
        loadStatus()
    }

    private fun update(transform: (KycWizardUiState) -> KycWizardUiState) {
        _uiState.value = transform(_uiState.value)
    }

    /** Refresh tier status to mark already-completed steps and land on the first incomplete one. */
    fun loadStatus() {
        update { it.copy(loading = true, fatalError = null) }
        viewModelScope.launch {
            when (val result = tierRepository.refreshTierStatus()) {
                is ApiResult.Success -> {
                    val reqs = result.data.requirements.associate { it.key to it.met }
                    val emailMet = reqs["email_verified"] == true
                    val phoneMet = reqs["phone_verified"] == true
                    // Any case/id requirement satisfied OR current tier already >= 2 means ID is effectively done.
                    val idMet = reqs["kyc_case_approved"] == true || result.data.current.level >= 2
                    update {
                        it.copy(
                            loading = false,
                            emailAlreadyVerified = emailMet,
                            phoneAlreadyVerified = phoneMet,
                            idAlreadyDone = idMet,
                            step = firstIncompleteStep(emailMet, phoneMet, idMet),
                        )
                    }
                }
                is ApiResult.Failure ->
                    // Non-fatal: the user can still run the steps; default to the first step.
                    update { it.copy(loading = false) }
                is ApiResult.NetworkError ->
                    update { it.copy(loading = false) }
            }
        }
    }

    private fun firstIncompleteStep(email: Boolean, phone: Boolean, id: Boolean): KycStep = when {
        !email -> KycStep.EMAIL
        !phone -> KycStep.PHONE
        !id -> KycStep.ID
        else -> KycStep.DONE
    }

    // ---- navigation between steps ----

    fun goToStep(step: KycStep) = update { it.copy(step = step) }

    /** Advance from the current step to the next one (clamped at DONE). */
    fun next() = update {
        val ordinal = (it.step.ordinal + 1).coerceAtMost(KycStep.DONE.ordinal)
        it.copy(step = KycStep.entries[ordinal])
    }

    fun back() = update {
        val ordinal = (it.step.ordinal - 1).coerceAtLeast(0)
        it.copy(step = KycStep.entries[ordinal])
    }

    // ---- email ----

    fun onEmailTargetChange(value: String) = update { it.copy(email = it.email.copy(target = value, error = null)) }
    fun onEmailCodeChange(value: String) = update { it.copy(email = it.email.copy(code = value, error = null)) }

    fun sendEmailCode() {
        if (work?.isActive == true) return
        update { it.copy(email = it.email.copy(phase = VerifyPhase.SENDING, error = null)) }
        work = viewModelScope.launch {
            when (val r = repository.startEmail(_uiState.value.email.target)) {
                is ApiResult.Success -> update {
                    it.copy(
                        email = it.email.copy(
                            phase = VerifyPhase.CODE_SENT,
                            sentTo = r.data.sentTo ?: it.email.target.ifBlank { null },
                            // dev_mode convenience: prefill the code so the user can confirm in one tap.
                            code = r.data.devCode ?: it.email.code,
                        ),
                    )
                }
                is ApiResult.Failure -> update {
                    it.copy(email = it.email.copy(phase = VerifyPhase.IDLE, error = r.error.message))
                }
                is ApiResult.NetworkError -> update {
                    it.copy(email = it.email.copy(phase = VerifyPhase.IDLE, error = OFFLINE))
                }
            }
            work = null
        }
    }

    fun confirmEmail() {
        if (work?.isActive == true) return
        val code = _uiState.value.email.code.trim()
        if (code.length < 4) {
            update { it.copy(email = it.email.copy(error = CODE_TOO_SHORT)) }
            return
        }
        update { it.copy(email = it.email.copy(phase = VerifyPhase.CONFIRMING, error = null)) }
        work = viewModelScope.launch {
            when (val r = repository.confirmEmail(code)) {
                is ApiResult.Success ->
                    update { it.copy(email = it.email.copy(phase = VerifyPhase.VERIFIED, error = null), step = KycStep.PHONE) }
                is ApiResult.Failure ->
                    update { it.copy(email = it.email.copy(phase = VerifyPhase.CODE_SENT, error = r.error.message)) }
                is ApiResult.NetworkError ->
                    update { it.copy(email = it.email.copy(phase = VerifyPhase.CODE_SENT, error = OFFLINE)) }
            }
            work = null
        }
    }

    // ---- phone ----

    fun onPhoneTargetChange(value: String) = update { it.copy(phone = it.phone.copy(target = value, error = null)) }
    fun onPhoneCodeChange(value: String) = update { it.copy(phone = it.phone.copy(code = value, error = null)) }

    fun sendPhoneCode() {
        if (work?.isActive == true) return
        val phone = _uiState.value.phone.target.trim()
        if (phone.length < 4) {
            update { it.copy(phone = it.phone.copy(error = PHONE_TOO_SHORT)) }
            return
        }
        update { it.copy(phone = it.phone.copy(phase = VerifyPhase.SENDING, error = null)) }
        work = viewModelScope.launch {
            when (val r = repository.startPhone(phone)) {
                is ApiResult.Success -> update {
                    it.copy(
                        phone = it.phone.copy(
                            phase = VerifyPhase.CODE_SENT,
                            sentTo = r.data.sentTo ?: phone,
                            code = r.data.devCode ?: it.phone.code,
                        ),
                    )
                }
                is ApiResult.Failure -> update {
                    it.copy(phone = it.phone.copy(phase = VerifyPhase.IDLE, error = r.error.message))
                }
                is ApiResult.NetworkError -> update {
                    it.copy(phone = it.phone.copy(phase = VerifyPhase.IDLE, error = OFFLINE))
                }
            }
            work = null
        }
    }

    fun confirmPhone() {
        if (work?.isActive == true) return
        val code = _uiState.value.phone.code.trim()
        if (code.length < 4) {
            update { it.copy(phone = it.phone.copy(error = CODE_TOO_SHORT)) }
            return
        }
        update { it.copy(phone = it.phone.copy(phase = VerifyPhase.CONFIRMING, error = null)) }
        work = viewModelScope.launch {
            when (val r = repository.confirmPhone(code)) {
                is ApiResult.Success ->
                    update { it.copy(phone = it.phone.copy(phase = VerifyPhase.VERIFIED, error = null), step = KycStep.ID) }
                is ApiResult.Failure ->
                    update { it.copy(phone = it.phone.copy(phase = VerifyPhase.CODE_SENT, error = r.error.message)) }
                is ApiResult.NetworkError ->
                    update { it.copy(phone = it.phone.copy(phase = VerifyPhase.CODE_SENT, error = OFFLINE)) }
            }
            work = null
        }
    }

    // ---- ID step ----

    /**
     * Mints a draft KYC case (idempotent for this VM: reuses one already created) and returns its id via
     * [onReady] so the screen can navigate to the ID-scanner. A blank id is never produced - failure sets an
     * inline error instead.
     */
    fun startIdCapture(onReady: (caseId: String) -> Unit) {
        if (work?.isActive == true) return
        _uiState.value.id.caseId?.let { existing ->
            onReady(existing)
            return
        }
        update { it.copy(id = it.id.copy(creatingCase = true, error = null)) }
        work = viewModelScope.launch {
            when (val r = repository.createCase()) {
                is ApiResult.Success -> {
                    update { it.copy(id = it.id.copy(creatingCase = false, caseId = r.data)) }
                    onReady(r.data)
                }
                is ApiResult.Failure ->
                    update { it.copy(id = it.id.copy(creatingCase = false, error = r.error.message)) }
                is ApiResult.NetworkError ->
                    update { it.copy(id = it.id.copy(creatingCase = false, error = OFFLINE)) }
            }
            work = null
        }
    }

    /** Called when the user returns from the ID-scanner having uploaded both sides. */
    fun onIdSubmitted() = update { it.copy(id = it.id.copy(submitted = true), step = KycStep.DONE) }

    companion object {
        private const val OFFLINE = "Couldn't reach the server. Check your connection and try again."
        private const val CODE_TOO_SHORT = "Enter the code we sent you."
        private const val PHONE_TOO_SHORT = "Enter a valid phone number."
    }
}
