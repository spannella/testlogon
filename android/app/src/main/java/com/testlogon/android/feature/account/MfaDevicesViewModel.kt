package com.testlogon.android.feature.account

import androidx.compose.runtime.Immutable
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.auth.DeviceChallenge
import com.testlogon.android.data.auth.MfaDevice
import com.testlogon.android.data.auth.MfaDeviceRepository
import com.testlogon.android.data.auth.MfaFactorType
import com.testlogon.android.data.auth.TotpEnrollment
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

/**
 * AND-064 — MFA device management screen state machine. Lists enrolled factors (merged from the three
 * per-type endpoints), enrolls TOTP (begin → QR/secret → two codes → confirm), adds SMS/email factors
 * (begin → code → confirm), and removes factors (TOTP single-step re-auth; SMS/email two-step
 * challenge). Secrets/recovery codes live only in transient state and are cleared on cancel/success.
 */
@HiltViewModel
class MfaDevicesViewModel @Inject constructor(
    private val repo: MfaDeviceRepository,
) : ViewModel() {

    enum class Step { Collecting, BeginInFlight, AwaitingCode, ConfirmInFlight }

    sealed interface EnrollState {
        data object None : EnrollState

        data class Totp(
            val step: Step,
            val enrollment: TotpEnrollment? = null,
            val code: String = "",
            val code2: String = "",
            val recoveryCodes: List<String> = emptyList(),
            val error: String? = null,
        ) : EnrollState

        data class Code(
            val type: MfaFactorType,
            val step: Step,
            val destination: String = "",
            val challenge: DeviceChallenge? = null,
            val code: String = "",
            val resendInSeconds: Int = 0,
            val recoveryCodes: List<String> = emptyList(),
            val error: String? = null,
        ) : EnrollState
    }

    sealed interface RemoveState {
        data object None : RemoveState
        data class Totp(val deviceId: String, val code: String = "", val inFlight: Boolean = false, val error: String? = null) : RemoveState
        data class Code(
            val type: MfaFactorType,
            val deviceId: String,
            val step: Step,
            val challenge: DeviceChallenge? = null,
            val code: String = "",
            val error: String? = null,
        ) : RemoveState
    }

    @Immutable
    data class UiState(
        val isLoading: Boolean = false,
        val devices: List<MfaDevice> = emptyList(),
        val enroll: EnrollState = EnrollState.None,
        val remove: RemoveState = RemoveState.None,
        val error: String? = null,
    )

    private val _state = MutableStateFlow(UiState())
    val state: StateFlow<UiState> = _state.asStateFlow()

    private var resendJob: Job? = null

    fun load() {
        _state.update { it.copy(isLoading = true, error = null) }
        viewModelScope.launch {
            when (val r = repo.list()) {
                is ApiResult.Success -> _state.update { it.copy(isLoading = false, devices = r.data) }
                is ApiResult.Failure -> _state.update { it.copy(isLoading = false, error = r.error.message) }
                is ApiResult.NetworkError ->
                    _state.update { it.copy(isLoading = false, error = NETWORK_MSG) }
            }
        }
    }

    // ── TOTP enroll ──

    fun startTotpEnroll() {
        _state.update { it.copy(enroll = EnrollState.Totp(step = Step.BeginInFlight)) }
        viewModelScope.launch {
            when (val r = repo.beginTotp()) {
                is ApiResult.Success ->
                    _state.update {
                        it.copy(enroll = EnrollState.Totp(step = Step.AwaitingCode, enrollment = r.data))
                    }
                is ApiResult.Failure -> failEnrollTotp(r.error.message)
                is ApiResult.NetworkError -> failEnrollTotp(NETWORK_MSG)
            }
        }
    }

    fun onTotpCodeChange(value: String) = updateTotp { it.copy(code = value, error = null) }
    fun onTotpCode2Change(value: String) = updateTotp { it.copy(code2 = value, error = null) }

    fun submitTotpConfirm() {
        val totp = _state.value.enroll as? EnrollState.Totp ?: return
        val enrollment = totp.enrollment ?: return
        if (totp.step == Step.ConfirmInFlight) return
        if (totp.code.isBlank() || totp.code2.isBlank()) {
            updateTotp { it.copy(error = "Enter both codes.") }
            return
        }
        updateTotp { it.copy(step = Step.ConfirmInFlight, error = null) }
        viewModelScope.launch {
            when (val r = repo.confirmTotp(enrollment.deviceId, totp.code, totp.code2)) {
                is ApiResult.Success -> {
                    if (r.data.recoveryCodes.isNotEmpty()) {
                        // Hold the enrollment sheet open to surface recovery codes once.
                        updateTotp {
                            it.copy(step = Step.AwaitingCode, recoveryCodes = r.data.recoveryCodes, code = "", code2 = "")
                        }
                    } else {
                        cancelEnroll()
                    }
                    load()
                }
                is ApiResult.Failure -> updateTotp { it.copy(step = Step.AwaitingCode, error = r.error.message) }
                is ApiResult.NetworkError -> updateTotp { it.copy(step = Step.AwaitingCode, error = NETWORK_MSG) }
            }
        }
    }

    // ── SMS / email enroll ──

    fun startCodeEnroll(type: MfaFactorType) {
        _state.update { it.copy(enroll = EnrollState.Code(type = type, step = Step.Collecting)) }
    }

    fun onDestinationChange(value: String) = updateCode { it.copy(destination = value, error = null) }
    fun onCodeChange(value: String) = updateCode { it.copy(code = value, error = null) }

    fun submitBegin() {
        val code = _state.value.enroll as? EnrollState.Code ?: return
        if (code.step == Step.BeginInFlight) return
        if (code.destination.isBlank()) {
            updateCode { it.copy(error = "Enter a destination.") }
            return
        }
        updateCode { it.copy(step = Step.BeginInFlight, error = null) }
        viewModelScope.launch {
            when (val r = repo.beginCode(code.type, code.destination)) {
                is ApiResult.Success -> {
                    updateCode { it.copy(step = Step.AwaitingCode, challenge = r.data) }
                    startResendCooldown()
                }
                is ApiResult.Failure -> updateCode { it.copy(step = Step.Collecting, error = r.error.message) }
                is ApiResult.NetworkError -> updateCode { it.copy(step = Step.Collecting, error = NETWORK_MSG) }
            }
        }
    }

    fun submitCodeConfirm() {
        val code = _state.value.enroll as? EnrollState.Code ?: return
        val challenge = code.challenge ?: return
        if (code.step == Step.ConfirmInFlight) return
        if (code.code.isBlank()) {
            updateCode { it.copy(error = "Enter the code.") }
            return
        }
        updateCode { it.copy(step = Step.ConfirmInFlight, error = null) }
        viewModelScope.launch {
            when (val r = repo.confirmCode(code.type, challenge.challengeId, code.code)) {
                is ApiResult.Success -> {
                    if (r.data.recoveryCodes.isNotEmpty()) {
                        updateCode { it.copy(step = Step.AwaitingCode, recoveryCodes = r.data.recoveryCodes, code = "") }
                    } else {
                        cancelEnroll()
                    }
                    load()
                }
                is ApiResult.Failure -> updateCode { it.copy(step = Step.AwaitingCode, error = r.error.message) }
                is ApiResult.NetworkError -> updateCode { it.copy(step = Step.AwaitingCode, error = NETWORK_MSG) }
            }
        }
    }

    fun resend() {
        val code = _state.value.enroll as? EnrollState.Code ?: return
        if (code.resendInSeconds > 0 || code.destination.isBlank()) return
        submitBegin()
    }

    fun cancelEnroll() {
        resendJob?.cancel()
        _state.update { it.copy(enroll = EnrollState.None) }
    }

    // ── remove ──

    fun requestRemove(device: MfaDevice) {
        val remove = when (device.type) {
            MfaFactorType.TOTP -> RemoveState.Totp(deviceId = device.deviceId)
            MfaFactorType.SMS, MfaFactorType.EMAIL ->
                RemoveState.Code(type = device.type, deviceId = device.deviceId, step = Step.Collecting)
        }
        _state.update { it.copy(remove = remove) }
    }

    fun onRemoveCodeChange(value: String) {
        _state.update { s ->
            when (val rm = s.remove) {
                is RemoveState.Totp -> s.copy(remove = rm.copy(code = value, error = null))
                is RemoveState.Code -> s.copy(remove = rm.copy(code = value, error = null))
                RemoveState.None -> s
            }
        }
    }

    /** TOTP: send remove({totp_code}). SMS/email: remove/begin then (on next call) remove/confirm. */
    fun confirmRemove() {
        when (val rm = _state.value.remove) {
            is RemoveState.Totp -> confirmRemoveTotp(rm)
            is RemoveState.Code -> when (rm.step) {
                Step.Collecting, Step.BeginInFlight -> beginRemoveCode(rm)
                else -> confirmRemoveCode(rm)
            }
            RemoveState.None -> Unit
        }
    }

    private fun confirmRemoveTotp(rm: RemoveState.Totp) {
        if (rm.inFlight) return
        if (rm.code.isBlank()) {
            _state.update { it.copy(remove = rm.copy(error = "Enter your code.")) }
            return
        }
        _state.update { it.copy(remove = rm.copy(inFlight = true, error = null)) }
        viewModelScope.launch {
            when (val r = repo.removeTotp(rm.deviceId, rm.code)) {
                is ApiResult.Success -> { dismissRemove(); load() }
                is ApiResult.Failure -> _state.update { it.copy(remove = rm.copy(inFlight = false, error = r.error.message)) }
                is ApiResult.NetworkError -> _state.update { it.copy(remove = rm.copy(inFlight = false, error = NETWORK_MSG)) }
            }
        }
    }

    private fun beginRemoveCode(rm: RemoveState.Code) {
        _state.update { it.copy(remove = rm.copy(step = Step.BeginInFlight, error = null)) }
        viewModelScope.launch {
            when (val r = repo.beginRemoveCode(rm.type, rm.deviceId)) {
                is ApiResult.Success ->
                    _state.update { it.copy(remove = rm.copy(step = Step.AwaitingCode, challenge = r.data)) }
                is ApiResult.Failure -> _state.update { it.copy(remove = rm.copy(step = Step.Collecting, error = r.error.message)) }
                is ApiResult.NetworkError -> _state.update { it.copy(remove = rm.copy(step = Step.Collecting, error = NETWORK_MSG)) }
            }
        }
    }

    private fun confirmRemoveCode(rm: RemoveState.Code) {
        val challenge = rm.challenge ?: return
        if (rm.step == Step.ConfirmInFlight) return
        if (rm.code.isBlank()) {
            _state.update { it.copy(remove = rm.copy(error = "Enter the code.")) }
            return
        }
        _state.update { it.copy(remove = rm.copy(step = Step.ConfirmInFlight, error = null)) }
        viewModelScope.launch {
            when (val r = repo.confirmRemoveCode(rm.type, challenge.challengeId, rm.code)) {
                is ApiResult.Success -> { dismissRemove(); load() }
                is ApiResult.Failure -> _state.update { it.copy(remove = rm.copy(step = Step.AwaitingCode, error = r.error.message)) }
                is ApiResult.NetworkError -> _state.update { it.copy(remove = rm.copy(step = Step.AwaitingCode, error = NETWORK_MSG)) }
            }
        }
    }

    fun dismissRemove() = _state.update { it.copy(remove = RemoveState.None) }

    fun dismissError() = _state.update { it.copy(error = null) }

    // ── helpers ──

    private fun startResendCooldown() {
        resendJob?.cancel()
        resendJob = viewModelScope.launch {
            updateCode { it.copy(resendInSeconds = RESEND_COOLDOWN_SECONDS) }
            while (isActive) {
                val current = (_state.value.enroll as? EnrollState.Code)?.resendInSeconds ?: 0
                if (current <= 0) break
                delay(1_000)
                updateCode { it.copy(resendInSeconds = (it.resendInSeconds - 1).coerceAtLeast(0)) }
            }
        }
    }

    private fun failEnrollTotp(message: String?) {
        _state.update { it.copy(enroll = EnrollState.None, error = message) }
    }

    private inline fun updateTotp(transform: (EnrollState.Totp) -> EnrollState.Totp) {
        _state.update { s ->
            val totp = s.enroll as? EnrollState.Totp ?: return@update s
            s.copy(enroll = transform(totp))
        }
    }

    private inline fun updateCode(transform: (EnrollState.Code) -> EnrollState.Code) {
        _state.update { s ->
            val code = s.enroll as? EnrollState.Code ?: return@update s
            s.copy(enroll = transform(code))
        }
    }

    companion object {
        const val RESEND_COOLDOWN_SECONDS = 30
        private const val NETWORK_MSG = "Couldn't reach the server. Check your connection and try again."
    }
}
