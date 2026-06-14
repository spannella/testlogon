package com.testlogon.android.feature.alerts

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.alerts.EmailAlertRepository
import com.testlogon.android.data.alerts.SmsAlertRepository
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.async
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.receiveAsFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import javax.inject.Inject

/** Which channel a sub-flow targets. */
enum class AlertChannel { EMAIL, SMS }

/** In-progress add (begin succeeded, awaiting code) — challenge-scoped, never a list row. */
data class PendingChallenge(
    val channel: AlertChannel,
    val challengeId: String,
    val sentTo: String,
)

data class AlertPrefsUiState(
    val isLoading: Boolean = true,
    val isStale: Boolean = false,
    val error: String? = null,
    val emails: List<String> = emptyList(),
    val smsNumbers: List<String> = emptyList(),
    val emailInput: String = "",
    val smsInput: String = "",
    val codeInput: String = "",
    val pending: PendingChallenge? = null,
    /** Actions currently in flight (drives spinners / disables). */
    val busy: Boolean = false,
) {
    val loaded: Boolean get() = !isLoading
}

/** One-shot snackbar effects. */
sealed interface AlertPrefsEvent {
    data class Message(val text: String) : AlertPrefsEvent
}

/**
 * AND-088 — unified Alert Preferences ViewModel: manages email + SMS alert TARGETS (add / verify /
 * remove) by composing the AND-086 / AND-087 repositories. The alert event-type matrix
 * (/ui/alerts/type-preferences) is intentionally NOT re-implemented here — it is owned by the
 * AND-080 Notification Preferences screen, which this screen links to.
 */
@HiltViewModel
class AlertPrefsViewModel @Inject constructor(
    private val emailRepo: EmailAlertRepository,
    private val smsRepo: SmsAlertRepository,
) : ViewModel() {

    private val _state = MutableStateFlow(AlertPrefsUiState())
    val state: StateFlow<AlertPrefsUiState> = _state.asStateFlow()

    private val _events = Channel<AlertPrefsEvent>(Channel.BUFFERED)
    val events: Flow<AlertPrefsEvent> = _events.receiveAsFlow()

    init {
        load()
    }

    fun load() {
        _state.update { it.copy(isLoading = true, error = null) }
        viewModelScope.launch {
            val emailsDeferred = async { emailRepo.listEmails() }
            val smsDeferred = async { smsRepo.listNumbers() }
            val emailsResult = emailsDeferred.await()
            val smsResult = smsDeferred.await()

            val emails = (emailsResult as? ApiResult.Success)?.data
            val sms = (smsResult as? ApiResult.Success)?.data

            if (emails == null && sms == null) {
                _state.update {
                    it.copy(isLoading = false, error = errorMessage(emailsResult))
                }
            } else {
                _state.update {
                    it.copy(
                        isLoading = false,
                        error = null,
                        isStale = emails == null || sms == null,
                        emails = emails ?: it.emails,
                        smsNumbers = sms ?: it.smsNumbers,
                    )
                }
            }
        }
    }

    fun onEmailInputChanged(value: String) = _state.update { it.copy(emailInput = value) }
    fun onSmsInputChanged(value: String) = _state.update { it.copy(smsInput = value) }
    fun onCodeInputChanged(value: String) = _state.update { it.copy(codeInput = value) }

    fun addEmail() {
        val email = _state.value.emailInput.trim()
        if (email.isBlank() || _state.value.busy) return
        beginAdd(AlertChannel.EMAIL) { emailRepo.begin(email) }
    }

    fun addSms() {
        val phone = _state.value.smsInput.trim()
        if (phone.isBlank() || _state.value.busy) return
        beginAdd(AlertChannel.SMS) { smsRepo.begin(phone) }
    }

    private fun beginAdd(
        channel: AlertChannel,
        block: suspend () -> ApiResult<com.testlogon.android.data.alerts.AlertBeginResult>,
    ) {
        _state.update { it.copy(busy = true) }
        viewModelScope.launch {
            when (val r = block()) {
                is ApiResult.Success -> _state.update {
                    it.copy(
                        busy = false,
                        codeInput = "",
                        pending = PendingChallenge(channel, r.data.challengeId, r.data.sentTo),
                    )
                }
                else -> finishWithError(r)
            }
        }
    }

    fun verify() {
        val pending = _state.value.pending ?: return
        val code = _state.value.codeInput.trim()
        if (code.length < CODE_MIN_LENGTH || _state.value.busy) return
        _state.update { it.copy(busy = true) }
        viewModelScope.launch {
            val result = when (pending.channel) {
                AlertChannel.EMAIL -> emailRepo.confirm(pending.challengeId, code)
                AlertChannel.SMS -> smsRepo.confirm(pending.challengeId, code)
            }
            when (result) {
                is ApiResult.Success -> _state.update {
                    when (pending.channel) {
                        AlertChannel.EMAIL -> it.copy(busy = false, pending = null, codeInput = "", emailInput = "", emails = result.data)
                        AlertChannel.SMS -> it.copy(busy = false, pending = null, codeInput = "", smsInput = "", smsNumbers = result.data)
                    }
                }
                else -> finishWithError(result)
            }
        }
    }

    fun resend() {
        val pending = _state.value.pending ?: return
        if (_state.value.busy) return
        _state.update { it.copy(busy = true) }
        viewModelScope.launch {
            val result = when (pending.channel) {
                AlertChannel.EMAIL -> emailRepo.begin(_state.value.emailInput.trim())
                AlertChannel.SMS -> smsRepo.resend(_state.value.smsInput.trim())
            }
            when (result) {
                is ApiResult.Success -> _state.update {
                    it.copy(busy = false, pending = pending.copy(challengeId = result.data.challengeId, sentTo = result.data.sentTo))
                }
                else -> finishWithError(result)
            }
        }
    }

    fun cancelPending() = _state.update { it.copy(pending = null, codeInput = "") }

    fun removeEmail(email: String) {
        if (_state.value.busy) return
        _state.update { it.copy(busy = true) }
        viewModelScope.launch {
            when (val r = emailRepo.remove(email)) {
                is ApiResult.Success -> _state.update { it.copy(busy = false, emails = r.data) }
                else -> finishWithError(r)
            }
        }
    }

    fun removeSms(phone: String) {
        if (_state.value.busy) return
        _state.update { it.copy(busy = true) }
        viewModelScope.launch {
            when (val r = smsRepo.remove(phone)) {
                is ApiResult.Success -> _state.update { it.copy(busy = false, smsNumbers = r.data) }
                else -> finishWithError(r)
            }
        }
    }

    fun dismissError() = _state.update { it.copy(error = null) }

    private fun finishWithError(result: ApiResult<*>) {
        _state.update { it.copy(busy = false) }
        _events.trySend(AlertPrefsEvent.Message(errorMessage(result)))
    }

    private fun errorMessage(result: ApiResult<*>): String = when (result) {
        is ApiResult.Failure -> result.error.message
        is ApiResult.NetworkError -> "Couldn't reach the server. Check your connection and try again."
        is ApiResult.Success -> ""
    }

    private companion object {
        const val CODE_MIN_LENGTH = 6
    }
}
