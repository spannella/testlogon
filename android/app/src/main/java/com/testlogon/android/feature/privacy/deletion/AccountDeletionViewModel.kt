package com.testlogon.android.feature.privacy.deletion

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.privacy.AccountDeletionRepository
import com.testlogon.android.data.privacy.DeletionStatus
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.Job
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import javax.inject.Inject

/** AND-386 - the server-required typed sentinel. Intentionally NOT localized: it must byte-match the wire
 * `confirm_text` (spec §9 / §16 claim 5). */
const val DELETE_SENTINEL = "DELETE MY ACCOUNT"

/** AND-386 - the multi-step confirmation gates (spec §4 / FR-2). */
enum class ConfirmStep { None, Warning, TypeToConfirm, FinalDialog, CancelDialog }

/** AND-386 - a transient, snackbar-surfaced message (success or error). No PII (spec §8 / AC-8). */
data class TransientMessage(val text: String, val isError: Boolean)

/** AND-386 - the account-deletion screen state (spec §4). */
sealed interface AccountDeletionUiState {

    data object Loading : AccountDeletionUiState

    /**
     * The interactive state. [status] is the authoritative server state (Active | Pending). [confirmStep]
     * drives the multi-step request overlay; [typedConfirmation] must equal [DELETE_SENTINEL] and [password]
     * must be non-empty before the final dialog can be shown. [mutationInFlight] disables both destructive
     * actions (double-submit guard). [isStale] indicates a last-known value shown while offline (FR-6).
     */
    data class Ready(
        val status: DeletionStatus,
        val confirmStep: ConfirmStep = ConfirmStep.None,
        val typedConfirmation: String = "",
        val password: String = "",
        val reason: String = "",
        val mutationInFlight: Boolean = false,
        val isStale: Boolean = false,
        val transient: TransientMessage? = null,
    ) : AccountDeletionUiState {

        /** True iff the typed sentinel matches (case-sensitive) AND the password is non-empty. */
        val confirmUnlocked: Boolean
            get() = typedConfirmation == DELETE_SENTINEL && password.isNotEmpty()
    }

    data class Error(val message: String, val retryable: Boolean) : AccountDeletionUiState
}

/** AND-386 - the screen events (spec §4). */
sealed interface AccountDeletionEvent {
    data object Refresh : AccountDeletionEvent
    data object StartRequest : AccountDeletionEvent
    data object AdvanceFromWarning : AccountDeletionEvent
    data class TypedConfirmationChanged(val text: String) : AccountDeletionEvent
    data class PasswordChanged(val text: String) : AccountDeletionEvent
    data class ReasonChanged(val text: String) : AccountDeletionEvent
    data object ShowFinalDialog : AccountDeletionEvent
    data object ConfirmDelete : AccountDeletionEvent
    data object StartCancel : AccountDeletionEvent
    data object ConfirmCancel : AccountDeletionEvent
    data object Dismiss : AccountDeletionEvent
    data object ConsumeTransient : AccountDeletionEvent
}

/**
 * AND-386 - presentation logic for the account-deletion screen.
 *
 * The server is the source of truth: [load] fetches on entry and every successful mutation re-derives state
 * from the server (no optimistic flip - deletion is too consequential). The request POST is gated behind the
 * three confirm steps and is non-idempotent (NEVER auto-retried; a second [ConfirmDelete] while in-flight is
 * ignored). When status cannot be fetched the screen shows the last-known value with a stale banner and
 * mutations are blocked (FR-6). The reason text is held in transient state and sent (optional) with the
 * request. No password / id / timestamp is ever logged (spec §8 / AC-8).
 */
@HiltViewModel
class AccountDeletionViewModel @Inject constructor(
    private val repo: AccountDeletionRepository,
) : ViewModel() {

    private val _uiState = MutableStateFlow<AccountDeletionUiState>(AccountDeletionUiState.Loading)
    val uiState: StateFlow<AccountDeletionUiState> = _uiState.asStateFlow()

    private var mutationJob: Job? = null
    private var loaded = false

    /** First-load entry (called by the screen on resume). Idempotent: only the first call fetches. */
    fun load() {
        if (loaded) return
        loaded = true
        fetch(initial = true)
    }

    fun onEvent(event: AccountDeletionEvent) {
        when (event) {
            AccountDeletionEvent.Refresh -> fetch(initial = false)
            AccountDeletionEvent.StartRequest -> setStep(ConfirmStep.Warning)
            AccountDeletionEvent.AdvanceFromWarning -> setStep(ConfirmStep.TypeToConfirm)
            is AccountDeletionEvent.TypedConfirmationChanged ->
                updateReady { it.copy(typedConfirmation = event.text) }
            is AccountDeletionEvent.PasswordChanged ->
                updateReady { it.copy(password = event.text) }
            is AccountDeletionEvent.ReasonChanged -> updateReady { it.copy(reason = event.text) }
            AccountDeletionEvent.ShowFinalDialog -> showFinalDialog()
            AccountDeletionEvent.ConfirmDelete -> confirmDelete()
            AccountDeletionEvent.StartCancel -> setStep(ConfirmStep.CancelDialog)
            AccountDeletionEvent.ConfirmCancel -> confirmCancel()
            AccountDeletionEvent.Dismiss -> dismiss()
            AccountDeletionEvent.ConsumeTransient -> updateReady { it.copy(transient = null) }
        }
    }

    private fun fetch(initial: Boolean) {
        viewModelScope.launch {
            if (initial) _uiState.value = AccountDeletionUiState.Loading
            when (val r = repo.getStatus()) {
                is ApiResult.Success ->
                    _uiState.value = AccountDeletionUiState.Ready(status = r.data, isStale = false)
                is ApiResult.NetworkError -> {
                    val last = repo.lastKnownStatus()
                    _uiState.value = if (last != null) {
                        AccountDeletionUiState.Ready(status = last, isStale = true)
                    } else {
                        AccountDeletionUiState.Error(MSG_OFFLINE, retryable = true)
                    }
                }
                is ApiResult.Failure -> {
                    val last = repo.lastKnownStatus()
                    _uiState.value = if (last != null) {
                        AccountDeletionUiState.Ready(
                            status = last,
                            isStale = false,
                            transient = TransientMessage(MSG_STATUS_FAILED, isError = true),
                        )
                    } else {
                        AccountDeletionUiState.Error(MSG_STATUS_FAILED, retryable = !r.error.isAuth)
                    }
                }
            }
        }
    }

    private fun showFinalDialog() {
        val ready = _uiState.value as? AccountDeletionUiState.Ready ?: return
        if (!ready.confirmUnlocked || ready.mutationInFlight) return
        _uiState.value = ready.copy(confirmStep = ConfirmStep.FinalDialog)
    }

    private fun confirmDelete() {
        val ready = _uiState.value as? AccountDeletionUiState.Ready ?: return
        if (mutationJob?.isActive == true || ready.mutationInFlight) return
        if (!ready.confirmUnlocked) return
        if (ready.isStale) {
            updateReady { it.copy(transient = TransientMessage(MSG_OFFLINE, isError = true)) }
            return
        }
        val password = ready.password
        val reasonArg = ready.reason
        mutationJob = viewModelScope.launch {
            updateReady { it.copy(mutationInFlight = true, transient = null) }
            when (val r = repo.requestDeletion(password, DELETE_SENTINEL, reasonArg)) {
                is ApiResult.Success ->
                    _uiState.value = AccountDeletionUiState.Ready(
                        status = r.data,
                        transient = TransientMessage(MSG_REQUEST_OK, isError = false),
                    )
                is ApiResult.NetworkError ->
                    updateReady {
                        it.copy(mutationInFlight = false, transient = TransientMessage(MSG_OFFLINE, true))
                    }
                is ApiResult.Failure ->
                    updateReady {
                        it.copy(
                            mutationInFlight = false,
                            confirmStep = ConfirmStep.None,
                            transient = TransientMessage(MSG_REQUEST_FAILED, isError = true),
                        )
                    }
            }
        }
    }

    private fun confirmCancel() {
        val ready = _uiState.value as? AccountDeletionUiState.Ready ?: return
        val pending = ready.status as? DeletionStatus.Pending ?: return
        if (mutationJob?.isActive == true || ready.mutationInFlight) return
        if (ready.isStale) {
            updateReady {
                it.copy(confirmStep = ConfirmStep.None, transient = TransientMessage(MSG_OFFLINE, true))
            }
            return
        }
        mutationJob = viewModelScope.launch {
            updateReady { it.copy(mutationInFlight = true, transient = null) }
            when (val r = repo.cancelDeletion(pending.requestId)) {
                is ApiResult.Success ->
                    _uiState.value = AccountDeletionUiState.Ready(
                        status = r.data,
                        transient = TransientMessage(MSG_CANCEL_OK, isError = false),
                    )
                is ApiResult.NetworkError ->
                    updateReady {
                        it.copy(
                            mutationInFlight = false,
                            confirmStep = ConfirmStep.None,
                            transient = TransientMessage(MSG_OFFLINE, true),
                        )
                    }
                is ApiResult.Failure ->
                    updateReady {
                        it.copy(
                            mutationInFlight = false,
                            confirmStep = ConfirmStep.None,
                            transient = TransientMessage(MSG_CANCEL_FAILED, isError = true),
                        )
                    }
            }
        }
    }

    private fun dismiss() = updateReady {
        it.copy(confirmStep = ConfirmStep.None, typedConfirmation = "", password = "", reason = "")
    }

    private fun setStep(step: ConfirmStep) = updateReady { it.copy(confirmStep = step) }

    private inline fun updateReady(transform: (AccountDeletionUiState.Ready) -> AccountDeletionUiState.Ready) {
        _uiState.update { current ->
            if (current is AccountDeletionUiState.Ready) transform(current) else current
        }
    }

    companion object {
        const val MSG_OFFLINE = "Can't reach server - try again."
        const val MSG_STATUS_FAILED = "Couldn't load your account status. Please try again."
        const val MSG_REQUEST_OK = "Account deletion scheduled."
        const val MSG_REQUEST_FAILED = "Could not schedule deletion. Check your password."
        const val MSG_CANCEL_OK = "Your account deletion request was cancelled."
        const val MSG_CANCEL_FAILED = "Couldn't cancel the request. It may already be resolved."
    }
}
