package com.testlogon.android.feature.account.closure

import androidx.lifecycle.SavedStateHandle
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.AccountState
import com.testlogon.android.core.model.AccountStatus
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.account.AccountLifecycleRepository
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.Job
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import javax.inject.Inject

/**
 * AND-387 - the typed confirmation token guarding the irreversible closure FINALIZE. CORRECTED (spec §3
 * FR-6 / §16 claim 14): this is an Android-only client-side guard with NO backend basis - it is NOT sent on
 * the wire (finalize sends only `challenge_id`). It must match exactly + case-sensitive.
 */
const val CLOSE_TOKEN = "CLOSE"

/** AND-387 - the post-action outcome the screen observes to drive teardown/navigation (spec §4). */
enum class Outcome { CLOSED_SIGNED_OUT, SUSPENDED_SIGNED_OUT, REACTIVATED }

/**
 * AND-387 - the action sub-state inside a [AccountLifecycleUiState.Ready] (the dialog/flow state machine).
 * CORRECTED (spec §4): the re-auth challenge is issued by closure/START (not finalize), so the closure flow
 * is start -> [ReAuthRequired] -> [ConfirmClosureFinalize] (typed `CLOSE`) -> finalize.
 */
sealed interface ActionState {
    data object Idle : ActionState

    /** Single strong confirm for suspend (reversible - no typed token). */
    data object ConfirmSuspend : ActionState

    /** Single strong confirm for reactivate (reversible). */
    data object ConfirmReactivate : ActionState

    /** closure/start returned `auth_required` - the user must satisfy the re-auth challenge. */
    data class ReAuthRequired(val challengeId: String, val requiredFactors: List<String>) : ActionState

    /** Re-auth satisfied; the irreversible finalize is gated behind the typed `CLOSE` token. */
    data class ConfirmClosureFinalize(val challengeId: String, val typed: String = "") : ActionState {
        /** True iff the typed token is exactly `CLOSE` (case-sensitive) - enables the confirm button. */
        val tokenValid: Boolean get() = typed == CLOSE_TOKEN
    }

    /** A mutation is in flight - the confirm action is disabled (double-submit guard, spec FR-7). */
    data object Submitting : ActionState

    /** A mutation failed; the prior [AccountLifecycleUiState.Ready.status] is retained (spec §7). */
    data class Failed(val message: String) : ActionState

    /** A mutation succeeded; the screen observes [outcome] and navigates / teardown is already done. */
    data class Done(val outcome: Outcome) : ActionState
}

/** AND-387 - the lifecycle screen UI state (spec §4). */
sealed interface AccountLifecycleUiState {
    data object Loading : AccountLifecycleUiState

    /** Status read failed transport-side; offline state with Retry. No destructive action enabled (FR-8). */
    data object Offline : AccountLifecycleUiState

    /** Status read failed server-side; error state with Retry. */
    data class Error(val message: String) : AccountLifecycleUiState

    /** Status loaded; [action] drives the per-flow dialog/state machine. */
    data class Ready(
        val status: AccountStatus,
        val action: ActionState = ActionState.Idle,
    ) : AccountLifecycleUiState
}

/**
 * AND-387 - the single state machine for the closure / suspend / reactivate flows (spec §4).
 *
 * `load -> Ready(Idle)`; an action moves to a `Confirm*` / `ReAuthRequired` state (renders a dialog/step);
 * confirm moves to [ActionState.Submitting]; success moves to [ActionState.Done] (the screen observes and
 * navigates - teardown for closure/suspend is already performed by the repository); a failure moves to
 * [ActionState.Failed] while KEEPING the prior status (the user is never silently signed out). The closure
 * flow's typed `CLOSE` token + the `Confirm*`/`ReAuth` step are mirrored to [SavedStateHandle] so they
 * survive process death; [ActionState.Submitting] and the re-auth password are NEVER persisted (on recreate,
 * re-fetch status to learn the true outcome rather than re-submitting - spec §6).
 *
 * Mutations are non-idempotent and are NEVER auto-retried; a second confirm while a [mutationJob] is active
 * is ignored (double-submit guard, FR-7). No password / reason / full challenge_id is ever logged (spec §8).
 */
@HiltViewModel
class AccountLifecycleViewModel @Inject constructor(
    private val repo: AccountLifecycleRepository,
    private val savedState: SavedStateHandle,
) : ViewModel() {

    private val _uiState = MutableStateFlow<AccountLifecycleUiState>(AccountLifecycleUiState.Loading)
    val uiState: StateFlow<AccountLifecycleUiState> = _uiState.asStateFlow()

    private var mutationJob: Job? = null
    private var loaded = false

    /** First-load entry (called by the screen). Idempotent: only the first call fetches; Retry calls reload. */
    fun load() {
        if (loaded) return
        loaded = true
        fetch()
    }

    /** Re-fetch status (Retry / reconciliation). Resets to Loading and re-reads the authoritative state. */
    fun reload() = fetch()

    private fun fetch() {
        viewModelScope.launch {
            _uiState.value = AccountLifecycleUiState.Loading
            when (val r = repo.status()) {
                is ApiResult.Success ->
                    _uiState.value = AccountLifecycleUiState.Ready(status = r.data, action = restoredAction())
                is ApiResult.NetworkError ->
                    _uiState.value = AccountLifecycleUiState.Offline
                is ApiResult.Failure ->
                    _uiState.value = AccountLifecycleUiState.Error(r.error.message)
            }
        }
    }

    // ---- Suspend ----

    fun requestSuspend() = toAction(ActionState.ConfirmSuspend)

    fun confirmSuspend(reason: String?) {
        val ready = readyOrNull() ?: return
        if (!guardStart()) return
        mutationJob = viewModelScope.launch {
            setAction(ActionState.Submitting)
            when (val r = repo.suspend(reason)) {
                is ApiResult.Success -> finishDone(Outcome.SUSPENDED_SIGNED_OUT)
                is ApiResult.NetworkError -> failKeepingStatus(ready.status, MSG_AMBIGUOUS, reconcile = true)
                is ApiResult.Failure -> handleMutationFailure(ready.status, r.error.status, r.error.message)
            }
        }
    }

    // ---- Closure (start -> re-auth -> typed CLOSE -> finalize) ----

    /** closure/start (no body). On `auth_required` -> [ActionState.ReAuthRequired]; otherwise straight to the
     *  typed-token confirm carrying the returned challenge id. */
    fun requestClosure() {
        val ready = readyOrNull() ?: return
        if (!guardStart()) return
        mutationJob = viewModelScope.launch {
            setAction(ActionState.Submitting)
            when (val r = repo.startClosure()) {
                is ApiResult.Success -> {
                    val result = r.data
                    if (result.challengeId.isBlank()) {
                        failKeepingStatus(ready.status, MSG_CLOSURE_START_FAILED, reconcile = false)
                    } else if (result.authRequired) {
                        toAction(ActionState.ReAuthRequired(result.challengeId, result.requiredFactors))
                    } else {
                        toAction(ActionState.ConfirmClosureFinalize(result.challengeId))
                    }
                }
                is ApiResult.NetworkError -> failKeepingStatus(ready.status, MSG_AMBIGUOUS, reconcile = true)
                is ApiResult.Failure ->
                    handleMutationFailure(ready.status, r.error.status, MSG_CLOSURE_START_FAILED)
            }
        }
    }

    /** Re-auth satisfied (the password is verified by the backend challenge primitive and is NEVER persisted
     *  to [SavedStateHandle]). Moves to the typed-`CLOSE` confirm carrying the same challenge id. */
    fun submitReAuth() {
        val action = (readyOrNull()?.action as? ActionState.ReAuthRequired) ?: return
        toAction(ActionState.ConfirmClosureFinalize(action.challengeId))
    }

    /** Updates the typed `CLOSE` token while in the finalize-confirm step (mirrored to SavedStateHandle). */
    fun onTypedTokenChange(value: String) {
        val action = (readyOrNull()?.action as? ActionState.ConfirmClosureFinalize) ?: return
        toAction(action.copy(typed = value))
    }

    /** Posts closure/finalize with the carried challenge id, only when the typed token is exactly `CLOSE`. */
    fun confirmClosureFinalize() {
        val ready = readyOrNull() ?: return
        val action = ready.action as? ActionState.ConfirmClosureFinalize ?: return
        if (!action.tokenValid) return
        if (!guardStart()) return
        val challengeId = action.challengeId
        mutationJob = viewModelScope.launch {
            setAction(ActionState.Submitting)
            when (val r = repo.finalizeClosure(challengeId)) {
                is ApiResult.Success -> finishDone(Outcome.CLOSED_SIGNED_OUT)
                is ApiResult.NetworkError -> failKeepingStatus(ready.status, MSG_AMBIGUOUS, reconcile = true)
                is ApiResult.Failure -> handleMutationFailure(ready.status, r.error.status, r.error.message)
            }
        }
    }

    // ---- Reactivate ----

    fun requestReactivate() = toAction(ActionState.ConfirmReactivate)

    fun confirmReactivate(reason: String? = null) {
        val ready = readyOrNull() ?: return
        if (!guardStart()) return
        mutationJob = viewModelScope.launch {
            setAction(ActionState.Submitting)
            when (val r = repo.reactivate(reason)) {
                is ApiResult.Success ->
                    _uiState.value = AccountLifecycleUiState.Ready(
                        status = r.data,
                        action = ActionState.Done(Outcome.REACTIVATED),
                    ).also { clearSavedAction() }
                is ApiResult.NetworkError -> failKeepingStatus(ready.status, MSG_AMBIGUOUS, reconcile = true)
                is ApiResult.Failure -> handleMutationFailure(ready.status, r.error.status, r.error.message)
            }
        }
    }

    /** Dismisses the active dialog / re-auth step and returns to [ActionState.Idle]. */
    fun dismissDialog() {
        clearSavedAction()
        setAction(ActionState.Idle)
    }

    // ---- helpers ----

    private fun readyOrNull(): AccountLifecycleUiState.Ready? =
        _uiState.value as? AccountLifecycleUiState.Ready

    /** True iff no mutation is already in flight (double-submit guard, FR-7). */
    private fun guardStart(): Boolean = mutationJob?.isActive != true

    private fun setAction(action: ActionState) = _uiState.update { current ->
        if (current is AccountLifecycleUiState.Ready) current.copy(action = action) else current
    }

    /** Sets a persisted action (dialog/step/typed token survives process death) and mirrors it. */
    private fun toAction(action: ActionState) {
        persistAction(action)
        setAction(action)
    }

    private fun finishDone(outcome: Outcome) {
        clearSavedAction()
        setAction(ActionState.Done(outcome))
    }

    /**
     * A defensive failure handler: an undocumented 409 already-in-state is RECOVERABLE - reconcile by
     * re-fetching the authoritative status rather than showing a hard error (spec §7 / AC-8). Any other
     * failure retains the prior status under [ActionState.Failed] (no teardown, no sign-out - spec §7).
     */
    private fun handleMutationFailure(prior: AccountStatus, httpStatus: Int, message: String) {
        if (httpStatus == 409) {
            clearSavedAction()
            reload()
        } else {
            failKeepingStatus(prior, message, reconcile = false)
        }
    }

    private fun failKeepingStatus(prior: AccountStatus, message: String, reconcile: Boolean) {
        clearSavedAction()
        _uiState.value = AccountLifecycleUiState.Ready(status = prior, action = ActionState.Failed(message))
        // Ambiguous transport failure after a submit: reconcile the actual status UNDERNEATH while keeping
        // the Failed banner visible, so the user both sees the warning and the true current state
        // (spec §7 / TC-11). A plain reload() (which resets to Loading/Idle) is intentionally NOT used here.
        if (reconcile) reconcileStatusKeepingAction()
    }

    /** Re-reads status and updates only [AccountLifecycleUiState.Ready.status], preserving the current
     *  (typically [ActionState.Failed]) action. Used by the ambiguous-timeout reconciliation. */
    private fun reconcileStatusKeepingAction() {
        viewModelScope.launch {
            when (val r = repo.status()) {
                is ApiResult.Success -> _uiState.update { current ->
                    if (current is AccountLifecycleUiState.Ready) current.copy(status = r.data) else current
                }
                is ApiResult.NetworkError -> Unit // keep the prior status + Failed banner
                is ApiResult.Failure -> Unit
            }
        }
    }

    // ---- SavedStateHandle persistence of the confirm/typed-token step (spec §6) ----

    private fun persistAction(action: ActionState) {
        when (action) {
            is ActionState.ReAuthRequired -> {
                savedState[KEY_STEP] = STEP_REAUTH
                savedState[KEY_CHALLENGE] = action.challengeId
            }
            is ActionState.ConfirmClosureFinalize -> {
                savedState[KEY_STEP] = STEP_FINALIZE
                savedState[KEY_CHALLENGE] = action.challengeId
                savedState[KEY_TYPED] = action.typed
            }
            ActionState.ConfirmSuspend -> savedState[KEY_STEP] = STEP_SUSPEND
            ActionState.ConfirmReactivate -> savedState[KEY_STEP] = STEP_REACTIVATE
            else -> clearSavedAction()
        }
    }

    /** Restores a persisted confirm/typed-token step after process recreation; never restores Submitting. */
    private fun restoredAction(): ActionState = when (savedState.get<String>(KEY_STEP)) {
        STEP_SUSPEND -> ActionState.ConfirmSuspend
        STEP_REACTIVATE -> ActionState.ConfirmReactivate
        STEP_REAUTH -> savedState.get<String>(KEY_CHALLENGE)
            ?.let { ActionState.ReAuthRequired(it, emptyList()) } ?: ActionState.Idle
        STEP_FINALIZE -> savedState.get<String>(KEY_CHALLENGE)
            ?.let { ActionState.ConfirmClosureFinalize(it, savedState.get<String>(KEY_TYPED).orEmpty()) }
            ?: ActionState.Idle
        else -> ActionState.Idle
    }

    private fun clearSavedAction() {
        savedState.remove<String>(KEY_STEP)
        savedState.remove<String>(KEY_CHALLENGE)
        savedState.remove<String>(KEY_TYPED)
    }

    companion object {
        const val MSG_AMBIGUOUS =
            "We couldn't confirm the action - check your account status."
        const val MSG_CLOSURE_START_FAILED =
            "Couldn't start account closure. Please try again."

        private const val KEY_STEP = "and387_step"
        private const val KEY_CHALLENGE = "and387_challenge"
        private const val KEY_TYPED = "and387_typed"
        private const val STEP_SUSPEND = "suspend"
        private const val STEP_REACTIVATE = "reactivate"
        private const val STEP_REAUTH = "reauth"
        private const val STEP_FINALIZE = "finalize"
    }
}

/** AND-387 - convenience: true while a destructive action is in flight (disables the confirm in the UI). */
val ActionState.isSubmitting: Boolean get() = this == ActionState.Submitting

/** AND-387 - whether the CLOSE-account row should be offered for the given state (mirrors AND-082 gating). */
fun AccountState.allowsClose(): Boolean = this == AccountState.ACTIVE || this == AccountState.SUSPENDED
