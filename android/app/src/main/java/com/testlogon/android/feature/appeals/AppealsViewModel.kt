package com.testlogon.android.feature.appeals

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.R
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.appeals.AppealsPage
import com.testlogon.android.data.appeals.EnforcementOption
import com.testlogon.android.data.appeals.AppealsRepository
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

/**
 * Drives [AppealsUiState] from [AppealsRepository].
 *
 * Loads the first page on first composition / pull-to-refresh. The app-bar "+" opens a submit form
 * (Enforcement ID + Appeal text); a successful submit reloads and shows a snackbar. "Withdraw" on an
 * eligible appeal confirms then POSTs and reloads. A hard 401 (after the network layer refresh+retry)
 * maps to SessionExpired; a failed refresh with a cached page shows a stale banner, else Error/Offline.
 * Effects are Channel-backed so they are not replayed.
 */
@HiltViewModel
class AppealsViewModel @Inject constructor(
    private val repository: AppealsRepository,
) : ViewModel() {

    private val _uiState = MutableStateFlow(AppealsUiState())
    val uiState: StateFlow<AppealsUiState> = _uiState.asStateFlow()

    private val _effects = Channel<AppealsEffect>(Channel.BUFFERED)
    @Volatile private var pendingPrefillId: String = ""
    val effects: Flow<AppealsEffect> = _effects.receiveAsFlow()

    init {
        load(fromUser = false)
    }

    fun onRefresh() = load(fromUser = true)

    fun onRetry() = load(fromUser = true)

    // ---- Submit form ----

    fun onOpenSubmit() {
        _uiState.update {
            it.copy(submit = SubmitFormState(isOpen = true, enforcementId = pendingPrefillId, optionsLoading = true))
        }
        loadEnforcementOptions()
    }

    /** MODX-13: a ban/removal alert deep-link may pre-select the enforcement to appeal. */
    fun onPrefillEnforcement(enforcementId: String?) {
        val id = enforcementId?.trim().orEmpty()
        if (id.isBlank()) return
        pendingPrefillId = id
        onOpenSubmit()
    }

    fun onSelectEnforcement(enforcementId: String) {
        _uiState.update { it.copy(submit = it.submit.copy(enforcementId = enforcementId)) }
    }

    private fun loadEnforcementOptions() {
        viewModelScope.launch {
            when (val result = repository.loadEnforcementOptions()) {
                is ApiResult.Success -> {
                    val opts = result.data
                    _uiState.update {
                        val selected = it.submit.enforcementId.ifBlank {
                            opts.firstOrNull { o -> !o.hasAppeal }?.enforcementId ?: opts.firstOrNull()?.enforcementId ?: ""
                        }
                        it.copy(submit = it.submit.copy(options = opts, optionsLoading = false, optionsLoaded = true, enforcementId = selected))
                    }
                }
                else -> _uiState.update { it.copy(submit = it.submit.copy(optionsLoading = false, optionsLoaded = true)) }
            }
        }
    }

    fun onDismissSubmit() {
        if (_uiState.value.submit.isSubmitting) return
        pendingPrefillId = ""
        _uiState.update { it.copy(submit = SubmitFormState(isOpen = false)) }
    }

    fun onEnforcementIdChange(value: String) {
        _uiState.update { it.copy(submit = it.submit.copy(enforcementId = value)) }
    }

    fun onAppealTextChange(value: String) {
        _uiState.update { it.copy(submit = it.submit.copy(appealText = value)) }
    }

    fun onSubmit() {
        val form = _uiState.value.submit
        if (!form.canSubmit) return
        _uiState.update { it.copy(submit = it.submit.copy(isSubmitting = true)) }
        viewModelScope.launch {
            when (val result = repository.submitAppeal(form.enforcementId, form.appealText)) {
                is ApiResult.Success -> {
                    pendingPrefillId = ""
                    _uiState.update { it.copy(submit = SubmitFormState(isOpen = false)) }
                    _effects.send(AppealsEffect.ShowMessage(R.string.appeals_submit_success))
                    load(fromUser = true)
                }
                is ApiResult.Failure -> {
                    _uiState.update { it.copy(submit = it.submit.copy(isSubmitting = false)) }
                    if (result.error.status == HTTP_UNAUTHORIZED) {
                        _uiState.update { it.copy(phase = AppealsUiState.Phase.SessionExpired) }
                    } else {
                        _effects.send(AppealsEffect.ShowMessage(R.string.appeals_submit_failed))
                    }
                }
                is ApiResult.NetworkError -> {
                    _uiState.update { it.copy(submit = it.submit.copy(isSubmitting = false)) }
                    _effects.send(AppealsEffect.ShowMessage(R.string.appeals_submit_failed))
                }
            }
        }
    }

    // ---- Withdraw ----

    fun onWithdraw(appealId: String) {
        val appeal = _uiState.value.page?.appeals?.firstOrNull { it.id == appealId } ?: return
        if (!appeal.canWithdraw || _uiState.value.isMutating) return
        _uiState.update { it.copy(isMutating = true) }
        viewModelScope.launch {
            when (val result = repository.withdrawAppeal(appealId)) {
                is ApiResult.Success -> {
                    _uiState.update { it.copy(isMutating = false) }
                    _effects.send(AppealsEffect.ShowMessage(R.string.appeals_withdraw_success))
                    load(fromUser = true)
                }
                is ApiResult.Failure -> {
                    _uiState.update { it.copy(isMutating = false) }
                    if (result.error.status == HTTP_UNAUTHORIZED) {
                        _uiState.update { it.copy(phase = AppealsUiState.Phase.SessionExpired) }
                    } else {
                        _effects.send(AppealsEffect.ShowMessage(R.string.appeals_withdraw_failed))
                    }
                }
                is ApiResult.NetworkError -> {
                    _uiState.update { it.copy(isMutating = false) }
                    _effects.send(AppealsEffect.ShowMessage(R.string.appeals_withdraw_failed))
                }
            }
        }
    }

    // ---- Load ----

    private fun load(fromUser: Boolean) {
        val state = _uiState.value
        if (state.isRefreshing) return
        val hasContent = state.page != null
        _uiState.update {
            it.copy(
                phase = if (hasContent) it.phase else AppealsUiState.Phase.Loading,
                isRefreshing = fromUser && hasContent,
                errorMessage = if (hasContent) it.errorMessage else null,
            )
        }
        viewModelScope.launch {
            when (val result = repository.loadAppeals()) {
                is ApiResult.Success -> reduceSuccess(result.data)
                is ApiResult.Failure -> {
                    if (result.error.status == HTTP_UNAUTHORIZED) {
                        _uiState.update {
                            it.copy(phase = AppealsUiState.Phase.SessionExpired, isRefreshing = false)
                        }
                    } else {
                        reduceFailure(result.error.message, offline = false)
                    }
                }
                is ApiResult.NetworkError -> reduceFailure(OFFLINE_FALLBACK, offline = true)
            }
        }
    }

    private fun reduceSuccess(data: AppealsPage) {
        _uiState.update {
            it.copy(
                phase = if (data.isEmpty) AppealsUiState.Phase.Empty else AppealsUiState.Phase.Content,
                page = data,
                isRefreshing = false,
                isStale = false,
                errorMessage = null,
            )
        }
    }

    private suspend fun reduceFailure(message: String, offline: Boolean) {
        val cached = repository.cached()
        if (cached != null) {
            _uiState.update {
                it.copy(
                    phase = if (cached.isEmpty) AppealsUiState.Phase.Empty else AppealsUiState.Phase.Content,
                    page = cached,
                    isRefreshing = false,
                    isStale = true,
                    errorMessage = null,
                )
            }
            _effects.send(AppealsEffect.ShowMessage(R.string.appeals_refresh_failed_stale))
        } else {
            _uiState.update {
                it.copy(
                    phase = if (offline) AppealsUiState.Phase.Offline else AppealsUiState.Phase.Error,
                    page = null,
                    isRefreshing = false,
                    isStale = false,
                    errorMessage = message,
                )
            }
        }
    }

    private companion object {
        private const val HTTP_UNAUTHORIZED = 401
        private const val OFFLINE_FALLBACK = "Could not reach the server. Pull down to retry."
    }
}
