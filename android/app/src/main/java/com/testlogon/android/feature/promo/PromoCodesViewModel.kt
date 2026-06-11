package com.testlogon.android.feature.promo

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.R
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.promo.PromoCode
import com.testlogon.android.data.promo.PromoCodesRepository
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
 * AND-266 — drives [PromoCodesUiState] from [PromoCodesRepository].
 *
 * Loads the list on first composition + pull-to-refresh. onCreate validates the form client-side BEFORE
 * any network call, POSTs the code, then re-fetches the list (web parity). onDeactivate flips a code and
 * re-fetches. Create/deactivate are non-idempotent (no auto-retry). One-shot banners use a [Channel]-
 * backed effects flow; validation errors are surfaced as resolved messages so the VM stays Android-free.
 */
@HiltViewModel
class PromoCodesViewModel @Inject constructor(
    private val repository: PromoCodesRepository,
) : ViewModel() {

    private val _uiState = MutableStateFlow(PromoCodesUiState())
    val uiState: StateFlow<PromoCodesUiState> = _uiState.asStateFlow()

    private val _effects = Channel<PromoCodesEffect>(Channel.BUFFERED)
    val effects: Flow<PromoCodesEffect> = _effects.receiveAsFlow()

    init {
        refresh(fromUser = false)
    }

    fun onRefresh() = refresh(fromUser = true)

    fun onRetry() = refresh(fromUser = true)

    fun onOpenSheet() = _uiState.update { it.copy(isSheetOpen = true) }

    fun onDismissSheet() = _uiState.update { it.copy(isSheetOpen = false) }

    /**
     * Validates [form] client-side; on success POSTs the code, then re-fetches the list. Returns the
     * validation error key (or null) so the sheet can surface field errors without a network call.
     */
    fun onCreate(form: CreatePromoForm): PromoFormError? {
        val error = form.validate()
        if (error != null) {
            viewModelScope.launch { _effects.send(PromoCodesEffect.ShowMessage(error.messageRes())) }
            return error
        }
        if (_uiState.value.isSubmitting) return null
        _uiState.update { it.copy(isSubmitting = true) }
        viewModelScope.launch {
            when (val result = repository.create(form.toRequest())) {
                is ApiResult.Success -> {
                    _uiState.update { it.copy(isSubmitting = false, isSheetOpen = false) }
                    _effects.send(PromoCodesEffect.ShowMessage(R.string.promo_create_success))
                    loadList()
                }
                is ApiResult.Failure -> {
                    _uiState.update { it.copy(isSubmitting = false) }
                    _effects.send(PromoCodesEffect.ShowError(result.error.message))
                }
                is ApiResult.NetworkError -> {
                    _uiState.update { it.copy(isSubmitting = false) }
                    _effects.send(PromoCodesEffect.ShowMessage(R.string.promo_create_failed))
                }
            }
        }
        return null
    }

    fun onDeactivate(codeId: String) {
        viewModelScope.launch {
            when (val result = repository.deactivate(codeId)) {
                is ApiResult.Success -> {
                    _effects.send(PromoCodesEffect.ShowMessage(R.string.promo_deactivate_success))
                    loadList()
                }
                is ApiResult.Failure -> _effects.send(PromoCodesEffect.ShowError(result.error.message))
                is ApiResult.NetworkError ->
                    _effects.send(PromoCodesEffect.ShowMessage(R.string.promo_deactivate_failed))
            }
        }
    }

    private fun refresh(fromUser: Boolean) {
        val state = _uiState.value
        if (state.isRefreshing) return
        val hasContent = state.codes.isNotEmpty()
        _uiState.update {
            it.copy(
                phase = if (hasContent) it.phase else PromoCodesUiState.Phase.Loading,
                isRefreshing = fromUser && hasContent,
            )
        }
        viewModelScope.launch { loadList() }
    }

    private suspend fun loadList() {
        when (val result = repository.listCodes()) {
            is ApiResult.Success -> reduceSuccess(result.data)
            is ApiResult.Failure -> reduceFailure(result.error.message, offline = false)
            is ApiResult.NetworkError -> reduceFailure(OFFLINE_FALLBACK, offline = true)
        }
    }

    private fun reduceSuccess(codes: List<PromoCode>) {
        _uiState.update {
            it.copy(
                phase = if (codes.isEmpty()) PromoCodesUiState.Phase.Empty else PromoCodesUiState.Phase.Content,
                codes = codes,
                isRefreshing = false,
                errorMessage = null,
            )
        }
    }

    private fun reduceFailure(message: String, offline: Boolean) {
        val hasContent = _uiState.value.codes.isNotEmpty()
        if (hasContent) {
            // Keep prior list visible (stale-while-error); surface the error as a transient banner.
            _uiState.update { it.copy(isRefreshing = false) }
            viewModelScope.launch { _effects.send(PromoCodesEffect.ShowError(message)) }
        } else {
            _uiState.update {
                it.copy(
                    phase = if (offline) PromoCodesUiState.Phase.Offline else PromoCodesUiState.Phase.Error,
                    isRefreshing = false,
                    errorMessage = message,
                )
            }
        }
    }

    private fun PromoFormError.messageRes(): Int = when (this) {
        PromoFormError.CODE_REQUIRED -> R.string.promo_err_code_required
        PromoFormError.CODE_LENGTH -> R.string.promo_err_code_length
        PromoFormError.DISCOUNT_VALUE -> R.string.promo_err_discount_value
        PromoFormError.PERCENT_RANGE -> R.string.promo_err_percent_range
        PromoFormError.TRIAL_DAYS -> R.string.promo_err_trial_days
    }

    companion object {
        private const val OFFLINE_FALLBACK = "Couldn't reach the server. Pull down to retry."
    }
}
