package com.testlogon.android.feature.apikeys.ui

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.network.error.ApiErrorParser
import com.testlogon.android.feature.apikeys.data.ApiKeyCapabilities
import com.testlogon.android.feature.apikeys.data.ApiKeysRepository
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.receiveAsFlow
import kotlinx.coroutines.launch
import javax.inject.Inject

/**
 * B-APIKEY (batch 7) - drives the [CreateApiKeyForm] for the create screen.
 *
 * [onLabelChange] / [onToggleCapability] / [onExpiresChange] update the form and re-derive [canSubmit] (FR: a
 * non-blank label). [submit] guards against double-submit, collects the selected canonical capabilities + the
 * optional expiry-days, POSTs the create (NON-idempotent -> NO auto-retry), and on success emits
 * [ApiKeysEffect.CreateSucceeded] (carrying the one-time secret) so the screen pops back and the list shows it
 * once. A 422 whose loc tail is `label` maps to the inline [CreateApiKeyForm.labelError]; other failures
 * populate [CreateApiKeyForm.submitError] (a 401 "Fresh MFA required" surfaces here verbatim so the user knows to
 * re-verify MFA). A TERMINAL 401 from an expired session -> one-shot NavigateToLogin.
 */
@HiltViewModel
class CreateApiKeyViewModel @Inject constructor(
    private val repo: ApiKeysRepository,
    private val errorParser: ApiErrorParser,
) : ViewModel() {

    private val _form = MutableStateFlow(CreateApiKeyForm())
    val form: StateFlow<CreateApiKeyForm> = _form.asStateFlow()

    private val _effects = Channel<ApiKeysEffect>(Channel.BUFFERED)
    val effects: Flow<ApiKeysEffect> = _effects.receiveAsFlow()

    fun onLabelChange(value: String) {
        _form.value = recompute(_form.value.copy(label = value, labelError = null, submitError = null))
    }

    fun onToggleCapability(id: String) {
        val current = _form.value
        val next = if (id in current.selectedCapabilities) {
            current.selectedCapabilities - id
        } else {
            current.selectedCapabilities + id
        }
        _form.value = current.copy(selectedCapabilities = next, submitError = null)
    }

    fun onExpiresChange(value: String) {
        // Keep digits only so the optional expiry parses cleanly (blank -> no expiry).
        _form.value = _form.value.copy(expiresInDays = value.filter { it.isDigit() }, submitError = null)
    }

    fun submit() {
        val current = _form.value
        if (current.submitting || !current.canSubmit) return
        _form.value = current.copy(submitting = true, submitError = null, labelError = null)
        viewModelScope.launch {
            // Canonical order (matches the catalog) for a stable request payload.
            val capabilities = ApiKeyCapabilities.ALL.map { it.id }.filter { it in current.selectedCapabilities }
            val expires = current.expiresInDays.toIntOrNull()?.takeIf { it > 0 }
            when (val result = repo.create(current.label.trim(), capabilities, expires)) {
                is ApiResult.Success -> {
                    _form.value = _form.value.copy(submitting = false)
                    _effects.send(ApiKeysEffect.CreateSucceeded(result.data.secret))
                }
                is ApiResult.Failure -> {
                    // A 403 fresh-MFA / session-expired 401 from this NON-idempotent create surfaces inline so the
                    // user can re-verify; only a 401 with no recoverable context routes to the re-auth handoff.
                    if (result.error.status == HTTP_UNAUTHORIZED && result.error.message.contains("MFA", ignoreCase = true).not()) {
                        _form.value = _form.value.copy(submitting = false)
                        _effects.send(ApiKeysEffect.NavigateToLogin)
                    } else {
                        val labelError = errorParser.fieldErrorForLocTail(result.error, FIELD_LABEL)
                        _form.value = _form.value.copy(
                            submitting = false,
                            labelError = labelError,
                            submitError = result.error.message,
                        )
                    }
                }
                is ApiResult.NetworkError ->
                    _form.value = _form.value.copy(submitting = false, submitError = OFFLINE_FALLBACK)
            }
        }
    }

    private fun recompute(form: CreateApiKeyForm): CreateApiKeyForm =
        form.copy(canSubmit = form.label.isNotBlank())

    companion object {
        private const val HTTP_UNAUTHORIZED = 401
        private const val FIELD_LABEL = "label"
        private const val OFFLINE_FALLBACK = "Couldn't reach the server. Try again."
    }
}
