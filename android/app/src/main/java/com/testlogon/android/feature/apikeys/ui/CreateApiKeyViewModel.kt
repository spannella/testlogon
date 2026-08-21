package com.testlogon.android.feature.apikeys.ui

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.network.error.ApiErrorParser
import com.testlogon.android.feature.apikeys.data.ApiKeyCapabilities
import com.testlogon.android.feature.apikeys.data.ApiKeysRepository
import com.testlogon.android.feature.apikeys.data.Protocol
import com.testlogon.android.feature.apikeys.data.TradingCredentialsFormat
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
 *
 * Full-access (admin:all) wildcard: the backend grants it ONLY to admin/root owners; a non-admin owner selecting
 * the "Full access (admin)" chip gets a 403 `api_key_wildcard_forbidden`, which we map to a clear inline
 * [CreateApiKeyForm.submitError] (the generic [ApiErrorParser] would otherwise collapse the unknown code to a
 * "something went wrong" fallback).
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

    init {
        loadGateway()
    }

    /** Best-effort load of the gateway availability (for the per-protocol hints). Silent on any failure/404. */
    private fun loadGateway() {
        viewModelScope.launch {
            when (val r = repo.gatewayEndpoints()) {
                is ApiResult.Success -> _form.value = _form.value.copy(gateway = r.data)
                else -> Unit // hints simply degrade to "availability unknown"
            }
        }
    }

    /** MULTI-PROTOCOL: toggle a transport protocol; re-derives per-protocol scope-requirement errors + canSubmit. */
    fun onToggleProtocol(protocol: Protocol) {
        val current = _form.value
        val next = if (protocol in current.selectedProtocols) {
            current.selectedProtocols - protocol
        } else {
            current.selectedProtocols + protocol
        }
        _form.value = recompute(current.copy(selectedProtocols = next, submitError = null))
    }

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
        // Recompute so a protocol scope-requirement error clears/appears as scopes change.
        _form.value = recompute(current.copy(selectedCapabilities = next, submitError = null))
    }

    fun onExpiresChange(value: String) {
        // Keep digits only so the optional expiry parses cleanly (blank -> no expiry).
        _form.value = _form.value.copy(expiresInDays = value.filter { it.isDigit() }, submitError = null)
    }

    /**
     * MULTI-PROTOCOL: dismiss the show-once created-credentials dialog. The one-time API secret + protocol
     * credentials have now been shown, so pop back to the (refreshing) list WITHOUT re-displaying the secret.
     */
    fun dismissCreatedCredentials() {
        _form.value = _form.value.copy(createdProtocolCredentials = null, createdApiSecret = null)
        viewModelScope.launch { _effects.send(ApiKeysEffect.CreateSucceededShown) }
    }

    fun submit() {
        val current = _form.value
        if (current.submitting || !current.canSubmit) return
        _form.value = current.copy(submitting = true, submitError = null, labelError = null)
        viewModelScope.launch {
            // Canonical order (matches the catalog) for a stable request payload.
            val capabilities = ApiKeyCapabilities.ALL.map { it.id }.filter { it in current.selectedCapabilities }
            val expires = current.expiresInDays.toIntOrNull()?.takeIf { it > 0 }
            // Canonical protocol order (rest, ws, fix, binary).
            val protocols = TradingCredentialsFormat.ALL_PROTOCOLS
                .filter { it in current.selectedProtocols }
                .map { it.wire }
            when (val result = repo.create(current.label.trim(), capabilities, expires, protocols)) {
                is ApiResult.Success -> {
                    val creds = result.data.protocolCredentials?.takeIf { !it.isEmpty }
                    if (creds != null) {
                        // A multi-protocol key: show the API secret + one-time protocol credentials show-once
                        // HERE (do NOT pop yet). On dismiss the screen pops back and refreshes the list WITHOUT
                        // re-displaying the secret.
                        _form.value = _form.value.copy(
                            submitting = false,
                            createdProtocolCredentials = creds,
                            createdApiSecret = result.data.secret,
                        )
                    } else {
                        // Content-only (or no protocol material): keep the existing flow — pop back and let the
                        // list show the one-time secret once.
                        _form.value = _form.value.copy(submitting = false)
                        _effects.send(ApiKeysEffect.CreateSucceeded(result.data.secret))
                    }
                }
                is ApiResult.Failure -> {
                    // A 403 fresh-MFA / session-expired 401 from this NON-idempotent create surfaces inline so the
                    // user can re-verify; only a 401 with no recoverable context routes to the re-auth handoff.
                    if (result.error.status == HTTP_UNAUTHORIZED && result.error.message.contains("MFA", ignoreCase = true).not()) {
                        _form.value = _form.value.copy(submitting = false)
                        _effects.send(ApiKeysEffect.NavigateToLogin)
                    } else {
                        val labelError = errorParser.fieldErrorForLocTail(result.error, FIELD_LABEL)
                        // The wildcard-forbidden 403 carries an unmapped code -> give it a clear, specific message.
                        val submitError =
                            if (result.error.code == WILDCARD_FORBIDDEN_CODE) WILDCARD_FORBIDDEN_MESSAGE
                            else result.error.message
                        _form.value = _form.value.copy(
                            submitting = false,
                            labelError = labelError,
                            submitError = submitError,
                        )
                    }
                }
                is ApiResult.NetworkError ->
                    _form.value = _form.value.copy(submitting = false, submitError = OFFLINE_FALLBACK)
            }
        }
    }

    private fun recompute(form: CreateApiKeyForm): CreateApiKeyForm {
        val errors = TradingCredentialsFormat.validateProtocolScopes(
            protocols = form.selectedProtocols,
            scopes = form.selectedCapabilities,
        ).associate { it.protocol to it.message }
        return form.copy(
            protocolErrors = errors,
            canSubmit = form.label.isNotBlank() && errors.isEmpty(),
        )
    }

    companion object {
        private const val HTTP_UNAUTHORIZED = 401
        private const val FIELD_LABEL = "label"
        private const val OFFLINE_FALLBACK = "Couldn't reach the server. Try again."
        private const val WILDCARD_FORBIDDEN_CODE = "api_key_wildcard_forbidden"
        private const val WILDCARD_FORBIDDEN_MESSAGE =
            "Full access (admin) can only be granted to admin or root owners."
    }
}
