package com.testlogon.android.feature.webhooks.ui

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.network.error.ApiErrorParser
import com.testlogon.android.feature.webhooks.data.WebhooksRepository
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
 * AND-398 - drives the [CreateWebhookForm] for the LIGHT create screen (screen 3).
 *
 * The subscribable event types are loaded from GET ui/webhooks/event-types (FR-3 / OQ-2 - a dynamic source, NOT
 * a static enum) into the multi-select. [onUrlChange] / [toggleEvent] update the form and re-derive [canSubmit]
 * (FR-4: a syntactically valid https:// URL AND >=1 selected event). [submit] guards against double-submit
 * (the in-flight submitting flag disables the action), POSTs the LIGHT create (NON-idempotent -> NO auto-retry),
 * and on 201 emits [WebhooksEffect.CreateSucceeded] (carrying the one-time secret, if any) so the screen pops
 * back to the refreshing list. A 422 whose loc tail is `url` maps to the inline [CreateWebhookForm.urlError]
 * (via [ApiErrorParser.fieldErrorForLocTail]); other failures populate [CreateWebhookForm.submitError]. A
 * TERMINAL 401 -> one-shot NavigateToLogin.
 */
@HiltViewModel
class CreateWebhookViewModel @Inject constructor(
    private val repo: WebhooksRepository,
    private val errorParser: ApiErrorParser,
) : ViewModel() {

    private val _form = MutableStateFlow(CreateWebhookForm())
    val form: StateFlow<CreateWebhookForm> = _form.asStateFlow()

    private val _effects = Channel<WebhooksEffect>(Channel.BUFFERED)
    val effects: Flow<WebhooksEffect> = _effects.receiveAsFlow()

    init {
        loadEventTypes()
    }

    /** Loads the subscribable event types into the multi-select; a failure leaves an empty (non-loading) list. */
    fun loadEventTypes() {
        _form.value = _form.value.copy(eventTypesLoading = true)
        viewModelScope.launch {
            when (val result = repo.eventTypes()) {
                is ApiResult.Success ->
                    _form.value = _form.value.copy(
                        eventTypes = result.data,
                        eventTypesLoading = false,
                    )
                is ApiResult.Failure -> {
                    if (result.error.status == HTTP_UNAUTHORIZED) {
                        _effects.send(WebhooksEffect.NavigateToLogin)
                    }
                    _form.value = _form.value.copy(eventTypesLoading = false)
                }
                is ApiResult.NetworkError ->
                    _form.value = _form.value.copy(eventTypesLoading = false)
            }
        }
    }

    fun onUrlChange(value: String) {
        _form.value = recompute(_form.value.copy(url = value, urlError = null, submitError = null))
    }

    fun toggleEvent(type: String) {
        val current = _form.value
        val next = current.selectedEvents.toMutableSet().apply {
            if (!add(type)) remove(type)
        }
        _form.value = recompute(current.copy(selectedEvents = next, submitError = null))
    }

    /**
     * Submits the LIGHT create. Double-submit guard: a no-op while already [CreateWebhookForm.submitting] or when
     * the form is not [CreateWebhookForm.canSubmit].
     */
    fun submit() {
        val current = _form.value
        if (current.submitting || !current.canSubmit) return
        _form.value = current.copy(submitting = true, submitError = null, urlError = null)
        viewModelScope.launch {
            when (val result = repo.create(current.url.trim(), current.selectedEvents.toList())) {
                is ApiResult.Success -> {
                    _form.value = _form.value.copy(submitting = false)
                    _effects.send(WebhooksEffect.CreateSucceeded(result.data.secret))
                }
                is ApiResult.Failure -> {
                    if (result.error.status == HTTP_UNAUTHORIZED) {
                        _form.value = _form.value.copy(submitting = false)
                        _effects.send(WebhooksEffect.NavigateToLogin)
                    } else {
                        val urlError = errorParser.fieldErrorForLocTail(result.error, FIELD_URL)
                        _form.value = _form.value.copy(
                            submitting = false,
                            urlError = urlError,
                            submitError = result.error.message,
                        )
                    }
                }
                is ApiResult.NetworkError ->
                    _form.value = _form.value.copy(
                        submitting = false,
                        submitError = OFFLINE_FALLBACK,
                    )
            }
        }
    }

    /** Re-derives [CreateWebhookForm.canSubmit] from the current url + selection (FR-4). */
    private fun recompute(form: CreateWebhookForm): CreateWebhookForm =
        form.copy(canSubmit = isValidHttpsUrl(form.url) && form.selectedEvents.isNotEmpty())

    companion object {
        private const val HTTP_UNAUTHORIZED = 401
        private const val FIELD_URL = "url"
        private const val OFFLINE_FALLBACK = "Couldn't reach the server. Try again."

        /**
         * AND-398 (FR-4) - client-side https-only URL validation. Rejects non-https schemes (plaintext http://
         * is refused for safety even though the dev backend is HTTP), requires a non-blank host, and is total
         * (never throws). Kept here (not android.net.Uri) so the gating is unit-testable on the JVM.
         */
        fun isValidHttpsUrl(raw: String): Boolean {
            val value = raw.trim()
            if (!value.startsWith("https://", ignoreCase = true)) return false
            val afterScheme = value.substring("https://".length)
            // Host is everything up to the first '/', '?' or '#'; it must be non-blank.
            val host = afterScheme.takeWhile { it != '/' && it != '?' && it != '#' }
            if (host.isBlank()) return false
            // A bare "https://" or "https:// " (host only whitespace) is already rejected above; also reject a
            // host that is only a port separator (e.g. "https://:8080").
            return host.substringBefore(':').isNotBlank()
        }
    }
}
