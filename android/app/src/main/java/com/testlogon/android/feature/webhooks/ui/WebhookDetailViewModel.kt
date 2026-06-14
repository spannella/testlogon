package com.testlogon.android.feature.webhooks.ui

import androidx.lifecycle.SavedStateHandle
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.ApiResult
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
 * AND-398 - drives the [WebhookDetailUiState] for the webhook DETAIL (screen 2).
 *
 * The endpoint id arrives as a nav arg via [SavedStateHandle] (survives process death). [load] prefers the
 * repository's cached list entry (FR-2 "detail data is taken from the list payload where complete"), falling
 * back to GET ui/webhooks/{endpointId} - both flow through [WebhooksRepository.get]. A non-2xx other than 401
 * resolves to [WebhookDetailUiState.Error]; a 404-shaped not-found (undeclared in the OpenAPI - handled
 * defensively) resolves to [WebhookDetailUiState.NotFound]. A TERMINAL 401 -> one-shot NavigateToLogin.
 */
@HiltViewModel
class WebhookDetailViewModel @Inject constructor(
    private val repo: WebhooksRepository,
    savedState: SavedStateHandle,
) : ViewModel() {

    val webhookId: String =
        checkNotNull(savedState[ARG_WEBHOOK_ID]) { "missing $ARG_WEBHOOK_ID nav arg" }

    private val _uiState = MutableStateFlow<WebhookDetailUiState>(WebhookDetailUiState.Loading)
    val uiState: StateFlow<WebhookDetailUiState> = _uiState.asStateFlow()

    private val _effects = Channel<WebhooksEffect>(Channel.BUFFERED)
    val effects: Flow<WebhooksEffect> = _effects.receiveAsFlow()

    init {
        load()
    }

    fun load() {
        _uiState.value = WebhookDetailUiState.Loading
        viewModelScope.launch {
            when (val result = repo.get(webhookId)) {
                is ApiResult.Success ->
                    _uiState.value = WebhookDetailUiState.Content(result.data)
                is ApiResult.Failure -> {
                    when (result.error.status) {
                        HTTP_UNAUTHORIZED -> _effects.send(WebhooksEffect.NavigateToLogin)
                        HTTP_NOT_FOUND -> _uiState.value = WebhookDetailUiState.NotFound
                        else -> _uiState.value = WebhookDetailUiState.Error(result.error.message)
                    }
                }
                is ApiResult.NetworkError ->
                    _uiState.value = WebhookDetailUiState.Error(OFFLINE_FALLBACK)
            }
        }
    }

    companion object {
        const val ARG_WEBHOOK_ID = "webhookId"

        private const val HTTP_UNAUTHORIZED = 401
        private const val HTTP_NOT_FOUND = 404
        private const val OFFLINE_FALLBACK = "Couldn't reach the server. Try again."
    }
}
