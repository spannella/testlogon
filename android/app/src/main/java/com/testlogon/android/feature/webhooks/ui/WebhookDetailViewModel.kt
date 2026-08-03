package com.testlogon.android.feature.webhooks.ui

import androidx.lifecycle.SavedStateHandle
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.model.webhooks.WebhookTestResult
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
 * AND-398 / PAR-26 - drives the [WebhookDetailUiState] for the webhook DETAIL (screen 2), plus the PAR-26
 * test-send and rotate-secret actions.
 *
 * The endpoint id arrives as a nav arg via [SavedStateHandle] (survives process death). [load] prefers the
 * repository's cached list entry (FR-2 "detail data is taken from the list payload where complete"), falling
 * back to GET ui/webhooks/{endpointId} - both flow through [WebhooksRepository.get]. A non-2xx other than 401
 * resolves to [WebhookDetailUiState.Error]; a 404-shaped not-found resolves to [WebhookDetailUiState.NotFound].
 * A TERMINAL 401 -> one-shot NavigateToLogin.
 *
 * PAR-26 (both NON-idempotent POSTs, each with an in-flight guard):
 *  - [runTest] POSTs a synthetic delivery and reflects the outcome in [testState]. A 200 with status="failed"
 *    (unreachable host) is surfaced as a FAILED delivery result (not an error); only a real HTTP / transport
 *    failure lands in [TestState.Error].
 *  - [rotateSecret] POSTs a secret rotation and reveals the NEW secret ONCE via [rotateState]. The rotated
 *    secret is held only in this transient state for the one-time reveal - it is never cached / persisted.
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

    private val _testState = MutableStateFlow<TestState>(TestState.Idle)
    val testState: StateFlow<TestState> = _testState.asStateFlow()

    private val _rotateState = MutableStateFlow<RotateState>(RotateState.Idle)
    val rotateState: StateFlow<RotateState> = _rotateState.asStateFlow()

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

    /**
     * PAR-26 - sends a synthetic test delivery. In-flight guard: a second tap while a test is running is a
     * no-op. A 200 status="failed" is a FAILED result (not an error); a 404 / other HTTP error or a transport
     * failure lands in [TestState.Error]. A 401 routes to the re-auth handoff.
     */
    fun runTest() {
        if (_testState.value is TestState.Running) return
        _testState.value = TestState.Running
        viewModelScope.launch {
            when (val result = repo.test(webhookId)) {
                is ApiResult.Success -> _testState.value = TestState.Result(result.data)
                is ApiResult.Failure -> {
                    if (result.error.status == HTTP_UNAUTHORIZED) {
                        _testState.value = TestState.Idle
                        _effects.send(WebhooksEffect.NavigateToLogin)
                    } else {
                        _testState.value = TestState.Error(result.error.message)
                    }
                }
                is ApiResult.NetworkError -> _testState.value = TestState.Error(OFFLINE_FALLBACK)
            }
        }
    }

    /** Dismisses the last test result / error card. */
    fun clearTest() {
        if (_testState.value !is TestState.Running) _testState.value = TestState.Idle
    }

    /**
     * PAR-26 - rotates the signing secret. In-flight guard: a second tap while a rotation is running is a
     * no-op. On success the NEW secret is revealed ONCE via [RotateState.Revealed]; a 401 routes to re-auth.
     */
    fun rotateSecret() {
        if (_rotateState.value is RotateState.Running) return
        _rotateState.value = RotateState.Running
        viewModelScope.launch {
            when (val result = repo.rotateSecret(webhookId)) {
                is ApiResult.Success -> _rotateState.value = RotateState.Revealed(result.data)
                is ApiResult.Failure -> {
                    if (result.error.status == HTTP_UNAUTHORIZED) {
                        _rotateState.value = RotateState.Idle
                        _effects.send(WebhooksEffect.NavigateToLogin)
                    } else {
                        _rotateState.value = RotateState.Error(result.error.message)
                    }
                }
                is ApiResult.NetworkError -> _rotateState.value = RotateState.Error(OFFLINE_FALLBACK)
            }
        }
    }

    /** Dismisses the one-time secret reveal / rotation error (the secret is NOT re-fetchable afterwards). */
    fun clearRotate() {
        if (_rotateState.value !is RotateState.Running) _rotateState.value = RotateState.Idle
    }

    /** PAR-26 - the test-send sub-state (independent of the detail load surface). */
    sealed interface TestState {
        data object Idle : TestState
        data object Running : TestState
        data class Result(val result: WebhookTestResult) : TestState
        data class Error(val message: String) : TestState
    }

    /** PAR-26 - the rotate-secret sub-state; [Revealed] carries the one-time plaintext secret. */
    sealed interface RotateState {
        data object Idle : RotateState
        data object Running : RotateState
        data class Revealed(val secret: String) : RotateState
        data class Error(val message: String) : RotateState
    }

    companion object {
        const val ARG_WEBHOOK_ID = "webhookId"

        private const val HTTP_UNAUTHORIZED = 401
        private const val HTTP_NOT_FOUND = 404
        private const val OFFLINE_FALLBACK = "Couldn't reach the server. Try again."
    }
}
