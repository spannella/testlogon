package com.testlogon.android.feature.questionnaire.respond.publicentry

import androidx.lifecycle.SavedStateHandle
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.feature.questionnaire.respond.RespondentSessionViewModel
import com.testlogon.android.feature.questionnaire.respond.data.RespondentSessionRepository
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.Job
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import javax.inject.Inject

/**
 * AND-395 - the public (UNAUTHENTICATED) respondent ENTRY state machine (epic E51). Resolves a
 * published [slug] to a reachable questionnaire, then RESUMES an existing session or STARTS a fresh
 * anonymous one, before the screen hands off to AND-349's editable [RespondentSessionViewModel] /
 * RespondScreen. The rich form UiState is AND-349's; this VM owns only the small
 * loading/ready/not-found/error entry shim.
 *
 * Anonymity is enforced at the transport layer (the [com.testlogon.android.core.network.Anonymous] tag
 * on getPublished/startSession): no `X-CSRF-Token`, and a 401 never triggers the auth-refresh / login
 * bounce (FR-5). This VM never logs the session id (FR-8 / privacy).
 *
 * Sequencing (FR-3/FR-8): bootstrap -> loadPublished (idempotent GET, retried by the OkHttp interceptor)
 * -> resolveSession: a persisted session RESUMES (no second start); else startAnonymousSession (POST, NO
 * auto-retry). A single-flight [Job] guards a cold-start deep-link race (R-3). [retry] re-runs the whole
 * bootstrap (the user-driven retry for a POST start failure, which is not auto-retried).
 *
 * NOTE: KDoc here deliberately avoids the comment-terminator character pair.
 */
@HiltViewModel
class PublicRespondViewModel @Inject constructor(
    savedState: SavedStateHandle,
    private val repository: RespondentSessionRepository,
) : ViewModel() {

    /** The published slug, carried by the typed route arg (survives process death via SavedState). */
    val slug: String = savedState.get<String>(RespondentSessionViewModel.ARG_SLUG).orEmpty()

    private val _state = MutableStateFlow<PublicEntryState>(PublicEntryState.Loading)
    val state: StateFlow<PublicEntryState> = _state.asStateFlow()

    /** Single-flight guard (R-3): a concurrent re-entry reuses the in-flight bootstrap. */
    private var bootstrapJob: Job? = null

    init { bootstrap() }

    /** FR-7 - user-driven retry; re-runs the full resolve (the start POST is not auto-retried). */
    fun retry() = bootstrap()

    private fun bootstrap() {
        if (bootstrapJob?.isActive == true) return
        bootstrapJob = viewModelScope.launch {
            if (slug.isBlank()) {
                _state.value = PublicEntryState.NotFound
                return@launch
            }
            _state.value = PublicEntryState.Loading
            when (val meta = repository.loadPublished(slug)) {        // FR-2 (idempotent anonymous GET)
                is ApiResult.Success -> resolveSession()
                is ApiResult.Failure ->
                    // FR-2/§7: 404 (runtime) or 422 (HTTPValidationError) -> NotFound; else retryable Error.
                    _state.value = if (meta.error.status == 404 || meta.error.status == 422) {
                        PublicEntryState.NotFound
                    } else {
                        PublicEntryState.Error(meta.error.message)
                    }
                is ApiResult.NetworkError ->
                    _state.value = PublicEntryState.Error(OFFLINE_MESSAGE)
            }
        }
    }

    /** FR-3/FR-8 - RESUME the persisted session if any (no duplicate start); else start anonymously. */
    private suspend fun resolveSession() {
        val existing = repository.persistedSession(slug)
        if (existing != null) {
            _state.value = PublicEntryState.Ready(existing.id, terminal = existing.isTerminal)
            return
        }
        when (val started = repository.startAnonymousSession(slug)) {   // POST, no auto-retry
            is ApiResult.Success ->
                _state.value = PublicEntryState.Ready(started.data.sessionId, terminal = false)
            is ApiResult.Failure ->
                _state.value = PublicEntryState.Error(started.error.message)
            is ApiResult.NetworkError ->
                _state.value = PublicEntryState.Error(OFFLINE_MESSAGE)
        }
    }

    private companion object {
        const val OFFLINE_MESSAGE = "You're offline. Connect to open this questionnaire."
    }
}

/**
 * AND-395 - the public-entry state: a small loading/ready/not-found/error machine distinct from
 * AND-349's rich RespondentSessionUiState (which is owned by the renderer route).
 */
sealed interface PublicEntryState {
    /** FR-2 - resolving the slug + session. */
    data object Loading : PublicEntryState

    /**
     * FR-3/4 - a session id is available; the screen hands off to AND-349's RespondScreen.
     * [terminal] true -> route to AND-349's Submitted confirmation (FR-3); false -> editable form.
     */
    data class Ready(val sessionId: String, val terminal: Boolean) : PublicEntryState

    /** FR-2 - 404 / 422 / unpublished / blank slug: "this questionnaire isn't available". */
    data object NotFound : PublicEntryState

    /** FR-7 - transport / 5xx failure: a retryable error (the message is already sanitized). */
    data class Error(val message: String) : PublicEntryState
}
