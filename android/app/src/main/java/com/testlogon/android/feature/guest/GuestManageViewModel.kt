package com.testlogon.android.feature.guest

import androidx.lifecycle.SavedStateHandle
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.ApiResult
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import javax.inject.Inject

/**
 * AND-312 - presentation logic for the host-side guest MANAGE surface.
 *
 * [uiState] combines the in-memory guests Flow (from [GuestRepository.observeGuests]) with transient UI flows
 * (the created invite, loading / stale / in-flight / error). Mutations (promote / mute / remove / revoke) are
 * OPTIMISTIC: the row key goes into inFlight (disabling the row), the repo runs, and on success the list is
 * refreshed + the key cleared, while on failure the key is rolled back and an error banner shows.
 *
 * POLL: there is NO auto-started loop in init (an unbounded delay loop would spin runTest's end-of-test
 * advanceUntilIdle forever). The screen drives [startPolling] / [stopPolling] from a DisposableEffect
 * (mirrors AND-310/311). [pollIntervalMillis] is a SETTABLE PROPERTY (NOT a ctor param - Hilt cannot inject a
 * bare Long or honour Kotlin ctor defaults); tests set it, drive a SINGLE iteration with runCurrent, then
 * call [stopPolling].
 *
 * FR-8 (guest self-leave): there is NO guest leave endpoint - self-leave is NOT implemented here. Only the
 * host can revoke an invite or remove a guest. See the KDoc on [GuestAcceptViewModel] and the AND-312 report.
 */
@HiltViewModel
class GuestManageViewModel @Inject constructor(
    private val repository: GuestRepository,
    savedState: SavedStateHandle,
) : ViewModel() {

    val sessionId: String = savedState.get<String>(ARG_SESSION_ID).orEmpty()

    /**
     * Poll interval (ms). NOT a constructor param - Hilt cannot provide a bare [Long] and ignores Kotlin
     * defaults. Tests set this directly after construction to drive fast single iterations.
     */
    internal var pollIntervalMillis: Long = DEFAULT_POLL_INTERVAL_MILLIS

    /** The most-recently created (or selected) invite, surfaced in the invite card. */
    private val invite = MutableStateFlow<GuestInvite?>(null)

    /** True until the first refresh resolves (initial cold load). */
    private val loading = MutableStateFlow(true)

    /** Set when a refresh fails while cached guests are shown (warm-cache stale). */
    private val stale = MutableStateFlow(false)

    /** Row keys (inputId / inviteId) with an in-flight optimistic mutation (rendered non-interactive). */
    private val inFlight = MutableStateFlow<Set<String>>(emptySet())

    /** One-shot human-readable error banner. */
    private val error = MutableStateFlow<String?>(null)

    private var pollJob: Job? = null

    private val transient = combine(invite, loading, stale, inFlight, error) { inv, l, s, f, e ->
        Transient(inv, l, s, f, e)
    }

    val uiState: StateFlow<GuestManageUiState> =
        combine(repository.observeGuests(sessionId), transient) { guests, t ->
            GuestManageUiState(
                guests = guests,
                invite = t.invite,
                isLoading = t.loading,
                isStale = t.stale,
                inFlight = t.inFlight,
                error = t.error,
            )
        }.stateIn(
            scope = viewModelScope,
            started = SharingStarted.Eagerly,
            initialValue = GuestManageUiState(),
        )

    init {
        // NOTE: polling is NOT auto-started (an unbounded delay loop in init would spin runTest forever).
        if (sessionId.isBlank()) {
            loading.value = false
            error.value = NO_SESSION
        }
    }

    /**
     * Begins the poll loop (refreshGuests, then delay) while the screen is resumed. Bounded to
     * [viewModelScope]; tests set [pollIntervalMillis], drive a SINGLE iteration with runCurrent, then call
     * [stopPolling]. Safe to call repeatedly. No-op for a blank session.
     */
    fun startPolling() {
        if (sessionId.isBlank()) return
        if (pollJob != null) return
        pollJob = viewModelScope.launch {
            while (isActive) {
                applyRefreshOutcome(repository.refreshGuests(sessionId))
                delay(pollIntervalMillis)
            }
        }
    }

    /** Stops the poll loop (called by the screen when paused/disposed; tests call it before finishing). */
    fun stopPolling() {
        pollJob?.cancel()
        pollJob = null
    }

    private fun applyRefreshOutcome(result: ApiResult<List<Guest>>) {
        loading.value = false
        when (result) {
            is ApiResult.Success -> {
                stale.value = false
            }
            is ApiResult.Failure -> stale.value = true
            is ApiResult.NetworkError -> stale.value = true
        }
    }

    /** Create a guest invite; on success surfaces it in the invite card and refreshes the list. */
    fun onCreateInvite(
        joinMode: String = GuestJoinMode.BROWSER,
        label: String = DEFAULT_LABEL,
        expiryMinutes: Int = DEFAULT_EXPIRY_MINUTES,
    ) {
        if (sessionId.isBlank()) return
        if (inFlight.value.contains(CREATE_KEY)) return
        inFlight.update { it + CREATE_KEY }
        viewModelScope.launch {
            when (val result = repository.createInvite(sessionId, joinMode, label, expiryMinutes)) {
                is ApiResult.Success -> {
                    invite.value = result.data
                    inFlight.update { it - CREATE_KEY }
                    refreshAfterMutation()
                }
                is ApiResult.Failure -> finishMutation(CREATE_KEY, result.error.message)
                is ApiResult.NetworkError -> finishMutation(CREATE_KEY, OFFLINE)
            }
        }
    }

    /**
     * Revoke the given invite; optimistically disables the invite card while in flight. On success the
     * surfaced invite card is cleared inside [mutate] (it matches inviteId == the in-flight key).
     */
    fun onRevokeInvite(inviteId: String) {
        mutate(inviteId) { repository.revokeInvite(sessionId, inviteId) }
    }

    /** Promote a guest (input) to the live program. */
    fun onPromote(inputId: String) {
        mutate(inputId) { repository.promote(sessionId, inputId) }
    }

    /** Mute / unmute a guest (input); the muted state is tracked client-side by the repository. */
    fun onToggleMute(inputId: String, muted: Boolean) {
        mutate(inputId) { repository.setMuted(sessionId, inputId, muted) }
    }

    /** Remove a guest (input) - the screen only calls this AFTER the confirm dialog is accepted. */
    fun onRemove(inputId: String) {
        mutate(inputId) { repository.remove(sessionId, inputId) }
    }

    /** Retry a failed refresh (stale warm cache or cold load). */
    fun onRetryRefresh() {
        if (sessionId.isBlank()) return
        viewModelScope.launch { applyRefreshOutcome(repository.refreshGuests(sessionId)) }
    }

    /** Clears the one-shot error banner after the UI has shown it. */
    fun consumeError() {
        error.value = null
    }

    /**
     * Shared optimistic mutation: add [key] to inFlight (disabling the row), run [action], then on success
     * refresh + clear the key, or on failure roll back + banner. POSTs are never retried.
     */
    private fun mutate(key: String, action: suspend () -> ApiResult<Unit>) {
        if (sessionId.isBlank()) return
        if (inFlight.value.contains(key)) return
        inFlight.update { it + key }
        viewModelScope.launch {
            when (val result = action()) {
                is ApiResult.Success -> {
                    inFlight.update { it - key }
                    // Clear a surfaced invite card if its invite was the one revoked.
                    if (invite.value?.inviteId == key) invite.value = null
                    refreshAfterMutation()
                }
                is ApiResult.Failure -> finishMutation(key, result.error.message)
                is ApiResult.NetworkError -> finishMutation(key, OFFLINE)
            }
        }
    }

    /** Immediate authoritative refresh after a successful mutation (FR: reconcile post-mutation). */
    private suspend fun refreshAfterMutation() {
        applyRefreshOutcome(repository.refreshGuests(sessionId))
    }

    private fun finishMutation(key: String, message: String) {
        inFlight.update { it - key }
        error.value = message
    }

    override fun onCleared() {
        pollJob?.cancel()
    }

    private data class Transient(
        val invite: GuestInvite?,
        val loading: Boolean,
        val stale: Boolean,
        val inFlight: Set<String>,
        val error: String?,
    )

    companion object {
        /** Nav arg carrying the broadcast session id. */
        const val ARG_SESSION_ID = "sessionId"

        /** Default poll interval (ms). Override via [pollIntervalMillis] in tests. */
        const val DEFAULT_POLL_INTERVAL_MILLIS = 5_000L

        /** inFlight key for the create-invite affordance (no row id of its own). */
        const val CREATE_KEY = "__create_invite__"

        private const val DEFAULT_LABEL = "Guest"
        private const val DEFAULT_EXPIRY_MINUTES = 60

        // Non-resource fallbacks (the screen prefers stringResource where it has a Context).
        private const val NO_SESSION = "No broadcast session is available."
        private const val OFFLINE = "Couldn't reach the server. Try again."
    }
}
