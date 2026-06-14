package com.testlogon.android.feature.sessions

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.auth.SessionInfo
import com.testlogon.android.data.auth.SessionsRepository
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import javax.inject.Inject

/** A session row with the resolved current-session flag (AND-043). */
data class SessionRow(val info: SessionInfo, val isCurrent: Boolean)

/** What a pending confirmation will execute. */
sealed interface ConfirmTarget {
    data class RevokeOne(val sessionId: String) : ConfirmTarget
    data object RevokeOthers : ConfirmTarget
}

data class ActiveSessionsUiState(
    val isLoading: Boolean = false,
    val isRefreshing: Boolean = false,
    val rows: List<SessionRow> = emptyList(),
    val pendingRevokeIds: Set<String> = emptySet(),
    val revokingOthers: Boolean = false,
    val error: String? = null,
    val confirm: ConfirmTarget? = null,
    val loaded: Boolean = false,
    /** AND-045: rows shown are a last-known-good snapshot served because the live fetch failed. */
    val isStale: Boolean = false,
) {
    /** A live refresh is in flight (drives the "reconnecting" affordance). */
    val isReconnecting: Boolean get() = isRefreshing || (isLoading && rows.isNotEmpty())

    /** Disabled when no current session can be identified (guards against self-logout). */
    val canRevokeOthers: Boolean
        get() = rows.any { it.isCurrent } && rows.any { !it.isCurrent } && !revokingOthers
}

/**
 * AND-043 — lists active sessions and drives revoke / revoke-others with optimistic update +
 * rollback and an explicit confirm step. Exactly one row is marked current (via `is_current` or the
 * getMe session-id fallback); "revoke others" is disabled if none resolves.
 */
@HiltViewModel
class ActiveSessionsViewModel @Inject constructor(
    private val repo: SessionsRepository,
) : ViewModel() {

    private val _state = MutableStateFlow(ActiveSessionsUiState())
    val state: StateFlow<ActiveSessionsUiState> = _state.asStateFlow()

    init {
        load()
    }

    fun load() {
        if (_state.value.isLoading) return
        _state.update { it.copy(isLoading = true, error = null) }
        fetch { _state.update { st -> st.copy(isLoading = false) } }
    }

    fun refresh() {
        if (_state.value.isRefreshing) return
        _state.update { it.copy(isRefreshing = true, error = null) }
        fetch { _state.update { st -> st.copy(isRefreshing = false) } }
    }

    private fun fetch(onDone: () -> Unit) {
        viewModelScope.launch {
            when (val result = repo.listSessions()) {
                is ApiResult.Success -> _state.update {
                    it.copy(rows = toRows(result.data), loaded = true, error = null, isStale = false)
                }
                is ApiResult.Failure -> _state.update { serveStaleOrError(it, result.error.message) }
                is ApiResult.NetworkError -> _state.update {
                    serveStaleOrError(it, "Couldn't reach the server. Check your connection and try again.")
                }
            }
            onDone()
        }
    }

    /**
     * AND-045: on a failed live fetch, render the last-known-good snapshot behind a stale indicator
     * instead of a blank error. With no cache, surface the error/empty state normally (FR-5).
     */
    private fun serveStaleOrError(st: ActiveSessionsUiState, message: String): ActiveSessionsUiState {
        val cached = repo.cachedSessions()
        return if (!cached.isNullOrEmpty()) {
            st.copy(rows = toRows(cached), loaded = true, isStale = true, error = null)
        } else {
            st.copy(error = message)
        }
    }

    private fun toRow(info: SessionInfo): SessionRow {
        val current = info.isCurrent || info.sessionId == repo.currentSessionId()
        return SessionRow(info = info, isCurrent = current)
    }

    /** Maps to rows and pins the current session to the top (stable for the rest). */
    private fun toRows(list: List<SessionInfo>): List<SessionRow> =
        list.map(::toRow).sortedByDescending { it.isCurrent }

    fun requestRevoke(sessionId: String) {
        if (_state.value.rows.firstOrNull { it.info.sessionId == sessionId }?.isCurrent == true) return
        _state.update { it.copy(confirm = ConfirmTarget.RevokeOne(sessionId)) }
    }

    fun requestRevokeOthers() {
        if (!_state.value.canRevokeOthers) return
        _state.update { it.copy(confirm = ConfirmTarget.RevokeOthers) }
    }

    fun dismissConfirm() = _state.update { it.copy(confirm = null) }

    fun dismissError() = _state.update { it.copy(error = null) }

    fun confirm() {
        when (val target = _state.value.confirm) {
            is ConfirmTarget.RevokeOne -> revokeOne(target.sessionId)
            ConfirmTarget.RevokeOthers -> revokeOthers()
            null -> Unit
        }
    }

    private fun revokeOne(sessionId: String) {
        val snapshot = _state.value.rows
        val index = snapshot.indexOfFirst { it.info.sessionId == sessionId }
        if (index < 0) {
            _state.update { it.copy(confirm = null) }
            return
        }
        val removedRow = snapshot[index]
        // Optimistic removal.
        _state.update {
            it.copy(
                confirm = null,
                pendingRevokeIds = it.pendingRevokeIds + sessionId,
                rows = it.rows.filterNot { row -> row.info.sessionId == sessionId },
            )
        }
        viewModelScope.launch {
            when (val result = repo.revoke(sessionId)) {
                is ApiResult.Success ->
                    _state.update { it.copy(pendingRevokeIds = it.pendingRevokeIds - sessionId) }
                is ApiResult.Failure -> {
                    // 404/409 -> already gone: keep it removed. Otherwise roll back at original index.
                    val gone = result.error.status == 404 || result.error.status == 409
                    rollbackOrDrop(sessionId, removedRow, index, gone, result.error.message)
                }
                is ApiResult.NetworkError ->
                    rollbackOrDrop(sessionId, removedRow, index, gone = false, message = "Couldn't revoke the session. Try again.")
            }
        }
    }

    private fun rollbackOrDrop(
        sessionId: String,
        row: SessionRow,
        index: Int,
        gone: Boolean,
        message: String,
    ) = _state.update { st ->
        val pending = st.pendingRevokeIds - sessionId
        if (gone) {
            st.copy(pendingRevokeIds = pending)
        } else {
            val restored = st.rows.toMutableList().apply {
                add(index.coerceIn(0, size), row)
            }
            st.copy(pendingRevokeIds = pending, rows = restored, error = message)
        }
    }

    private fun revokeOthers() {
        val snapshot = _state.value.rows
        val kept = snapshot.filter { it.isCurrent }
        _state.update { it.copy(confirm = null, revokingOthers = true) }
        viewModelScope.launch {
            when (val result = repo.revokeOthers()) {
                is ApiResult.Success -> _state.update { it.copy(revokingOthers = false, rows = kept) }
                is ApiResult.Failure ->
                    _state.update { it.copy(revokingOthers = false, error = result.error.message) }
                is ApiResult.NetworkError ->
                    _state.update { it.copy(revokingOthers = false, error = "Couldn't revoke other sessions. Try again.") }
            }
        }
    }
}
