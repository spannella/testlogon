package com.testlogon.android.feature.alerts

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.R
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.alerts.AlertsPage
import com.testlogon.android.data.alerts.AlertsRepository
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
 * Drives [AlertsUiState] from [AlertsRepository].
 *
 * Loads the first page on first composition / pull-to-refresh / filter toggle. Tapping an unread alert
 * marks it read (optimistic local flip after the server ack); the app-bar action marks all read. A hard
 * 401 (after the network layer refresh+retry) maps to SessionExpired; a failed refresh with a cached
 * page shows a stale banner, else Error/Offline. Effects are Channel-backed so they are not replayed.
 */
@HiltViewModel
class AlertsViewModel @Inject constructor(
    private val repository: AlertsRepository,
) : ViewModel() {

    private val _uiState = MutableStateFlow(AlertsUiState())
    val uiState: StateFlow<AlertsUiState> = _uiState.asStateFlow()

    private val _effects = Channel<AlertsEffect>(Channel.BUFFERED)
    val effects: Flow<AlertsEffect> = _effects.receiveAsFlow()

    init {
        load(fromUser = false)
    }

    fun onRefresh() = load(fromUser = true)

    fun onRetry() = load(fromUser = true)

    fun onToggleUnreadOnly() {
        _uiState.update { it.copy(unreadOnly = !it.unreadOnly) }
        load(fromUser = true)
    }

    fun onAlertClick(alertId: String) {
        val page = _uiState.value.page ?: return
        val alert = page.alerts.firstOrNull { it.id == alertId } ?: return
        if (!alert.isUnread) return
        viewModelScope.launch {
            when (repository.markRead(listOf(alertId))) {
                is ApiResult.Success -> applyLocalRead(setOf(alertId))
                else -> _effects.send(AlertsEffect.ShowMessage(R.string.alerts_inbox_mark_failed))
            }
        }
    }

    fun onMarkAllRead() {
        val state = _uiState.value
        if (state.isMutating || !state.hasUnread) return
        _uiState.update { it.copy(isMutating = true) }
        viewModelScope.launch {
            when (repository.markAllRead()) {
                is ApiResult.Success -> {
                    applyLocalRead(allUnreadIds())
                    _uiState.update { it.copy(isMutating = false) }
                    _effects.send(AlertsEffect.ShowMessage(R.string.alerts_inbox_marked_all))
                }
                else -> {
                    _uiState.update { it.copy(isMutating = false) }
                    _effects.send(AlertsEffect.ShowMessage(R.string.alerts_inbox_mark_failed))
                }
            }
        }
    }

    private fun allUnreadIds(): Set<String> =
        _uiState.value.page?.alerts?.filter { it.isUnread }?.map { it.id }?.toSet() ?: emptySet()

    private fun applyLocalRead(ids: Set<String>) {
        if (ids.isEmpty()) return
        val now = System.currentTimeMillis() / 1000L
        _uiState.update { st ->
            val page = st.page ?: return@update st
            st.copy(
                page = page.copy(
                    alerts = page.alerts.map {
                        if (it.id in ids && it.isUnread) it.copy(readAt = now) else it
                    },
                ),
            )
        }
    }

    private fun load(fromUser: Boolean) {
        val state = _uiState.value
        if (state.isRefreshing) return
        val hasContent = state.page != null
        _uiState.update {
            it.copy(
                phase = if (hasContent) it.phase else AlertsUiState.Phase.Loading,
                isRefreshing = fromUser && hasContent,
                errorMessage = if (hasContent) it.errorMessage else null,
            )
        }
        viewModelScope.launch {
            when (val result = repository.loadAlerts(_uiState.value.unreadOnly)) {
                is ApiResult.Success -> reduceSuccess(result.data)
                is ApiResult.Failure -> {
                    if (result.error.status == HTTP_UNAUTHORIZED) {
                        _uiState.update {
                            it.copy(phase = AlertsUiState.Phase.SessionExpired, isRefreshing = false)
                        }
                    } else {
                        reduceFailure(result.error.message, offline = false)
                    }
                }
                is ApiResult.NetworkError -> reduceFailure(OFFLINE_FALLBACK, offline = true)
            }
        }
    }

    private fun reduceSuccess(data: AlertsPage) {
        _uiState.update {
            it.copy(
                phase = if (data.isEmpty) AlertsUiState.Phase.Empty else AlertsUiState.Phase.Content,
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
                    phase = if (cached.isEmpty) AlertsUiState.Phase.Empty else AlertsUiState.Phase.Content,
                    page = cached,
                    isRefreshing = false,
                    isStale = true,
                    errorMessage = null,
                )
            }
            _effects.send(AlertsEffect.ShowMessage(R.string.alerts_inbox_refresh_failed_stale))
        } else {
            _uiState.update {
                it.copy(
                    phase = if (offline) AlertsUiState.Phase.Offline else AlertsUiState.Phase.Error,
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
