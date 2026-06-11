package com.testlogon.android.feature.calendar.integrations

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.calendar.Calendar
import com.testlogon.android.data.calendar.CalendarRepository
import com.testlogon.android.data.gcal.ConnectPhase
import com.testlogon.android.data.gcal.GoogleCalendarRepository
import com.testlogon.android.data.gcal.GoogleCalendarReturn
import com.testlogon.android.data.gcal.GoogleCalendarReturnDispatcher
import com.testlogon.android.data.gcal.GoogleCalendarStatus
import com.testlogon.android.data.gcal.ProviderCalendar
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
 * AND-273 — drives the Google Calendar Connect screen.
 *
 * Backend-mediated OAuth (no Google SDK): onConnectClicked() calls startConnect() and emits an
 * OpenCustomTab effect (the authorization_url). The PRIMARY return path is onReturnedFromCustomTab()
 * -> refreshStatus() (read connection_active). A custom-scheme deep link is the optional fallback; the
 * Activity emits the parsed return through [GoogleCalendarReturnDispatcher] and onCallback() validates the
 * echoed state then calls completeConnect(). One-shot signals use Channel+receiveAsFlow (never state).
 *
 * In Connected, the screen lists the flat Google provider calendars and offers a per-row mapping picker
 * over the AND-270 internal calendars (POST .../mappings). Account email comes from the connect callback
 * (status omits it) and is shown if cached; it never reaches logs/telemetry.
 */
@HiltViewModel
class GoogleCalendarViewModel @Inject constructor(
    private val repo: GoogleCalendarRepository,
    private val calendarRepository: CalendarRepository,
    returnDispatcher: GoogleCalendarReturnDispatcher,
) : ViewModel() {

    private val _state = MutableStateFlow<GoogleCalendarUiState>(GoogleCalendarUiState.Loading)
    val state: StateFlow<GoogleCalendarUiState> = _state.asStateFlow()

    private val effectChannel = Channel<GoogleCalendarEffect>(Channel.BUFFERED)
    val effects: Flow<GoogleCalendarEffect> = effectChannel.receiveAsFlow()

    private var connectInFlight = false

    init {
        // Instant render from the cached projection, then refresh.
        viewModelScope.launch {
            repo.cachedStatus()?.let { cached -> _state.value = render(cached, stale = true) }
            refresh()
        }
        // Optional deep-link return path (custom scheme), mirroring AND-231.
        viewModelScope.launch {
            returnDispatcher.returns.collect { onCallback(it) }
        }
    }

    fun onRetry() {
        _state.value = GoogleCalendarUiState.Loading
        viewModelScope.launch { refresh() }
    }

    fun onConnectClicked() {
        if (connectInFlight) return
        connectInFlight = true
        viewModelScope.launch {
            when (val r = repo.startConnect()) {
                is ApiResult.Success -> {
                    _state.value = GoogleCalendarUiState.Connecting
                    effectChannel.send(GoogleCalendarEffect.OpenCustomTab(r.data.authorizationUrl))
                }
                is ApiResult.Failure ->
                    _state.value = GoogleCalendarUiState.Disconnected(r.error.message)
                is ApiResult.NetworkError ->
                    _state.value = GoogleCalendarUiState.Disconnected(OFFLINE_MESSAGE)
            }
            connectInFlight = false
        }
    }

    /** Called when the user returns to the app from the Custom Tab. Re-reads status. */
    fun onReturnedFromCustomTab() {
        if (_state.value !is GoogleCalendarUiState.Connecting) return
        viewModelScope.launch { refresh(afterConnectAttempt = true) }
    }

    /** Optional deep-link return: validate the echoed state, then drive the GET callback. */
    fun onCallback(ret: GoogleCalendarReturn) {
        viewModelScope.launch {
            if (ret.cancelled || ret.error != null) {
                onConnectCancelled()
                return@launch
            }
            val code = ret.code
            val state = ret.state
            if (code == null || state == null) {
                refresh(afterConnectAttempt = true)
                return@launch
            }
            val pending = repo.pendingOauthState()
            if (pending != null && pending != state) {
                repo.clearPendingOauth()
                _state.value = GoogleCalendarUiState.Disconnected(STATE_MISMATCH)
                effectChannel.send(GoogleCalendarEffect.ShowMessage(STATE_MISMATCH))
                return@launch
            }
            when (val r = repo.completeConnect(code, state)) {
                is ApiResult.Success -> applyStatus(r.data)
                is ApiResult.Failure ->
                    _state.value = GoogleCalendarUiState.Disconnected(r.error.message)
                is ApiResult.NetworkError ->
                    _state.value = GoogleCalendarUiState.Disconnected(OFFLINE_MESSAGE)
            }
        }
    }

    fun onConnectCancelled() {
        viewModelScope.launch {
            repo.clearPendingOauth()
            effectChannel.send(GoogleCalendarEffect.ShowMessage(CANCELLED))
            refresh()
        }
    }

    fun onMapCalendar(googleCalendarId: String, internalCalendarId: String) {
        viewModelScope.launch {
            when (repo.createMapping(internalCalendarId, googleCalendarId)) {
                is ApiResult.Success -> loadProviderCalendars()
                is ApiResult.Failure ->
                    effectChannel.send(GoogleCalendarEffect.ShowMessage(MAP_FAILED))
                is ApiResult.NetworkError ->
                    effectChannel.send(GoogleCalendarEffect.ShowMessage(OFFLINE_MESSAGE))
            }
        }
    }

    fun onRunSync() {
        val connected = _state.value as? GoogleCalendarUiState.Connected ?: return
        _state.value = connected.copy(syncRunning = true)
        viewModelScope.launch {
            repo.runSync()
            (_state.value as? GoogleCalendarUiState.Connected)?.let {
                _state.value = it.copy(syncRunning = false)
            }
            effectChannel.send(GoogleCalendarEffect.ShowMessage(SYNC_STARTED))
        }
    }

    fun onDisconnect() {
        viewModelScope.launch {
            when (repo.disconnect()) {
                is ApiResult.Success -> {
                    _state.value = GoogleCalendarUiState.Disconnected()
                    effectChannel.send(GoogleCalendarEffect.ShowMessage(DISCONNECTED))
                }
                is ApiResult.Failure ->
                    effectChannel.send(GoogleCalendarEffect.ShowMessage(DISCONNECT_FAILED))
                is ApiResult.NetworkError ->
                    effectChannel.send(GoogleCalendarEffect.ShowMessage(OFFLINE_MESSAGE))
            }
        }
    }

    private suspend fun refresh(afterConnectAttempt: Boolean = false) {
        when (val r = repo.refreshStatus()) {
            is ApiResult.Success -> applyStatus(r.data)
            is ApiResult.Failure -> {
                val cached = (_state.value as? GoogleCalendarUiState.Connected)
                if (cached != null) {
                    _state.value = cached.copy(stale = true)
                } else {
                    _state.value = GoogleCalendarUiState.Error(r.error.message, isOffline = false)
                }
            }
            is ApiResult.NetworkError -> {
                val cached = (_state.value as? GoogleCalendarUiState.Connected)
                if (cached != null) {
                    _state.value = cached.copy(stale = true)
                } else {
                    _state.value = GoogleCalendarUiState.Error(OFFLINE_MESSAGE, isOffline = true)
                }
            }
        }
        if (afterConnectAttempt && _state.value !is GoogleCalendarUiState.Connected) {
            // Returned without an active connection -> treat as cancelled.
            effectChannel.send(GoogleCalendarEffect.ShowMessage(CANCELLED))
        }
    }

    private suspend fun applyStatus(status: GoogleCalendarStatus) {
        when (status.phase) {
            ConnectPhase.CONNECTED, ConnectPhase.REAUTH_REQUIRED -> {
                _state.value = render(status, stale = false)
                loadProviderCalendars()
            }
            ConnectPhase.DISCONNECTED, ConnectPhase.CONNECTING ->
                _state.value = GoogleCalendarUiState.Disconnected()
        }
    }

    private fun render(status: GoogleCalendarStatus, stale: Boolean): GoogleCalendarUiState =
        if (status.connectionActive || status.reauthRequired) {
            GoogleCalendarUiState.Connected(
                accountEmail = status.accountEmail,
                calendars = emptyList(),
                internalCalendars = emptyList(),
                listState = ListState.LOADING,
                reauthRequired = status.reauthRequired,
                stale = stale,
            )
        } else {
            GoogleCalendarUiState.Disconnected()
        }

    private suspend fun loadProviderCalendars() {
        val connected = _state.value as? GoogleCalendarUiState.Connected ?: return
        _state.value = connected.copy(listState = ListState.LOADING)
        val internal = loadInternalCalendars()
        when (val r = repo.listProviderCalendars()) {
            is ApiResult.Success -> {
                val list: List<ProviderCalendar> = r.data
                _state.value = (_state.value as? GoogleCalendarUiState.Connected ?: connected).copy(
                    calendars = list,
                    internalCalendars = internal,
                    listState = if (list.isEmpty()) ListState.EMPTY else ListState.LOADED,
                )
            }
            is ApiResult.Failure, is ApiResult.NetworkError ->
                _state.value = (_state.value as? GoogleCalendarUiState.Connected ?: connected).copy(
                    internalCalendars = internal,
                    listState = ListState.ERROR,
                )
        }
    }

    private suspend fun loadInternalCalendars(): List<Calendar> =
        when (val r = calendarRepository.calendars()) {
            is ApiResult.Success -> r.data
            else -> emptyList()
        }

    private companion object {
        const val OFFLINE_MESSAGE = "You're offline. Try again when connected."
        const val STATE_MISMATCH = "Connection failed, please try again"
        const val CANCELLED = "Connection cancelled"
        const val DISCONNECTED = "Disconnected from Google Calendar"
        const val DISCONNECT_FAILED = "Couldn't disconnect. Try again."
        const val MAP_FAILED = "Couldn't update mapping. Try again."
        const val SYNC_STARTED = "Sync started"
    }
}
