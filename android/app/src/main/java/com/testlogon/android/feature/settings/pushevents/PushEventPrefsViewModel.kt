package com.testlogon.android.feature.settings.pushevents

import androidx.annotation.StringRes
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.R
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.preferences.PushEventPrefs
import com.testlogon.android.data.preferences.PushEventPrefsRepository
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

/** D2 - one transactional PUSH event shown in the preferences screen. */
data class PushEventRow(
    val eventType: String,
    @StringRes val titleRes: Int,
    @StringRes val subtitleRes: Int,
    val enabled: Boolean,
    val defaultOn: Boolean,
)

sealed interface PushEventPrefsUiState {
    data object Loading : PushEventPrefsUiState
    data class Error(val message: String, val retryable: Boolean) : PushEventPrefsUiState
    data class Ready(val rows: List<PushEventRow>, val saving: Boolean = false) : PushEventPrefsUiState
}

sealed interface PushEventPrefsEffect {
    data class ShowMessage(val message: String) : PushEventPrefsEffect
}

/**
 * D2 - notification-preferences (per-event PUSH toggles) presentation. Reads/writes the opt-in /
 * opt-out alert-prefs model via [PushEventPrefsRepository]. Default-ON transactional events render ON
 * and toggle OFF (opt-out); opt-in events render off until enabled.
 */
@HiltViewModel
class PushEventPrefsViewModel @Inject constructor(
    private val repository: PushEventPrefsRepository,
) : ViewModel() {

    private val _state = MutableStateFlow<PushEventPrefsUiState>(PushEventPrefsUiState.Loading)
    val state: StateFlow<PushEventPrefsUiState> = _state.asStateFlow()

    private val _effects = Channel<PushEventPrefsEffect>(Channel.BUFFERED)
    val effects: Flow<PushEventPrefsEffect> = _effects.receiveAsFlow()

    private var current: PushEventPrefs? = null

    init { load() }

    fun load() {
        _state.value = PushEventPrefsUiState.Loading
        viewModelScope.launch {
            when (val res = repository.get()) {
                is ApiResult.Success -> {
                    current = res.data
                    _state.value = PushEventPrefsUiState.Ready(rowsFor(res.data))
                }
                is ApiResult.Failure ->
                    _state.value = PushEventPrefsUiState.Error(res.error.message, retryable = true)
                is ApiResult.NetworkError ->
                    _state.value = PushEventPrefsUiState.Error("You're offline", retryable = true)
            }
        }
    }

    fun retry() = load()

    fun onToggle(eventType: String, enabled: Boolean) {
        val base = current ?: return
        val next = base.withToggle(eventType, enabled)
        // Optimistic: reflect the toggle + a saving flag immediately.
        current = next
        _state.value = PushEventPrefsUiState.Ready(rowsFor(next), saving = true)
        viewModelScope.launch {
            when (val res = repository.save(next)) {
                is ApiResult.Success -> {
                    current = res.data
                    _state.value = PushEventPrefsUiState.Ready(rowsFor(res.data), saving = false)
                }
                is ApiResult.Failure, is ApiResult.NetworkError -> {
                    // Revert the optimistic change and surface a message.
                    current = base
                    _state.value = PushEventPrefsUiState.Ready(rowsFor(base), saving = false)
                    _effects.trySend(PushEventPrefsEffect.ShowMessage("Couldn't save. Try again."))
                }
            }
        }
    }

    private fun rowsFor(prefs: PushEventPrefs): List<PushEventRow> = EVENTS.map { def ->
        PushEventRow(
            eventType = def.eventType,
            titleRes = def.titleRes,
            subtitleRes = def.subtitleRes,
            enabled = prefs.isPushEnabled(def.eventType),
            defaultOn = prefs.isDefaultOn(def.eventType),
        )
    }

    private data class EventDef(val eventType: String, @StringRes val titleRes: Int, @StringRes val subtitleRes: Int)

    companion object {
        // The transactional PUSH events shown, in display order. All default-ON (opt-out) today.
        private val EVENTS = listOf(
            EventDef("shop_item_sold", R.string.push_event_sold_title, R.string.push_event_sold_sub),
            EventDef("order_shipped", R.string.push_event_shipped_title, R.string.push_event_shipped_sub),
            EventDef("order_out_for_delivery", R.string.push_event_ofd_title, R.string.push_event_ofd_sub),
            EventDef("order_delivered", R.string.push_event_delivered_title, R.string.push_event_delivered_sub),
            EventDef("post_tip", R.string.push_event_post_tip_title, R.string.push_event_post_tip_sub),
            EventDef("message_tip", R.string.push_event_message_tip_title, R.string.push_event_message_tip_sub),
            EventDef("subscription_started", R.string.push_event_subscription_title, R.string.push_event_subscription_sub),
        )
    }
}
