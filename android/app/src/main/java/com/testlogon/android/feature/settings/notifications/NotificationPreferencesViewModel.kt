package com.testlogon.android.feature.settings.notifications

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.model.NotificationChannel
import com.testlogon.android.core.model.NotificationTypePreference
import com.testlogon.android.data.preferences.NotificationPreferencesRepository
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
 * AND-080 — per-category notification channel toggles (push/email/SMS), persisted via the alert
 * type-preferences endpoint. Toggling a switch updates the UI optimistically and immediately POSTs;
 * on failure the toggle rolls back to the last persisted value and a transient error is shown.
 */
data class CategoryRow(
    val alertType: String,
    val titleRes: Int,
    val pref: NotificationTypePreference,
    val savingChannels: Set<NotificationChannel> = emptySet(),
)

sealed interface NotificationPrefsUiState {
    data object Loading : NotificationPrefsUiState
    data object Empty : NotificationPrefsUiState
    data class Ready(
        val rows: List<CategoryRow>,
        val isStale: Boolean = false,
    ) : NotificationPrefsUiState

    data class Error(val message: String) : NotificationPrefsUiState
}

sealed interface NotificationPrefsEffect {
    data class ShowMessage(val message: String) : NotificationPrefsEffect
}

/** A known alert-type catalog used for display titles; unknown server types still render by id. */
internal data class AlertTypeMeta(val alertType: String, val titleRes: Int)

@HiltViewModel
class NotificationPreferencesViewModel @Inject constructor(
    private val repository: NotificationPreferencesRepository,
) : ViewModel() {

    private val _state = MutableStateFlow<NotificationPrefsUiState>(NotificationPrefsUiState.Loading)
    val state: StateFlow<NotificationPrefsUiState> = _state.asStateFlow()

    private val _effects = Channel<NotificationPrefsEffect>(Channel.BUFFERED)
    val effects: Flow<NotificationPrefsEffect> = _effects.receiveAsFlow()

    init {
        load()
    }

    fun load() {
        _state.value = NotificationPrefsUiState.Loading
        viewModelScope.launch {
            when (val result = repository.getTypePreferences()) {
                is ApiResult.Success -> _state.value = toReady(result.data, isStale = false)
                is ApiResult.Failure -> _state.value = NotificationPrefsUiState.Error(result.error.message)
                is ApiResult.NetworkError ->
                    _state.value = NotificationPrefsUiState.Error(NETWORK_MESSAGE)
            }
        }
    }

    private fun toReady(prefs: List<NotificationTypePreference>, isStale: Boolean): NotificationPrefsUiState {
        if (prefs.isEmpty()) return NotificationPrefsUiState.Empty
        val rows = prefs.map { pref ->
            CategoryRow(
                alertType = pref.alertType,
                titleRes = titleResFor(pref.alertType),
                pref = pref,
            )
        }
        return NotificationPrefsUiState.Ready(rows = rows, isStale = isStale)
    }

    fun onToggle(alertType: String, channel: NotificationChannel, enabled: Boolean) {
        val ready = _state.value as? NotificationPrefsUiState.Ready ?: return
        val row = ready.rows.firstOrNull { it.alertType == alertType } ?: return
        val previous = row.pref
        val optimistic = previous.withChannel(channel, enabled)

        // Optimistic UI + mark channel saving.
        updateRow(alertType) { it.copy(pref = optimistic, savingChannels = it.savingChannels + channel) }

        viewModelScope.launch {
            when (val result = repository.updateTypePreference(optimistic)) {
                is ApiResult.Success -> {
                    // Reconcile from server truth for this type (fall back to optimistic).
                    val server = result.data.firstOrNull { it.alertType == alertType } ?: optimistic
                    updateRow(alertType) { it.copy(pref = server, savingChannels = it.savingChannels - channel) }
                }
                is ApiResult.Failure -> rollback(alertType, channel, previous, result.error.message)
                is ApiResult.NetworkError -> rollback(alertType, channel, previous, NETWORK_MESSAGE)
            }
        }
    }

    private suspend fun rollback(
        alertType: String,
        channel: NotificationChannel,
        previous: NotificationTypePreference,
        message: String,
    ) {
        updateRow(alertType) { it.copy(pref = previous, savingChannels = it.savingChannels - channel) }
        _effects.send(NotificationPrefsEffect.ShowMessage(message))
    }

    private fun updateRow(alertType: String, transform: (CategoryRow) -> CategoryRow) {
        val ready = _state.value as? NotificationPrefsUiState.Ready ?: return
        _state.value = ready.copy(
            rows = ready.rows.map { if (it.alertType == alertType) transform(it) else it },
        )
    }

    private fun titleResFor(alertType: String): Int =
        CATALOG.firstOrNull { it.alertType == alertType }?.titleRes
            ?: com.testlogon.android.R.string.notif_prefs_category_generic

    companion object {
        private const val NETWORK_MESSAGE =
            "Couldn't reach the server. Check your connection and try again."

        /** Known alert types -> localized titles (titles fall back to a generic label otherwise). */
        internal val CATALOG: List<AlertTypeMeta> = listOf(
            AlertTypeMeta("security_alerts", com.testlogon.android.R.string.notif_prefs_category_security),
            AlertTypeMeta("account_activity", com.testlogon.android.R.string.notif_prefs_category_account),
            AlertTypeMeta("product_updates", com.testlogon.android.R.string.notif_prefs_category_product),
            AlertTypeMeta("billing", com.testlogon.android.R.string.notif_prefs_category_billing),
            AlertTypeMeta("marketing", com.testlogon.android.R.string.notif_prefs_category_marketing),
        )
    }
}
