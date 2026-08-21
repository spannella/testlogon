package com.testlogon.android.feature.bailout

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.bailout.BailoutRepository
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import javax.inject.Inject

data class BailoutSettingsUiState(
    val loading: Boolean = true,
    val autoEnabled: Boolean = false,
    val defaultMaxShareBps: Int = 2_000,
    /** True when the value shown is the device-local fallback (the server endpoint 404'd). */
    val deviceLocal: Boolean = false,
    val actionMessage: String? = null,
    val saving: Boolean = false,
)

/**
 * Drives the AUTO-BAILOUT PROTECTION account setting: when enabled a bailout auction auto-opens on
 * band-entry (else the trader must open it manually), offering up to a default max position-share.
 * Wired to `GET/PUT me/prefs/bailout`; degrades to a device-local ([BailoutPrefsStore]) copy — labelled
 * "saved on this device" — when the server endpoint 404s.
 */
@HiltViewModel
class BailoutSettingsViewModel @Inject constructor(
    private val repository: BailoutRepository,
) : ViewModel() {

    private val _uiState = MutableStateFlow(BailoutSettingsUiState())
    val uiState: StateFlow<BailoutSettingsUiState> = _uiState.asStateFlow()

    init {
        load()
    }

    fun consumeActionMessage() = _uiState.update { it.copy(actionMessage = null) }

    fun load() {
        _uiState.update { it.copy(loading = true) }
        viewModelScope.launch {
            when (val r = repository.prefs()) {
                is ApiResult.Success -> _uiState.update {
                    it.copy(
                        loading = false,
                        autoEnabled = r.data.autoEnabled,
                        defaultMaxShareBps = r.data.defaultMaxShareBps.takeIf { v -> v > 0 } ?: 2_000,
                        // The repository degrades to the local copy on 404, so a Success may be local; we
                        // can't distinguish here, so treat any non-network result as authoritative-enough
                        // and label device-local only when the save path reports it.
                        deviceLocal = it.deviceLocal,
                    )
                }
                is ApiResult.Failure -> _uiState.update { it.copy(loading = false, deviceLocal = true) }
                is ApiResult.NetworkError -> _uiState.update { it.copy(loading = false, deviceLocal = true) }
            }
        }
    }

    fun setAutoEnabled(enabled: Boolean) = save(enabled, _uiState.value.defaultMaxShareBps)

    fun setDefaultMaxShareBps(bps: Int) =
        save(_uiState.value.autoEnabled, bps.coerceIn(0, 10_000))

    private fun save(autoEnabled: Boolean, defaultMaxShareBps: Int) {
        if (_uiState.value.saving) return
        _uiState.update { it.copy(saving = true, autoEnabled = autoEnabled, defaultMaxShareBps = defaultMaxShareBps) }
        viewModelScope.launch {
            val msg = when (val r = repository.putPrefs(autoEnabled, defaultMaxShareBps)) {
                is ApiResult.Success -> {
                    _uiState.update {
                        it.copy(autoEnabled = r.data.autoEnabled, defaultMaxShareBps = r.data.defaultMaxShareBps.takeIf { v -> v > 0 } ?: defaultMaxShareBps)
                    }
                    "Auto-bailout preference saved."
                }
                is ApiResult.Failure -> "Saved on this device (backend pending)."
                is ApiResult.NetworkError -> "No connection — saved on this device."
            }
            _uiState.update { it.copy(saving = false, actionMessage = msg) }
        }
    }
}
