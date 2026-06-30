package com.testlogon.android.feature.settings.callrate

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.ApiResult
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import javax.inject.Inject
import kotlin.math.roundToInt

/**
 * Drives [CallRateUiState] for the paid-calls rate settings. Loads the caller's own rate (absent -> a sensible
 * default form), validates the form (rate 1..100 $/min, min-balance 1..60, max-duration 1..480), and on Save
 * POSTs (create) or PUTs (update). Disable deletes the rate. Mirrors the web CallRateSettings form/validation.
 */
@HiltViewModel
class CallRateViewModel @Inject constructor(
    private val repo: CallRateRepository,
) : ViewModel() {

    private val _uiState = MutableStateFlow<CallRateUiState>(CallRateUiState.Loading)
    val uiState: StateFlow<CallRateUiState> = _uiState.asStateFlow()

    init {
        load()
    }

    fun load() {
        _uiState.value = CallRateUiState.Loading
        viewModelScope.launch {
            when (val result = repo.getOwnRate()) {
                is ApiResult.Success -> {
                    val rate = result.data
                    _uiState.value = if (rate != null && rate.rateCentsPerMinute > 0) {
                        CallRateUiState.Content(
                            hasRate = true,
                            rateDollars = (rate.rateCentsPerMinute / 100.0).toString(),
                            minBalanceMinutes = rate.minBalanceMinutes.toString(),
                            maxDurationMinutes = rate.maxDurationMinutes.toString(),
                            enabled = rate.enabled,
                            currency = rate.currency,
                        )
                    } else {
                        CallRateUiState.Content(
                            hasRate = false,
                            rateDollars = "1.0",
                            minBalanceMinutes = "5",
                            maxDurationMinutes = "120",
                            enabled = true,
                        )
                    }
                }
                is ApiResult.Failure -> _uiState.value = CallRateUiState.Error(result.error.message)
                is ApiResult.NetworkError -> _uiState.value = CallRateUiState.Error(NETWORK_MESSAGE)
            }
        }
    }

    fun onRateChanged(v: String) = edit { it.copy(rateDollars = v, formError = null, savedMessage = null) }
    fun onMinBalanceChanged(v: String) = edit { it.copy(minBalanceMinutes = v, formError = null, savedMessage = null) }
    fun onMaxDurationChanged(v: String) = edit { it.copy(maxDurationMinutes = v, formError = null, savedMessage = null) }
    fun onEnabledChanged(v: Boolean) = edit { it.copy(enabled = v, savedMessage = null) }

    private fun edit(transform: (CallRateUiState.Content) -> CallRateUiState.Content) {
        val current = _uiState.value as? CallRateUiState.Content ?: return
        _uiState.value = transform(current)
    }

    fun save() {
        val current = _uiState.value as? CallRateUiState.Content ?: return
        if (current.saving || current.deleting) return

        val rateDollars = current.rateDollars.toDoubleOrNull()
        val minBalance = current.minBalanceMinutes.toIntOrNull()
        val maxDuration = current.maxDurationMinutes.toIntOrNull()
        val error = when {
            rateDollars == null || rateDollars < 1.0 || rateDollars > 100.0 ->
                "Rate must be between \$1 and \$100 per minute."
            minBalance == null || minBalance < 1 || minBalance > 60 ->
                "Min balance must be between 1 and 60 minutes."
            maxDuration == null || maxDuration < 1 || maxDuration > 480 ->
                "Max duration must be between 1 and 480 minutes."
            else -> null
        }
        if (error != null) {
            _uiState.value = current.copy(formError = error)
            return
        }

        val domain = CallRate(
            rateCentsPerMinute = (rateDollars!! * 100).roundToInt(),
            enabled = current.enabled,
            currency = current.currency,
            minBalanceMinutes = minBalance!!,
            maxDurationMinutes = maxDuration!!,
        )
        _uiState.value = current.copy(saving = true, formError = null, savedMessage = null)
        viewModelScope.launch {
            when (val result = repo.saveRate(domain, update = current.hasRate)) {
                is ApiResult.Success -> {
                    val saved = result.data
                    _uiState.value = CallRateUiState.Content(
                        hasRate = true,
                        rateDollars = (saved.rateCentsPerMinute / 100.0).toString(),
                        minBalanceMinutes = saved.minBalanceMinutes.toString(),
                        maxDurationMinutes = saved.maxDurationMinutes.toString(),
                        enabled = saved.enabled,
                        currency = saved.currency,
                        savedMessage = "Call rate saved.",
                    )
                }
                is ApiResult.Failure -> failSave(result.error.message)
                is ApiResult.NetworkError -> failSave(NETWORK_MESSAGE)
            }
        }
    }

    private fun failSave(message: String) {
        val current = _uiState.value as? CallRateUiState.Content ?: return
        _uiState.value = current.copy(saving = false, formError = message)
    }

    fun delete() {
        val current = _uiState.value as? CallRateUiState.Content ?: return
        if (!current.hasRate || current.saving || current.deleting) return
        _uiState.value = current.copy(deleting = true, formError = null, savedMessage = null)
        viewModelScope.launch {
            when (val result = repo.deleteRate()) {
                is ApiResult.Success -> _uiState.value = CallRateUiState.Content(
                    hasRate = false,
                    rateDollars = "1.0",
                    minBalanceMinutes = "5",
                    maxDurationMinutes = "120",
                    enabled = true,
                    savedMessage = "Paid calls disabled.",
                )
                is ApiResult.Failure -> failDelete(result.error.message)
                is ApiResult.NetworkError -> failDelete(NETWORK_MESSAGE)
            }
        }
    }

    private fun failDelete(message: String) {
        val current = _uiState.value as? CallRateUiState.Content ?: return
        _uiState.value = current.copy(deleting = false, formError = message)
    }

    private companion object {
        const val NETWORK_MESSAGE = "Couldn't reach the server. Check your connection and try again."
    }
}
