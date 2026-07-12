package com.testlogon.android.feature.settings.geo

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.ApiResult
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import javax.inject.Inject

/**
 * Drives [GeoSettingsUiState]. On load it fetches the country list and the viewer's detected country in
 * parallel-ish (sequential, both small). The dry-run [test] POSTs the entered mode + country CSV and surfaces
 * the allow/block outcome. No poll loop.
 */
@HiltViewModel
class GeoSettingsViewModel @Inject constructor(
    private val repo: GeoSettingsRepository,
) : ViewModel() {

    private val _uiState = MutableStateFlow<GeoSettingsUiState>(GeoSettingsUiState.Loading)
    val uiState: StateFlow<GeoSettingsUiState> = _uiState.asStateFlow()

    init {
        load()
    }

    fun load() {
        _uiState.value = GeoSettingsUiState.Loading
        viewModelScope.launch {
            val countriesResult = repo.listCountries()
            val countries = (countriesResult as? ApiResult.Success)?.data
            if (countries == null) {
                _uiState.value = GeoSettingsUiState.Error(messageOf(countriesResult))
                return@launch
            }
            val myCountry = (repo.getMyCountry() as? ApiResult.Success)?.data
            _uiState.value = GeoSettingsUiState.Content(
                myCountry = myCountry,
                countries = countries,
            )
        }
    }

    fun onModeChanged(mode: String) {
        val current = _uiState.value as? GeoSettingsUiState.Content ?: return
        _uiState.value = current.copy(testMode = mode)
    }

    fun onCountriesChanged(value: String) {
        val current = _uiState.value as? GeoSettingsUiState.Content ?: return
        _uiState.value = current.copy(testCountries = value.uppercase())
    }

    fun test() {
        val current = _uiState.value as? GeoSettingsUiState.Content ?: return
        if (current.testing) return
        _uiState.value = current.copy(testing = true, result = null, resultError = null)
        viewModelScope.launch {
            when (val result = repo.check(current.testMode, current.testCountries)) {
                is ApiResult.Success -> {
                    val now = _uiState.value as? GeoSettingsUiState.Content ?: return@launch
                    _uiState.value = now.copy(testing = false, result = result.data)
                }
                is ApiResult.Failure -> failTest(result.error.message)
                is ApiResult.NetworkError -> failTest(NETWORK_MESSAGE)
            }
        }
    }

    private fun failTest(message: String) {
        val now = _uiState.value as? GeoSettingsUiState.Content ?: return
        _uiState.value = now.copy(testing = false, resultError = message)
    }

    private fun messageOf(result: ApiResult<*>): String = when (result) {
        is ApiResult.Failure -> result.error.message
        is ApiResult.NetworkError -> NETWORK_MESSAGE
        is ApiResult.Success -> ""
    }

    private companion object {
        const val NETWORK_MESSAGE = "Couldn't reach the server. Check your connection and try again."
    }
}
