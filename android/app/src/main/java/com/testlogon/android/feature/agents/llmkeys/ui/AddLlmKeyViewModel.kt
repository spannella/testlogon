package com.testlogon.android.feature.agents.llmkeys.ui

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.network.agents.CreateLlmKeyRequest
import com.testlogon.android.feature.agents.llmkeys.data.LlmKeysRepository
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
 * AGENTS-BASICS (web-parity) - drives the add-LLM-key form (web AddLlmKeyDialog). Loads the provider catalog on
 * init to seed the provider picker + default base URL. [submit] POSTs the create and emits
 * [LlmKeysEffect.AddSucceeded] so the screen pops back and the list refreshes.
 */
@HiltViewModel
class AddLlmKeyViewModel @Inject constructor(
    private val repo: LlmKeysRepository,
) : ViewModel() {

    private val _form = MutableStateFlow(AddLlmKeyForm())
    val form: StateFlow<AddLlmKeyForm> = _form.asStateFlow()

    private val _effects = Channel<LlmKeysEffect>(Channel.BUFFERED)
    val effects: Flow<LlmKeysEffect> = _effects.receiveAsFlow()

    init { loadProviders() }

    private fun loadProviders() {
        viewModelScope.launch {
            val providers = (repo.providers() as? ApiResult.Success)?.data.orEmpty()
            _form.value = _form.value.copy(
                providers = providers,
                provider = _form.value.provider.ifBlank { providers.firstOrNull()?.provider.orEmpty() },
                loadingProviders = false,
            )
        }
    }

    fun onProviderChange(v: String) {
        // Prefill base URL from the provider catalog default.
        val base = _form.value.providers.firstOrNull { it.provider == v }?.baseUrl.orEmpty()
        _form.value = _form.value.copy(provider = v, baseUrl = base, submitError = null)
    }

    fun onLabelChange(v: String) { _form.value = _form.value.copy(label = v, submitError = null) }
    fun onApiKeyChange(v: String) { _form.value = _form.value.copy(apiKey = v, submitError = null) }
    fun onBaseUrlChange(v: String) { _form.value = _form.value.copy(baseUrl = v, submitError = null) }
    fun onModelPreferenceChange(v: String) { _form.value = _form.value.copy(modelPreference = v) }

    fun submit() {
        val current = _form.value
        if (!current.canSubmit) return
        _form.value = current.copy(submitting = true, submitError = null)
        viewModelScope.launch {
            val request = CreateLlmKeyRequest(
                provider = current.provider,
                label = current.label.trim(),
                apiKey = current.apiKey.trim(),
                baseUrl = current.baseUrl.trim(),
                modelPreference = current.modelPreference.trim(),
            )
            when (val result = repo.create(request)) {
                is ApiResult.Success -> {
                    _form.value = _form.value.copy(submitting = false)
                    _effects.send(LlmKeysEffect.AddSucceeded)
                }
                is ApiResult.Failure -> {
                    if (result.error.status == HTTP_UNAUTHORIZED) {
                        _form.value = _form.value.copy(submitting = false)
                        _effects.send(LlmKeysEffect.NavigateToLogin)
                    } else {
                        _form.value = _form.value.copy(submitting = false, submitError = result.error.message)
                    }
                }
                is ApiResult.NetworkError ->
                    _form.value = _form.value.copy(submitting = false, submitError = OFFLINE)
            }
        }
    }

    companion object {
        private const val HTTP_UNAUTHORIZED = 401
        private const val OFFLINE = "Couldn't reach the server. Try again."
    }
}
