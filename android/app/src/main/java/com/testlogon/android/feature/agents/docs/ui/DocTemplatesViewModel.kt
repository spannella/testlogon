package com.testlogon.android.feature.agents.docs.ui

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.network.agents.CreateDocTemplateRequest
import com.testlogon.android.feature.agents.docs.data.DocsRepository
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.Job
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.receiveAsFlow
import kotlinx.coroutines.launch
import javax.inject.Inject

/**
 * AGENTS-BASICS (web-parity) - drives the doc-templates screen (web /agents/docs/templates). Lists templates,
 * creates a new template, and deletes one. A terminal 401 -> [DocsEffect.NavigateToLogin].
 */
@HiltViewModel
class DocTemplatesViewModel @Inject constructor(
    private val repo: DocsRepository,
) : ViewModel() {

    private val _uiState = MutableStateFlow<DocTemplatesUiState>(DocTemplatesUiState.Loading)
    val uiState: StateFlow<DocTemplatesUiState> = _uiState.asStateFlow()

    private val _effects = Channel<DocsEffect>(Channel.BUFFERED)
    val effects: Flow<DocsEffect> = _effects.receiveAsFlow()

    private var loadJob: Job? = null

    init { load() }

    fun load() {
        if (loadJob?.isActive == true) return
        _uiState.value = DocTemplatesUiState.Loading
        fetch(isRefresh = false)
    }

    fun onRetry() = load()

    fun refresh() {
        if (loadJob?.isActive == true) return
        (_uiState.value as? DocTemplatesUiState.Content)?.let { _uiState.value = it.copy(isRefreshing = true) }
        fetch(isRefresh = true)
    }

    private fun fetch(isRefresh: Boolean) {
        loadJob = viewModelScope.launch {
            when (val result = repo.listTemplates()) {
                is ApiResult.Success -> _uiState.value = DocTemplatesUiState.Content(templates = result.data)
                is ApiResult.Failure -> {
                    if (result.error.status == HTTP_UNAUTHORIZED) {
                        _effects.send(DocsEffect.NavigateToLogin)
                        clearRefreshing()
                    } else emitFailure(isRefresh, result.error.message)
                }
                is ApiResult.NetworkError -> emitFailure(isRefresh, OFFLINE)
            }
        }
    }

    fun create(name: String, docType: String, body: String, requiredSections: List<String>) {
        if (name.isBlank() || body.isBlank()) return
        mutate {
            repo.createTemplate(
                CreateDocTemplateRequest(
                    name = name.trim(),
                    docType = docType,
                    templateBody = body.trim(),
                    requiredSections = requiredSections,
                ),
            )
        }
    }

    fun delete(templateId: String) = mutate { repo.deleteTemplate(templateId) }

    private fun mutate(block: suspend () -> ApiResult<*>) {
        val current = _uiState.value as? DocTemplatesUiState.Content ?: return
        if (current.busy) return
        _uiState.value = current.copy(busy = true, actionError = null)
        viewModelScope.launch {
            when (val result = block()) {
                is ApiResult.Success -> when (val reload = repo.listTemplates()) {
                    is ApiResult.Success -> _uiState.value = DocTemplatesUiState.Content(templates = reload.data)
                    else -> clearBusy(null)
                }
                is ApiResult.Failure -> {
                    if (result.error.status == HTTP_UNAUTHORIZED) _effects.send(DocsEffect.NavigateToLogin)
                    clearBusy(result.error.message)
                }
                is ApiResult.NetworkError -> clearBusy(OFFLINE)
            }
        }
    }

    private fun clearBusy(message: String?) {
        (_uiState.value as? DocTemplatesUiState.Content)?.let { _uiState.value = it.copy(busy = false, actionError = message) }
    }

    private fun emitFailure(isRefresh: Boolean, message: String) {
        val prior = _uiState.value as? DocTemplatesUiState.Content
        _uiState.value = if (isRefresh && prior != null) prior.copy(isRefreshing = false, actionError = message)
        else DocTemplatesUiState.Error(message)
    }

    private fun clearRefreshing() {
        (_uiState.value as? DocTemplatesUiState.Content)?.let { _uiState.value = it.copy(isRefreshing = false) }
    }

    private companion object {
        const val HTTP_UNAUTHORIZED = 401
        const val OFFLINE = "Couldn't reach the server. Pull down to retry."
    }
}
