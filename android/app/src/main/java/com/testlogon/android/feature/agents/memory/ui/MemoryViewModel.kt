package com.testlogon.android.feature.agents.memory.ui

import androidx.lifecycle.SavedStateHandle
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.network.agents.MemoryEntryCreateRequest
import com.testlogon.android.core.network.agents.ProjectContextUpdateRequest
import com.testlogon.android.feature.agents.memory.data.MemoryRepository
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
 * AGENTS-BASICS (web-parity) - drives the per-worker MEMORY screen. Loads identity + project + entries together,
 * saves identity/project via PUT, and adds/deletes entries. A terminal 401 -> [MemoryEffect.NavigateToLogin].
 */
@HiltViewModel
class MemoryViewModel @Inject constructor(
    savedStateHandle: SavedStateHandle,
    private val repo: MemoryRepository,
) : ViewModel() {

    private val workerId: String = savedStateHandle.get<String>(ARG_WORKER_ID).orEmpty()

    private val _uiState = MutableStateFlow<MemoryUiState>(MemoryUiState.Loading)
    val uiState: StateFlow<MemoryUiState> = _uiState.asStateFlow()

    private val _effects = Channel<MemoryEffect>(Channel.BUFFERED)
    val effects: Flow<MemoryEffect> = _effects.receiveAsFlow()

    init { load() }

    fun load() {
        _uiState.value = MemoryUiState.Loading
        viewModelScope.launch {
            val identityR = repo.getIdentity(workerId)
            if (identityR.handledTerminal()) return@launch
            val projectR = repo.getProject(workerId)
            if (projectR.handledTerminal()) return@launch
            val entriesR = repo.listEntries(workerId)
            if (entriesR.handledTerminal()) return@launch

            if (identityR is ApiResult.Success && projectR is ApiResult.Success && entriesR is ApiResult.Success) {
                _uiState.value = MemoryUiState.Content(
                    identity = identityR.data,
                    project = projectR.data,
                    entries = entriesR.data.entries,
                    totalTokens = entriesR.data.totalTokens,
                )
            } else {
                _uiState.value = MemoryUiState.Error(firstMessage(identityR, projectR, entriesR))
            }
        }
    }

    fun onRetry() = load()

    fun saveIdentity(identityText: String, customInstructions: String) = mutate {
        repo.updateIdentity(workerId, identityText.trim(), customInstructions.trim())
    }

    fun saveProject(repoUrl: String, branchConvention: String, codingStandards: String, testFramework: String) = mutate {
        repo.updateProject(
            workerId,
            ProjectContextUpdateRequest(
                repoUrl = repoUrl.trim(),
                branchConvention = branchConvention.trim(),
                codingStandards = codingStandards.trim(),
                testFramework = testFramework.trim(),
            ),
        )
    }

    fun addEntry(category: String, title: String, content: String, importance: Int) {
        if (title.isBlank() || content.isBlank()) return
        mutate {
            repo.addEntry(
                workerId,
                MemoryEntryCreateRequest(
                    category = category,
                    title = title.trim(),
                    content = content.trim(),
                    importance = importance,
                ),
            )
        }
    }

    fun deleteEntry(memoryId: String) = mutate { repo.deleteEntry(workerId, memoryId) }

    /** Runs a mutation with a saving flag, then re-reads everything on success. */
    private fun mutate(block: suspend () -> ApiResult<*>) {
        val current = _uiState.value as? MemoryUiState.Content ?: return
        if (current.saving) return
        _uiState.value = current.copy(saving = true, actionError = null)
        viewModelScope.launch {
            when (val result = block()) {
                is ApiResult.Success -> {
                    _effects.send(MemoryEffect.Toast("Saved"))
                    reload(keepSavingFalse = true)
                }
                is ApiResult.Failure -> {
                    if (result.error.status == HTTP_UNAUTHORIZED) _effects.send(MemoryEffect.NavigateToLogin)
                    clearSaving(result.error.message)
                }
                is ApiResult.NetworkError -> clearSaving(OFFLINE)
            }
        }
    }

    private suspend fun reload(keepSavingFalse: Boolean) {
        val identityR = repo.getIdentity(workerId)
        val projectR = repo.getProject(workerId)
        val entriesR = repo.listEntries(workerId)
        if (identityR is ApiResult.Success && projectR is ApiResult.Success && entriesR is ApiResult.Success) {
            _uiState.value = MemoryUiState.Content(
                identity = identityR.data,
                project = projectR.data,
                entries = entriesR.data.entries,
                totalTokens = entriesR.data.totalTokens,
                saving = false,
            )
        } else if (keepSavingFalse) {
            clearSaving(null)
        }
    }

    private fun clearSaving(message: String?) {
        (_uiState.value as? MemoryUiState.Content)?.let { _uiState.value = it.copy(saving = false, actionError = message) }
    }

    private suspend fun ApiResult<*>.handledTerminal(): Boolean {
        if (this is ApiResult.Failure && error.status == HTTP_UNAUTHORIZED) {
            _effects.send(MemoryEffect.NavigateToLogin)
            _uiState.value = MemoryUiState.Error(error.message)
            return true
        }
        return false
    }

    private fun firstMessage(vararg results: ApiResult<*>): String {
        results.forEach {
            when (it) {
                is ApiResult.Failure -> return it.error.message
                is ApiResult.NetworkError -> return OFFLINE
                else -> Unit
            }
        }
        return "Something went wrong."
    }

    companion object {
        const val ARG_WORKER_ID = "workerId"
        private const val HTTP_UNAUTHORIZED = 401
        private const val OFFLINE = "Couldn't reach the server. Tap retry."
    }
}
