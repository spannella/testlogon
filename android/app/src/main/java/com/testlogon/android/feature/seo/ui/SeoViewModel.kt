package com.testlogon.android.feature.seo.ui

import androidx.lifecycle.SavedStateHandle
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.feature.seo.data.ResourceType
import com.testlogon.android.feature.seo.data.SeoRepository
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.Job
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import javax.inject.Inject

/**
 * AND-400 - drives [SeoUiState] from [SeoRepository] for the read-only SEO inspector.
 *
 * Reads resourceType / id / secondaryId from [SavedStateHandle] (the nav args; restored across process
 * death so the screen re-fetches on recreation - acceptable for a cheap public GET). A refresh / retry
 * cancels the in-flight load and uses a request generation so a slow earlier response cannot overwrite
 * newer state (last-write-wins). On success an empty payload (available=false / no renderable fields)
 * reduces to [SeoUiState.Empty]; a transport / 5xx failure -&gt; retryable Error; a 422 -&gt; non-retryable
 * Error (the public endpoint has no 401/403/404).
 */
@HiltViewModel
class SeoViewModel @Inject constructor(
    private val repository: SeoRepository,
    savedStateHandle: SavedStateHandle,
) : ViewModel() {

    private val type: ResourceType = ResourceType.from(savedStateHandle.get<String>(ARG_RESOURCE_TYPE))
    private val id: String = savedStateHandle.get<String>(ARG_ID).orEmpty()
    private val secondaryId: String? = savedStateHandle.get<String>(ARG_SECONDARY_ID)

    private val _state = MutableStateFlow<SeoUiState>(SeoUiState.Loading)
    val state: StateFlow<SeoUiState> = _state.asStateFlow()

    private var loadJob: Job? = null
    private var requestGen = 0L

    init {
        load()
    }

    /** (Re-)fetches the metadata. Bound to the Retry button and pull-to-refresh. */
    fun load() {
        val gen = ++requestGen
        loadJob?.cancel()
        _state.value = SeoUiState.Loading
        loadJob = viewModelScope.launch {
            val result = repository.metadata(type, id, secondaryId)
            if (gen != requestGen) return@launch // superseded by a newer load; drop the stale result
            _state.value = when (result) {
                is ApiResult.Success ->
                    if (result.data.isEmpty) SeoUiState.Empty else SeoUiState.Content(result.data)
                is ApiResult.Failure ->
                    SeoUiState.Error(result.error.message, retryable = result.error.status >= 500)
                is ApiResult.NetworkError ->
                    SeoUiState.Error(OFFLINE_MESSAGE, retryable = true)
            }
        }
    }

    companion object {
        const val ARG_RESOURCE_TYPE = "resourceType"
        const val ARG_ID = "id"
        const val ARG_SECONDARY_ID = "secondaryId"

        private const val OFFLINE_MESSAGE = "Couldn't reach the server. Tap retry."
    }
}
