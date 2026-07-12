package com.testlogon.android.feature.syndicates.ui

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.ApiError
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.model.syndicates.SyndicateListItem
import com.testlogon.android.feature.syndicates.data.SyndicateRepository
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.receiveAsFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import javax.inject.Inject

/**
 * Batch-7 - drives the [SyndicateListUiState] for the "syndicates the caller belongs to" LIST screen, now
 * backed by the real GET ui/syndicates list endpoint, plus the create-syndicate flow (POST ui/syndicates).
 *
 * load() is the first read (Loading -> Content/Empty/Error). refresh() keeps the cached list and surfaces a
 * non-fatal staleError banner on failure. create*() drive the dialog; submitCreate() POSTs, and on success
 * closes the dialog, emits the new id (one-shot) so the screen navigates into it, and reloads the list.
 * There is NO poll loop.
 */
@HiltViewModel
class SyndicateListViewModel @Inject constructor(
    private val repository: SyndicateRepository,
) : ViewModel() {

    private val _uiState = MutableStateFlow<SyndicateListUiState>(SyndicateListUiState.Loading)
    val uiState: StateFlow<SyndicateListUiState> = _uiState.asStateFlow()

    private val _createState = MutableStateFlow(CreateSyndicateFormState())
    val createState: StateFlow<CreateSyndicateFormState> = _createState.asStateFlow()

    /** One-shot: emits the new syndicate id on a successful create so the screen navigates into it. */
    private val _created = Channel<String>(Channel.BUFFERED)
    val created = _created.receiveAsFlow()

    init {
        load()
    }

    fun load() {
        if (_uiState.value !is SyndicateListUiState.Content) {
            _uiState.value = SyndicateListUiState.Loading
        }
        viewModelScope.launch { fetch(isRefresh = false) }
    }

    fun retry() = load()

    fun refresh() {
        val cached = _uiState.value as? SyndicateListUiState.Content
        if (cached != null) {
            _uiState.value = cached.copy(isRefreshing = true, staleError = null)
        }
        viewModelScope.launch { fetch(isRefresh = true) }
    }

    private suspend fun fetch(isRefresh: Boolean) {
        val cached = _uiState.value as? SyndicateListUiState.Content
        when (val result = repository.listMySyndicates()) {
            is ApiResult.Success -> _uiState.value = reduceSuccess(result.data)
            is ApiResult.Failure -> _uiState.value = reduceFailure(result.error, isRefresh, cached)
            is ApiResult.NetworkError ->
                _uiState.value = reduceFailure(networkError(), isRefresh, cached)
        }
    }

    private fun reduceSuccess(items: List<SyndicateListItem>): SyndicateListUiState =
        if (items.isEmpty()) {
            SyndicateListUiState.Empty
        } else {
            SyndicateListUiState.Content(items = items, isRefreshing = false, staleError = null)
        }

    private fun reduceFailure(
        error: ApiError,
        isRefresh: Boolean,
        cached: SyndicateListUiState.Content?,
    ): SyndicateListUiState =
        if (isRefresh && cached != null) {
            cached.copy(isRefreshing = false, staleError = error)
        } else {
            SyndicateListUiState.Error(error)
        }

    // ---- Create-syndicate form ----

    fun openCreate() {
        _createState.value = CreateSyndicateFormState(visible = true)
    }

    fun dismissCreate() {
        _createState.value = CreateSyndicateFormState(visible = false)
    }

    fun onCreateNameChange(value: String) =
        _createState.update { it.copy(name = value, nameError = null, submitError = null) }

    fun onCreateDescriptionChange(value: String) =
        _createState.update { it.copy(description = value, submitError = null) }

    fun submitCreate() {
        val form = _createState.value
        if (!form.isValid || form.submitting) return
        _createState.update { it.copy(submitting = true, nameError = null, submitError = null) }
        viewModelScope.launch {
            val result = repository.createSyndicate(
                name = form.name.trim(),
                description = form.description.trim().takeIf { it.isNotBlank() },
            )
            when (result) {
                is ApiResult.Success -> {
                    _createState.value = CreateSyndicateFormState(visible = false)
                    _created.send(result.data.id)
                    load()
                }
                is ApiResult.Failure ->
                    _createState.update { it.copy(submitting = false, submitError = result.error.message) }
                is ApiResult.NetworkError ->
                    _createState.update { it.copy(submitting = false, submitError = OFFLINE_FALLBACK) }
            }
        }
    }

    private fun networkError(): ApiError =
        ApiError(status = ApiError.STATUS_NETWORK, message = OFFLINE_FALLBACK)

    private companion object {
        const val OFFLINE_FALLBACK = "Couldn't reach the server. Pull down to retry."
    }
}
