package com.testlogon.android.feature.groups

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.ApiError
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.model.groups.Group
import com.testlogon.android.feature.groups.data.GroupsRepository
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
 * AND-355 - drives the [GroupsListUiState] for the social-groups discovery list (GET ui/groups, the
 * {groups} ENVELOPE).
 *
 * load() is the first read (Loading -> Content/Empty/Error). refresh() is the pull-to-refresh: it keeps
 * the last-cached list while the read is in flight, and on failure it RETAINS that list, surfacing a
 * non-fatal [GroupsListUiState.Content.staleError] banner instead of dropping to a terminal Error. There
 * is NO poll loop.
 */
@HiltViewModel
class GroupsListViewModel @Inject constructor(
    private val repository: GroupsRepository,
) : ViewModel() {

    private val _uiState = MutableStateFlow<GroupsListUiState>(GroupsListUiState.Loading)
    val uiState: StateFlow<GroupsListUiState> = _uiState.asStateFlow()

    /** The create-group dialog sub-state (independent of the list surface). */
    private val _createState = MutableStateFlow(CreateGroupFormState())
    val createState: StateFlow<CreateGroupFormState> = _createState.asStateFlow()

    /** One-shot: emits the new group's id on a successful create so the screen can navigate into it. */
    private val _created = Channel<String>(Channel.BUFFERED)
    val created = _created.receiveAsFlow()

    init {
        load()
    }

    /** First / retry load (drops to Loading when there is no cached content). */
    fun load() {
        if (_uiState.value !is GroupsListUiState.Content) {
            _uiState.value = GroupsListUiState.Loading
        }
        viewModelScope.launch { fetch(isRefresh = false) }
    }

    /** Pull-to-refresh: keeps the cached list; a failure becomes a stale banner, not a terminal error. */
    fun refresh() {
        val cached = _uiState.value as? GroupsListUiState.Content
        if (cached != null) {
            _uiState.value = cached.copy(isRefreshing = true, staleError = null)
        }
        viewModelScope.launch { fetch(isRefresh = true) }
    }

    private suspend fun fetch(isRefresh: Boolean) {
        val cached = _uiState.value as? GroupsListUiState.Content
        when (val result = repository.listMyGroups()) {
            is ApiResult.Success -> _uiState.value = reduceSuccess(result.data)
            is ApiResult.Failure -> _uiState.value = reduceFailure(result.error, isRefresh, cached)
            is ApiResult.NetworkError ->
                _uiState.value = reduceFailure(networkError(), isRefresh, cached)
        }
    }

    private fun reduceSuccess(groups: List<Group>): GroupsListUiState =
        if (groups.isEmpty()) {
            GroupsListUiState.Empty
        } else {
            GroupsListUiState.Content(groups = groups, isRefreshing = false, staleError = null)
        }

    private fun reduceFailure(
        error: ApiError,
        isRefresh: Boolean,
        cached: GroupsListUiState.Content?,
    ): GroupsListUiState =
        // On a pull-to-refresh failure keep the cached list with a stale banner; a cache-less / first-load
        // failure is terminal.
        if (isRefresh && cached != null) {
            cached.copy(isRefreshing = false, staleError = error)
        } else {
            GroupsListUiState.Error(error)
        }

    private fun networkError(): ApiError =
        ApiError(status = ApiError.STATUS_NETWORK, message = OFFLINE_FALLBACK)

    // ---- Create-group form ----

    /** Opens the create-group dialog (fresh, clearing any prior draft/errors). */
    fun openCreate() {
        _createState.value = CreateGroupFormState(visible = true)
    }

    /** Dismisses the create-group dialog (drops the draft). */
    fun dismissCreate() {
        _createState.value = CreateGroupFormState(visible = false)
    }

    fun onCreateNameChange(value: String) =
        _createState.update { it.copy(name = value, nameError = null, submitError = null) }

    fun onCreateDescriptionChange(value: String) =
        _createState.update { it.copy(description = value, submitError = null) }

    fun onCreateVisibilityChange(isPublic: Boolean) =
        _createState.update { it.copy(isPublic = isPublic, submitError = null) }

    /**
     * Submits the create-group form. Guarded by [CreateGroupFormState.isValid] + a re-entrancy flag. On
     * success: closes the dialog, emits the new group id (one-shot) so the screen navigates into it, and
     * reloads the list. On failure: keeps the dialog open with a retryable error.
     */
    fun submitCreate() {
        val form = _createState.value
        if (!form.isValid || form.submitting) return
        _createState.update { it.copy(submitting = true, nameError = null, submitError = null) }
        viewModelScope.launch {
            val result = repository.createGroup(
                name = form.name.trim(),
                description = form.description.trim().takeIf { it.isNotBlank() },
                visibility = if (form.isPublic) VISIBILITY_PUBLIC else VISIBILITY_PRIVATE,
                topic = null,
            )
            when (result) {
                is ApiResult.Success -> {
                    _createState.value = CreateGroupFormState(visible = false)
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

    private companion object {
        const val OFFLINE_FALLBACK = "Couldn't reach the server. Pull down to retry."
        const val VISIBILITY_PUBLIC = "public"
        const val VISIBILITY_PRIVATE = "private"
    }
}

/**
 * The create-group dialog sub-state. [isValid] enforces the server's 3..100 char name. `isPublic` toggles
 * the public/private visibility; description is optional.
 */
data class CreateGroupFormState(
    val visible: Boolean = false,
    val name: String = "",
    val description: String = "",
    val isPublic: Boolean = true,
    val submitting: Boolean = false,
    val nameError: String? = null,
    val submitError: String? = null,
) {
    val isValid: Boolean get() = name.trim().length in 3..100
}
