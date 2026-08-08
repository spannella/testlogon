package com.testlogon.android.feature.groups

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.ApiError
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.model.groups.Group
import com.testlogon.android.feature.groups.data.GroupsRepository
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.Job
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.receiveAsFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import javax.inject.Inject

/**
 * AND-355 / PAR-10 - drives the [GroupsListUiState] for the social-groups list, now across a My / Discover
 * tab ([GroupsTab]).
 *
 *  - MINE loads GET ui/groups (the {groups} envelope) - the caller's groups.
 *  - DISCOVER loads GET ui/groups/discover (public, joinable groups) with a debounced search query.
 *
 * A tab switch cancels any in-flight load for the other tab (via [loadJob]) and starts the new tab fresh.
 * load() / refresh() operate on the ACTIVE tab (so the existing route wiring keeps working). join() POSTs
 * ui/groups/{id}/join with a per-row in-flight guard; a 409 (already a member / pending / invited) is surfaced
 * as a one-shot [snackbar] message rather than a terminal error, and a successful public join drops the row
 * from the discover list (it is now one of the caller's groups). There is NO poll loop.
 */
@HiltViewModel
class GroupsListViewModel @Inject constructor(
    private val repository: GroupsRepository,
) : ViewModel() {

    private val _uiState = MutableStateFlow<GroupsListUiState>(GroupsListUiState.Loading)
    val uiState: StateFlow<GroupsListUiState> = _uiState.asStateFlow()

    private val _tab = MutableStateFlow(GroupsTab.MINE)
    val tab: StateFlow<GroupsTab> = _tab.asStateFlow()

    private val _searchQuery = MutableStateFlow("")
    val searchQuery: StateFlow<String> = _searchQuery.asStateFlow()

    /** The create-group dialog sub-state (independent of the list surface). */
    private val _createState = MutableStateFlow(CreateGroupFormState())
    val createState: StateFlow<CreateGroupFormState> = _createState.asStateFlow()

    /** One-shot: emits the new group's id on a successful create so the screen can navigate into it. */
    private val _created = Channel<String>(Channel.BUFFERED)
    val created = _created.receiveAsFlow()

    /** One-shot: transient user-facing messages (e.g. a 409 already-member on join). */
    private val _snackbar = Channel<String>(Channel.BUFFERED)
    val snackbar = _snackbar.receiveAsFlow()

    /** The active load coroutine (cancelled on a tab switch / new debounced search). */
    private var loadJob: Job? = null

    /** The debounced discover-search coroutine. */
    private var searchJob: Job? = null

    init {
        load()
    }

    /** First / retry load of the ACTIVE tab (drops to Loading when there is no cached content). */
    fun load() {
        if (_uiState.value !is GroupsListUiState.Content) {
            _uiState.value = GroupsListUiState.Loading
        }
        startLoad(isRefresh = false)
    }

    /** Pull-to-refresh the ACTIVE tab: keeps the cached list; a failure becomes a stale banner. */
    fun refresh() {
        val cached = _uiState.value as? GroupsListUiState.Content
        if (cached != null) {
            _uiState.value = cached.copy(isRefreshing = true, staleError = null)
        }
        startLoad(isRefresh = true)
    }

    /** PAR-10 - switches tabs; cancels any in-flight load and loads the newly selected tab fresh. */
    fun selectTab(tab: GroupsTab) {
        if (_tab.value == tab) return
        _tab.value = tab
        searchJob?.cancel()
        _uiState.value = GroupsListUiState.Loading
        startLoad(isRefresh = false)
    }

    /** PAR-10 - discover search box changed; debounce, then reload the Discover tab (no-op on the Mine tab). */
    fun onSearchChange(query: String) {
        _searchQuery.value = query
        if (_tab.value != GroupsTab.DISCOVER) return
        searchJob?.cancel()
        searchJob = viewModelScope.launch {
            delay(SEARCH_DEBOUNCE_MS)
            startLoad(isRefresh = false)
        }
    }

    private fun startLoad(isRefresh: Boolean) {
        loadJob?.cancel()
        val activeTab = _tab.value
        val query = _searchQuery.value
        loadJob = viewModelScope.launch {
            val cached = _uiState.value as? GroupsListUiState.Content
            val result = when (activeTab) {
                GroupsTab.MINE -> repository.listMyGroups()
                GroupsTab.DISCOVER -> repository.discover(query = query)
            }
            when (result) {
                is ApiResult.Success -> _uiState.value = reduceSuccess(result.data)
                is ApiResult.Failure -> _uiState.value = reduceFailure(result.error, isRefresh, cached)
                is ApiResult.NetworkError ->
                    _uiState.value = reduceFailure(networkError(), isRefresh, cached)
            }
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
        if (isRefresh && cached != null) {
            cached.copy(isRefreshing = false, staleError = error)
        } else {
            GroupsListUiState.Error(error)
        }

    private fun networkError(): ApiError =
        ApiError(status = ApiError.STATUS_NETWORK, message = OFFLINE_FALLBACK)

    /**
     * PAR-10 - joins a discovered group. Per-row in-flight guard via [GroupsListUiState.Content.joining]. On
     * success (public join) the row is dropped from the discover list; a 409 (already a member / pending /
     * invited) surfaces as a one-shot snackbar without dropping the row; any other failure surfaces its
     * message.
     */
    fun join(groupId: String) {
        val content = _uiState.value as? GroupsListUiState.Content ?: return
        if (groupId in content.joining) return
        _uiState.value = content.copy(joining = content.joining + groupId)
        viewModelScope.launch {
            when (val result = repository.join(groupId)) {
                is ApiResult.Success -> dropRow(groupId)
                is ApiResult.Failure -> {
                    clearJoining(groupId)
                    _snackbar.send(
                        if (result.error.status == HTTP_CONFLICT) ALREADY_MEMBER else result.error.message,
                    )
                }
                is ApiResult.NetworkError -> {
                    clearJoining(groupId)
                    _snackbar.send(OFFLINE_FALLBACK)
                }
            }
        }
    }

    private fun dropRow(groupId: String) {
        val content = _uiState.value as? GroupsListUiState.Content ?: return
        val remaining = content.groups.filterNot { it.id == groupId }
        _uiState.value = if (remaining.isEmpty()) {
            GroupsListUiState.Empty
        } else {
            content.copy(groups = remaining, joining = content.joining - groupId)
        }
    }

    private fun clearJoining(groupId: String) {
        (_uiState.value as? GroupsListUiState.Content)?.let {
            _uiState.value = it.copy(joining = it.joining - groupId)
        }
    }

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
                    // A newly created group lands on the Mine tab.
                    _tab.value = GroupsTab.MINE
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
        const val SEARCH_DEBOUNCE_MS = 350L
        const val HTTP_CONFLICT = 409
        const val ALREADY_MEMBER = "You're already a member of this group."
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
