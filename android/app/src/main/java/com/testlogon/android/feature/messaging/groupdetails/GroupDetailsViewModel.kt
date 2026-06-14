package com.testlogon.android.feature.messaging.groupdetails

import androidx.lifecycle.SavedStateHandle
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.messaging.Contact
import com.testlogon.android.data.messaging.MessagingRepository
import com.testlogon.android.data.messaging.group.GroupRepository
import com.testlogon.android.data.messaging.group.GroupRole
import com.testlogon.android.data.messaging.group.GroupRoster
import com.testlogon.android.feature.messaging.thread.debounceCompat
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.flow.distinctUntilChanged
import kotlinx.coroutines.flow.flatMapLatest
import kotlinx.coroutines.flow.flow
import kotlinx.coroutines.flow.flowOf
import kotlinx.coroutines.flow.launchIn
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.flow.onEach
import kotlinx.coroutines.flow.receiveAsFlow
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import javax.inject.Inject

/** AND-158 — the roster UI phase. Content holds the live roster + per-row mutation state. */
sealed interface RosterUiState {
    data object Loading : RosterUiState
    data class Content(
        val roster: GroupRoster,
        /** Rows with an in-flight mutation (drives per-row spinners + disables their controls). */
        val pendingUserIds: Set<String> = emptySet(),
        val isRefreshing: Boolean = false,
        /** AND-158 — the "add members" sheet state; null when closed. */
        val addPicker: AddPickerState? = null,
    ) : RosterUiState {
        val canManage: Boolean get() = roster.canManage
    }

    data class Error(val message: String, val retryable: Boolean) : RosterUiState
}

/** AND-158 — state for the in-screen "add members" contact picker. */
data class AddPickerState(
    val query: String = "",
    val candidates: List<Contact> = emptyList(),
    val isSearching: Boolean = false,
)

/** AND-158 — one-shot events (transient errors surfaced as a snackbar). */
sealed interface GroupDetailsEvent {
    data class ShowError(val message: String) : GroupDetailsEvent
}

/**
 * AND-158 — group participants management presentation logic.
 *
 * Read path is offline-first: [RosterUiState] combines [GroupRepository.observeRoster] (Room-backed)
 * with the local mutation/picker state, and refreshes from the network on init. Mutations
 * (add/remove/role-change) are optimistic in the repository (Room write -> API -> reconcile/rollback);
 * this VM only tracks per-row pending state + the add-picker, and gates controls by `my_role` (admin)
 * plus self/last-admin protections (the server is the authoritative gate).
 */
@OptIn(ExperimentalCoroutinesApi::class)
@HiltViewModel
class GroupDetailsViewModel @Inject constructor(
    private val groupRepository: GroupRepository,
    private val messagingRepository: MessagingRepository,
    savedStateHandle: SavedStateHandle,
) : ViewModel() {

    private val conversationId: String =
        checkNotNull(savedStateHandle[ARG_CONVERSATION_ID]) { "missing $ARG_CONVERSATION_ID" }

    private val pendingUserIds = MutableStateFlow<Set<String>>(emptySet())
    private val isRefreshing = MutableStateFlow(false)
    private val loadError = MutableStateFlow<String?>(null)
    private val addPicker = MutableStateFlow<AddPickerState?>(null)

    val uiState: StateFlow<RosterUiState> =
        combine(
            groupRepository.observeRoster(conversationId),
            pendingUserIds,
            isRefreshing,
            addPicker,
            loadError,
        ) { roster, pending, refreshing, picker, error ->
            when {
                roster != null -> RosterUiState.Content(
                    roster = roster,
                    pendingUserIds = pending,
                    isRefreshing = refreshing,
                    addPicker = picker,
                )
                error != null -> RosterUiState.Error(error, retryable = true)
                else -> RosterUiState.Loading
            }
        }.stateIn(viewModelScope, SharingStarted.WhileSubscribed(5_000), RosterUiState.Loading)

    private val _events = Channel<GroupDetailsEvent>(Channel.BUFFERED)
    val events: Flow<GroupDetailsEvent> = _events.receiveAsFlow()

    private val pickerQuery = MutableStateFlow("")

    init {
        refresh()
        startPickerSearch()
    }

    fun refresh() {
        isRefreshing.value = true
        viewModelScope.launch {
            when (val r = groupRepository.refreshRoster(conversationId)) {
                is ApiResult.Success -> loadError.value = null
                is ApiResult.Failure -> setLoadErrorIfEmpty(r.error.message)
                is ApiResult.NetworkError -> setLoadErrorIfEmpty(OFFLINE_MESSAGE)
            }
            isRefreshing.value = false
        }
    }

    /** Only set the terminal Error phase when there is no cached roster to show. */
    private fun setLoadErrorIfEmpty(message: String) {
        if (uiState.value !is RosterUiState.Content) loadError.value = message
    }

    // ---- add members ----

    fun onOpenAddPicker() { addPicker.value = AddPickerState() }

    fun onCloseAddPicker() {
        addPicker.value = null
        pickerQuery.value = ""
    }

    fun onAddPickerQueryChange(value: String) {
        val capped = value.take(MAX_QUERY_LENGTH)
        addPicker.update { it?.copy(query = capped) }
        if (capped.trim().isEmpty()) addPicker.update { it?.copy(candidates = emptyList(), isSearching = false) }
        pickerQuery.value = capped
    }

    /** AND-158 — confirm adding [userId]; already-members are filtered out by the screen. */
    fun onAddParticipant(userId: String) {
        val content = uiState.value as? RosterUiState.Content ?: return
        if (!content.canManage) return
        if (content.roster.participants.any { it.userId == userId }) return
        onCloseAddPicker()
        withPending(userId) { groupRepository.addParticipants(conversationId, listOf(userId)) }
    }

    // ---- remove / role ----

    fun onRemove(userId: String) {
        val content = uiState.value as? RosterUiState.Content ?: return
        if (!canMutateRow(content, userId)) return
        withPending(userId) { groupRepository.removeParticipant(conversationId, userId) }
    }

    fun onChangeRole(userId: String, role: GroupRole) {
        val content = uiState.value as? RosterUiState.Content ?: return
        if (!canMutateRow(content, userId)) return
        // Self-protection: a demotion of the last admin is blocked client-side.
        if (role == GroupRole.MEMBER && isLastAdmin(content.roster, userId)) {
            viewModelScope.launch { _events.send(GroupDetailsEvent.ShowError(LAST_ADMIN_MESSAGE)) }
            return
        }
        withPending(userId) { groupRepository.changeRole(conversationId, userId, role) }
    }

    /**
     * AND-158 self-protection: must be an admin, the target must not be the current user (no
     * self-remove / self-demote), and no mutation may already be in flight for that row.
     */
    private fun canMutateRow(content: RosterUiState.Content, userId: String): Boolean =
        content.canManage &&
            userId != content.roster.currentUserId &&
            !content.pendingUserIds.contains(userId)

    private fun isLastAdmin(roster: GroupRoster, userId: String): Boolean {
        val target = roster.participants.firstOrNull { it.userId == userId } ?: return false
        return target.role == GroupRole.ADMIN && roster.adminCount <= 1
    }

    private fun withPending(userId: String, block: suspend () -> ApiResult<Unit>) {
        if (pendingUserIds.value.contains(userId)) return
        pendingUserIds.update { it + userId }
        viewModelScope.launch {
            when (val r = block()) {
                is ApiResult.Success -> Unit
                is ApiResult.Failure -> _events.send(GroupDetailsEvent.ShowError(r.error.message))
                is ApiResult.NetworkError -> _events.send(GroupDetailsEvent.ShowError(OFFLINE_MESSAGE))
            }
            pendingUserIds.update { it - userId }
        }
    }

    private fun startPickerSearch() {
        pickerQuery
            .debounceCompat(DEBOUNCE_MS)
            .map { it.trim().take(MAX_QUERY_LENGTH) }
            .distinctUntilChanged()
            .flatMapLatest { q ->
                if (q.isEmpty()) {
                    flowOf<PickerEmission>(PickerEmission.Skipped)
                } else {
                    flow<PickerEmission> {
                        emit(PickerEmission.Loading)
                        emit(PickerEmission.Done(messagingRepository.searchContacts(q)))
                    }
                }
            }
            .onEach { applyPicker(it) }
            .launchIn(viewModelScope)
    }

    private fun applyPicker(emission: PickerEmission) {
        when (emission) {
            PickerEmission.Skipped -> Unit
            PickerEmission.Loading -> addPicker.update { it?.copy(isSearching = true) }
            is PickerEmission.Done -> when (val r = emission.result) {
                is ApiResult.Success ->
                    addPicker.update { it?.copy(isSearching = false, candidates = r.data) }
                is ApiResult.Failure ->
                    addPicker.update { it?.copy(isSearching = false, candidates = emptyList()) }
                is ApiResult.NetworkError ->
                    addPicker.update { it?.copy(isSearching = false, candidates = emptyList()) }
            }
        }
    }

    private sealed interface PickerEmission {
        data object Skipped : PickerEmission
        data object Loading : PickerEmission
        data class Done(val result: ApiResult<List<Contact>>) : PickerEmission
    }

    companion object {
        const val ARG_CONVERSATION_ID = "conversationId"
        const val DEBOUNCE_MS = 300L
        const val MAX_QUERY_LENGTH = 64
        const val OFFLINE_MESSAGE = "You're offline. Try again when you're back online."
        const val LAST_ADMIN_MESSAGE = "A group must have at least one admin."
    }
}
