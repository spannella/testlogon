package com.testlogon.android.feature.messaging.groupcreate

import androidx.lifecycle.SavedStateHandle
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.messaging.Contact
import com.testlogon.android.data.messaging.MessagingRepository
import com.testlogon.android.data.messaging.group.GroupRepository
import com.testlogon.android.feature.messaging.thread.debounceCompat
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.distinctUntilChanged
import kotlinx.coroutines.flow.flatMapLatest
import kotlinx.coroutines.flow.flow
import kotlinx.coroutines.flow.flowOf
import kotlinx.coroutines.flow.launchIn
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.flow.onEach
import kotlinx.coroutines.flow.receiveAsFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import javax.inject.Inject

/** AND-157 — a selectable person in the group-create picker (mapped from a [Contact]). */
data class ParticipantUi(
    val userId: String,
    val displayName: String,
)

/** AND-157 — group-create form state. */
data class GroupCreateUiState(
    val name: String = "",
    val query: String = "",
    val candidates: List<ParticipantUi> = emptyList(),
    val selected: List<ParticipantUi> = emptyList(),
    val isSearching: Boolean = false,
    val isSubmitting: Boolean = false,
    val errorMessage: String? = null,
) {
    /** Set of selected user ids for fast dedupe / membership checks. */
    val selectedIds: Set<String> get() = selected.mapTo(mutableSetOf()) { it.userId }

    /** AND-157 — Create is enabled with a non-blank name (<= cap) and 2..MAX participants, not in flight. */
    val canCreate: Boolean
        get() = name.isNotBlank() &&
            name.length <= MAX_NAME_LENGTH &&
            selected.size in MIN_PARTICIPANTS..MAX_PARTICIPANTS &&
            !isSubmitting

    companion object {
        const val MIN_PARTICIPANTS = 2
        const val MAX_PARTICIPANTS = 256
        const val MAX_NAME_LENGTH = 80
    }
}

/** AND-157 — one-shot events for the group-create screen. */
sealed interface GroupCreateEvent {
    data class Created(val conversationId: String) : GroupCreateEvent
}

/**
 * AND-157 — group-create presentation logic.
 *
 * Reuses the EXISTING contacts search ([MessagingRepository.searchContacts], AND-153) for member
 * selection — the picker rows are mapped from [Contact]. Create posts to [GroupRepository.createGroup]
 * (POST /messaging/conversations/group) and, on success, emits a one-shot [GroupCreateEvent.Created]
 * so the host navigates into the new thread (the repo already upserted the conversation into the cache).
 *
 * Avatar upload is out of scope here (gap): the create endpoint accepts an `icon` ref via a separate
 * presign flow; the form currently creates without an avatar. See AND-157 §13 OQ-2.
 */
@HiltViewModel
class GroupCreateViewModel @Inject constructor(
    private val messagingRepository: MessagingRepository,
    private val groupRepository: GroupRepository,
    private val saved: SavedStateHandle,
) : ViewModel() {

    private val _state = MutableStateFlow(
        GroupCreateUiState(
            name = saved.get<String>(KEY_NAME).orEmpty(),
            query = saved.get<String>(KEY_QUERY).orEmpty(),
        ),
    )
    val state: StateFlow<GroupCreateUiState> = _state.asStateFlow()

    private val _events = Channel<GroupCreateEvent>(Channel.BUFFERED)
    val events: Flow<GroupCreateEvent> = _events.receiveAsFlow()

    private val queryFlow = MutableStateFlow(_state.value.query)

    init {
        startSearchEngine()
        if (_state.value.query.trim().isNotEmpty()) queryFlow.value = _state.value.query
    }

    fun onNameChange(value: String) {
        val capped = value.take(GroupCreateUiState.MAX_NAME_LENGTH)
        _state.update { it.copy(name = capped) }
        saved[KEY_NAME] = capped
    }

    fun onQueryChange(value: String) {
        val capped = value.take(MAX_QUERY_LENGTH)
        _state.update { it.copy(query = capped) }
        saved[KEY_QUERY] = capped
        if (capped.trim().isEmpty()) {
            _state.update { it.copy(candidates = emptyList(), isSearching = false) }
        }
        queryFlow.value = capped
    }

    fun onToggleParticipant(userId: String) {
        _state.update { s ->
            if (s.selectedIds.contains(userId)) {
                s.copy(selected = s.selected.filterNot { it.userId == userId })
            } else {
                val candidate = s.candidates.firstOrNull { it.userId == userId } ?: return@update s
                if (s.selected.size >= GroupCreateUiState.MAX_PARTICIPANTS) return@update s
                s.copy(selected = s.selected + candidate)
            }
        }
    }

    fun onRemoveParticipant(userId: String) {
        _state.update { it.copy(selected = it.selected.filterNot { p -> p.userId == userId }) }
    }

    fun onCreateClick() {
        val s = _state.value
        if (!s.canCreate) return
        _state.update { it.copy(isSubmitting = true, errorMessage = null) }
        viewModelScope.launch {
            val result = groupRepository.createGroup(
                title = s.name.trim(),
                participantIds = s.selected.map { it.userId },
            )
            when (result) {
                is ApiResult.Success -> _events.send(GroupCreateEvent.Created(result.data.id))
                is ApiResult.Failure ->
                    _state.update { it.copy(isSubmitting = false, errorMessage = result.error.message) }
                is ApiResult.NetworkError ->
                    _state.update { it.copy(isSubmitting = false, errorMessage = OFFLINE_MESSAGE) }
            }
        }
    }

    fun onErrorShown() = _state.update { it.copy(errorMessage = null) }

    @OptIn(ExperimentalCoroutinesApi::class)
    private fun startSearchEngine() {
        queryFlow
            .debounceCompat(DEBOUNCE_MS)
            .map { it.trim().take(MAX_QUERY_LENGTH) }
            .distinctUntilChanged()
            .flatMapLatest { q ->
                if (q.isEmpty()) {
                    flowOf<SearchEmission>(SearchEmission.Skipped)
                } else {
                    flow<SearchEmission> {
                        emit(SearchEmission.Loading)
                        emit(SearchEmission.Done(messagingRepository.searchContacts(q)))
                    }
                }
            }
            .onEach { applyEmission(it) }
            .launchIn(viewModelScope)
    }

    private fun applyEmission(emission: SearchEmission) {
        when (emission) {
            SearchEmission.Skipped -> Unit
            SearchEmission.Loading -> _state.update { it.copy(isSearching = true) }
            is SearchEmission.Done -> applyResult(emission.result)
        }
    }

    private fun applyResult(result: ApiResult<List<Contact>>) {
        when (result) {
            is ApiResult.Success ->
                _state.update {
                    it.copy(
                        isSearching = false,
                        candidates = result.data.map { c -> ParticipantUi(c.id, c.displayName) },
                    )
                }
            is ApiResult.Failure ->
                _state.update { it.copy(isSearching = false, errorMessage = result.error.message) }
            is ApiResult.NetworkError ->
                _state.update { it.copy(isSearching = false, errorMessage = OFFLINE_MESSAGE) }
        }
    }

    private sealed interface SearchEmission {
        data object Skipped : SearchEmission
        data object Loading : SearchEmission
        data class Done(val result: ApiResult<List<Contact>>) : SearchEmission
    }

    companion object {
        const val DEBOUNCE_MS = 300L
        const val MAX_QUERY_LENGTH = 64
        const val OFFLINE_MESSAGE = "You're offline. Try again when you're back online."

        private const val KEY_NAME = "group_create_name"
        private const val KEY_QUERY = "group_create_query"
    }
}
