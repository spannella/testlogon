package com.testlogon.android.feature.messaging.contacts

import androidx.lifecycle.SavedStateHandle
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.messaging.Contact
import com.testlogon.android.data.messaging.MessagingRepository
import com.testlogon.android.feature.messaging.thread.debounceCompat
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
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

/**
 * AND-153 / AND-155 — non-list status for the contacts (people-search) screen. The result rows
 * themselves live in [ContactsUiState.contacts]; this enum drives the body (idle / loading / results
 * / empty / error). The contacts search endpoint returns a single bounded array (no pagination), so a
 * plain [StateFlow] is sufficient — Paging 3 is intentionally NOT used (verified: no `cursor` param,
 * bare array response — see AND-153 spec section 4 / 16).
 */
sealed interface ContactsPhase {
    data object Idle : ContactsPhase
    data object Loading : ContactsPhase
    data object Results : ContactsPhase
    data class Empty(val query: String) : ContactsPhase
    data class Error(val message: String, val offline: Boolean) : ContactsPhase
}

data class ContactsUiState(
    val query: String = "",
    val phase: ContactsPhase = ContactsPhase.Idle,
    val contacts: List<Contact> = emptyList(),
    /** AND-154 — the contact whose DM is currently resolving; null when idle. Drives a row spinner. */
    val pendingDmUserId: String? = null,
)

/**
 * AND-154 — one-shot effects for the contacts screen (delivered exactly once; never replayed on
 * recomposition / config change). [OpenThread] navigates into the resolved DM; [ShowError] surfaces a
 * start-DM failure in a snackbar with an optional retry target.
 */
sealed interface ContactsEffect {
    data class OpenThread(val conversationId: String) : ContactsEffect
    data class ShowError(val message: String, val retryUserId: String?) : ContactsEffect
}

/**
 * AND-153 / AND-154 / AND-155 — contacts search + start-conversation presentation logic.
 *
 * Search (AND-153/155): the trimmed query is debounced (300 ms) via the shared [debounceCompat]
 * helper and de-duplicated; [flatMapLatest] cancels superseded requests so only the newest query's
 * result is applied. A blank query short-circuits to [ContactsPhase.Idle] with no network call (a
 * blank `q` would 422 — guarded in both the VM and [MessagingRepository.searchContacts]).
 *
 * Start conversation (AND-154): tapping a contact resolves a DM via the EXISTING
 * [MessagingRepository.findOrCreateDm] (AND-127 — self-DM guard + cache upsert live there; not
 * re-implemented) and emits a one-shot [ContactsEffect.OpenThread]. A double-tap while a resolution
 * is pending is ignored (single-flight via [ContactsUiState.pendingDmUserId]).
 */
@HiltViewModel
class ContactsViewModel @Inject constructor(
    private val repository: MessagingRepository,
    private val saved: SavedStateHandle,
) : ViewModel() {

    private val _uiState = MutableStateFlow(
        ContactsUiState(query = saved.get<String>(KEY_QUERY).orEmpty()),
    )
    val uiState: StateFlow<ContactsUiState> = _uiState

    private val _effects = Channel<ContactsEffect>(Channel.BUFFERED)
    val effects: Flow<ContactsEffect> = _effects.receiveAsFlow()

    /** Drives the search engine; emits the raw query whenever it changes (debounced downstream). */
    private val queryFlow = MutableStateFlow(_uiState.value.query)

    init {
        startEngine()
        // Re-issue on restore when a non-blank query survived a config change.
        if (_uiState.value.query.trim().isNotEmpty()) queryFlow.value = _uiState.value.query
    }

    fun onQueryChange(raw: String) {
        val capped = raw.take(MAX_QUERY_LENGTH)
        _uiState.update { it.copy(query = capped) }
        saved[KEY_QUERY] = capped
        if (capped.trim().isEmpty()) {
            // Blank -> idle immediately (no debounce wait, no network).
            _uiState.update { it.copy(phase = ContactsPhase.Idle, contacts = emptyList()) }
        }
        queryFlow.value = capped
    }

    fun onClear() = onQueryChange("")

    /** Re-issue the current query. [distinctUntilChanged] would drop an identical re-emit, so run directly. */
    fun retry() = runSearchOnce(_uiState.value.query)

    @OptIn(ExperimentalCoroutinesApi::class)
    private fun startEngine() {
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
                        emit(SearchEmission.Done(q, repository.searchContacts(q)))
                    }
                }
            }
            .onEach { applyEmission(it) }
            .launchIn(viewModelScope)
    }

    private fun runSearchOnce(raw: String) {
        val trimmed = raw.trim().take(MAX_QUERY_LENGTH)
        if (trimmed.isEmpty()) return
        _uiState.update { it.copy(phase = ContactsPhase.Loading) }
        viewModelScope.launch {
            applyResult(trimmed, repository.searchContacts(trimmed))
        }
    }

    private fun applyEmission(emission: SearchEmission) {
        when (emission) {
            SearchEmission.Skipped -> Unit // phase already set to Idle in onQueryChange
            SearchEmission.Loading -> _uiState.update { it.copy(phase = ContactsPhase.Loading) }
            is SearchEmission.Done -> applyResult(emission.query, emission.result)
        }
    }

    private fun applyResult(query: String, result: ApiResult<List<Contact>>) {
        when (result) {
            is ApiResult.Success ->
                _uiState.update {
                    it.copy(
                        contacts = result.data,
                        phase = if (result.data.isEmpty()) {
                            ContactsPhase.Empty(query)
                        } else {
                            ContactsPhase.Results
                        },
                    )
                }
            is ApiResult.Failure ->
                _uiState.update {
                    it.copy(
                        contacts = emptyList(),
                        phase = ContactsPhase.Error(result.error.message, offline = false),
                    )
                }
            is ApiResult.NetworkError ->
                _uiState.update {
                    it.copy(
                        contacts = emptyList(),
                        phase = ContactsPhase.Error(OFFLINE_MESSAGE, offline = true),
                    )
                }
        }
    }

    // ---- AND-154: contact -> start conversation ----

    /** AND-154 — tapping a contact row resolves a DM and (on success) navigates to the thread. */
    fun onContactClick(contact: Contact) = startDm(contact.id)

    private fun startDm(targetUserId: String) {
        if (_uiState.value.pendingDmUserId != null) return // single-flight / double-tap guard (FR-4)
        _uiState.update { it.copy(pendingDmUserId = targetUserId) }
        viewModelScope.launch {
            // Reuse AND-127 find-or-create: self-DM guard + cache upsert are handled in the repository.
            when (val result = repository.findOrCreateDm(targetUserId)) {
                is ApiResult.Success ->
                    _effects.send(ContactsEffect.OpenThread(result.data.id))
                is ApiResult.Failure ->
                    _effects.send(ContactsEffect.ShowError(result.error.message, retryUserId = targetUserId))
                is ApiResult.NetworkError ->
                    _effects.send(ContactsEffect.ShowError(OFFLINE_MESSAGE, retryUserId = targetUserId))
            }
            _uiState.update { it.copy(pendingDmUserId = null) }
        }
    }

    /** AND-154 — re-attempt a failed start-DM (driven by the snackbar Retry action). */
    fun retryStartDm(userId: String) = startDm(userId)

    private sealed interface SearchEmission {
        data object Skipped : SearchEmission
        data object Loading : SearchEmission
        data class Done(val query: String, val result: ApiResult<List<Contact>>) : SearchEmission
    }

    companion object {
        const val DEBOUNCE_MS = 300L

        /** Server `q` maxLength is 64; cap input client-side to avoid a 422. */
        const val MAX_QUERY_LENGTH = 64

        const val OFFLINE_MESSAGE = "You're offline. Try again when you're back online."

        private const val KEY_QUERY = "contacts_search_query"
    }
}
