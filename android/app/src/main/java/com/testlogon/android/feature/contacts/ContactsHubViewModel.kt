package com.testlogon.android.feature.contacts

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.contacts.ContactsRepository
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.receiveAsFlow
import kotlinx.coroutines.launch
import javax.inject.Inject

sealed interface ContactsHubEvent {
    data class ShowSnackbar(val message: String) : ContactsHubEvent

    /** Navigate to the contact detail card for [userId]. */
    data class OpenContactCard(val userId: String) : ContactsHubEvent
}

/**
 * Feature 1 — Contacts hub ViewModel. Loads the saved address book + "people you may know"
 * suggestions on entry, and drives add / remove / favorite mutations with optimistic UI +
 * rollback on server failure. All list-shaping is delegated to [ContactsHubReducer] (pure,
 * unit-tested).
 */
@HiltViewModel
class ContactsHubViewModel @Inject constructor(
    private val repository: ContactsRepository,
) : ViewModel() {

    private val _state = MutableStateFlow<ContactsHubUiState>(ContactsHubUiState.Loading)
    val state: StateFlow<ContactsHubUiState> = _state.asStateFlow()

    private val _events = Channel<ContactsHubEvent>(Channel.BUFFERED)
    val events: Flow<ContactsHubEvent> = _events.receiveAsFlow()

    // Feature 2 — the device contact-sync overlay (idle until "Find people you know").
    private val _matchState = MutableStateFlow<MatchSyncState>(MatchSyncState.Idle)
    val matchState: StateFlow<MatchSyncState> = _matchState.asStateFlow()

    init {
        refresh(initial = true)
    }

    fun refresh(initial: Boolean = false) {
        viewModelScope.launch {
            if (!initial) markRefreshing(true)
            val contactsResult = repository.listContacts()
            val suggestionsResult = repository.suggestions()

            when (contactsResult) {
                is ApiResult.Success -> {
                    val suggestions = (suggestionsResult as? ApiResult.Success)?.data ?: emptyList()
                    _state.value = ContactsHubReducer.content(contactsResult.data, suggestions)
                }
                is ApiResult.Failure ->
                    reduceError(contactsResult.error.message, offline = false, initial = initial)
                is ApiResult.NetworkError ->
                    reduceError("You appear to be offline.", offline = true, initial = initial)
            }
        }
    }

    fun onSaveSuggestion(userId: String) {
        val content = _state.value as? ContactsHubUiState.Content ?: return
        _state.value = ContactsHubReducer.markSuggestionAdding(content, userId, adding = true)
        viewModelScope.launch {
            when (val result = repository.addContact(userId)) {
                is ApiResult.Success -> {
                    (_state.value as? ContactsHubUiState.Content)?.let {
                        _state.value = ContactsHubReducer.promoteSuggestion(it, result.data)
                    }
                    _events.trySend(ContactsHubEvent.ShowSnackbar("Added to contacts"))
                }
                is ApiResult.Failure -> {
                    clearAdding(userId)
                    _events.trySend(ContactsHubEvent.ShowSnackbar(result.error.message))
                }
                is ApiResult.NetworkError -> {
                    clearAdding(userId)
                    _events.trySend(ContactsHubEvent.ShowSnackbar("Couldn't add contact — you're offline."))
                }
            }
        }
    }

    fun onRemoveContact(userId: String) {
        val content = _state.value as? ContactsHubUiState.Content ?: return
        val snapshot = content
        // Optimistic remove.
        _state.value = ContactsHubReducer.removeContact(content, userId)
        viewModelScope.launch {
            when (val result = repository.removeContact(userId)) {
                is ApiResult.Success ->
                    _events.trySend(ContactsHubEvent.ShowSnackbar("Removed from contacts"))
                is ApiResult.Failure -> {
                    _state.value = snapshot // rollback
                    _events.trySend(ContactsHubEvent.ShowSnackbar(result.error.message))
                }
                is ApiResult.NetworkError -> {
                    _state.value = snapshot
                    _events.trySend(ContactsHubEvent.ShowSnackbar("Couldn't remove — you're offline."))
                }
            }
        }
    }

    fun onToggleFavorite(userId: String, favorite: Boolean) {
        val content = _state.value as? ContactsHubUiState.Content ?: return
        val snapshot = content
        _state.value = ContactsHubReducer.toggleFavorite(content, userId, favorite)
        viewModelScope.launch {
            when (val result = repository.setFavorite(userId, favorite)) {
                is ApiResult.Success -> Unit
                is ApiResult.Failure -> {
                    _state.value = snapshot
                    _events.trySend(ContactsHubEvent.ShowSnackbar(result.error.message))
                }
                is ApiResult.NetworkError -> {
                    _state.value = snapshot
                    _events.trySend(ContactsHubEvent.ShowSnackbar("Couldn't update favorite — you're offline."))
                }
            }
        }
    }

    fun onOpenContact(userId: String) {
        _events.trySend(ContactsHubEvent.OpenContactCard(userId))
    }

    // ── Feature 2: device contact sync ──────────────────────────────────────

    /** Called after READ_CONTACTS is GRANTED: read+hash on-device, then match. */
    fun onPermissionGranted() {
        _matchState.value = MatchSyncState.Syncing
        viewModelScope.launch {
            when (val result = repository.matchDeviceContacts()) {
                is ApiResult.Success -> {
                    val savedContacts = (_state.value as? ContactsHubUiState.Content)?.contacts ?: emptyList()
                    _matchState.value = ContactsHubReducer.matchResults(result.data, savedContacts)
                }
                is ApiResult.Failure ->
                    _matchState.value = MatchSyncState.Failed(result.error.message, offline = false)
                is ApiResult.NetworkError ->
                    _matchState.value = MatchSyncState.Failed("You appear to be offline.", offline = true)
            }
        }
    }

    /** Called when the runtime permission request comes back DENIED. */
    fun onPermissionDenied(permanentlyDenied: Boolean) {
        _matchState.value = MatchSyncState.PermissionNeeded(permanentlyDenied)
    }

    /** Dismiss the sync overlay back to the hub. */
    fun onDismissSync() {
        _matchState.value = MatchSyncState.Idle
    }

    /** Add a matched person to contacts (optimistic; promotes into the saved list too). */
    fun onAddMatch(userId: String) {
        val results = _matchState.value as? MatchSyncState.Results ?: return
        _matchState.value = ContactsHubReducer.markMatchAdding(results, userId, adding = true)
        viewModelScope.launch {
            when (val result = repository.addContact(userId)) {
                is ApiResult.Success -> {
                    (_matchState.value as? MatchSyncState.Results)?.let {
                        _matchState.value = ContactsHubReducer.removeMatch(it, userId)
                    }
                    // Reflect the new contact in the underlying hub list too.
                    (_state.value as? ContactsHubUiState.Content)?.let {
                        _state.value = ContactsHubReducer.promoteSuggestion(it, result.data)
                    }
                    _events.trySend(ContactsHubEvent.ShowSnackbar("Added to contacts"))
                }
                is ApiResult.Failure -> {
                    clearMatchAdding(userId)
                    _events.trySend(ContactsHubEvent.ShowSnackbar(result.error.message))
                }
                is ApiResult.NetworkError -> {
                    clearMatchAdding(userId)
                    _events.trySend(ContactsHubEvent.ShowSnackbar("Couldn't add contact — you're offline."))
                }
            }
        }
    }

    private fun clearMatchAdding(userId: String) {
        (_matchState.value as? MatchSyncState.Results)?.let {
            _matchState.value = ContactsHubReducer.markMatchAdding(it, userId, adding = false)
        }
    }

    private fun clearAdding(userId: String) {
        (_state.value as? ContactsHubUiState.Content)?.let {
            _state.value = ContactsHubReducer.markSuggestionAdding(it, userId, adding = false)
        }
    }

    private fun markRefreshing(refreshing: Boolean) {
        (_state.value as? ContactsHubUiState.Content)?.let {
            _state.value = it.copy(isRefreshing = refreshing)
        }
    }

    private fun reduceError(message: String, offline: Boolean, initial: Boolean) {
        val current = _state.value
        if (current is ContactsHubUiState.Content) {
            // Keep showing cached content; just surface the failure + stop the spinner.
            _state.value = current.copy(isRefreshing = false)
            _events.trySend(ContactsHubEvent.ShowSnackbar(message))
        } else {
            _state.value = ContactsHubUiState.Error(message, offline)
        }
    }
}
