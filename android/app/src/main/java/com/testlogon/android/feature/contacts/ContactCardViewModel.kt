package com.testlogon.android.feature.contacts

import androidx.lifecycle.SavedStateHandle
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.contacts.ContactsRepository
import com.testlogon.android.data.profile.ProfileApi
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.receiveAsFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import javax.inject.Inject

/** Loaded contact-card data + the live relationship flags that drive the action buttons. */
data class ContactCardData(
    val userId: String,
    val displayName: String,
    val photoUrl: String?,
    val isFollowing: Boolean,
    val isMutual: Boolean,
    val isSaved: Boolean,
    val isFavorite: Boolean,
)

sealed interface ContactCardUiState {
    data object Loading : ContactCardUiState
    data class Content(val data: ContactCardData, val actionInFlight: Boolean = false) : ContactCardUiState
    data class Error(val message: String, val offline: Boolean) : ContactCardUiState
}

sealed interface ContactCardEvent {
    data class ShowSnackbar(val message: String) : ContactCardEvent
    data class OpenThread(val conversationId: String) : ContactCardEvent
    data class PlaceCall(val route: String) : ContactCardEvent
    data class OpenFullProfile(val userId: String) : ContactCardEvent
}

/**
 * Feature 1 — the contact detail card. Loads the peer's public identity + follow relationship +
 * whether they're already saved, then wires the action set: Message, Audio/Video call, Follow/
 * unfollow, Save/Remove + favorite, and (delegated to the full profile surface) Tip + View profile.
 *
 * Message/Call resolve a conversation via the messaging DM find-or-create rail so the same
 * conversation backs both the thread and the 1:1 call — reusing the app's existing money/call paths
 * rather than duplicating them.
 */
@HiltViewModel
class ContactCardViewModel @Inject constructor(
    savedStateHandle: SavedStateHandle,
    private val contactsRepository: ContactsRepository,
    private val messagingRepository: com.testlogon.android.data.messaging.MessagingRepository,
    private val profileApi: ProfileApi,
) : ViewModel() {

    val userId: String = requireNotNull(savedStateHandle.get<String>(ARG_USER_ID)) {
        "ContactCard requires a $ARG_USER_ID argument"
    }

    private val _state = MutableStateFlow<ContactCardUiState>(ContactCardUiState.Loading)
    val state: StateFlow<ContactCardUiState> = _state.asStateFlow()

    private val _events = Channel<ContactCardEvent>(Channel.BUFFERED)
    val events: Flow<ContactCardEvent> = _events.receiveAsFlow()

    init {
        load()
    }

    fun load() {
        viewModelScope.launch {
            _state.value = ContactCardUiState.Loading

            // Identity (name + photo) — best-effort; the card still works if this 404s.
            var displayName = userId
            var photoUrl: String? = null
            runCatching { profileApi.getProfileByIdentifier(userId) }.getOrNull()?.let { dto ->
                displayName = dto.profile.displayName
                    ?: listOfNotNull(dto.profile.firstName, dto.profile.lastName)
                        .joinToString(" ").ifBlank { null }
                    ?: dto.identifier
                photoUrl = dto.profile.profilePhotoUrl
            }

            // Follow relationship (authoritative for the Follow button).
            var following = false
            var mutual = false
            when (val rel = contactsRepository.followStatus(userId)) {
                is ApiResult.Success -> {
                    following = rel.data.isFollowing
                    mutual = rel.data.isMutual
                }
                is ApiResult.Failure -> Unit
                is ApiResult.NetworkError -> {
                    _state.value = ContactCardUiState.Error("You appear to be offline.", offline = true)
                    return@launch
                }
            }

            // Saved / favorite state (from the address book).
            var saved = false
            var favorite = false
            when (val list = contactsRepository.listContacts()) {
                is ApiResult.Success -> list.data.firstOrNull { it.userId == userId }?.let {
                    saved = true
                    favorite = it.isFavorite
                }
                is ApiResult.Failure -> Unit
                is ApiResult.NetworkError -> Unit
            }

            _state.value = ContactCardUiState.Content(
                ContactCardData(
                    userId = userId,
                    displayName = displayName,
                    photoUrl = photoUrl,
                    isFollowing = following,
                    isMutual = mutual,
                    isSaved = saved,
                    isFavorite = favorite,
                ),
            )
        }
    }

    fun onMessage() {
        val data = content()?.data ?: return
        withInFlight {
            when (val result = messagingRepository.findOrCreateDm(data.userId)) {
                is ApiResult.Success -> _events.trySend(ContactCardEvent.OpenThread(result.data.id))
                is ApiResult.Failure -> emitSnack(result.error.message)
                is ApiResult.NetworkError -> emitSnack("Couldn't open chat — you're offline.")
            }
        }
    }

    fun onCall(video: Boolean) {
        val data = content()?.data ?: return
        withInFlight {
            when (val result = messagingRepository.findOrCreateDm(data.userId)) {
                is ApiResult.Success -> {
                    val route = com.testlogon.android.feature.call.nav.CallRoutes.outgoing(
                        conversationId = result.data.id,
                        calleeUserId = data.userId,
                        mode = if (video) com.testlogon.android.data.call.CallMode.VIDEO.wire
                        else com.testlogon.android.data.call.CallMode.AUDIO.wire,
                        peerName = data.displayName,
                    )
                    _events.trySend(ContactCardEvent.PlaceCall(route))
                }
                is ApiResult.Failure -> emitSnack(result.error.message)
                is ApiResult.NetworkError -> emitSnack("Couldn't start call — you're offline.")
            }
        }
    }

    fun onToggleFollow() {
        val data = content()?.data ?: return
        val wantFollow = !data.isFollowing
        // Optimistic flip.
        updateData { it.copy(isFollowing = wantFollow, isMutual = if (wantFollow) it.isMutual else false) }
        viewModelScope.launch {
            val result = if (wantFollow) contactsRepository.follow(data.userId)
            else contactsRepository.unfollow(data.userId)
            when (result) {
                is ApiResult.Success -> emitSnack(if (wantFollow) "Following" else "Unfollowed")
                is ApiResult.Failure -> {
                    updateData { it.copy(isFollowing = data.isFollowing, isMutual = data.isMutual) }
                    emitSnack(result.error.message)
                }
                is ApiResult.NetworkError -> {
                    updateData { it.copy(isFollowing = data.isFollowing, isMutual = data.isMutual) }
                    emitSnack("Couldn't update — you're offline.")
                }
            }
        }
    }

    fun onToggleSaved() {
        val data = content()?.data ?: return
        if (data.isSaved) {
            updateData { it.copy(isSaved = false, isFavorite = false) }
            viewModelScope.launch {
                when (val result = contactsRepository.removeContact(data.userId)) {
                    is ApiResult.Success -> emitSnack("Removed from contacts")
                    is ApiResult.Failure -> { updateData { it.copy(isSaved = true, isFavorite = data.isFavorite) }; emitSnack(result.error.message) }
                    is ApiResult.NetworkError -> { updateData { it.copy(isSaved = true, isFavorite = data.isFavorite) }; emitSnack("Couldn't remove — you're offline.") }
                }
            }
        } else {
            updateData { it.copy(isSaved = true) }
            viewModelScope.launch {
                when (val result = contactsRepository.addContact(data.userId)) {
                    is ApiResult.Success -> emitSnack("Added to contacts")
                    is ApiResult.Failure -> { updateData { it.copy(isSaved = false) }; emitSnack(result.error.message) }
                    is ApiResult.NetworkError -> { updateData { it.copy(isSaved = false) }; emitSnack("Couldn't add — you're offline.") }
                }
            }
        }
    }

    fun onToggleFavorite() {
        val data = content()?.data ?: return
        if (!data.isSaved) return // can only favorite a saved contact
        val want = !data.isFavorite
        updateData { it.copy(isFavorite = want) }
        viewModelScope.launch {
            when (val result = contactsRepository.setFavorite(data.userId, want)) {
                is ApiResult.Success -> Unit
                is ApiResult.Failure -> { updateData { it.copy(isFavorite = data.isFavorite) }; emitSnack(result.error.message) }
                is ApiResult.NetworkError -> { updateData { it.copy(isFavorite = data.isFavorite) }; emitSnack("Couldn't update favorite — you're offline.") }
            }
        }
    }

    fun onViewFullProfile() {
        _events.trySend(ContactCardEvent.OpenFullProfile(userId))
    }

    // ── helpers ──────────────────────────────────────────────────────────────

    private fun content(): ContactCardUiState.Content? = _state.value as? ContactCardUiState.Content

    private fun updateData(transform: (ContactCardData) -> ContactCardData) {
        _state.update { s -> if (s is ContactCardUiState.Content) s.copy(data = transform(s.data)) else s }
    }

    private fun withInFlight(block: suspend () -> Unit) {
        _state.update { if (it is ContactCardUiState.Content) it.copy(actionInFlight = true) else it }
        viewModelScope.launch {
            try {
                block()
            } finally {
                _state.update { if (it is ContactCardUiState.Content) it.copy(actionInFlight = false) else it }
            }
        }
    }

    private fun emitSnack(message: String) {
        _events.trySend(ContactCardEvent.ShowSnackbar(message))
    }

    companion object {
        const val ARG_USER_ID = "userId"
    }
}
