package com.testlogon.android.feature.support.ui

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.feed.CurrentUserRepository
import com.testlogon.android.feature.support.data.HelpdeskAvailability
import com.testlogon.android.feature.support.data.SupportLiveChatRepository
import com.testlogon.android.feature.support.data.SupportRepository
import com.testlogon.android.feature.support.data.SupportTicket
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import javax.inject.Inject

/**
 * B-SUP (batch 7) — drives the role-branched Support landing. First resolves the caller's admin status from
 * `GET /ui/me.is_admin`; while UNKNOWN/failed it DEGRADES SAFELY to the USER help experience (never shows an
 * admin surface to a non-admin). For the USER role it also loads "My tickets".
 */
sealed interface SupportRole {
    data object Resolving : SupportRole
    data object User : SupportRole
    data object Admin : SupportRole
}

data class SupportHomeUiState(
    val role: SupportRole = SupportRole.Resolving,
    val ticketsLoading: Boolean = false,
    val tickets: List<SupportTicket> = emptyList(),
    val ticketsError: String? = null,
    // B8 #13 — live-agent chat
    val liveChat: LiveChatUiState = LiveChatUiState(),
)

/**
 * B8 #13 — customer-side live-agent chat state. [availability] is best-effort (null while unknown / on a
 * benign failure — the entry is still tappable and the chat queues). [startingChat] guards the create call;
 * [openConversationId] is a one-shot nav signal consumed by the screen.
 */
data class LiveChatUiState(
    val availability: HelpdeskAvailability? = null,
    val startingChat: Boolean = false,
    val startError: String? = null,
    val openConversationId: String? = null,
)

@HiltViewModel
class SupportHomeViewModel @Inject constructor(
    private val currentUser: CurrentUserRepository,
    private val repository: SupportRepository,
    private val liveChatRepository: SupportLiveChatRepository,
) : ViewModel() {

    private val _uiState = MutableStateFlow(SupportHomeUiState())
    val uiState: StateFlow<SupportHomeUiState> = _uiState.asStateFlow()

    init {
        resolveRole()
    }

    private fun resolveRole() {
        viewModelScope.launch {
            val admin = when (val r = currentUser.isAdmin()) {
                is ApiResult.Success -> r.data
                else -> false // safe degrade: treat unknown/failed as a normal user
            }
            if (admin) {
                _uiState.value = _uiState.value.copy(role = SupportRole.Admin)
            } else {
                _uiState.value = _uiState.value.copy(role = SupportRole.User)
                loadMyTickets()
                loadLiveChatAvailability()
            }
        }
    }

    fun loadMyTickets() {
        viewModelScope.launch {
            _uiState.value = _uiState.value.copy(ticketsLoading = true, ticketsError = null)
            when (val r = repository.listTickets(limit = 50)) {
                is ApiResult.Success ->
                    _uiState.value = _uiState.value.copy(
                        ticketsLoading = false,
                        tickets = r.data.tickets.sortedByDescending { it.updatedAt },
                        ticketsError = null,
                    )
                is ApiResult.Failure ->
                    _uiState.value = _uiState.value.copy(ticketsLoading = false, ticketsError = r.error.message)
                is ApiResult.NetworkError ->
                    _uiState.value = _uiState.value.copy(
                        ticketsLoading = false,
                        ticketsError = "You appear to be offline. Pull to retry.",
                    )
            }
        }
    }

    /**
     * B8 #14 — re-pull "My tickets" when the Support landing resumes (e.g. returning from create-ticket or
     * from a ticket detail where the user closed/cancelled it) so the list reflects the latest state without
     * a manual refresh. No-op while still resolving the role or in the admin surface.
     */
    fun onResumed() {
        if (_uiState.value.role == SupportRole.User) {
            loadMyTickets()
            loadLiveChatAvailability()
        }
    }

    /** B8 #13 — best-effort agent availability for the live-chat entry. */
    fun loadLiveChatAvailability() {
        viewModelScope.launch {
            val avail = when (val r = liveChatRepository.availability()) {
                is ApiResult.Success -> r.data
                else -> null // benign: leave the entry tappable, the chat will queue
            }
            _uiState.value = _uiState.value.copy(
                liveChat = _uiState.value.liveChat.copy(availability = avail),
            )
        }
    }

    /** B8 #13 — open (create-or-resume) a live-agent chat, then signal the screen to navigate to its thread. */
    fun startLiveChat() {
        if (_uiState.value.liveChat.startingChat) return
        viewModelScope.launch {
            _uiState.value = _uiState.value.copy(
                liveChat = _uiState.value.liveChat.copy(startingChat = true, startError = null),
            )
            val lc = when (val r = liveChatRepository.startLiveChat()) {
                is ApiResult.Success ->
                    _uiState.value.liveChat.copy(startingChat = false, openConversationId = r.data)
                is ApiResult.Failure ->
                    _uiState.value.liveChat.copy(startingChat = false, startError = r.error.message)
                is ApiResult.NetworkError ->
                    _uiState.value.liveChat.copy(startingChat = false, startError = "You appear to be offline.")
            }
            _uiState.value = _uiState.value.copy(liveChat = lc)
        }
    }

    fun consumeOpenConversation() {
        _uiState.value = _uiState.value.copy(liveChat = _uiState.value.liveChat.copy(openConversationId = null))
    }

    fun clearLiveChatError() {
        _uiState.value = _uiState.value.copy(liveChat = _uiState.value.liveChat.copy(startError = null))
    }
}
