package com.testlogon.android.feature.support.ui

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.feed.CurrentUserRepository
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
)

@HiltViewModel
class SupportHomeViewModel @Inject constructor(
    private val currentUser: CurrentUserRepository,
    private val repository: SupportRepository,
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
}
