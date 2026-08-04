package com.testlogon.android.feature.orgs

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.ApiError
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.model.orgs.OrgMember
import com.testlogon.android.data.auth.AuthStateStore
import com.testlogon.android.feature.orgs.data.OrgsRepository
import com.testlogon.android.feature.orgs.data.SelectedOrgStore
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.receiveAsFlow
import kotlinx.coroutines.launch
import javax.inject.Inject

/**
 * PAR-35(c) - render-ready state for the transfer-ownership member picker.
 *
 * [Content.candidates] is the roster with the CALLER (current owner) removed - you cannot transfer to
 * yourself. [transferringSub] marks the row whose transfer POST is in flight.
 */
sealed interface TransferOwnershipUiState {
    data object Loading : TransferOwnershipUiState
    data class Content(
        val candidates: List<OrgMember>,
        val transferringSub: String? = null,
    ) : TransferOwnershipUiState
    data object Empty : TransferOwnershipUiState
    data class Error(val error: ApiError) : TransferOwnershipUiState
}

/** PAR-35(c) - one-shot outcomes: a successful transfer pops back; a failure surfaces a snackbar. */
sealed interface TransferOwnershipEvent {
    data object Transferred : TransferOwnershipEvent
    data class Message(val text: String) : TransferOwnershipEvent
}

/**
 * PAR-35(c) - drives the transfer-ownership member picker. Loads the roster for the CURRENT org (the
 * selected org, defaulting to the caller's primary), removes the caller from the candidate list, and on a
 * pick calls [OrgsRepository.transferOwnership]. On success emits [TransferOwnershipEvent.Transferred]
 * (the screen pops and the overview reloads its roles). There is NO poll loop.
 */
@HiltViewModel
class TransferOwnershipViewModel @Inject constructor(
    private val repository: OrgsRepository,
    private val selectedOrgStore: SelectedOrgStore,
    private val authStateStore: AuthStateStore,
) : ViewModel() {

    private val _uiState = MutableStateFlow<TransferOwnershipUiState>(TransferOwnershipUiState.Loading)
    val uiState: StateFlow<TransferOwnershipUiState> = _uiState.asStateFlow()

    private val _events = Channel<TransferOwnershipEvent>(Channel.BUFFERED)
    val events: Flow<TransferOwnershipEvent> = _events.receiveAsFlow()

    private var orgId: String? = null

    init {
        load()
    }

    fun onRetry() = load()

    private fun load() {
        _uiState.value = TransferOwnershipUiState.Loading
        viewModelScope.launch {
            val resolved = resolveOrgId()
            if (resolved == null) {
                _uiState.value = TransferOwnershipUiState.Empty
                return@launch
            }
            orgId = resolved
            when (val members = repository.listMembers(resolved)) {
                is ApiResult.Success -> {
                    val me = authStateStore.userSub.first()
                    val candidates = members.data.filter { it.userSub != me }
                    _uiState.value = if (candidates.isEmpty()) {
                        TransferOwnershipUiState.Empty
                    } else {
                        TransferOwnershipUiState.Content(candidates = candidates)
                    }
                }
                is ApiResult.Failure -> _uiState.value = TransferOwnershipUiState.Error(members.error)
                is ApiResult.NetworkError ->
                    _uiState.value = TransferOwnershipUiState.Error(networkError())
            }
        }
    }

    private suspend fun resolveOrgId(): String? {
        selectedOrgStore.selectedOrgId.first()?.let { return it }
        return when (val orgs = repository.listOrgs()) {
            is ApiResult.Success -> orgs.data.firstOrNull()?.orgId
            else -> null
        }
    }

    /** Transfers ownership to [newOwnerSub]. On success emits [TransferOwnershipEvent.Transferred]. */
    fun transferTo(newOwnerSub: String) {
        val content = _uiState.value as? TransferOwnershipUiState.Content ?: return
        val org = orgId ?: return
        if (content.transferringSub != null) return
        _uiState.value = content.copy(transferringSub = newOwnerSub)
        viewModelScope.launch {
            val result = repository.transferOwnership(org, newOwnerSub)
            val now = _uiState.value as? TransferOwnershipUiState.Content
            when (result) {
                is ApiResult.Success -> _events.send(TransferOwnershipEvent.Transferred)
                is ApiResult.Failure -> {
                    if (now != null) _uiState.value = now.copy(transferringSub = null)
                    _events.send(TransferOwnershipEvent.Message(TRANSFER_FAILED))
                }
                is ApiResult.NetworkError -> {
                    if (now != null) _uiState.value = now.copy(transferringSub = null)
                    _events.send(TransferOwnershipEvent.Message(OFFLINE_FALLBACK))
                }
            }
        }
    }

    private fun networkError(): ApiError =
        ApiError(status = ApiError.STATUS_NETWORK, message = OFFLINE_FALLBACK)

    private companion object {
        const val OFFLINE_FALLBACK = "Couldn't reach the server. Pull down to retry."
        const val TRANSFER_FAILED = "Couldn't transfer ownership. Please try again."
    }
}
