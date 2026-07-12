package com.testlogon.android.feature.watchparties

import androidx.lifecycle.SavedStateHandle
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.watchparties.WatchPartiesRepository
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import javax.inject.Inject

/**
 * Resolves an invite code (web /party/{inviteCode}) to a party id via GET ui/watch-parties/join/{code},
 * so the caller can replace this transient screen with the real detail destination. Reads its code from
 * [SavedStateHandle].
 */
@HiltViewModel
class WatchPartyInviteViewModel @Inject constructor(
    private val repository: WatchPartiesRepository,
    savedStateHandle: SavedStateHandle,
) : ViewModel() {

    private val inviteCode: String = checkNotNull(savedStateHandle[ARG_INVITE_CODE]) {
        "WatchPartyInviteViewModel requires an '$ARG_INVITE_CODE' nav argument"
    }

    private val _uiState = MutableStateFlow<InviteUiState>(InviteUiState.Resolving)
    val uiState: StateFlow<InviteUiState> = _uiState.asStateFlow()

    init {
        resolve()
    }

    fun onRetry() = resolve()

    private fun resolve() {
        _uiState.value = InviteUiState.Resolving
        viewModelScope.launch {
            when (val result = repository.resolveInvite(inviteCode)) {
                is ApiResult.Success -> _uiState.value = InviteUiState.Resolved(result.data.partyId)
                else -> _uiState.value = InviteUiState.Failed
            }
        }
    }

    sealed interface InviteUiState {
        data object Resolving : InviteUiState
        data class Resolved(val partyId: String) : InviteUiState
        data object Failed : InviteUiState
    }

    companion object {
        const val ARG_INVITE_CODE = "inviteCode"
    }
}
