package com.testlogon.android.feature.guest

import androidx.lifecycle.SavedStateHandle
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.ApiResult
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import javax.inject.Inject

/**
 * AND-312 - presentation logic for the guest ACCEPT screen.
 *
 * Identity is (sessionId, inviteId) - there is NO token (both come from the deep link / nav args via
 * SavedStateHandle). [onAccept] requires a non-blank display_name (1..100) and POSTs the accept; on success
 * it surfaces the [GuestAcceptResult] (input_id / ingest_url) for the AND-308 media handoff (which is FLAGGED
 * - this VM only surfaces the result, it does NOT start media).
 *
 * FR-8 (guest self-leave): there is NO guest leave endpoint, so there is NO leave action here. A guest can
 * only stop participating by closing the app / the host revoking or removing them. This is documented and
 * STOP-AND-FLAGGED in the AND-312 report.
 */
@HiltViewModel
class GuestAcceptViewModel @Inject constructor(
    private val repository: GuestRepository,
    savedState: SavedStateHandle,
) : ViewModel() {

    val sessionId: String = savedState.get<String>(ARG_SESSION_ID).orEmpty()
    val inviteId: String = savedState.get<String>(ARG_INVITE_ID).orEmpty()

    private val _uiState = MutableStateFlow(GuestAcceptUiState())
    val uiState: StateFlow<GuestAcceptUiState> = _uiState.asStateFlow()

    /** Update the typed display name (clears any prior error). */
    fun onDisplayNameChange(value: String) {
        _uiState.update { it.copy(displayName = value, error = null) }
    }

    /**
     * Accept the invite with the current display name. No-op when the name is blank/out-of-range, while a
     * submit is in flight, or once already accepted. On success exposes the [GuestAcceptResult].
     */
    fun onAccept() {
        val current = _uiState.value
        val name = current.displayName.trim()
        if (sessionId.isBlank() || inviteId.isBlank()) {
            _uiState.update { it.copy(error = MISSING_INVITE) }
            return
        }
        if (!current.canSubmit) return

        _uiState.update { it.copy(isSubmitting = true, error = null) }
        viewModelScope.launch {
            when (val result = repository.acceptInvite(sessionId, inviteId, name)) {
                is ApiResult.Success ->
                    _uiState.update { it.copy(isSubmitting = false, accepted = result.data) }
                is ApiResult.Failure ->
                    _uiState.update { it.copy(isSubmitting = false, error = result.error.message) }
                is ApiResult.NetworkError ->
                    _uiState.update { it.copy(isSubmitting = false, error = OFFLINE) }
            }
        }
    }

    companion object {
        /** Nav args carrying the broadcast session id + the invite id (identity, NOT a token). */
        const val ARG_SESSION_ID = "sessionId"
        const val ARG_INVITE_ID = "inviteId"

        // Non-resource fallbacks (the screen prefers stringResource where it has a Context).
        private const val OFFLINE = "Couldn't reach the server. Try again."
        private const val MISSING_INVITE = "This invite link is missing or invalid."
    }
}
