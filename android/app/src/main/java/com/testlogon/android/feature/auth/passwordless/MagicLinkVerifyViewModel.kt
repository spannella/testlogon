package com.testlogon.android.feature.auth.passwordless

import androidx.lifecycle.SavedStateHandle
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.ApiError
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.auth.PasswordlessRepository
import com.testlogon.android.data.auth.PasswordlessVerified
import com.testlogon.android.navigation.AuthDest
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.Job
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.receiveAsFlow
import kotlinx.coroutines.launch
import javax.inject.Inject

/** Terminal error kinds for the magic-link verify screen (AND-061). */
enum class MagicLinkError { MISSING_TOKEN, EXPIRED, USED, INVALID, NETWORK, SERVER }

/** Hoisted magic-link-verify screen state (AND-061). */
sealed interface MagicLinkVerifyUiState {
    data object Verifying : MagicLinkVerifyUiState
    data class Error(val kind: MagicLinkError) : MagicLinkVerifyUiState
}

/** One-shot navigation effects from the magic-link verify screen (AND-061). */
sealed interface MagicLinkVerifyEffect {
    /** Full session granted → let the auth gate swap to the authenticated graph; pop verify. */
    data object Authenticated : MagicLinkVerifyEffect

    /** First factor passed, MFA still required → hand off to the existing MFA route; pop verify. */
    data class MfaRequired(
        val challengeId: String,
        val requiredFactors: List<String>,
    ) : MagicLinkVerifyEffect
}

/**
 * Magic-link deep-link verify state machine (AND-061).
 *
 * On construction it reads the one-time `token` from [SavedStateHandle] (the deep-link nav arg) and
 * immediately POSTs it to `/ui/passwordless/verify`, then branches:
 *  - full session → [MagicLinkVerifyEffect.Authenticated] (the repository already ran getMe, which set
 *    the durable auth state so the nav gate swaps graphs);
 *  - MFA required → [MagicLinkVerifyEffect.MfaRequired] (hand off to the password-login MFA route);
 *  - otherwise → a terminal [MagicLinkVerifyUiState.Error] with a recovery action.
 *
 * CONTRACT:
 *  - verify is a non-idempotent POST and is NEVER auto-retried; "Try again" re-issues it manually.
 *  - The verify call fires exactly once per ViewModel instance (guarded by [verifyJob]); it survives
 *    config change. The token is never logged.
 */
@HiltViewModel
class MagicLinkVerifyViewModel @Inject constructor(
    savedStateHandle: SavedStateHandle,
    private val repository: PasswordlessRepository,
) : ViewModel() {

    private val token: String? = savedStateHandle[AuthDest.MagicLinkVerify.ARG_TOKEN]

    private val _uiState = MutableStateFlow<MagicLinkVerifyUiState>(MagicLinkVerifyUiState.Verifying)
    val uiState: StateFlow<MagicLinkVerifyUiState> = _uiState.asStateFlow()

    // Channel-backed one-shot effects: buffers events emitted before a collector subscribes (the
    // verify completes from init), unlike a replay=0 SharedFlow.
    private val _effects = Channel<MagicLinkVerifyEffect>(Channel.BUFFERED)
    val effects: Flow<MagicLinkVerifyEffect> = _effects.receiveAsFlow()

    private var verifyJob: Job? = null

    init {
        verify()
    }

    /** (Re)issue the verify call for the carried token. Deduped while a call is in flight. */
    fun verify() {
        if (token.isNullOrBlank()) {
            _uiState.value = MagicLinkVerifyUiState.Error(MagicLinkError.MISSING_TOKEN)
            return
        }
        if (verifyJob?.isActive == true) return
        verifyJob = viewModelScope.launch {
            _uiState.value = MagicLinkVerifyUiState.Verifying
            when (val result = repository.verify(token)) {
                is ApiResult.Success -> when (val outcome = result.data) {
                    is PasswordlessVerified.Authenticated ->
                        _effects.trySend(MagicLinkVerifyEffect.Authenticated)
                    is PasswordlessVerified.MfaRequired ->
                        _effects.trySend(
                            MagicLinkVerifyEffect.MfaRequired(
                                challengeId = outcome.challengeId,
                                requiredFactors = outcome.requiredFactors,
                            ),
                        )
                    is PasswordlessVerified.Invalid ->
                        _uiState.value = MagicLinkVerifyUiState.Error(MagicLinkError.INVALID)
                }
                is ApiResult.Failure ->
                    _uiState.value = MagicLinkVerifyUiState.Error(result.error.toMagicLinkError())
                is ApiResult.NetworkError ->
                    _uiState.value = MagicLinkVerifyUiState.Error(MagicLinkError.NETWORK)
            }
        }
    }

    /**
     * Best-effort error mapping. Only 200/422 are documented for this op; expired/used are aspirational
     * (read an optional `detail.code`) and fall back to INVALID, exactly as the web client collapses
     * all failures into one generic "expired or already used" message.
     */
    private fun ApiError.toMagicLinkError(): MagicLinkError = when {
        status == ApiError.STATUS_NETWORK -> MagicLinkError.NETWORK
        status in 500..599 -> MagicLinkError.SERVER
        code == "token_expired" || code == "expired" -> MagicLinkError.EXPIRED
        code == "token_used" || code == "used" -> MagicLinkError.USED
        else -> MagicLinkError.INVALID
    }
}
