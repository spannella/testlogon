package com.testlogon.android.feature.profile.publicprofile

import androidx.lifecycle.SavedStateHandle
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.data.auth.AuthStateStore
import com.testlogon.android.data.profile.ProfileRepository
import com.testlogon.android.data.profile.ProfileResult
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.launch
import javax.inject.Inject

/**
 * AND-073 / AND-075 / AND-390 — drives [PublicProfileUiState] for the /u/{identifier} screen.
 *
 * Reads `identifier` from [SavedStateHandle] (the route/deep-link arg). A blank identifier resolves
 * to [PublicProfileUiState.NotFound] without a network call. Retry re-issues the idempotent GET and
 * is debounced while loading.
 *
 * AND-390 polish: exposes [isAuthenticated] (collected from [AuthStateStore], AND-029) so the screen
 * can suppress auth-only affordances and pick the unauth Sign-in CTA (FR-7/FR-8); and [shareUrl], the
 * canonical production https `/u/{identifier}` link (never the dev host) used by the share/copy
 * affordances (FR-5). The public read itself stays auth-optional — no `GET /ui/me` success is
 * required to render a public profile (FR-1).
 */
@HiltViewModel
class PublicProfileViewModel @Inject constructor(
    private val repository: ProfileRepository,
    authStateStore: AuthStateStore,
    shareHostProvider: ProfileShareHostProvider,
    savedStateHandle: SavedStateHandle,
) : ViewModel() {

    val identifier: String = savedStateHandle.get<String>(ARG_IDENTIFIER).orEmpty()

    private val _uiState = MutableStateFlow<PublicProfileUiState>(PublicProfileUiState.Loading)
    val uiState: StateFlow<PublicProfileUiState> = _uiState.asStateFlow()

    /**
     * AND-390 — current auth state, gating auth-only affordances and the Sign-in CTA (FR-7/FR-8). This
     * does NOT gate the public read (FR-1); it only changes presentation. Mirrors the durable
     * [AuthStateStore] projection so the screen reacts without a network round-trip.
     */
    val isAuthenticated: StateFlow<Boolean> =
        authStateStore.isAuthenticated.stateIn(
            viewModelScope,
            SharingStarted.WhileSubscribed(5_000),
            authStateStore.isAuthenticated.value,
        )

    /**
     * AND-390 — the canonical, auth-free https `/u/{identifier}` share URL on the published App Link
     * host (FR-5). Always production host so a shared link round-trips back into the app (FR-6); never
     * the plaintext dev base URL (TC-AND-390-04). Available even before the payload loads (it needs
     * only the identifier), so copy-link may be enabled before Content (§7).
     */
    val shareUrl: String? =
        identifier.takeIf { it.isNotBlank() }?.let { ProfileShareUrl.build(shareHostProvider.host(), it) }

    init {
        load()
    }

    /** Retry; debounced while a load is already in flight. */
    fun onRetry() {
        if (loading) return
        load()
    }

    private fun load() {
        if (identifier.isBlank()) {
            _uiState.value = PublicProfileUiState.NotFound
            return
        }
        loading = true
        _uiState.value = PublicProfileUiState.Loading
        viewModelScope.launch {
            _uiState.value = when (val result = repository.getPublicProfile(identifier)) {
                is ProfileResult.Found -> PublicProfileUiState.Content(result.profile, isStale = false)
                is ProfileResult.NotFound -> PublicProfileUiState.NotFound
                is ProfileResult.RateLimited -> PublicProfileUiState.RateLimited(result.retryAfterSeconds)
                is ProfileResult.Offline ->
                    PublicProfileUiState.Error(OFFLINE_FALLBACK, retryable = true)
                is ProfileResult.Error ->
                    PublicProfileUiState.Error(result.error.message, retryable = result.retryable)
            }
            loading = false
        }
    }

    private var loading = false

    private companion object {
        const val ARG_IDENTIFIER = "identifier"
        const val OFFLINE_FALLBACK = "Couldn't reach the server. Try again."
    }
}
