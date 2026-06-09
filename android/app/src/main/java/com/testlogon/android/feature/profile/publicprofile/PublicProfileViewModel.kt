package com.testlogon.android.feature.profile.publicprofile

import androidx.lifecycle.SavedStateHandle
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.data.profile.ProfileRepository
import com.testlogon.android.data.profile.ProfileResult
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import javax.inject.Inject

/**
 * AND-073 / AND-075 — drives [PublicProfileUiState] for the /u/{identifier} screen.
 *
 * Reads `identifier` from [SavedStateHandle] (the route/deep-link arg). A blank identifier resolves
 * to [PublicProfileUiState.NotFound] without a network call. Retry re-issues the idempotent GET and
 * is debounced while loading.
 */
@HiltViewModel
class PublicProfileViewModel @Inject constructor(
    private val repository: ProfileRepository,
    savedStateHandle: SavedStateHandle,
) : ViewModel() {

    val identifier: String = savedStateHandle.get<String>(ARG_IDENTIFIER).orEmpty()

    private val _uiState = MutableStateFlow<PublicProfileUiState>(PublicProfileUiState.Loading)
    val uiState: StateFlow<PublicProfileUiState> = _uiState.asStateFlow()

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
