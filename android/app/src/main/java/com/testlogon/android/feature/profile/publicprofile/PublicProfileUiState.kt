package com.testlogon.android.feature.profile.publicprofile

import com.testlogon.android.core.model.profile.PublicProfile

/**
 * AND-073 / AND-075 — public-profile state.
 *
 * Note: the backend folds private/suppressed into 404, so there is no `Private` phase — privacy is a
 * subset of [NotFound]. 429 maps to [RateLimited] (a retryable surface honoring Retry-After).
 */
sealed interface PublicProfileUiState {
    data object Loading : PublicProfileUiState
    data class Content(val profile: PublicProfile, val isStale: Boolean = false) : PublicProfileUiState
    data object NotFound : PublicProfileUiState
    data class RateLimited(val retryAfterSeconds: Long?) : PublicProfileUiState
    data class Error(val message: String, val retryable: Boolean) : PublicProfileUiState
}
