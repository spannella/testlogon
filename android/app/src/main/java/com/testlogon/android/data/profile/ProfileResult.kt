package com.testlogon.android.data.profile

import com.testlogon.android.core.model.ApiError
import com.testlogon.android.core.model.profile.PublicProfile

/**
 * AND-073 — typed outcome for a public-profile lookup.
 *
 * The backend folds private/suppressed profiles into 404 (`not_found_or_suppressed`), so there is no
 * distinct "private" branch. 429 (rate-limited, honoring `Retry-After`) is the real third terminal
 * branch (reference: src/api/endpoints/profile.ts: mapProfileLookupError).
 */
sealed interface ProfileResult {
    data class Found(val profile: PublicProfile) : ProfileResult
    data object NotFound : ProfileResult
    data class RateLimited(val retryAfterSeconds: Long?) : ProfileResult
    data class Error(val error: ApiError, val retryable: Boolean) : ProfileResult
    data object Offline : ProfileResult
}
