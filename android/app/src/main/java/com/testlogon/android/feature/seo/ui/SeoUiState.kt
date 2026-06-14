package com.testlogon.android.feature.seo.ui

import com.testlogon.android.feature.seo.data.SeoMetadata

/**
 * AND-400 - the mutually-exclusive top-level surfaces of the read-only SEO inspector.
 *
 * [Error.retryable] distinguishes a transient transport / 5xx failure (Retry shown) from a
 * non-retryable 422 validation error (Retry hidden), mapped from the ApiResult NetworkError vs Failure
 * split in the ViewModel.
 */
sealed interface SeoUiState {
    data object Loading : SeoUiState
    data object Empty : SeoUiState
    data class Content(val metadata: SeoMetadata) : SeoUiState
    data class Error(val message: String, val retryable: Boolean) : SeoUiState
}
