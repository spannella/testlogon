package com.testlogon.android.feature.webhooks.ui

import com.testlogon.android.core.model.ApiError
import com.testlogon.android.core.model.webhooks.Webhook
import com.testlogon.android.core.model.webhooks.WebhookEventType

/**
 * AND-398 - exhaustive UI state for the WEBHOOKS LIST (screen 1 of the 3-screen flow).
 *
 * Sealed so the screen renders mutually-exclusive surfaces; a new variant forces an exhaustive `when`.
 * [Loading] is the first-load spinner; [Content] carries the endpoints plus an in-memory [isStale] flag
 * (last-good kept on a refresh failure - FR-5 stale banner, IN-MEMORY only, NOT persisted) and an
 * [isRefreshing] flag (pull-to-refresh spinner); [Empty] is the zero-endpoints state (with the create CTA);
 * [Error] carries the [ApiError] for the retry surface. A terminal 401 is emitted as the one-shot
 * [WebhooksEffect.NavigateToLogin], NOT a variant here.
 */
sealed interface WebhooksListUiState {

    data object Loading : WebhooksListUiState

    data class Content(
        val items: List<Webhook>,
        val isStale: Boolean = false,
        val isRefreshing: Boolean = false,
    ) : WebhooksListUiState

    data object Empty : WebhooksListUiState

    data class Error(val message: String, val retryable: Boolean) : WebhooksListUiState
}

/**
 * AND-398 - exhaustive UI state for the WEBHOOK DETAIL (screen 2). [Loading] while fetching; [Content] with the
 * endpoint; [NotFound] for a missing id (defensive - the OpenAPI does not declare a 404, so any non-2xx other
 * than 401 that yields no cached / fetched endpoint resolves here); [Error] for a retryable failure.
 */
sealed interface WebhookDetailUiState {

    data object Loading : WebhookDetailUiState

    data class Content(val webhook: Webhook) : WebhookDetailUiState

    data object NotFound : WebhookDetailUiState

    data class Error(val message: String) : WebhookDetailUiState
}

/**
 * AND-398 - the create-screen form state. [canSubmit] is derived (a valid https:// [url] AND >=1
 * [selectedEvents]); [urlError] is the inline field error (client https-only validation or a 422 loc:["body",
 * "url"] mapping); [submitError] is the form-level error. [eventTypes] is the metadata-sourced multi-select
 * (FR-3 / OQ-2); [eventTypesLoading] gates the chip area while the metadata call is in flight.
 */
data class CreateWebhookForm(
    val url: String = "",
    val selectedEvents: Set<String> = emptySet(),
    val eventTypes: List<WebhookEventType> = emptyList(),
    val eventTypesLoading: Boolean = true,
    val submitting: Boolean = false,
    val urlError: String? = null,
    val submitError: String? = null,
    val canSubmit: Boolean = false,
)

/**
 * AND-398 - one-shot effects shared by the webhooks ViewModels.
 *
 * [NavigateToLogin] is emitted on a TERMINAL 401 (after the shared client's one auth refresh) so the screen
 * routes to the unauthenticated graph (re-auth handoff) instead of rendering a generic error. [CreateSucceeded]
 * is emitted after a successful create so the create screen pops back to the (refreshing) list, carrying the
 * one-time signing [secret] (if any) for one-time in-session display. Delivered via a Channel (one-shot, never
 * re-delivered on rotation).
 */
sealed interface WebhooksEffect {
    data object NavigateToLogin : WebhooksEffect
    data class CreateSucceeded(val secret: String?) : WebhooksEffect
}
