package com.testlogon.android.feature.apikeys.ui

import com.testlogon.android.feature.apikeys.data.ApiKey

/**
 * B-APIKEY (batch 7) - exhaustive UI state for the API-keys LIST screen.
 *
 * Sealed so the screen renders mutually-exclusive surfaces. [Loading] is the first-load spinner; [Content]
 * carries the keys plus an in-memory [isStale] flag (last-good kept on a refresh failure, IN-MEMORY only) and an
 * [isRefreshing] flag; [Empty] is the zero-keys state (with the create CTA); [Error] carries the message for the
 * retry surface. A terminal 401 is emitted as the one-shot [ApiKeysEffect.NavigateToLogin], NOT a variant here.
 * [revokingId] is the id of a key whose revoke is in flight (its row shows a spinner + disables actions).
 * [newSecret] holds the one-time secret to display after a create round-trip (cleared on dismiss).
 */
sealed interface ApiKeysListUiState {

    data object Loading : ApiKeysListUiState

    data class Content(
        val items: List<ApiKey>,
        val isStale: Boolean = false,
        val isRefreshing: Boolean = false,
        val revokingId: String? = null,
        val newSecret: String? = null,
        val actionError: String? = null,
    ) : ApiKeysListUiState

    data object Empty : ApiKeysListUiState

    data class Error(val message: String, val retryable: Boolean) : ApiKeysListUiState
}

/**
 * B-APIKEY (batch 7; batch 8 #17) - the create-screen form state. [canSubmit] is derived (a non-blank [label]);
 * [labelError] is the inline field error; [submitError] is the form-level error. [selectedCapabilities] is the
 * multi-select set of canonical capability ids (empty -> the backend applies its default scopes); the screen
 * renders a labelled chip per [ApiKeyCapabilities.ALL] entry instead of a free-text field.
 */
data class CreateApiKeyForm(
    val label: String = "",
    val selectedCapabilities: Set<String> = emptySet(),
    val expiresInDays: String = "",
    val submitting: Boolean = false,
    val labelError: String? = null,
    val submitError: String? = null,
    val canSubmit: Boolean = false,
)

/**
 * Batch 8 (#17, #18) - UI state for the API-key DETAIL screen (capability editing + IP-rule management).
 *
 * [capabilities] is the server's authoritative current set; [editedCapabilities] is the in-progress selection
 * (the Save button is enabled only when [capabilitiesDirty]). [allowCidrs]/[denyCidrs] are the live IP rules (each
 * add/edit/remove POSTs the full replacement list, so they always reflect the server). [savingCapabilities] /
 * [savingIpRules] gate their respective sections during a round-trip.
 */
data class ApiKeyDetailUiState(
    val keyId: String,
    val label: String = "",
    val prefix: String = "",
    val loading: Boolean = false,
    val loadError: String? = null,
    val capabilities: List<String> = emptyList(),
    val editedCapabilities: Set<String> = emptySet(),
    val savingCapabilities: Boolean = false,
    val capabilityError: String? = null,
    val allowCidrs: List<String> = emptyList(),
    val denyCidrs: List<String> = emptyList(),
    val savingIpRules: Boolean = false,
    val ipRuleError: String? = null,
) {
    /** True when the edited capability selection differs from the saved set. */
    val capabilitiesDirty: Boolean get() = editedCapabilities != capabilities.toSet()
}

/**
 * B-APIKEY (batch 7) - one-shot effects shared by the API-keys ViewModels.
 *
 * [NavigateToLogin] is emitted on a TERMINAL 401 (re-auth handoff). [CreateSucceeded] is emitted after a
 * successful create so the create screen pops back to the (refreshing) list, carrying the one-time secret for
 * one-time in-session display. Delivered via a Channel (one-shot, never re-delivered on rotation).
 */
sealed interface ApiKeysEffect {
    data object NavigateToLogin : ApiKeysEffect
    data class CreateSucceeded(val secret: String) : ApiKeysEffect
}
