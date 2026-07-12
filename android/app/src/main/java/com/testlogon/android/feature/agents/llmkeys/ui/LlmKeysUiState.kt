package com.testlogon.android.feature.agents.llmkeys.ui

import com.testlogon.android.feature.agents.llmkeys.data.LlmKey
import com.testlogon.android.feature.agents.llmkeys.data.LlmProvider

/** AGENTS-BASICS (web-parity) - UI state for the LLM provider KEYS surfaces (list + add). */

sealed interface LlmKeysListUiState {
    data object Loading : LlmKeysListUiState
    data class Content(
        val items: List<LlmKey>,
        val isRefreshing: Boolean = false,
        val busyId: String? = null,
        val actionError: String? = null,
        val testResult: String? = null,
    ) : LlmKeysListUiState
    data object Empty : LlmKeysListUiState
    data class Error(val message: String) : LlmKeysListUiState
}

/** The add-key form. [canSubmit] is derived (provider + non-blank label + api_key >= 8 chars). */
data class AddLlmKeyForm(
    val provider: String = "",
    val label: String = "",
    val apiKey: String = "",
    val baseUrl: String = "",
    val modelPreference: String = "",
    val providers: List<LlmProvider> = emptyList(),
    val loadingProviders: Boolean = true,
    val submitting: Boolean = false,
    val submitError: String? = null,
) {
    val canSubmit: Boolean
        get() = provider.isNotBlank() && label.isNotBlank() && apiKey.length >= 8 && !submitting
}

sealed interface LlmKeysEffect {
    data object NavigateToLogin : LlmKeysEffect
    data object AddSucceeded : LlmKeysEffect
}
