package com.testlogon.android.feature.settings.msgprivacy

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.ApiResult
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import javax.inject.Inject

/**
 * TIP-B4 (TIP-404) — drives [MessagePrivacyUiState] for the pay-to-message settings.
 *
 * Loads the caller's gate, validates the min-tip via [MessagePrivacyMath] (must be > $0 when the
 * gate is on, <= $1000), and on Save PUTs require_tip_to_message + min_tip_cents. The allowlist
 * add/remove go through the dedicated endpoints and refresh the list from the server's echo. All
 * pure validation/formatting lives in [MessagePrivacyMath].
 */
@HiltViewModel
class MessagePrivacyViewModel @Inject constructor(
    private val repo: MessagePrivacyRepository,
) : ViewModel() {

    private val _uiState = MutableStateFlow<MessagePrivacyUiState>(MessagePrivacyUiState.Loading)
    val uiState: StateFlow<MessagePrivacyUiState> = _uiState.asStateFlow()

    init {
        load()
    }

    fun load() {
        _uiState.value = MessagePrivacyUiState.Loading
        viewModelScope.launch {
            when (val result = repo.get()) {
                is ApiResult.Success -> _uiState.value = result.data.toContent()
                is ApiResult.Failure -> _uiState.value = MessagePrivacyUiState.Error(result.error.message)
                is ApiResult.NetworkError -> _uiState.value = MessagePrivacyUiState.Error(NETWORK_MESSAGE)
            }
        }
    }

    fun onRequireChanged(v: Boolean) = edit { it.copy(requireTip = v, formError = null, savedMessage = null) }
    fun onMinTipChanged(v: String) = edit { it.copy(minTipDollars = v, formError = null, savedMessage = null) }
    fun onAllowlistInputChanged(v: String) = edit { it.copy(allowlistInput = v, formError = null, savedMessage = null) }

    private fun edit(transform: (MessagePrivacyUiState.Content) -> MessagePrivacyUiState.Content) {
        val current = _uiState.value as? MessagePrivacyUiState.Content ?: return
        _uiState.value = transform(current)
    }

    fun save() {
        val current = _uiState.value as? MessagePrivacyUiState.Content ?: return
        if (current.saving || current.mutatingAllowlist != null) return

        val minCents = when (
            val v = MessagePrivacyMath.validateMinTip(current.requireTip, current.minTipDollars)
        ) {
            is MessagePrivacyMath.MinTipResult.Invalid -> return fail(current, v.message)
            is MessagePrivacyMath.MinTipResult.Valid -> v.cents
        }

        _uiState.value = current.copy(saving = true, formError = null, savedMessage = null)
        viewModelScope.launch {
            when (val result = repo.update(requireTipToMessage = current.requireTip, minTipCents = minCents)) {
                is ApiResult.Success -> _uiState.value = result.data.toContent(
                    allowlistInput = current.allowlistInput,
                    savedMessage = "Message settings saved.",
                )
                is ApiResult.Failure -> fail(current.copy(saving = false), result.error.message)
                is ApiResult.NetworkError -> fail(current.copy(saving = false), NETWORK_MESSAGE)
            }
        }
    }

    fun addAllowlist() {
        val current = _uiState.value as? MessagePrivacyUiState.Content ?: return
        val userId = MessagePrivacyMath.normalizeAllowlistInput(current.allowlistInput)
            ?: return fail(current, "Enter a user id to allow.")
        if (MessagePrivacyMath.isDuplicateAllowlistEntry(current.allowlist, userId)) {
            return fail(current, "That user is already on the allowlist.")
        }
        if (current.saving || current.mutatingAllowlist != null) return
        _uiState.value = current.copy(mutatingAllowlist = userId, formError = null, savedMessage = null)
        viewModelScope.launch {
            when (val result = repo.addAllowlist(userId)) {
                is ApiResult.Success -> _uiState.value = result.data.toContent(
                    allowlistInput = "",
                    savedMessage = "Added to the tip-free allowlist.",
                )
                is ApiResult.Failure -> fail(current.copy(mutatingAllowlist = null), result.error.message)
                is ApiResult.NetworkError -> fail(current.copy(mutatingAllowlist = null), NETWORK_MESSAGE)
            }
        }
    }

    fun removeAllowlist(userId: String) {
        val current = _uiState.value as? MessagePrivacyUiState.Content ?: return
        if (current.saving || current.mutatingAllowlist != null) return
        _uiState.value = current.copy(mutatingAllowlist = userId, formError = null, savedMessage = null)
        viewModelScope.launch {
            when (val result = repo.removeAllowlist(userId)) {
                is ApiResult.Success -> _uiState.value = result.data.toContent(
                    allowlistInput = current.allowlistInput,
                    savedMessage = "Removed from the tip-free allowlist.",
                )
                is ApiResult.Failure -> fail(current.copy(mutatingAllowlist = null), result.error.message)
                is ApiResult.NetworkError -> fail(current.copy(mutatingAllowlist = null), NETWORK_MESSAGE)
            }
        }
    }

    private fun fail(base: MessagePrivacyUiState.Content, message: String) {
        _uiState.value = base.copy(saving = false, mutatingAllowlist = null, formError = message)
    }

    private fun MessagePrivacy.toContent(
        allowlistInput: String = "",
        savedMessage: String? = null,
    ) = MessagePrivacyUiState.Content(
        requireTip = requireTipToMessage,
        minTipDollars = MessagePrivacyMath.centsToDollarsField(minTipCents),
        allowlist = tipFreeAllowlist,
        allowlistInput = allowlistInput,
        savedMessage = savedMessage,
    )

    private companion object {
        const val NETWORK_MESSAGE = "Couldn't reach the server. Check your connection and try again."
    }
}
