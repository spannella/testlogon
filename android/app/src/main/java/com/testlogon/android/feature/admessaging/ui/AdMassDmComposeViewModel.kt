package com.testlogon.android.feature.admessaging.ui

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.ApiError
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.network.admessaging.AdMassDmCreateReq
import com.testlogon.android.feature.admessaging.data.AdDmAudience
import com.testlogon.android.feature.admessaging.data.AdMessageSend
import com.testlogon.android.feature.admessaging.data.AdMessagingRepository
import com.testlogon.android.feature.ads.create.data.AdsStudioSelection
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import javax.inject.Inject

/**
 * ADV2-602/603/607 (F6) — presentation logic for the advertiser DIRECT mass-DM composer.
 *
 * On open it resolves the eligible audience ([AdMessagingRepository.audiencePreview]) so the advertiser
 * sees the REACHABLE count (existing relationships minus per-user ad opt-outs) BEFORE sending — a non-
 * relationship user is never enumerated, an opted-out follower is excluded and reported. On send the
 * message goes AS the advertiser to that audience, billed the hybrid stack PLATFORM-100% (no creator
 * share); the funds-guard stops the send if the balance runs out. Account/campaign PREFILL from the
 * [AdsStudioSelection] but stay editable. NON-idempotent: a second [send] while in flight is IGNORED.
 */
@HiltViewModel
class AdMassDmComposeViewModel @Inject constructor(
    private val repository: AdMessagingRepository,
    selection: AdsStudioSelection,
) : ViewModel() {

    sealed interface AudienceState {
        data object Loading : AudienceState
        data class Loaded(val audience: AdDmAudience) : AudienceState
        data class Error(val message: String) : AudienceState
    }

    sealed interface SendState {
        data object Idle : SendState
        data object Sending : SendState
        data class Success(val send: AdMessageSend) : SendState
        data class Error(val message: String) : SendState
    }

    private val _audience = MutableStateFlow<AudienceState>(AudienceState.Loading)
    val audience: StateFlow<AudienceState> = _audience.asStateFlow()

    private val _body = MutableStateFlow("")
    val body: StateFlow<String> = _body.asStateFlow()

    private val _ctaUrl = MutableStateFlow("")
    val ctaUrl: StateFlow<String> = _ctaUrl.asStateFlow()

    private val _accountId = MutableStateFlow(selection.current.accountId.orEmpty())
    val accountId: StateFlow<String> = _accountId.asStateFlow()

    private val _campaignId = MutableStateFlow(selection.current.campaignId.orEmpty())
    val campaignId: StateFlow<String> = _campaignId.asStateFlow()

    private val _sponsorLabel = MutableStateFlow("")
    val sponsorLabel: StateFlow<String> = _sponsorLabel.asStateFlow()

    private val _sendState = MutableStateFlow<SendState>(SendState.Idle)
    val sendState: StateFlow<SendState> = _sendState.asStateFlow()

    init { loadAudience() }

    fun loadAudience() {
        _audience.value = AudienceState.Loading
        viewModelScope.launch {
            _audience.value = when (val result = repository.audiencePreview()) {
                is ApiResult.Success -> AudienceState.Loaded(result.data)
                is ApiResult.Failure -> AudienceState.Error(result.error.message)
                is ApiResult.NetworkError -> AudienceState.Error(OFFLINE)
            }
        }
    }

    fun onBody(text: String) { _body.value = text; clearError() }
    fun onCtaUrl(text: String) { _ctaUrl.value = text; clearError() }
    fun onAccountId(text: String) { _accountId.value = text; clearError() }
    fun onCampaignId(text: String) { _campaignId.value = text; clearError() }
    fun onSponsorLabel(text: String) { _sponsorLabel.value = text; clearError() }

    val canSend: Boolean
        get() = _body.value.isNotBlank() &&
            _accountId.value.isNotBlank() &&
            _campaignId.value.isNotBlank()

    fun send() {
        if (_sendState.value is SendState.Sending) return
        if (!canSend) return
        _sendState.value = SendState.Sending
        val req = AdMassDmCreateReq(
            accountId = _accountId.value.trim(),
            campaignId = _campaignId.value.trim(),
            body = _body.value.trim(),
            ctaUrl = _ctaUrl.value.trim(),
            sponsorLabel = _sponsorLabel.value.trim(),
        )
        viewModelScope.launch {
            _sendState.value = when (val result = repository.sendMassDm(req)) {
                is ApiResult.Success -> SendState.Success(result.data)
                is ApiResult.Failure -> SendState.Error(friendly(result.error))
                is ApiResult.NetworkError -> SendState.Error(OFFLINE)
            }
        }
    }

    private fun clearError() {
        if (_sendState.value is SendState.Error) _sendState.value = SendState.Idle
    }

    private fun friendly(error: ApiError): String = when (error.status) {
        403 -> error.message.ifBlank { "You don't own this ad account." }
        400, 422 -> error.message.ifBlank { "Please check the details and try again." }
        else -> error.message
    }

    private companion object {
        const val OFFLINE = "Couldn't reach the server. Try again."
    }
}
