package com.testlogon.android.feature.admessaging.ui

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.ApiError
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.network.admessaging.AdMessageOfferReq
import com.testlogon.android.feature.admessaging.data.AdMessageOffer
import com.testlogon.android.feature.admessaging.data.AdMessagingRepository
import com.testlogon.android.feature.ads.create.data.AdsStudioSelection
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import javax.inject.Inject

/**
 * ADV2-501/507 (F5) — presentation logic for the advertiser "propose a sponsored MESSAGE to a creator"
 * composer.
 *
 * The advertiser picks a target creator + drafts the body (+ optional CTA link/label), and supplies the
 * billing linkage (ad account + campaign) that funds the per-recipient hybrid charges once the creator
 * approves. Account/campaign are PREFILLED from the [AdsStudioSelection] but stay editable. On submit ->
 * POST ui/ads/sponsored-messages/offers; the offer sits pending_creator until the creator approves
 * (NOTHING sends here — D3). NON-idempotent: a second [submit] while in flight is IGNORED.
 */
@HiltViewModel
class AdMessageComposeViewModel @Inject constructor(
    private val repository: AdMessagingRepository,
    selection: AdsStudioSelection,
) : ViewModel() {

    sealed interface SubmitState {
        data object Idle : SubmitState
        data object Submitting : SubmitState
        data class Success(val offer: AdMessageOffer) : SubmitState
        data class Error(val message: String) : SubmitState
    }

    private val _creatorSub = MutableStateFlow("")
    val creatorSub: StateFlow<String> = _creatorSub.asStateFlow()

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

    private val _submitState = MutableStateFlow<SubmitState>(SubmitState.Idle)
    val submitState: StateFlow<SubmitState> = _submitState.asStateFlow()

    fun onCreatorSub(text: String) { _creatorSub.value = text; clearError() }
    fun onBody(text: String) { _body.value = text; clearError() }
    fun onCtaUrl(text: String) { _ctaUrl.value = text; clearError() }
    fun onAccountId(text: String) { _accountId.value = text; clearError() }
    fun onCampaignId(text: String) { _campaignId.value = text; clearError() }
    fun onSponsorLabel(text: String) { _sponsorLabel.value = text; clearError() }

    /** Requires a target creator + body text; the billing linkage (account+campaign) is required so the
     *  approved send can actually charge per recipient (delivered/open/click). */
    val canSubmit: Boolean
        get() = _creatorSub.value.isNotBlank() &&
            _body.value.isNotBlank() &&
            _accountId.value.isNotBlank() &&
            _campaignId.value.isNotBlank()

    fun submit() {
        if (_submitState.value is SubmitState.Submitting) return
        if (!canSubmit) return
        _submitState.value = SubmitState.Submitting
        val req = AdMessageOfferReq(
            creatorSub = _creatorSub.value.trim(),
            body = _body.value.trim(),
            ctaUrl = _ctaUrl.value.trim(),
            accountId = _accountId.value.trim(),
            campaignId = _campaignId.value.trim(),
            sponsorLabel = _sponsorLabel.value.trim(),
        )
        viewModelScope.launch {
            _submitState.value = when (val result = repository.createOffer(req)) {
                is ApiResult.Success -> SubmitState.Success(result.data)
                is ApiResult.Failure -> SubmitState.Error(friendly(result.error))
                is ApiResult.NetworkError -> SubmitState.Error(OFFLINE)
            }
        }
    }

    private fun clearError() {
        if (_submitState.value is SubmitState.Error) _submitState.value = SubmitState.Idle
    }

    private fun friendly(error: ApiError): String = when (error.status) {
        403 -> error.message.ifBlank { "This creator does not accept advertiser proposals." }
        422 -> error.message.ifBlank { "Please check the details and try again." }
        else -> error.message
    }

    private companion object {
        const val OFFLINE = "Couldn't reach the server. Try again."
    }
}
