package com.testlogon.android.feature.sponsoredpost.ui

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.ApiError
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.network.sponsoredpost.SponsoredPostProposalReq
import com.testlogon.android.feature.ads.create.data.AdsStudioSelection
import com.testlogon.android.feature.sponsoredpost.data.SponsoredPostProposal
import com.testlogon.android.feature.sponsoredpost.data.SponsoredPostRepository
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import javax.inject.Inject

/**
 * ADV2-407 (F4) — presentation logic for the advertiser "propose a sponsored post to a creator" composer.
 *
 * The advertiser picks a target creator + drafts the body, and supplies the billing linkage (ad account +
 * campaign) that funds the engagement charges once the creator approves. Account/campaign are PREFILLED from
 * the [AdsStudioSelection] (the in-process selection set by the ads create/picker flow) but stay editable.
 * On submit -> POST ui/ads/sponsored-posts/proposals; the proposal sits as draft_proposed until the creator
 * approves (NOTHING publishes here). NON-idempotent: a second [submit] while in flight is IGNORED.
 */
@HiltViewModel
class SponsoredPostComposeViewModel @Inject constructor(
    private val repository: SponsoredPostRepository,
    selection: AdsStudioSelection,
) : ViewModel() {

    sealed interface SubmitState {
        data object Idle : SubmitState
        data object Submitting : SubmitState
        data class Success(val proposal: SponsoredPostProposal) : SubmitState
        data class Error(val message: String) : SubmitState
    }

    private val _creatorSub = MutableStateFlow("")
    val creatorSub: StateFlow<String> = _creatorSub.asStateFlow()

    private val _body = MutableStateFlow("")
    val body: StateFlow<String> = _body.asStateFlow()

    private val _accountId = MutableStateFlow(selection.current.accountId.orEmpty())
    val accountId: StateFlow<String> = _accountId.asStateFlow()

    private val _campaignId = MutableStateFlow(selection.current.campaignId.orEmpty())
    val campaignId: StateFlow<String> = _campaignId.asStateFlow()

    private val _sponsorLabel = MutableStateFlow("")
    val sponsorLabel: StateFlow<String> = _sponsorLabel.asStateFlow()

    private val _disclosure = MutableStateFlow("")
    val disclosure: StateFlow<String> = _disclosure.asStateFlow()

    private val _submitState = MutableStateFlow<SubmitState>(SubmitState.Idle)
    val submitState: StateFlow<SubmitState> = _submitState.asStateFlow()

    fun onCreatorSub(text: String) { _creatorSub.value = text; clearError() }
    fun onBody(text: String) { _body.value = text; clearError() }
    fun onAccountId(text: String) { _accountId.value = text; clearError() }
    fun onCampaignId(text: String) { _campaignId.value = text; clearError() }
    fun onSponsorLabel(text: String) { _sponsorLabel.value = text; clearError() }
    fun onDisclosure(text: String) { _disclosure.value = text; clearError() }

    /** Requires a target creator + body text; the billing linkage (account+campaign) is required so the
     *  approved post can actually charge per engagement (the backend placement mint needs both). */
    val canSubmit: Boolean
        get() = _creatorSub.value.isNotBlank() &&
            _body.value.isNotBlank() &&
            _accountId.value.isNotBlank() &&
            _campaignId.value.isNotBlank()

    fun submit() {
        if (_submitState.value is SubmitState.Submitting) return
        if (!canSubmit) return
        _submitState.value = SubmitState.Submitting
        val req = SponsoredPostProposalReq(
            creatorSub = _creatorSub.value.trim(),
            body = _body.value.trim(),
            accountId = _accountId.value.trim(),
            campaignId = _campaignId.value.trim(),
            sponsorLabel = _sponsorLabel.value.trim(),
            disclosure = _disclosure.value.trim(),
        )
        viewModelScope.launch {
            _submitState.value = when (val result = repository.createProposal(req)) {
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
