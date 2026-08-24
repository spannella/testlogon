package com.testlogon.android.feature.rewards

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.rewards.RewardsRepository
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.receiveAsFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import javax.inject.Inject

/**
 * Drives [ReferralHubUiState] from [RewardsRepository] against the GET me/referral + me/referral/list
 * contract. Loads the summary + list on first composition and on retry; a 404 degrades to an honest
 * coming-soon state (available=false), a transport failure to a retryable offline error. The share/copy
 * text is built PURELY here (RewardsMath.referralShareText) and the Route performs the Android side
 * effect, so this VM stays free of Android framework types.
 */
@HiltViewModel
class ReferralHubViewModel @Inject constructor(
    private val repository: RewardsRepository,
) : ViewModel() {

    private val _uiState = MutableStateFlow(ReferralHubUiState())
    val uiState: StateFlow<ReferralHubUiState> = _uiState.asStateFlow()

    private val _effects = Channel<RewardsEffect>(Channel.BUFFERED)
    val effects: Flow<RewardsEffect> = _effects.receiveAsFlow()

    init {
        load()
    }

    fun onRetry() = load()

    fun load() {
        _uiState.update { it.copy(loading = true, errorMessage = null, offline = false) }
        viewModelScope.launch {
            when (val r = repository.referral()) {
                is ApiResult.Success -> _uiState.update {
                    it.copy(loading = false, available = r.data.available, summary = r.data)
                }
                is ApiResult.Failure -> _uiState.update {
                    it.copy(loading = false, errorMessage = r.error.message.ifBlank { "Couldn't load your referrals." })
                }
                is ApiResult.NetworkError -> _uiState.update {
                    it.copy(loading = false, offline = true, errorMessage = "No connection. Pull to retry.")
                }
            }
            // The referral list is optional context; a failure just leaves it empty (never an error).
            when (val list = repository.referralList()) {
                is ApiResult.Success -> _uiState.update { it.copy(referrals = list.data) }
                else -> Unit
            }
        }
    }

    /** Shares the referral link/code via the system share sheet. */
    fun onShare() {
        val s = _uiState.value.summary
        if (!_uiState.value.hasShareable) return
        val text = RewardsMath.referralShareText(s.code, s.link, s.rewardPerReferralCents)
        viewModelScope.launch { _effects.send(RewardsEffect.ShareText(text)) }
    }

    /** Copies the referral link (or code) to the clipboard. */
    fun onCopy() {
        val s = _uiState.value.summary
        if (!_uiState.value.hasShareable) return
        val toCopy = s.link.ifBlank { s.code }
        viewModelScope.launch {
            _effects.send(RewardsEffect.CopyText(toCopy))
            _effects.send(RewardsEffect.Toast("Referral link copied"))
        }
    }
}
