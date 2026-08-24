package com.testlogon.android.feature.rewards

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.rewards.LeaderboardPeriod
import com.testlogon.android.data.rewards.RewardsRepository
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import javax.inject.Inject

/**
 * Drives [ReferralLeaderboardUiState] from [RewardsRepository] against GET me/referral/leaderboard.
 * Loads the selected [LeaderboardPeriod] on first composition, on retry and on a period-toggle; a 404
 * degrades to an honest coming-soon state (available=false), a transport failure to a retryable offline
 * error. The shown top-N slice + the pinned "your rank" row are computed PURELY via
 * [ReferralLeaderboardMath], so this VM stays free of Android framework types.
 */
@HiltViewModel
class ReferralLeaderboardViewModel @Inject constructor(
    private val repository: RewardsRepository,
) : ViewModel() {

    private val _uiState = MutableStateFlow(ReferralLeaderboardUiState())
    val uiState: StateFlow<ReferralLeaderboardUiState> = _uiState.asStateFlow()

    init {
        load(_uiState.value.period)
    }

    fun onRetry() = load(_uiState.value.period)

    /** Switch the time window (no-op if already selected); reloads for the new period. */
    fun onPeriodSelected(period: LeaderboardPeriod) {
        if (period == _uiState.value.period && !_uiState.value.loading) load(period) else load(period)
    }

    fun load(period: LeaderboardPeriod) {
        _uiState.update {
            it.copy(loading = true, period = period, errorMessage = null, offline = false)
        }
        viewModelScope.launch {
            when (val r = repository.referralLeaderboard(period)) {
                is ApiResult.Success -> {
                    val board = r.data
                    val shown = ReferralLeaderboardMath.topN(board.entries)
                    val youRow = ReferralLeaderboardMath.resolveYouRow(shown, board.you)
                    _uiState.update {
                        it.copy(
                            loading = false,
                            available = board.available,
                            board = board,
                            shown = shown,
                            youRow = youRow,
                        )
                    }
                }
                is ApiResult.Failure -> _uiState.update {
                    it.copy(
                        loading = false,
                        errorMessage = r.error.message.ifBlank { "Couldn't load the leaderboard." },
                    )
                }
                is ApiResult.NetworkError -> _uiState.update {
                    it.copy(loading = false, offline = true, errorMessage = "No connection. Pull to retry.")
                }
            }
        }
    }
}
