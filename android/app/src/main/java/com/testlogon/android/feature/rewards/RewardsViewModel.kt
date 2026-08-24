package com.testlogon.android.feature.rewards

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.rewards.CatalogReward
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
 * Drives [RewardsUiState] from [RewardsRepository] against the GET me/rewards + me/rewards/history +
 * me/rewards/catalog reads and the POST me/rewards/redeem mutation.
 *
 * Reads degrade-on-404 to an honest coming-soon state; a transport failure is a retryable offline error.
 * [confirmRedeem] is invoked only AFTER the UI money-safety confirm is accepted; crediting is entirely
 * server-side, so a rejection surfaces as a clear error and NEVER a silent success, and balances are
 * re-read from the server after every redemption (the client never fabricates the new balance).
 */
@HiltViewModel
class RewardsViewModel @Inject constructor(
    private val repository: RewardsRepository,
) : ViewModel() {

    private val _uiState = MutableStateFlow(RewardsUiState())
    val uiState: StateFlow<RewardsUiState> = _uiState.asStateFlow()

    private val _effects = Channel<RewardsEffect>(Channel.BUFFERED)
    val effects: Flow<RewardsEffect> = _effects.receiveAsFlow()

    init {
        load()
    }

    fun onRetry() = load()

    fun consumeMessages() = _uiState.update { it.copy(errorMessage = null, successMessage = null) }

    fun load() {
        _uiState.update { it.copy(loading = true, errorMessage = null, offline = false) }
        viewModelScope.launch {
            when (val r = repository.rewards()) {
                is ApiResult.Success -> _uiState.update {
                    it.copy(loading = false, available = r.data.available, rewards = r.data)
                }
                is ApiResult.Failure -> _uiState.update {
                    it.copy(loading = false, errorMessage = r.error.message.ifBlank { "Couldn't load your rewards." })
                }
                is ApiResult.NetworkError -> _uiState.update {
                    it.copy(loading = false, offline = true, errorMessage = "No connection. Pull to retry.")
                }
            }
            when (val c = repository.rewardsCatalog()) {
                is ApiResult.Success -> _uiState.update { it.copy(catalog = c.data) }
                else -> Unit
            }
            when (val h = repository.rewardsHistory()) {
                is ApiResult.Success -> _uiState.update { it.copy(history = h.data) }
                else -> Unit
            }
        }
    }

    /** Called AFTER the redeem confirm is accepted. A rejection is a clear error, never a silent success. */
    fun confirmRedeem(reward: CatalogReward) {
        val s = _uiState.value
        if (s.redeeming) return
        if (!RewardsMath.canRedeem(reward, s.points)) {
            _uiState.update {
                it.copy(errorMessage = "You need ${RewardsMath.formatPoints(RewardsMath.pointsNeeded(reward, s.points))} more to redeem this.")
            }
            return
        }
        _uiState.update { it.copy(redeeming = true, errorMessage = null, successMessage = null) }
        viewModelScope.launch {
            when (val r = repository.redeem(reward.id)) {
                is ApiResult.Success -> {
                    if (r.data.ok) {
                        val note = if (RewardsMath.isCashReward(reward)) {
                            "Redeemed ${reward.name}. ${RewardsMath.formatCentsUsd(reward.valueCents)} was credited to your USD wallet."
                        } else {
                            "Redeemed ${reward.name}."
                        }
                        _uiState.update { it.copy(redeeming = false, successMessage = note) }
                        // Re-read balances/history from the server (never fabricate the new balance).
                        load()
                    } else {
                        _uiState.update {
                            it.copy(redeeming = false, errorMessage = r.data.reason?.ifBlank { null } ?: "Redemption was declined. No points were spent.")
                        }
                    }
                }
                is ApiResult.Failure -> _uiState.update {
                    it.copy(redeeming = false, errorMessage = r.error.message.ifBlank { "Redeeming isn't available right now. No points were spent." })
                }
                is ApiResult.NetworkError -> _uiState.update {
                    it.copy(redeeming = false, errorMessage = "No connection. No points were spent.")
                }
            }
        }
    }
}
