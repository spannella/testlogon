package com.testlogon.android.feature.rewards

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.rewards.RewardsRepository
import com.testlogon.android.data.rewards.RewardsStatus
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import javax.inject.Inject

/**
 * UI state for the REWARDS STATUS / loyalty TIER LEVELS screen (feature/rewards). Drives the current
 * tier badge + lifetime points + multiplier, the progress bar to the next tier, and the full status
 * ladder with the current rung highlighted + achieved rungs checked. The membership ladder is driven by
 * LIFETIME reward points -- DISTINCT from the maker/taker FEE tiers.
 *
 * [resolved] is null until the first load completes. The screen prefers the AUTHORITATIVE status (live
 * badge) when GET me/rewards/status is deployed, else the CLIENT computation from lifetime points (est
 * badge). [available] is false only when BOTH the status read AND the rewards read degraded (so there
 * is genuinely no lifetime-points signal) -> the screen shows an honest coming-soon empty state.
 */
data class StatusTierUiState(
    val loading: Boolean = true,
    val available: Boolean = true,
    val resolved: StatusTierMath.ResolvedStatus? = null,
    val errorMessage: String? = null,
    val offline: Boolean = false,
) {
    /** The full canonical ladder, always shown (the reference table). */
    val ladder: List<StatusTierMath.StatusTier> get() = StatusTierMath.STATUS_TIERS

    /** True once a resolved status view exists to render. */
    val hasStatus: Boolean get() = resolved != null
}

/**
 * Drives [StatusTierUiState] from [RewardsRepository]. Loads the OPTIONAL authoritative status
 * (GET me/rewards/status) and the rewards balance (GET me/rewards, for lifetime points). The tier is
 * resolved purely by [StatusTierMath]: authoritative when present + sane, else computed client-side
 * from lifetime points against the canonical table. Reads degrade-on-404 to an honest empty state; a
 * transport failure is a retryable offline error. READ-ONLY -- this screen never moves points/cash.
 */
@HiltViewModel
class StatusTierViewModel @Inject constructor(
    private val repository: RewardsRepository,
) : ViewModel() {

    private val _uiState = MutableStateFlow(StatusTierUiState())
    val uiState: StateFlow<StatusTierUiState> = _uiState.asStateFlow()

    init {
        load()
    }

    fun onRetry() = load()

    fun consumeMessages() = _uiState.update { it.copy(errorMessage = null) }

    fun load() {
        _uiState.update { it.copy(loading = true, errorMessage = null, offline = false) }
        viewModelScope.launch {
            // Rewards balance -> lifetime points (drives available + the client-computed tier).
            val rewards = when (val r = repository.rewards()) {
                is ApiResult.Success -> r.data
                is ApiResult.NetworkError -> {
                    _uiState.update {
                        it.copy(loading = false, offline = true, errorMessage = "No connection. Pull to retry.")
                    }
                    return@launch
                }
                is ApiResult.Failure -> {
                    _uiState.update {
                        it.copy(loading = false, errorMessage = r.error.message.ifBlank { "Couldn't load your status." })
                    }
                    return@launch
                }
            }

            // Optional authoritative status; degrade-on-404 -> unavailable -> client compute takes over.
            val authoritative: RewardsStatus? =
                (repository.rewardsStatus() as? ApiResult.Success)?.data?.takeIf { it.available }

            val resolved = StatusTierMath.resolveStatus(rewards.lifetimePoints, authoritative)

            // Honest empty state only when there is truly no signal: rewards unavailable AND no authoritative status.
            val available = rewards.available || (authoritative != null)

            _uiState.update {
                it.copy(
                    loading = false,
                    available = available,
                    resolved = if (available) resolved else null,
                )
            }
        }
    }
}
