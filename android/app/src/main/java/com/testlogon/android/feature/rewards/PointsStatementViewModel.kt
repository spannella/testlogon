package com.testlogon.android.feature.rewards

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.rewards.PointsExpiry
import com.testlogon.android.data.rewards.Rewards
import com.testlogon.android.data.rewards.RewardsHistoryEntry
import com.testlogon.android.data.rewards.RewardsRepository
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import javax.inject.Inject

/**
 * Drives [PointsStatementUiState] from [RewardsRepository]. Loads the points balance (GET me/rewards),
 * the activity history (GET me/rewards/history) and the OPTIONAL authoritative expiry (GET
 * me/rewards/expiry). The running-balance statement + the FIFO client-expiry are computed purely by
 * [PointsExpiryMath]; the authoritative expiry (when deployed + non-empty) overrides the client estimate.
 *
 * Reads degrade-on-404 to an honest empty state; a transport failure is a retryable offline error. This
 * screen is READ-ONLY — it never moves points/cash (redemption lives on the Rewards screen).
 */
@HiltViewModel
class PointsStatementViewModel @Inject constructor(
    private val repository: RewardsRepository,
) : ViewModel() {

    private fun now(): Long = System.currentTimeMillis()

    private val _uiState = MutableStateFlow(PointsStatementUiState())
    val uiState: StateFlow<PointsStatementUiState> = _uiState.asStateFlow()

    init {
        load()
    }

    fun onRetry() = load()

    fun consumeMessages() = _uiState.update { it.copy(errorMessage = null) }

    /** Change the statement period filter; re-projects rows + CSV purely (no network round-trip). */
    fun onPeriodChanged(period: PointsExpiryMath.StatementPeriod) {
        _uiState.update { s -> s.copy(period = period).withProjectedRows() }
    }

    fun load() {
        _uiState.update { it.copy(loading = true, errorMessage = null, offline = false) }
        viewModelScope.launch {
            val now = now()
            // Balance (drives available + points).
            val rewards: Rewards = when (val r = repository.rewards()) {
                is ApiResult.Success -> r.data
                is ApiResult.NetworkError -> {
                    _uiState.update { it.copy(loading = false, offline = true, errorMessage = "No connection. Pull to retry.") }
                    return@launch
                }
                is ApiResult.Failure -> {
                    _uiState.update { it.copy(loading = false, errorMessage = r.error.message.ifBlank { "Couldn't load your points." }) }
                    return@launch
                }
            }

            val history: List<RewardsHistoryEntry> = (repository.rewardsHistory() as? ApiResult.Success)?.data ?: emptyList()
            val authoritative: PointsExpiry? = (repository.rewardsExpiry() as? ApiResult.Success)?.data

            val client = PointsExpiryMath.computeExpiryFromHistory(history, now)
            val resolved = PointsExpiryMath.resolve(authoritative, client)
            val allRows = PointsExpiryMath.statementRows(history)

            _uiState.update {
                it.copy(
                    loading = false,
                    available = rewards.available,
                    points = rewards.points,
                    lifetimePoints = rewards.lifetimePoints,
                    history = history,
                    allRows = allRows,
                    expiryPolicyMonths = resolved.policyMonths.takeIf { m -> m > 0 } ?: PointsExpiryMath.EXPIRY_MONTHS,
                    expiringSoonPoints = resolved.expiringSoonPoints,
                    nextExpiryTs = resolved.nextExpiryTs,
                    nextExpiryPoints = resolved.nextExpiryPoints,
                    upcoming = resolved.lots,
                    expiryEstimated = resolved.estimated,
                ).withProjectedRows()
            }
        }
    }

    /** Re-derive the shown rows + CSV from [allRows] + the current period. Pure; no network. */
    private fun PointsStatementUiState.withProjectedRows(): PointsStatementUiState {
        val filtered = PointsExpiryMath.filterByPeriod(allRows, period, now())
        val suffix = when (period) {
            PointsExpiryMath.StatementPeriod.ALL -> "all"
            PointsExpiryMath.StatementPeriod.THIS_YEAR -> "this-year"
            PointsExpiryMath.StatementPeriod.THIS_MONTH -> "this-month"
        }
        return copy(
            rows = filtered,
            csv = PointsExpiryMath.expiryToCsv(filtered),
            csvName = "points-statement-$suffix",
        )
    }
}
