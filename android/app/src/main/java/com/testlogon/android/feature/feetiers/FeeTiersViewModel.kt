package com.testlogon.android.feature.feetiers

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.exchange.FeeTierAuthoritative
import com.testlogon.android.data.exchange.FillsFees
import com.testlogon.android.data.exchange.TradingRepository
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.async
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import javax.inject.Inject

/**
 * ViewModel for the maker/taker FEE TIER (VIP schedule) screen. Assembles the account's 30-day
 * trading volume CLIENT-SIDE from the same live fills feed the Tax report uses (GET me/fills/fees;
 * degrades to empty on 404) and runs the pure [FeeTierMath] engine to derive the current tier, rates,
 * and progress to the next tier. An OPTIONAL authoritative backend read (GET me/fees/tier) is
 * PREFERRED when present; on 404 the screen falls back to the client estimate ("estimated from your
 * trade history"). No money movement.
 */
@HiltViewModel
class FeeTiersViewModel @Inject constructor(
    private val trading: TradingRepository,
) : ViewModel() {

    private val _uiState = MutableStateFlow(FeeTiersUiState())
    val uiState: StateFlow<FeeTiersUiState> = _uiState.asStateFlow()

    init {
        refresh()
    }

    fun refresh() {
        _uiState.value = FeeTiersUiState(loading = true)
        viewModelScope.launch {
            _uiState.value = coroutineScope {
                val fillsDef = async { trading.fillsFees() }
                val tierDef = async { trading.feeTier() }
                project(fillsDef.await(), tierDef.await(), System.currentTimeMillis())
            }
        }
    }

    internal fun project(
        fillsResult: ApiResult<FillsFees>,
        tierResult: ApiResult<FeeTierAuthoritative?>,
        nowMs: Long,
    ): FeeTiersUiState {
        // Prefer the authoritative read when the backend actually served a tier.
        val authoritative = (tierResult as? ApiResult.Success)?.data
        if (authoritative != null && authoritative.tierId.isNotBlank()) {
            return fromAuthoritative(authoritative)
        }

        // Client estimate from the fills feed.
        val fills = when (fillsResult) {
            is ApiResult.Success -> fillsResult.data.fills
            is ApiResult.NetworkError -> return FeeTiersUiState(loading = false, error = "Network error. Pull to retry.")
            is ApiResult.Failure -> return FeeTiersUiState(loading = false, error = "Couldn't load trade history.")
        }

        if (fills.isEmpty()) {
            // Honest empty state: no fills AND no authoritative read -> show the schedule at Standard.
            return baseState(
                estimated = true,
                empty = true,
                volumeCents = 0L,
                tier = FeeTierMath.FEE_TIERS.first(),
            )
        }

        val volume = FeeTierMath.volume30dCents(FeeTierMath.fromFills(fills), nowMs)
        val tier = FeeTierMath.tierForVolume(volume)
        return baseState(estimated = true, empty = false, volumeCents = volume, tier = tier)
    }

    private fun fromAuthoritative(a: FeeTierAuthoritative): FeeTiersUiState {
        // Resolve the authoritative tier against the canonical table for the highlight + full schedule;
        // fall back to the wire fields when the id is unknown.
        val canonical = FeeTierMath.tierById(a.tierId)
        val effectiveTierId = canonical?.id ?: a.tierId
        val makerBps = a.makerBps.takeIf { it > 0 } ?: canonical?.makerBps ?: 0
        val takerBps = a.takerBps.takeIf { it > 0 } ?: canonical?.takerBps ?: 0
        val next = canonical?.let { FeeTierMath.nextTier(it) }
        val nextName = next?.name ?: a.nextTierId?.let { FeeTierMath.tierById(it)?.name }
        val nextMin = next?.minVolumeCents ?: a.nextTierMinVolumeCents
        val toNext = if (nextMin != null) (nextMin - a.volume30dCents).coerceAtLeast(0L) else 0L
        val progress = if (canonical != null) {
            FeeTierMath.progressToNextFraction(a.volume30dCents)
        } else if (nextMin != null && nextMin > 0L) {
            (a.volume30dCents.toDouble() / nextMin.toDouble()).coerceIn(0.0, 1.0)
        } else 1.0

        return FeeTiersUiState(
            loading = false,
            estimated = false,
            empty = false,
            volume30dCents = a.volume30dCents,
            currentTierId = effectiveTierId,
            currentTierName = a.name.ifBlank { canonical?.name ?: effectiveTierId },
            makerBps = makerBps,
            takerBps = takerBps,
            nextTierName = nextName,
            nextTierMinVolumeCents = nextMin,
            volumeToNextCents = toNext,
            progressToNext = progress.toFloat(),
            isTopTier = nextName == null,
            tiers = tableRows(effectiveTierId),
        )
    }

    private fun baseState(
        estimated: Boolean,
        empty: Boolean,
        volumeCents: Long,
        tier: FeeTierMath.FeeTier,
    ): FeeTiersUiState {
        val next = FeeTierMath.nextTier(tier)
        return FeeTiersUiState(
            loading = false,
            estimated = estimated,
            empty = empty,
            volume30dCents = volumeCents,
            currentTierId = tier.id,
            currentTierName = tier.name,
            makerBps = tier.makerBps,
            takerBps = tier.takerBps,
            nextTierName = next?.name,
            nextTierMinVolumeCents = next?.minVolumeCents,
            volumeToNextCents = FeeTierMath.volumeToNextTierCents(volumeCents),
            progressToNext = FeeTierMath.progressToNextFraction(volumeCents).toFloat(),
            isTopTier = next == null,
            tiers = tableRows(tier.id),
        )
    }

    private fun tableRows(currentId: String): List<FeeTierRow> =
        FeeTierMath.FEE_TIERS.map {
            FeeTierRow(
                id = it.id,
                name = it.name,
                minVolumeCents = it.minVolumeCents,
                makerBps = it.makerBps,
                takerBps = it.takerBps,
                isCurrent = it.id == currentId,
            )
        }
}
