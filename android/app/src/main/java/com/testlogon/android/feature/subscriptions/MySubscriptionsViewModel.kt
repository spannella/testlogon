package com.testlogon.android.feature.subscriptions

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.model.getOrNull
import com.testlogon.android.data.fanclub.FanClubRepository
import com.testlogon.android.data.fanclub.FanClubTier
import com.testlogon.android.data.subscriptions.CreatorSubscription
import com.testlogon.android.data.subscriptions.SubscriptionState
import com.testlogon.android.data.subscriptions.SubscriptionsRepository
import com.testlogon.android.feature.subscriptions.entitlement.EntitlementResolver
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.async
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import javax.inject.Inject

/** AND-241 — a single "my subscriptions" row (active or lapsed), screen-ready (price text at render). */
data class MySubscriptionRow(
    val subscriptionId: String,
    val planId: String,
    val creatorId: String,
    val status: SubscriptionState,
    val cancelAtPeriodEnd: Boolean,
    val priceCents: Long?,
    val currency: String?,
    val currentPeriodEndEpochSeconds: Long?,
) {
    val isActive: Boolean
        get() = status == SubscriptionState.ACTIVE || status == SubscriptionState.TRIALING
}

/** AND-241 — a "my fan clubs" row: a tier the viewer is currently a member of (active sub at its plan). */
data class MyFanClubRow(
    val tierId: String,
    val name: String,
    val level: Int,
    val planId: String?,
    val memberCount: Int,
)

/**
 * AND-241 — the consolidated "My subscriptions + my fan clubs" overview state.
 *
 * Holds [Loading], [Content] (with [isRefreshing]/[isStale]), [Empty], [Error] per the §6 state contract.
 * Both lists feed the shared [EntitlementResolver], so fan-club membership is derived from the SAME
 * subscription data the subscriptions section renders (they cannot disagree).
 */
data class MySubscriptionsUiState(
    val isLoading: Boolean = false,
    val isRefreshing: Boolean = false,
    val isStale: Boolean = false,
    val subscriptions: List<MySubscriptionRow> = emptyList(),
    val fanClubs: List<MyFanClubRow> = emptyList(),
    val error: String? = null,
) {
    val isEmpty: Boolean
        get() = !isLoading && error == null && subscriptions.isEmpty() && fanClubs.isEmpty()

    companion object {
        fun initial() = MySubscriptionsUiState(isLoading = true)
    }
}

/**
 * AND-241 — the shared overview ViewModel the spec calls for ("a shared my-subscriptions + my-fan-clubs
 * overview VM if the spec calls for it"). It consolidates FR-2 (my subscriptions) and FR-3 (the viewer's
 * fan-club memberships) into one screen-ready state, reusing the AND-234 [SubscriptionsRepository] and
 * the AND-238/240 [FanClubRepository] plus the AND-241 [EntitlementResolver]. It does NOT duplicate the
 * per-creator tier-browse (SubscriptionTiersViewModel) or manage (ManageSubscriptionViewModel) VMs.
 *
 * Single init load (FR-7); refresh()/retry() re-fetch with stale-while-revalidate (FR-5/§7): a refresh
 * failure keeps the last-good data and sets isStale instead of dropping to Error. The two repository
 * reads run as independent async legs (structured concurrency) so a slow fan-club read does not serialize
 * behind subscriptions; a fan-club failure degrades to an empty fan-club section, not a screen error.
 */
@HiltViewModel
class MySubscriptionsViewModel @Inject constructor(
    private val subscriptionsRepository: SubscriptionsRepository,
    private val fanClubRepository: FanClubRepository,
    private val entitlements: EntitlementResolver,
) : ViewModel() {

    private val _uiState = MutableStateFlow(MySubscriptionsUiState.initial())
    val uiState: StateFlow<MySubscriptionsUiState> = _uiState.asStateFlow()

    init {
        load(isRefresh = false)
    }

    fun refresh() {
        if (_uiState.value.isRefreshing) return
        load(isRefresh = true)
    }

    fun retry() = load(isRefresh = false)

    private fun load(isRefresh: Boolean) {
        _uiState.update {
            if (isRefresh) it.copy(isRefreshing = true) else it.copy(isLoading = true, error = null)
        }
        viewModelScope.launch {
            val subsDeferred = async { subscriptionsRepository.getMySubscriptions() }
            // Fan-club tiers for the viewer's own context (null creatorId = self).
            val tiersDeferred = async { fanClubRepository.getTiers(creatorId = null) }
            // Independent async legs (structured concurrency) so neither read serializes behind the other.
            val subsResult = subsDeferred.await()
            val tiersResult = tiersDeferred.await()
            reduce(subsResult, tiersResult)
        }
    }

    private fun reduce(
        subsResult: ApiResult<List<CreatorSubscription>>,
        tiersResult: ApiResult<List<FanClubTier>>,
    ) {
        when (subsResult) {
            is ApiResult.Success -> {
                val subs = subsResult.data
                // Fan-club tiers are an advisory join: a tiers failure -> empty fan-club section, no error.
                val tiers = tiersResult.getOrNull().orEmpty()
                val subRows = subs
                    .sortedByDescending { it.currentPeriodEndEpochSeconds ?: it.startAtEpochSeconds ?: 0L }
                    .map { it.toRow() }
                val fanClubRows = tiers
                    .filter { it.planId != null && entitlements.ownsTier(subs, it.planId!!) }
                    .sortedByDescending { it.level }
                    .map { it.toRow() }
                _uiState.update {
                    it.copy(
                        isLoading = false,
                        isRefreshing = false,
                        isStale = false,
                        subscriptions = subRows,
                        fanClubs = fanClubRows,
                        error = null,
                    )
                }
            }
            else -> {
                val message = subsResult.messageOrOffline()
                val hasData = _uiState.value.subscriptions.isNotEmpty() || _uiState.value.fanClubs.isNotEmpty()
                if (hasData) {
                    // Stale-while-revalidate: keep last-good content, mark stale, no destructive error.
                    _uiState.update { it.copy(isLoading = false, isRefreshing = false, isStale = true) }
                } else {
                    _uiState.update {
                        it.copy(isLoading = false, isRefreshing = false, error = message)
                    }
                }
            }
        }
    }

    private fun CreatorSubscription.toRow(): MySubscriptionRow = MySubscriptionRow(
        subscriptionId = subscriptionId,
        planId = planId,
        creatorId = creatorId,
        status = status,
        cancelAtPeriodEnd = cancelAtPeriodEnd,
        priceCents = priceCents,
        currency = currency,
        currentPeriodEndEpochSeconds = currentPeriodEndEpochSeconds,
    )

    private fun FanClubTier.toRow(): MyFanClubRow = MyFanClubRow(
        tierId = id,
        name = name,
        level = level,
        planId = planId,
        memberCount = memberCount,
    )

    private fun ApiResult<*>.messageOrOffline(): String = when (this) {
        is ApiResult.Failure -> error.message
        is ApiResult.NetworkError -> OFFLINE_MESSAGE
        is ApiResult.Success -> ""
    }

    companion object {
        const val ROUTE = "subscriptions/mine"
        private const val OFFLINE_MESSAGE = "You're offline"
    }
}
