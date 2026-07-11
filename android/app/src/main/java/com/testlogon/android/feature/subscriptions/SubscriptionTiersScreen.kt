@file:OptIn(ExperimentalLayoutApi::class, ExperimentalMaterial3Api::class)

package com.testlogon.android.feature.subscriptions

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ExperimentalLayoutApi
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.Check
import androidx.compose.material3.AssistChip
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.pulltorefresh.PullToRefreshBox
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.clearAndSetSemantics
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.testlogon.android.R
import com.testlogon.android.core.ui.state.EmptyState
import com.testlogon.android.core.ui.state.ErrorState
import com.testlogon.android.core.ui.state.LoadingState
import com.testlogon.android.data.subscriptions.TierBenefit

/** AND-235 — stable test tags for the subscription tiers browse screen. */
object SubscriptionTiersTestTags {
    const val SCREEN = "subs_tiers_screen"
    const val LIST = "subs_tiers_list"
    const val EMPTY = "subs_tiers_empty"
    const val ERROR = "subs_tiers_error"
    const val CARD = "subs_tiers_card"
    const val CURRENT_BADGE = "subs_tiers_current_badge"
    fun card(id: String) = "subs_tiers_card_$id"
    fun cta(id: String) = "subs_tiers_cta_$id"
}

/**
 * AND-235 — subscription tiers browse route. Collects [SubscriptionTiersUiState] + one-shot events and
 * renders [SubscriptionTiersScreen]. The Subscribe CTA routes the purchase through the
 * BillingAuthorizer stub in the ViewModel; a payments-unavailable effect shows a "coming soon"
 * snackbar (no checkout route, no charge).
 */
@Composable
fun SubscriptionTiersRoute(
    onNavigateToCheckout: (SubscriptionsEvent.NavigateToCheckout) -> Unit,
    onNavigateToManage: () -> Unit,
    onNavigateToGift: () -> Unit,
    onBack: () -> Unit,
    modifier: Modifier = Modifier,
    viewModel: SubscriptionTiersViewModel = hiltViewModel(),
) {
    val state by viewModel.uiState.collectAsStateWithLifecycle()
    val snackbarHostState = remember { SnackbarHostState() }
    val comingSoon = stringResource(R.string.subs_tiers_coming_soon)

    androidx.compose.runtime.LaunchedEffect(Unit) {
        viewModel.events.collect { event ->
            when (event) {
                is SubscriptionsEvent.NavigateToCheckout -> onNavigateToCheckout(event)
                is SubscriptionsEvent.NavigateToManage -> onNavigateToManage()
                is SubscriptionsEvent.PaymentsUnavailable -> snackbarHostState.showSnackbar(comingSoon)
                is SubscriptionsEvent.ShowMessage -> snackbarHostState.showSnackbar(event.message)
            }
        }
    }

    SubscriptionTiersScreen(
        state = state,
        snackbarHostState = snackbarHostState,
        onSubscribeClick = viewModel::onSubscribeClick,
        onManageClick = viewModel::onManageClick,
        onGiftClick = onNavigateToGift,
        onRetry = viewModel::onRetry,
        onRefresh = viewModel::onRefresh,
        onBack = onBack,
        modifier = modifier,
    )
}

@Composable
fun SubscriptionTiersScreen(
    state: SubscriptionTiersUiState,
    snackbarHostState: SnackbarHostState,
    onSubscribeClick: (String) -> Unit,
    onManageClick: () -> Unit,
    onGiftClick: () -> Unit,
    onRetry: () -> Unit,
    onRefresh: () -> Unit,
    onBack: () -> Unit,
    modifier: Modifier = Modifier,
) {
    Scaffold(
        modifier = modifier.testTag(SubscriptionTiersTestTags.SCREEN),
        topBar = {
            TopAppBar(
                title = {
                    Text(state.creatorDisplayName ?: stringResource(R.string.subs_tiers_title))
                },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(
                            Icons.AutoMirrored.Filled.ArrowBack,
                            contentDescription = stringResource(R.string.action_back),
                        )
                    }
                },
                actions = {
                    // SUB-E2: gift a subscription of this creator to another user.
                    TextButton(onClick = onGiftClick) {
                        Text(stringResource(R.string.gift_sub_action))
                    }
                },
            )
        },
        snackbarHost = { SnackbarHost(snackbarHostState) },
    ) { padding ->
        Box(Modifier.fillMaxSize().padding(padding)) {
            when {
                state.isLoading -> LoadingState()

                state.error != null && state.tiers.isEmpty() ->
                    ErrorState(
                        message = state.error,
                        onRetry = onRetry,
                        modifier = Modifier.testTag(SubscriptionTiersTestTags.ERROR),
                    )

                state.isEmpty ->
                    EmptyState(
                        title = stringResource(R.string.subs_tiers_empty),
                        modifier = Modifier.testTag(SubscriptionTiersTestTags.EMPTY),
                    )

                else ->
                    PullToRefreshBox(
                        isRefreshing = state.isRefreshing,
                        onRefresh = onRefresh,
                        modifier = Modifier.fillMaxSize(),
                    ) {
                        TierList(
                            tiers = state.tiers,
                            onSubscribeClick = onSubscribeClick,
                            onManageClick = onManageClick,
                        )
                    }
            }
        }
    }
}

@Composable
private fun TierList(
    tiers: List<TierUiModel>,
    onSubscribeClick: (String) -> Unit,
    onManageClick: () -> Unit,
) {
    LazyColumn(
        modifier = Modifier.fillMaxSize().testTag(SubscriptionTiersTestTags.LIST),
        contentPadding = PaddingValues(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        items(items = tiers, key = { it.id }) { tier ->
            TierCard(tier = tier, onSubscribeClick = onSubscribeClick, onManageClick = onManageClick)
        }
    }
}

/** SUB-E0 - renders a tier's structured benefits as a checkmarked perk list (label + optional detail). */
@Composable
private fun TierBenefitList(benefits: List<TierBenefit>) {
    Column(
        modifier = Modifier.fillMaxWidth(),
        verticalArrangement = Arrangement.spacedBy(6.dp),
    ) {
        benefits.forEach { benefit ->
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(8.dp),
                verticalAlignment = androidx.compose.ui.Alignment.Top,
            ) {
                Icon(
                    imageVector = Icons.Filled.Check,
                    contentDescription = null,
                    tint = MaterialTheme.colorScheme.primary,
                    modifier = Modifier.padding(top = 2.dp).heightIn(min = 18.dp),
                )
                Column(modifier = Modifier.fillMaxWidth()) {
                    Text(benefit.label, style = MaterialTheme.typography.bodyMedium)
                    benefit.detail?.takeIf { it.isNotBlank() }?.let {
                        Text(
                            it,
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                    }
                }
            }
        }
    }
}

@Composable
private fun TierCard(
    tier: TierUiModel,
    onSubscribeClick: (String) -> Unit,
    onManageClick: () -> Unit,
) {
    val freeLabel = stringResource(R.string.subs_tiers_free)
    val price = formatTierPrice(tier.priceCents, tier.currency, freeLabel)
    val intervalLabel = if (tier.priceCents == 0L) {
        ""
    } else {
        intervalSuffix(
            interval = tier.interval,
            monthLabel = stringResource(R.string.subs_tiers_interval_month),
            yearLabel = stringResource(R.string.subs_tiers_interval_year),
            weekLabel = stringResource(R.string.subs_tiers_interval_week),
        )
    }
    val currentLabel = stringResource(R.string.subs_tiers_current_badge)
    val cardCd = stringResource(
        if (tier.isCurrent) R.string.subs_tiers_card_cd_current else R.string.subs_tiers_card_cd,
        tier.name,
        "$price$intervalLabel",
    )

    Card(
        modifier = Modifier
            .fillMaxWidth()
            .testTag(SubscriptionTiersTestTags.card(tier.id)),
    ) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            // Info block carries a single merged a11y label so TalkBack reads one coherent string;
            // the CTA button below stays independently focusable/clickable.
            Column(
                modifier = Modifier
                    .fillMaxWidth()
                    .clearAndSetSemantics { contentDescription = cardCd },
                verticalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = androidx.compose.ui.Alignment.CenterVertically,
                ) {
                    Text(tier.name, style = MaterialTheme.typography.titleMedium)
                    if (tier.isCurrent) {
                        Surface(
                            color = MaterialTheme.colorScheme.primaryContainer,
                            contentColor = MaterialTheme.colorScheme.onPrimaryContainer,
                            modifier = Modifier.testTag(SubscriptionTiersTestTags.CURRENT_BADGE),
                        ) {
                            Text(
                                currentLabel,
                                style = MaterialTheme.typography.labelMedium,
                                modifier = Modifier.padding(horizontal = 8.dp, vertical = 4.dp),
                            )
                        }
                    }
                }

                Text(
                    text = "$price$intervalLabel",
                    style = MaterialTheme.typography.headlineSmall,
                    color = MaterialTheme.colorScheme.primary,
                )

                tier.description?.takeIf { it.isNotBlank() }?.let {
                    Text(it, style = MaterialTheme.typography.bodyMedium)
                }

                // SUB-E0: the creator-authored structured benefits (label + optional detail).
                if (tier.benefits.isNotEmpty()) {
                    TierBenefitList(tier.benefits)
                }

                if (tier.perks.isNotEmpty()) {
                    FlowRow(
                        horizontalArrangement = Arrangement.spacedBy(8.dp),
                        modifier = Modifier.fillMaxWidth(),
                    ) {
                        tier.perks.forEach { perk ->
                            AssistChip(onClick = {}, label = { Text(perk) })
                        }
                    }
                }
            }

            if (tier.isCurrent) {
                OutlinedButton(
                    onClick = onManageClick,
                    modifier = Modifier
                        .fillMaxWidth()
                        .heightIn(min = 48.dp)
                        .testTag(SubscriptionTiersTestTags.cta(tier.id)),
                ) {
                    Text(stringResource(R.string.subs_tiers_manage))
                }
            } else {
                Button(
                    onClick = { onSubscribeClick(tier.id) },
                    modifier = Modifier
                        .fillMaxWidth()
                        .heightIn(min = 48.dp)
                        .testTag(SubscriptionTiersTestTags.cta(tier.id)),
                ) {
                    Text(stringResource(R.string.subs_tiers_subscribe))
                }
            }
        }
    }
}
