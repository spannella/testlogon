@file:OptIn(ExperimentalMaterial3Api::class)

package com.testlogon.android.feature.billing.config

import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.ListItem
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.pulltorefresh.PullToRefreshBox
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.heading
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.testlogon.android.R
import com.testlogon.android.core.ui.i18n.asString
import com.testlogon.android.core.ui.state.EmptyState
import com.testlogon.android.core.ui.state.ErrorState
import com.testlogon.android.core.ui.state.LoadingState
import com.testlogon.android.core.ui.state.StaleBanner
import com.testlogon.android.data.billing.AdminBillingConfig
import com.testlogon.android.data.billing.PayoutSchedule

/** AND-248 — stable testTags for the read-only billing-config screen. */
object BillingConfigTestTags {
    const val SCREEN = "billing_config_screen"
    const val CONTENT = "billing_config_content"
    const val EMPTY = "billing_config_empty"
    const val ERROR = "billing_config_error"
    const val ROW = "billing_config_row"
}

/** AND-248 — route-level read-only billing-config screen, reachable from the More hub. */
@Composable
fun BillingConfigRoute(
    onBack: () -> Unit,
    modifier: Modifier = Modifier,
    viewModel: BillingConfigViewModel = hiltViewModel(),
) {
    val state by viewModel.state.collectAsStateWithLifecycle()
    BillingConfigScreen(
        state = state,
        onRetry = viewModel::retry,
        onRefresh = viewModel::refresh,
        onBack = onBack,
        modifier = modifier,
    )
}

@Composable
fun BillingConfigScreen(
    state: BillingConfigUiState,
    onRetry: () -> Unit,
    onRefresh: () -> Unit,
    onBack: () -> Unit,
    modifier: Modifier = Modifier,
) {
    Scaffold(
        modifier = modifier.testTag(BillingConfigTestTags.SCREEN),
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.billing_config_title)) },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(
                            Icons.AutoMirrored.Filled.ArrowBack,
                            contentDescription = stringResource(R.string.action_back),
                        )
                    }
                },
            )
        },
    ) { padding ->
        Box(Modifier.fillMaxSize().padding(padding)) {
            when (val s = state) {
                BillingConfigUiState.Loading ->
                    LoadingState(message = stringResource(R.string.billing_config_loading))

                BillingConfigUiState.Empty ->
                    EmptyState(
                        title = stringResource(R.string.billing_config_empty),
                        modifier = Modifier.testTag(BillingConfigTestTags.EMPTY),
                    )

                is BillingConfigUiState.Error ->
                    ErrorState(
                        message = s.message.asString(),
                        onRetry = if (s.canRetry) onRetry else ({}),
                        modifier = Modifier.testTag(BillingConfigTestTags.ERROR),
                    )

                is BillingConfigUiState.Content -> BillingConfigContent(
                    config = s.config,
                    isStale = s.isStale,
                    isRefreshing = s.isRefreshing,
                    onRefresh = onRefresh,
                )
            }
        }
    }
}

/** A flattened, ordered display item: either a section header or a label/value row. */
private sealed interface ConfigItem {
    data class Header(val title: String) : ConfigItem
    data class Row(val label: String, val value: String) : ConfigItem
}

@Composable
private fun BillingConfigContent(
    config: AdminBillingConfig,
    isStale: Boolean,
    isRefreshing: Boolean,
    onRefresh: () -> Unit,
) {
    val configItems = buildConfigItems(config)
    PullToRefreshBox(
        isRefreshing = isRefreshing,
        onRefresh = onRefresh,
        modifier = Modifier.fillMaxSize(),
    ) {
        LazyColumn(modifier = Modifier.fillMaxSize().testTag(BillingConfigTestTags.CONTENT)) {
            if (isStale) {
                item { StaleBanner(stale = true, refreshing = false, onRetry = onRefresh) }
            }
            items(configItems) { entry ->
                when (entry) {
                    is ConfigItem.Header -> SectionHeader(entry.title)
                    is ConfigItem.Row -> ConfigRow(label = entry.label, value = entry.value)
                }
            }
        }
    }
}

/** Resolves all labels/values in composable scope (so no @Composable runs in a non-composable lambda). */
@Composable
private fun buildConfigItems(config: AdminBillingConfig): List<ConfigItem> {
    val out = mutableListOf<ConfigItem>()
    val currency = config.defaultCurrency
    val enabled = stringResource(R.string.billing_config_enabled)
    val disabled = stringResource(R.string.billing_config_disabled)
    fun bool(value: Boolean) = if (value) enabled else disabled

    out += ConfigItem.Header(stringResource(R.string.billing_config_section_fees))
    out += ConfigItem.Row(stringResource(R.string.billing_config_fee_tips), formatBps(config.feeTipsBps))
    out += ConfigItem.Row(stringResource(R.string.billing_config_fee_unlocks), formatBps(config.feeUnlocksBps))
    out += ConfigItem.Row(
        stringResource(R.string.billing_config_fee_subscriptions),
        formatBps(config.feeSubscriptionsBps),
    )
    out += ConfigItem.Row(stringResource(R.string.billing_config_fee_catalog), formatBps(config.feeCatalogBps))
    out += ConfigItem.Row(
        stringResource(R.string.billing_config_fee_ad_revenue),
        formatBps(config.feeAdRevenueBps),
    )

    out += ConfigItem.Header(stringResource(R.string.billing_config_section_payouts))
    out += ConfigItem.Row(
        stringResource(R.string.billing_config_min_payout),
        formatConfigCents(config.minPayoutCents, currency),
    )
    out += ConfigItem.Row(
        stringResource(R.string.billing_config_payout_fee),
        formatConfigCents(config.payoutFeeCents, currency),
    )
    out += ConfigItem.Row(
        stringResource(R.string.billing_config_payout_schedule),
        payoutScheduleLabel(config.payoutSchedule),
    )
    out += ConfigItem.Row(stringResource(R.string.billing_config_auto_payout), bool(config.autoPayoutEnabled))

    out += ConfigItem.Header(stringResource(R.string.billing_config_section_deposits))
    out += ConfigItem.Row(
        stringResource(R.string.billing_config_min_deposit),
        formatConfigCents(config.minDepositCents, currency),
    )
    out += ConfigItem.Row(
        stringResource(R.string.billing_config_max_deposit),
        formatConfigCents(config.maxDepositCents, currency),
    )
    out += ConfigItem.Row(stringResource(R.string.billing_config_deposit_fee), formatBps(config.depositFeeBps))

    out += ConfigItem.Header(stringResource(R.string.billing_config_section_currency))
    out += ConfigItem.Row(
        stringResource(R.string.billing_config_default_currency),
        currency.uppercase(),
    )
    out += ConfigItem.Row(
        stringResource(R.string.billing_config_supported_currencies),
        config.supportedCurrencies.joinToString(", ") { it.uppercase() }.ifBlank { "—" },
    )

    out += ConfigItem.Header(stringResource(R.string.billing_config_section_tax))
    out += ConfigItem.Row(stringResource(R.string.billing_config_tax_enabled), bool(config.taxEnabled))
    out += ConfigItem.Row(
        stringResource(R.string.billing_config_default_tax_rate),
        formatBps(config.defaultTaxRateBps),
    )

    if (config.updatedBy != null) {
        out += ConfigItem.Header(stringResource(R.string.billing_config_section_updated))
        out += ConfigItem.Row(stringResource(R.string.billing_config_updated_by), config.updatedBy)
    }
    return out
}

@Composable
private fun payoutScheduleLabel(schedule: PayoutSchedule): String = when (schedule) {
    PayoutSchedule.Daily -> stringResource(R.string.billing_config_schedule_daily)
    PayoutSchedule.Weekly -> stringResource(R.string.billing_config_schedule_weekly)
    PayoutSchedule.Monthly -> stringResource(R.string.billing_config_schedule_monthly)
    is PayoutSchedule.Unknown -> schedule.raw.ifBlank { "—" }
}

@Composable
private fun SectionHeader(title: String) {
    Column {
        HorizontalDivider()
        Text(
            text = title,
            style = MaterialTheme.typography.titleSmall,
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 16.dp, vertical = 12.dp)
                .semantics { heading() },
        )
    }
}

/**
 * AND-248 — the atomic READ-ONLY row: a label/value [ListItem] with a single merged accessibility node
 * ("label: value"). It carries NO click/edit affordance (the read-only guarantee is the AC).
 */
@Composable
private fun ConfigRow(label: String, value: String) {
    ListItem(
        headlineContent = { Text(label) },
        supportingContent = { Text(value, style = MaterialTheme.typography.bodyMedium) },
        modifier = Modifier
            .fillMaxWidth()
            .testTag(BillingConfigTestTags.ROW)
            .semantics(mergeDescendants = true) { contentDescription = "$label: $value" },
    )
}
