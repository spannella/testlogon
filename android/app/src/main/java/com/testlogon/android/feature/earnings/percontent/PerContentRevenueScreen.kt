@file:OptIn(ExperimentalMaterial3Api::class, ExperimentalLayoutApi::class)

package com.testlogon.android.feature.earnings.percontent

import androidx.compose.animation.AnimatedVisibility
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ExperimentalLayoutApi
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FilterChip
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.paging.LoadState
import androidx.paging.compose.LazyPagingItems
import androidx.paging.compose.collectAsLazyPagingItems
import com.testlogon.android.R
import com.testlogon.android.core.ui.state.EmptyState
import com.testlogon.android.core.ui.state.ErrorState
import com.testlogon.android.core.ui.state.LoadingState
import com.testlogon.android.data.earnings.ContentRevenue
import com.testlogon.android.data.earnings.RevenueSortKey
import com.testlogon.android.data.earnings.SortOrder
import com.testlogon.android.feature.earnings.formatEarningsMoney
import com.testlogon.android.feature.earnings.formatPublishedDate

/** AND-253 — stable testTags for the per-content revenue screen. */
object PerContentTestTags {
    const val SCREEN = "per_content_screen"
    const val LIST = "per_content_list"
    const val EMPTY = "per_content_empty"
    const val ERROR = "per_content_error"
    const val ROW = "per_content_row"
    const val HEADER = "per_content_header"
    const val SORT_PREFIX = "per_content_sort_"
    const val APPEND_FOOTER = "per_content_append_footer"
    const val APPEND_RETRY = "per_content_append_retry"
}

/** AND-253 — route-level per-content revenue entry. */
@Composable
fun PerContentRevenueRoute(
    onBack: () -> Unit,
    modifier: Modifier = Modifier,
    viewModel: PerContentRevenueViewModel = hiltViewModel(),
) {
    val state by viewModel.uiState.collectAsStateWithLifecycle()
    val items = viewModel.items.collectAsLazyPagingItems()
    PerContentRevenueScreen(
        state = state,
        items = items,
        onBack = onBack,
        onSortChange = viewModel::onSortChange,
        modifier = modifier,
    )
}

@Composable
fun PerContentRevenueScreen(
    state: PerContentRevenueViewModel.UiState,
    items: LazyPagingItems<ContentRevenue>,
    onBack: () -> Unit,
    onSortChange: (RevenueSortKey, SortOrder) -> Unit,
    modifier: Modifier = Modifier,
) {
    Scaffold(
        modifier = modifier.testTag(PerContentTestTags.SCREEN),
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.per_content_title)) },
                navigationIcon = {
                    IconButton(onClick = onBack, modifier = Modifier.testTag("per_content_back")) {
                        Icon(
                            Icons.AutoMirrored.Filled.ArrowBack,
                            contentDescription = stringResource(R.string.action_back),
                        )
                    }
                },
            )
        },
    ) { padding ->
        Column(Modifier.fillMaxSize().padding(padding)) {
            SortBar(
                selectedKey = state.query.sortBy,
                selectedOrder = state.query.sortOrder,
                onSortChange = onSortChange,
            )
            HeaderSummary(state = state)
            HorizontalDivider()
            Box(Modifier.fillMaxSize()) {
                val refresh = items.loadState.refresh
                when {
                    refresh is LoadState.Loading && items.itemCount == 0 ->
                        LoadingState(message = stringResource(R.string.per_content_loading))

                    refresh is LoadState.Error && items.itemCount == 0 -> {
                        val message = (refresh.error as? ContentRevenueLoadException)?.message
                            ?: stringResource(R.string.per_content_error_generic)
                        ErrorState(
                            message = message,
                            onRetry = items::refresh,
                            modifier = Modifier.testTag(PerContentTestTags.ERROR),
                        )
                    }

                    refresh is LoadState.NotLoading && items.itemCount == 0 ->
                        EmptyState(
                            title = stringResource(R.string.per_content_empty),
                            modifier = Modifier.testTag(PerContentTestTags.EMPTY),
                        )

                    else -> RevenueList(items = items, currency = state.currency)
                }
            }
        }
    }
}

@Composable
private fun SortBar(
    selectedKey: RevenueSortKey,
    selectedOrder: SortOrder,
    onSortChange: (RevenueSortKey, SortOrder) -> Unit,
) {
    FlowRow(
        modifier = Modifier.fillMaxWidth().padding(horizontal = 16.dp, vertical = 8.dp),
        horizontalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        RevenueSortKey.entries.forEach { key ->
            val isSelected = key == selectedKey
            FilterChip(
                selected = isSelected,
                onClick = {
                    // Tapping the active key toggles direction; otherwise switch key (keep order).
                    val nextOrder = if (isSelected) {
                        if (selectedOrder == SortOrder.DESC) SortOrder.ASC else SortOrder.DESC
                    } else {
                        selectedOrder
                    }
                    onSortChange(key, nextOrder)
                },
                label = { Text(sortLabel(key)) },
                modifier = Modifier.testTag(PerContentTestTags.SORT_PREFIX + key.apiValue),
            )
        }
    }
}

@Composable
private fun sortLabel(key: RevenueSortKey): String = when (key) {
    RevenueSortKey.TOTAL -> stringResource(R.string.per_content_sort_total)
    RevenueSortKey.TIPS -> stringResource(R.string.earnings_source_tips)
    RevenueSortKey.UNLOCKS -> stringResource(R.string.earnings_source_unlocks)
    RevenueSortKey.SUBSCRIPTIONS -> stringResource(R.string.earnings_source_subscriptions)
    RevenueSortKey.ADS -> stringResource(R.string.per_content_source_ads)
    RevenueSortKey.VOD -> stringResource(R.string.per_content_source_vod)
    RevenueSortKey.PUBLISHED -> stringResource(R.string.per_content_sort_published)
}

@Composable
private fun HeaderSummary(state: PerContentRevenueViewModel.UiState) {
    Row(
        Modifier
            .fillMaxWidth()
            .padding(horizontal = 16.dp, vertical = 8.dp)
            .testTag(PerContentTestTags.HEADER),
        horizontalArrangement = Arrangement.SpaceBetween,
    ) {
        Text(
            text = stringResource(R.string.per_content_total_items, state.totalItems),
            style = MaterialTheme.typography.bodyMedium,
        )
        Text(
            text = formatEarningsMoney(state.totalRevenueCents, state.currency),
            style = MaterialTheme.typography.titleSmall,
        )
    }
}

@Composable
private fun RevenueList(items: LazyPagingItems<ContentRevenue>, currency: String) {
    LazyColumn(modifier = Modifier.fillMaxSize().testTag(PerContentTestTags.LIST)) {
        items(
            count = items.itemCount,
            key = { index -> items.peek(index)?.contentId ?: index },
        ) { index ->
            val item = items[index]
            if (item != null) {
                ContentRevenueRow(item = item, currency = currency)
                HorizontalDivider()
            }
        }

        when (items.loadState.append) {
            is LoadState.Loading -> item {
                Box(
                    Modifier.fillMaxWidth().padding(16.dp).testTag(PerContentTestTags.APPEND_FOOTER),
                    contentAlignment = Alignment.Center,
                ) {
                    CircularProgressIndicator(modifier = Modifier.size(24.dp))
                }
            }
            is LoadState.Error -> item {
                Row(
                    Modifier.fillMaxWidth().padding(16.dp).testTag(PerContentTestTags.APPEND_FOOTER),
                    horizontalArrangement = Arrangement.Center,
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    Text(
                        stringResource(R.string.per_content_append_error),
                        style = MaterialTheme.typography.bodyMedium,
                    )
                    TextButton(
                        onClick = items::retry,
                        modifier = Modifier.testTag(PerContentTestTags.APPEND_RETRY),
                    ) { Text(stringResource(R.string.action_retry)) }
                }
            }
            else -> Unit
        }
    }
}

@Composable
private fun ContentRevenueRow(item: ContentRevenue, currency: String) {
    var expanded by rememberSaveable(item.contentId) { mutableStateOf(false) }
    val publishedText = formatPublishedDate(item.publishedAtEpochSec)
        ?: stringResource(R.string.per_content_date_unknown)
    val totalText = formatEarningsMoney(item.totalCents, currency)

    Column(
        modifier = Modifier
            .fillMaxWidth()
            .clickable { expanded = !expanded }
            .padding(horizontal = 16.dp, vertical = 12.dp)
            .testTag(PerContentTestTags.ROW),
    ) {
        Row(
            Modifier.fillMaxWidth().heightIn(min = 48.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Column(Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(2.dp)) {
                Text(
                    text = item.displayTitle,
                    style = MaterialTheme.typography.bodyLarge,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                )
                Text(
                    text = "$publishedText · ${item.contentType}",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                )
            }
            Text(
                text = totalText,
                style = MaterialTheme.typography.bodyLarge,
                fontWeight = FontWeight.SemiBold,
            )
        }
        AnimatedVisibility(visible = expanded) {
            Column(Modifier.padding(top = 8.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
                BreakdownLine(stringResource(R.string.earnings_source_tips), item.tipsCents, currency)
                BreakdownLine(stringResource(R.string.earnings_source_unlocks), item.unlocksCents, currency)
                BreakdownLine(stringResource(R.string.earnings_source_subscriptions), item.subscriptionsCents, currency)
                BreakdownLine(stringResource(R.string.per_content_source_ads), item.adsCents, currency)
                BreakdownLine(stringResource(R.string.per_content_source_vod), item.vodCents, currency)
            }
        }
    }
}

@Composable
private fun BreakdownLine(label: String, cents: Long, currency: String) {
    Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
        Text(label, style = MaterialTheme.typography.bodySmall)
        Text(formatEarningsMoney(cents, currency), style = MaterialTheme.typography.bodySmall)
    }
}
