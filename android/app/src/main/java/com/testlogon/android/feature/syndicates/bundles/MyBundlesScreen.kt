@file:OptIn(ExperimentalMaterial3Api::class)

package com.testlogon.android.feature.syndicates.bundles

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ExperimentalLayoutApi
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.outlined.Inventory2
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.AssistChip
import androidx.compose.material3.Badge
import androidx.compose.material3.Card
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.pulltorefresh.PullToRefreshBox
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.testlogon.android.R
import com.testlogon.android.core.model.syndicates.formatCents
import com.testlogon.android.core.ui.state.EmptyState
import com.testlogon.android.core.ui.state.ErrorState
import com.testlogon.android.core.ui.state.LoadingState
import com.testlogon.android.core.ui.state.OfflineBanner
import java.time.Instant
import java.time.ZoneId
import java.time.format.DateTimeFormatter
import java.time.format.FormatStyle

/** Stable testTags for the My Bundles screen. */
object MyBundlesTestTags {
    const val SCREEN = "my_bundles_screen"
    const val EMPTY = "my_bundles_empty"

    fun row(id: String) = "my_bundle_row_$id"
    fun cancel(id: String) = "my_bundle_cancel_$id"
}

/** Route-level entry for the My Bundles screen. */
@Composable
fun MyBundlesRoute(
    onBack: () -> Unit,
    viewModel: MyBundlesViewModel = hiltViewModel(),
) {
    val state by viewModel.uiState.collectAsStateWithLifecycle()
    MyBundlesScreen(
        state = state,
        onBack = onBack,
        onRetry = viewModel::retry,
        onRefresh = viewModel::refresh,
        onCancel = viewModel::cancel,
    )
}

@Composable
fun MyBundlesScreen(
    state: MyBundlesUiState,
    onBack: () -> Unit,
    onRetry: () -> Unit,
    onRefresh: () -> Unit,
    onCancel: (String) -> Unit,
    modifier: Modifier = Modifier,
) {
    Scaffold(
        modifier = modifier.testTag(MyBundlesTestTags.SCREEN),
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.my_bundles_title)) },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = stringResource(R.string.my_bundles_back))
                    }
                },
            )
        },
    ) { padding ->
        Column(Modifier.fillMaxSize().padding(padding)) {
            when (state) {
                is MyBundlesUiState.Loading -> LoadingState()
                is MyBundlesUiState.Empty ->
                    EmptyState(
                        modifier = Modifier.testTag(MyBundlesTestTags.EMPTY),
                        title = stringResource(R.string.my_bundles_empty_title),
                        body = stringResource(R.string.my_bundles_empty_body),
                        imageVector = Icons.Outlined.Inventory2,
                    )
                is MyBundlesUiState.Error -> ErrorState(message = state.message, onRetry = onRetry)
                is MyBundlesUiState.Content -> ContentBody(state = state, onRefresh = onRefresh, onRetry = onRetry, onCancel = onCancel)
            }
        }
    }
}

@Composable
private fun ContentBody(
    state: MyBundlesUiState.Content,
    onRefresh: () -> Unit,
    onRetry: () -> Unit,
    onCancel: (String) -> Unit,
) {
    if (state.isStale) OfflineBanner(onRetry = onRetry)
    if (state.actionError != null) {
        Text(
            text = state.actionError,
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.error,
            modifier = Modifier.fillMaxWidth().padding(horizontal = 16.dp, vertical = 8.dp),
        )
    }
    PullToRefreshBox(
        isRefreshing = state.isRefreshing,
        onRefresh = onRefresh,
        modifier = Modifier.fillMaxSize(),
    ) {
        LazyColumn(
            modifier = Modifier.fillMaxSize(),
            contentPadding = PaddingValues(16.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            items(items = state.items, key = { it.subscriptionId }) { bundle ->
                BundleCard(
                    bundle = bundle,
                    cancelling = state.cancellingId == bundle.subscriptionId,
                    onCancel = { onCancel(bundle.subscriptionId) },
                )
            }
        }
    }
}

@OptIn(ExperimentalLayoutApi::class)
@Composable
private fun BundleCard(
    bundle: BundleSubscription,
    cancelling: Boolean,
    onCancel: () -> Unit,
) {
    var showConfirm by remember { mutableStateOf(false) }
    Card(modifier = Modifier.fillMaxWidth().testTag(MyBundlesTestTags.row(bundle.subscriptionId))) {
        Column(modifier = Modifier.fillMaxWidth().padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                Text(
                    text = bundle.syndicateName,
                    style = MaterialTheme.typography.titleMedium,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                    modifier = Modifier.weight(1f),
                )
                Badge { Text(bundle.status) }
            }
            Text(
                text = stringResource(
                    R.string.my_bundles_price,
                    formatCents(bundle.priceCents.toLong()),
                    bundle.interval,
                ),
                style = MaterialTheme.typography.titleSmall,
            )
            val period = periodLabel(bundle)
            if (period != null) {
                Text(text = period, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
            }
            if (bundle.includedCreators.isNotEmpty()) {
                Text(
                    text = stringResource(R.string.my_bundles_included_creators),
                    style = MaterialTheme.typography.labelMedium,
                )
                FlowRow(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                    bundle.includedCreators.forEach { creator ->
                        AssistChip(onClick = {}, label = { Text(creator.displayName, style = MaterialTheme.typography.labelSmall) })
                    }
                }
            }
            if (bundle.isActive) {
                if (cancelling) {
                    CircularProgressIndicator(strokeWidth = 2.dp, modifier = Modifier.size(20.dp))
                } else {
                    OutlinedButton(
                        onClick = { showConfirm = true },
                        modifier = Modifier.testTag(MyBundlesTestTags.cancel(bundle.subscriptionId)),
                    ) {
                        Text(stringResource(R.string.my_bundles_cancel), color = MaterialTheme.colorScheme.error)
                    }
                }
            }
        }
    }

    if (showConfirm) {
        val periodEnd = bundle.currentPeriodEnd?.let { formatDate(it) }
        AlertDialog(
            onDismissRequest = { showConfirm = false },
            title = { Text(stringResource(R.string.my_bundles_cancel_title)) },
            text = {
                Text(
                    if (periodEnd != null) {
                        stringResource(R.string.my_bundles_cancel_body_dated, periodEnd)
                    } else {
                        stringResource(R.string.my_bundles_cancel_body)
                    },
                )
            },
            confirmButton = {
                TextButton(onClick = {
                    showConfirm = false
                    onCancel()
                }) {
                    Text(stringResource(R.string.my_bundles_cancel_confirm), color = MaterialTheme.colorScheme.error)
                }
            },
            dismissButton = {
                TextButton(onClick = { showConfirm = false }) {
                    Text(stringResource(R.string.my_bundles_cancel_keep))
                }
            },
        )
    }
}

@Composable
private fun periodLabel(bundle: BundleSubscription): String? {
    val start = bundle.currentPeriodStart?.let { formatDate(it) }
    val end = bundle.currentPeriodEnd?.let { formatDate(it) }
    return if (start != null && end != null) {
        stringResource(R.string.my_bundles_period, start, end)
    } else {
        null
    }
}

private val dateFormatter: DateTimeFormatter = DateTimeFormatter.ofLocalizedDate(FormatStyle.MEDIUM)

private fun formatDate(epochSeconds: Long): String =
    runCatching {
        Instant.ofEpochSecond(epochSeconds).atZone(ZoneId.systemDefault()).toLocalDate().format(dateFormatter)
    }.getOrDefault("")
