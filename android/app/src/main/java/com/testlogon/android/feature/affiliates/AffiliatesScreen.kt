@file:OptIn(ExperimentalMaterial3Api::class, ExperimentalLayoutApi::class)

package com.testlogon.android.feature.affiliates

import android.content.ActivityNotFoundException
import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ExperimentalLayoutApi
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.outlined.ContentCopy
import androidx.compose.material.icons.outlined.Delete
import androidx.compose.material.icons.outlined.Share
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.AssistChip
import androidx.compose.material3.Button
import androidx.compose.material3.ElevatedCard
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.ExtendedFloatingActionButton
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.pulltorefresh.PullToRefreshBox
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.clearAndSetSemantics
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.testlogon.android.R
import com.testlogon.android.core.ui.state.EmptyState
import com.testlogon.android.core.ui.state.ErrorState
import com.testlogon.android.core.ui.state.LoadingState
import com.testlogon.android.core.ui.state.OfflineBanner
import com.testlogon.android.data.affiliates.AffiliateEarnings
import com.testlogon.android.data.affiliates.AffiliateLink
import com.testlogon.android.data.referrals.DEFAULT_CURRENCY_USD
import com.testlogon.android.feature.charts.SeriesChartType
import com.testlogon.android.feature.charts.TestLogonSeriesChart
import com.testlogon.android.feature.earnings.formatEarningsMoney

/** AND-265 — stable testTags for the affiliates dashboard screen. */
object AffiliatesTestTags {
    const val SCREEN = "affiliates_screen"
    const val CONTENT = "affiliates_content"
    const val LOADING = "affiliates_loading"
    const val EMPTY = "affiliates_empty"
    const val ERROR = "affiliates_error"
    const val OFFLINE = "affiliates_offline"
    const val EARNINGS = "affiliates_earnings"
    const val CHART = "affiliates_chart"
    const val KPI_PREFIX = "affiliates_kpi_"
    const val LINK_PREFIX = "affiliates_link_"
    const val CREATE_FAB = "affiliates_create_fab"
    const val CREATE_DIALOG = "affiliates_create_dialog"
    const val DELETE_DIALOG = "affiliates_delete_dialog"
}

/** AND-265 — route-level affiliates entry (reachable from the More hub). */
@Composable
fun AffiliatesRoute(
    onBack: () -> Unit,
    modifier: Modifier = Modifier,
    viewModel: AffiliatesViewModel = hiltViewModel(),
) {
    val state by viewModel.uiState.collectAsStateWithLifecycle()
    val snackbarHostState = remember { SnackbarHostState() }
    val context = LocalContext.current
    val shareChooserTitle = stringResource(R.string.affiliates_share_chooser_title)

    LaunchedEffect(viewModel) {
        viewModel.effects.collect { effect ->
            when (effect) {
                is AffiliatesEffect.CopyUrl -> copyToClipboard(context, effect.url)
                is AffiliatesEffect.ShareUrl -> shareUrl(context, effect.url, shareChooserTitle)
                is AffiliatesEffect.ShowMessage ->
                    snackbarHostState.showSnackbar(context.getString(effect.resId))
            }
        }
    }

    AffiliatesScreen(
        state = state,
        onBack = onBack,
        onRefresh = viewModel::onRefresh,
        onRetry = viewModel::onRetry,
        onChartPointSelected = viewModel::onChartPointSelected,
        onCopyLink = viewModel::onCopyLink,
        onShareLink = viewModel::onShareLink,
        onOpenCreate = viewModel::onOpenCreate,
        onDismissCreate = viewModel::onDismissCreate,
        onCreateFormChanged = viewModel::onCreateFormChanged,
        onSubmitCreate = viewModel::onSubmitCreate,
        onRequestDelete = viewModel::onRequestDelete,
        onDismissDelete = viewModel::onDismissDelete,
        onConfirmDelete = viewModel::onConfirmDelete,
        snackbarHostState = snackbarHostState,
        modifier = modifier,
    )
}

@Composable
fun AffiliatesScreen(
    state: AffiliatesUiState,
    onBack: () -> Unit,
    onRefresh: () -> Unit,
    onRetry: () -> Unit,
    onChartPointSelected: (Int?) -> Unit,
    onCopyLink: (String) -> Unit,
    onShareLink: (String) -> Unit,
    onOpenCreate: () -> Unit,
    onDismissCreate: () -> Unit,
    onCreateFormChanged: (String?, String?, String?, String?) -> Unit,
    onSubmitCreate: () -> Unit,
    onRequestDelete: (String) -> Unit,
    onDismissDelete: () -> Unit,
    onConfirmDelete: () -> Unit,
    modifier: Modifier = Modifier,
    snackbarHostState: SnackbarHostState = remember { SnackbarHostState() },
) {
    Scaffold(
        modifier = modifier.testTag(AffiliatesTestTags.SCREEN),
        snackbarHost = { SnackbarHost(snackbarHostState) },
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.affiliates_title)) },
                navigationIcon = {
                    IconButton(onClick = onBack, modifier = Modifier.testTag("affiliates_back")) {
                        Icon(
                            Icons.AutoMirrored.Filled.ArrowBack,
                            contentDescription = stringResource(R.string.action_back),
                        )
                    }
                },
            )
        },
        floatingActionButton = {
            if (state.phase != AffiliatesUiState.Phase.Loading) {
                ExtendedFloatingActionButton(
                    onClick = onOpenCreate,
                    icon = { Icon(Icons.Filled.Add, contentDescription = null) },
                    text = { Text(stringResource(R.string.affiliates_create_action)) },
                    modifier = Modifier.testTag(AffiliatesTestTags.CREATE_FAB),
                )
            }
        },
    ) { padding ->
        Box(modifier = Modifier.padding(padding).fillMaxSize()) {
            when (state.phase) {
                AffiliatesUiState.Phase.Loading ->
                    LoadingState(modifier = Modifier.testTag(AffiliatesTestTags.LOADING))

                AffiliatesUiState.Phase.Empty ->
                    EmptyState(
                        title = stringResource(R.string.affiliates_empty_title),
                        body = stringResource(R.string.affiliates_empty_body),
                        modifier = Modifier.testTag(AffiliatesTestTags.EMPTY),
                    )

                AffiliatesUiState.Phase.Error ->
                    ErrorState(
                        message = state.errorMessage ?: stringResource(R.string.affiliates_error_generic),
                        onRetry = onRetry,
                        modifier = Modifier.testTag(AffiliatesTestTags.ERROR),
                    )

                AffiliatesUiState.Phase.Offline ->
                    ErrorState(
                        message = state.errorMessage ?: stringResource(R.string.affiliates_error_generic),
                        onRetry = onRetry,
                        modifier = Modifier.testTag(AffiliatesTestTags.OFFLINE),
                    )

                AffiliatesUiState.Phase.Content -> {
                    val dashboard = state.dashboard
                    if (dashboard == null) {
                        LoadingState(modifier = Modifier.testTag(AffiliatesTestTags.LOADING))
                    } else {
                        PullToRefreshBox(
                            isRefreshing = state.isRefreshing,
                            onRefresh = onRefresh,
                            modifier = Modifier.fillMaxSize(),
                        ) {
                            Column(
                                modifier = Modifier
                                    .testTag(AffiliatesTestTags.CONTENT)
                                    .fillMaxSize()
                                    .verticalScroll(rememberScrollState())
                                    .padding(16.dp),
                                verticalArrangement = Arrangement.spacedBy(16.dp),
                            ) {
                                if (state.isStale) {
                                    OfflineBanner(onRetry = onRetry)
                                }
                                EarningsCard(
                                    earnings = dashboard.earnings,
                                    links = dashboard.links,
                                    selectedIndex = state.selectedChartIndex,
                                    onPointSelected = onChartPointSelected,
                                )
                                dashboard.links.forEach { link ->
                                    LinkRow(
                                        link = link,
                                        onCopy = { onCopyLink(link.id) },
                                        onShare = { onShareLink(link.id) },
                                        onDelete = { onRequestDelete(link.id) },
                                    )
                                }
                            }
                        }
                    }
                }
            }

            state.createForm?.let { form ->
                CreateLinkDialog(
                    form = form,
                    onChanged = onCreateFormChanged,
                    onDismiss = onDismissCreate,
                    onSubmit = onSubmitCreate,
                )
            }

            state.pendingDelete?.let { pending ->
                DeleteLinkDialog(
                    pending = pending,
                    onDismiss = onDismissDelete,
                    onConfirm = onConfirmDelete,
                )
            }
        }
    }
}

@Composable
private fun EarningsCard(
    earnings: AffiliateEarnings,
    links: List<AffiliateLink>,
    selectedIndex: Int?,
    onPointSelected: (Int?) -> Unit,
) {
    ElevatedCard(modifier = Modifier.fillMaxWidth().testTag(AffiliatesTestTags.EARNINGS)) {
        Column(
            modifier = Modifier.padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            FlowRow(horizontalArrangement = Arrangement.spacedBy(16.dp)) {
                Kpi("earned", R.string.affiliates_kpi_earned, formatEarningsMoney(earnings.totalEarned.cents, DEFAULT_CURRENCY_USD))
                Kpi("revenue", R.string.affiliates_kpi_revenue, formatEarningsMoney(earnings.totalRevenue.cents, DEFAULT_CURRENCY_USD))
                Kpi("links", R.string.affiliates_kpi_links, formatCount(earnings.linkCount))
                Kpi("clicks", R.string.affiliates_kpi_clicks, formatCount(earnings.totalClicks))
                Kpi("conversions", R.string.affiliates_kpi_conversions, formatCount(earnings.totalConversions))
            }
            Text(
                stringResource(R.string.affiliates_chart_title),
                style = MaterialTheme.typography.labelMedium,
            )
            TestLogonSeriesChart(
                geometry = links.commissionSeriesGeometry(),
                chartType = SeriesChartType.BAR,
                lineColor = MaterialTheme.colorScheme.primary,
                gridColor = MaterialTheme.colorScheme.outlineVariant,
                fillColor = MaterialTheme.colorScheme.primaryContainer,
                selectedColor = MaterialTheme.colorScheme.tertiary,
                selectedIndex = selectedIndex,
                onPointSelected = onPointSelected,
                modifier = Modifier.testTag(AffiliatesTestTags.CHART),
            )
        }
    }
}

@Composable
private fun Kpi(key: String, labelRes: Int, value: String) {
    val label = stringResource(labelRes)
    Column(
        modifier = Modifier
            .testTag(AffiliatesTestTags.KPI_PREFIX + key)
            .semantics(mergeDescendants = true) {},
    ) {
        Text(label, style = MaterialTheme.typography.labelMedium)
        Text(value, style = MaterialTheme.typography.titleMedium)
    }
}

@Composable
private fun LinkRow(
    link: AffiliateLink,
    onCopy: () -> Unit,
    onShare: () -> Unit,
    onDelete: () -> Unit,
) {
    ElevatedCard(
        modifier = Modifier
            .fillMaxWidth()
            .testTag(AffiliatesTestTags.LINK_PREFIX + link.id),
    ) {
        Row(
            modifier = Modifier.padding(16.dp).fillMaxWidth(),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            Column(
                modifier = Modifier.semantics(mergeDescendants = true) {},
            ) {
                Text(
                    link.label.ifBlank { link.trackingCode },
                    style = MaterialTheme.typography.titleMedium,
                )
                Text(
                    displayUrl(link.shortUrl),
                    style = MaterialTheme.typography.bodySmall,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                )
                val statusLabel = link.rawStatus.ifBlank { stringResource(R.string.affiliates_status_unknown) }
                AssistChip(onClick = {}, label = { Text(statusLabel) })
                Text(
                    stringResource(
                        R.string.affiliates_link_metrics,
                        formatCount(link.clicks),
                        formatCount(link.conversions),
                        formatPercent(link.commissionPercent),
                        formatEarningsMoney(link.commissionEarned.cents, DEFAULT_CURRENCY_USD),
                    ),
                    style = MaterialTheme.typography.bodySmall,
                )
            }
            val copyCd = stringResource(R.string.affiliates_action_copy)
            val shareCd = stringResource(R.string.affiliates_action_share)
            val deleteCd = stringResource(R.string.affiliates_action_delete)
            IconButton(
                onClick = onCopy,
                modifier = Modifier.clearAndSetSemantics { contentDescription = copyCd },
            ) {
                Icon(Icons.Outlined.ContentCopy, contentDescription = null)
            }
            IconButton(
                onClick = onShare,
                modifier = Modifier.clearAndSetSemantics { contentDescription = shareCd },
            ) {
                Icon(Icons.Outlined.Share, contentDescription = null)
            }
            IconButton(
                onClick = onDelete,
                modifier = Modifier
                    .testTag(AffiliatesTestTags.LINK_PREFIX + link.id + "_delete")
                    .clearAndSetSemantics { contentDescription = deleteCd },
            ) {
                Icon(Icons.Outlined.Delete, contentDescription = null)
            }
        }
    }
}

@Composable
private fun CreateLinkDialog(
    form: AffiliatesUiState.CreateForm,
    onChanged: (String?, String?, String?, String?) -> Unit,
    onDismiss: () -> Unit,
    onSubmit: () -> Unit,
) {
    AlertDialog(
        onDismissRequest = onDismiss,
        modifier = Modifier.testTag(AffiliatesTestTags.CREATE_DIALOG),
        title = { Text(stringResource(R.string.affiliates_create_title)) },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                OutlinedTextField(
                    value = form.targetId,
                    onValueChange = { onChanged(null, it, null, null) },
                    label = { Text(stringResource(R.string.affiliates_create_target_id)) },
                    singleLine = true,
                    enabled = !form.submitting,
                    modifier = Modifier.fillMaxWidth().testTag("affiliates_create_target_id"),
                )
                OutlinedTextField(
                    value = form.targetType,
                    onValueChange = { onChanged(it, null, null, null) },
                    label = { Text(stringResource(R.string.affiliates_create_target_type)) },
                    singleLine = true,
                    enabled = !form.submitting,
                    modifier = Modifier.fillMaxWidth(),
                )
                OutlinedTextField(
                    value = form.commissionPercent,
                    onValueChange = { onChanged(null, null, it, null) },
                    label = { Text(stringResource(R.string.affiliates_create_commission)) },
                    singleLine = true,
                    enabled = !form.submitting,
                    keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
                    modifier = Modifier.fillMaxWidth(),
                )
                OutlinedTextField(
                    value = form.customCode,
                    onValueChange = { onChanged(null, null, null, it) },
                    label = { Text(stringResource(R.string.affiliates_create_custom_code)) },
                    singleLine = true,
                    enabled = !form.submitting,
                    modifier = Modifier.fillMaxWidth(),
                )
                form.errorRes?.let {
                    Text(
                        stringResource(it),
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.error,
                    )
                }
            }
        },
        confirmButton = {
            Button(
                onClick = onSubmit,
                enabled = form.canSubmit,
                modifier = Modifier.testTag("affiliates_create_submit"),
            ) {
                Text(stringResource(R.string.affiliates_create_submit))
            }
        },
        dismissButton = {
            TextButton(onClick = onDismiss, enabled = !form.submitting) {
                Text(stringResource(R.string.action_cancel))
            }
        },
    )
}

@Composable
private fun DeleteLinkDialog(
    pending: AffiliatesUiState.PendingDelete,
    onDismiss: () -> Unit,
    onConfirm: () -> Unit,
) {
    AlertDialog(
        onDismissRequest = onDismiss,
        modifier = Modifier.testTag(AffiliatesTestTags.DELETE_DIALOG),
        title = { Text(stringResource(R.string.affiliates_delete_title)) },
        text = { Text(stringResource(R.string.affiliates_delete_body, pending.label)) },
        confirmButton = {
            Button(
                onClick = onConfirm,
                enabled = !pending.deleting,
                modifier = Modifier.testTag("affiliates_delete_confirm"),
            ) {
                Text(stringResource(R.string.affiliates_delete_confirm))
            }
        },
        dismissButton = {
            TextButton(onClick = onDismiss, enabled = !pending.deleting) {
                Text(stringResource(R.string.action_cancel))
            }
        },
    )
}

// ---- Android side-effect seams (only the URL string crosses; never amounts/account ids) ----

private fun copyToClipboard(context: Context, text: String) {
    val clipboard = context.getSystemService(Context.CLIPBOARD_SERVICE) as? ClipboardManager ?: return
    clipboard.setPrimaryClip(ClipData.newPlainText("affiliate_link", text))
}

private fun shareUrl(context: Context, url: String, chooserTitle: String) {
    val send = Intent(Intent.ACTION_SEND).apply {
        type = "text/plain"
        putExtra(Intent.EXTRA_TEXT, url)
    }
    val chooser = Intent.createChooser(send, chooserTitle).apply {
        addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
    }
    try {
        context.startActivity(chooser)
    } catch (_: ActivityNotFoundException) {
        // No share target available; copy remains as a fallback.
    }
}
