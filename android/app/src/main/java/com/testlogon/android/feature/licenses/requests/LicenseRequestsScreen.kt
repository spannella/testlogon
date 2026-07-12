@file:OptIn(ExperimentalMaterial3Api::class)

package com.testlogon.android.feature.licenses.requests

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.ExperimentalLayoutApi
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.LazyRow
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.outlined.Description
import androidx.compose.material3.AssistChip
import androidx.compose.material3.AssistChipDefaults
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SegmentedButton
import androidx.compose.material3.SegmentedButtonDefaults
import androidx.compose.material3.SingleChoiceSegmentedButtonRow
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.pulltorefresh.PullToRefreshBox
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.testlogon.android.core.ui.state.EmptyState
import com.testlogon.android.core.ui.state.ErrorState
import com.testlogon.android.core.ui.state.LoadingState
import com.testlogon.android.data.licenses.FullLicenseRequest
import com.testlogon.android.data.licenses.LicenseTerms

object LicenseRequestsTestTags {
    const val SCREEN = "license_requests_screen"
    const val TABS = "license_requests_tabs"
    const val LIST = "license_requests_list"
    const val LOADING = "license_requests_loading"
    const val EMPTY = "license_requests_empty"
    const val ERROR = "license_requests_error"
    const val ROW_PREFIX = "license_request_row_"
    const val FILTER_PREFIX = "license_requests_filter_"
    const val TAB_PREFIX = "license_requests_tab_"
}

@Composable
fun LicenseRequestsRoute(
    onBack: () -> Unit,
    modifier: Modifier = Modifier,
    viewModel: LicenseRequestsViewModel = hiltViewModel(),
) {
    val state by viewModel.uiState.collectAsStateWithLifecycle()
    val snackbarHostState = remember { SnackbarHostState() }
    val context = LocalContext.current

    LaunchedEffect(viewModel) {
        viewModel.effects.collect { msg -> snackbarHostState.showSnackbar(context.getString(msg)) }
    }

    LicenseRequestsScreen(
        state = state,
        onBack = onBack,
        onRefresh = viewModel::refresh,
        onRetry = viewModel::refresh,
        onSelectTab = viewModel::selectTab,
        onSelectStatus = viewModel::selectStatus,
        onApprove = viewModel::approve,
        onOpenDeny = viewModel::openDeny,
        onOpenCounter = viewModel::openCounter,
        onAcceptCounter = viewModel::acceptCounter,
        onRejectCounter = viewModel::rejectCounter,
        onWithdraw = viewModel::withdraw,
        onCloseDeny = viewModel::closeDeny,
        onConfirmDeny = viewModel::confirmDeny,
        onCloseCounter = viewModel::closeCounter,
        onConfirmCounter = viewModel::confirmCounter,
        snackbarHostState = snackbarHostState,
        modifier = modifier,
    )
}

@Composable
fun LicenseRequestsScreen(
    state: LicenseRequestsUiState,
    onBack: () -> Unit,
    onRefresh: () -> Unit,
    onRetry: () -> Unit,
    onSelectTab: (RequestsTab) -> Unit,
    onSelectStatus: (String) -> Unit,
    onApprove: (FullLicenseRequest) -> Unit,
    onOpenDeny: (FullLicenseRequest) -> Unit,
    onOpenCounter: (FullLicenseRequest) -> Unit,
    onAcceptCounter: (FullLicenseRequest) -> Unit,
    onRejectCounter: (FullLicenseRequest) -> Unit,
    onWithdraw: (FullLicenseRequest) -> Unit,
    onCloseDeny: () -> Unit,
    onConfirmDeny: (String) -> Unit,
    onCloseCounter: () -> Unit,
    onConfirmCounter: (Double, Double, Long) -> Unit,
    modifier: Modifier = Modifier,
    snackbarHostState: SnackbarHostState = remember { SnackbarHostState() },
) {
    Scaffold(
        modifier = modifier.testTag(LicenseRequestsTestTags.SCREEN),
        snackbarHost = { SnackbarHost(snackbarHostState) },
        topBar = {
            TopAppBar(
                title = { Text("License Requests") },
                navigationIcon = {
                    IconButton(onClick = onBack, modifier = Modifier.testTag("license_requests_back")) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Back")
                    }
                },
            )
        },
    ) { padding ->
        Column(modifier = Modifier.padding(padding).fillMaxSize()) {
            TabsRow(state.tab, onSelectTab)
            StatusFilterRow(state.statusFilter, onSelectStatus)
            Box(modifier = Modifier.fillMaxSize()) {
                when (state.phase) {
                    LicenseRequestsUiState.Phase.Loading ->
                        LoadingState(modifier = Modifier.testTag(LicenseRequestsTestTags.LOADING))

                    LicenseRequestsUiState.Phase.Error ->
                        ErrorState(
                            message = state.errorMessage ?: "Could not load requests.",
                            onRetry = onRetry,
                            modifier = Modifier.testTag(LicenseRequestsTestTags.ERROR),
                        )

                    LicenseRequestsUiState.Phase.Empty ->
                        PullToRefreshBox(
                            isRefreshing = state.isRefreshing,
                            onRefresh = onRefresh,
                            modifier = Modifier.fillMaxSize(),
                        ) {
                            EmptyState(
                                title = "No license requests",
                                body = if (state.tab == RequestsTab.INBOX) {
                                    "Requests for your content will appear here."
                                } else {
                                    "License requests you have sent will appear here."
                                },
                                imageVector = Icons.Outlined.Description,
                                modifier = Modifier.fillMaxSize().testTag(LicenseRequestsTestTags.EMPTY),
                            )
                        }

                    LicenseRequestsUiState.Phase.Content ->
                        PullToRefreshBox(
                            isRefreshing = state.isRefreshing,
                            onRefresh = onRefresh,
                            modifier = Modifier.fillMaxSize(),
                        ) {
                            LazyColumn(
                                modifier = Modifier.fillMaxSize().testTag(LicenseRequestsTestTags.LIST),
                                contentPadding = PaddingValues(vertical = 8.dp),
                            ) {
                                items(state.items, key = { it.requestId }) { r ->
                                    RequestCard(
                                        r = r,
                                        isInbox = state.tab == RequestsTab.INBOX,
                                        busy = state.actionInProgressId != null,
                                        onApprove = onApprove,
                                        onOpenDeny = onOpenDeny,
                                        onOpenCounter = onOpenCounter,
                                        onAcceptCounter = onAcceptCounter,
                                        onRejectCounter = onRejectCounter,
                                        onWithdraw = onWithdraw,
                                    )
                                    HorizontalDivider()
                                }
                            }
                        }
                }
            }
        }
    }

    state.denyTarget?.let { target ->
        DenyDialog(contentId = target.contentId, onDismiss = onCloseDeny, onConfirm = onConfirmDeny)
    }
    state.counterTarget?.let { target ->
        CounterOfferDialog(target = target, onDismiss = onCloseCounter, onConfirm = onConfirmCounter)
    }
}

@Composable
private fun TabsRow(selected: RequestsTab, onSelect: (RequestsTab) -> Unit) {
    val tabs = RequestsTab.entries
    SingleChoiceSegmentedButtonRow(
        modifier = Modifier
            .fillMaxWidth()
            .padding(horizontal = 16.dp, vertical = 8.dp)
            .testTag(LicenseRequestsTestTags.TABS),
    ) {
        tabs.forEachIndexed { index, tab ->
            SegmentedButton(
                selected = tab == selected,
                onClick = { onSelect(tab) },
                shape = SegmentedButtonDefaults.itemShape(index = index, count = tabs.size),
                modifier = Modifier.testTag(LicenseRequestsTestTags.TAB_PREFIX + tab.name.lowercase()),
            ) {
                Text(if (tab == RequestsTab.INBOX) "Inbox" else "Sent")
            }
        }
    }
}

@Composable
private fun StatusFilterRow(selected: String, onSelect: (String) -> Unit) {
    LazyRow(
        modifier = Modifier.fillMaxWidth().padding(horizontal = 8.dp, vertical = 2.dp),
        horizontalArrangement = Arrangement.spacedBy(8.dp),
        contentPadding = PaddingValues(horizontal = 8.dp),
    ) {
        items(REQUEST_STATUS_OPTIONS, key = { it }) { opt ->
            val isSel = opt == selected
            AssistChip(
                onClick = { onSelect(opt) },
                label = { Text(if (opt == "all") "All" else opt.replaceFirstChar { it.uppercase() }) },
                modifier = Modifier.testTag(LicenseRequestsTestTags.FILTER_PREFIX + opt),
                colors = if (isSel) {
                    AssistChipDefaults.assistChipColors(containerColor = MaterialTheme.colorScheme.secondaryContainer)
                } else {
                    AssistChipDefaults.assistChipColors()
                },
            )
        }
    }
}

@OptIn(ExperimentalLayoutApi::class)
@Composable
private fun RequestCard(
    r: FullLicenseRequest,
    isInbox: Boolean,
    busy: Boolean,
    onApprove: (FullLicenseRequest) -> Unit,
    onOpenDeny: (FullLicenseRequest) -> Unit,
    onOpenCounter: (FullLicenseRequest) -> Unit,
    onAcceptCounter: (FullLicenseRequest) -> Unit,
    onRejectCounter: (FullLicenseRequest) -> Unit,
    onWithdraw: (FullLicenseRequest) -> Unit,
) {
    Card(
        modifier = Modifier
            .fillMaxWidth()
            .padding(horizontal = 12.dp, vertical = 6.dp)
            .testTag(LicenseRequestsTestTags.ROW_PREFIX + r.requestId),
    ) {
        Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
            ) {
                Text(r.contentId, style = MaterialTheme.typography.bodyLarge, fontWeight = FontWeight.SemiBold)
                AssistChip(onClick = {}, label = { Text(r.statusLabel().ifBlank { r.status }) })
            }
            val counterparty = if (isInbox) r.requesterId else r.ownerId
            val meta = listOf(r.contentType, counterparty, r.formattedCreated())
                .filter { it.isNotBlank() }
                .joinToString("  -  ")
            if (meta.isNotBlank()) {
                Text(meta, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
            }
            Text("Proposed: ${termsText(r.proposedTerms)}", style = MaterialTheme.typography.bodyMedium)
            r.counterTerms?.let {
                Text("Counter: ${termsText(it)}", style = MaterialTheme.typography.bodyMedium)
            }
            if (r.message.isNotBlank()) {
                Text("\"${r.message}\"", style = MaterialTheme.typography.bodySmall)
            }
            if (r.denialReason.isNotBlank()) {
                Text("Denied: ${r.denialReason}", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.error)
            }
            FlowRow(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                if (isInbox && r.isActionableByOwner) {
                    Button(onClick = { onApprove(r) }, enabled = !busy) { Text("Approve") }
                    OutlinedButton(onClick = { onOpenCounter(r) }, enabled = !busy) { Text("Counter") }
                    OutlinedButton(onClick = { onOpenDeny(r) }, enabled = !busy) { Text("Deny") }
                }
                if (!isInbox && r.isWithdrawableBySender) {
                    OutlinedButton(onClick = { onWithdraw(r) }, enabled = !busy) { Text("Withdraw") }
                }
                if (!isInbox && r.isCounterPendingForSender) {
                    Button(onClick = { onAcceptCounter(r) }, enabled = !busy) { Text("Accept") }
                    OutlinedButton(onClick = { onRejectCounter(r) }, enabled = !busy) { Text("Reject") }
                    OutlinedButton(onClick = { onWithdraw(r) }, enabled = !busy) { Text("Withdraw") }
                }
            }
        }
    }
}

internal fun termsText(terms: LicenseTerms?): String {
    if (terms == null) return "--"
    val parts = mutableListOf<String>()
    if (terms.profitSharePct > 0) parts.add("${fmtPct(terms.profitSharePct)}% profit")
    if (terms.revenueSharePct > 0) parts.add("${fmtPct(terms.revenueSharePct)}% revenue")
    if (terms.fixedCostCents > 0) parts.add("$${"%.2f".format(terms.fixedCostCents / 100.0)} fixed")
    return if (parts.isEmpty()) "No cost" else parts.joinToString(", ")
}

private fun fmtPct(v: Double): String =
    if (v == v.toLong().toDouble()) v.toLong().toString() else v.toString()
