@file:OptIn(ExperimentalMaterial3Api::class)

package com.testlogon.android.feature.licenses.compliance

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.LazyRow
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.outlined.Verified
import androidx.compose.material3.AssistChip
import androidx.compose.material3.AssistChipDefaults
import androidx.compose.material3.Card
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.ModalBottomSheet
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.pulltorefresh.PullToRefreshBox
import androidx.compose.material3.rememberModalBottomSheetState
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
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
import com.testlogon.android.data.licenses.ComplianceDetail
import com.testlogon.android.data.licenses.ComplianceItem
import com.testlogon.android.data.licenses.ComplianceSummary

object ComplianceTestTags {
    const val SCREEN = "compliance_screen"
    const val LIST = "compliance_list"
    const val LOADING = "compliance_loading"
    const val EMPTY = "compliance_empty"
    const val ERROR = "compliance_error"
    const val SUMMARY = "compliance_summary"
    const val ROW_PREFIX = "compliance_row_"
    const val FILTER_PREFIX = "compliance_filter_"
    const val DETAIL_SHEET = "compliance_detail_sheet"
    const val CHECK_NOW = "compliance_check_now"
    const val REPORT = "compliance_report"
}

val COMPLIANCE_STATUSES = listOf(
    "compliant",
    "expiring_soon",
    "license_expired",
    "license_revoked",
    "flagged",
    "under_review",
    "action_required",
    "removed",
    "resolved",
)

@Composable
fun ComplianceRoute(
    onBack: () -> Unit,
    modifier: Modifier = Modifier,
    viewModel: ComplianceViewModel = hiltViewModel(),
) {
    val state by viewModel.uiState.collectAsStateWithLifecycle()
    val snackbarHostState = remember { SnackbarHostState() }
    val context = LocalContext.current

    LaunchedEffect(viewModel) {
        viewModel.effects.collect { msg ->
            snackbarHostState.showSnackbar(context.getString(msg))
        }
    }

    ComplianceScreen(
        state = state,
        onBack = onBack,
        onRefresh = viewModel::refresh,
        onRetry = viewModel::refresh,
        onSelectStatus = viewModel::selectStatus,
        onOpenDetail = viewModel::openDetail,
        onCloseDetail = viewModel::closeDetail,
        onCheckNow = viewModel::checkNow,
        onOpenFlag = viewModel::openFlag,
        onCloseFlag = viewModel::closeFlag,
        onSubmitFlag = viewModel::submitFlag,
        snackbarHostState = snackbarHostState,
        modifier = modifier,
    )
}

@Composable
fun ComplianceScreen(
    state: ComplianceUiState,
    onBack: () -> Unit,
    onRefresh: () -> Unit,
    onRetry: () -> Unit,
    onSelectStatus: (String) -> Unit,
    onOpenDetail: (String) -> Unit,
    onCloseDetail: () -> Unit,
    onCheckNow: (String) -> Unit,
    onOpenFlag: () -> Unit,
    onCloseFlag: () -> Unit,
    onSubmitFlag: (contentId: String, reason: String, evidence: String) -> Unit,
    modifier: Modifier = Modifier,
    snackbarHostState: SnackbarHostState = remember { SnackbarHostState() },
) {
    Scaffold(
        modifier = modifier.testTag(ComplianceTestTags.SCREEN),
        snackbarHost = { SnackbarHost(snackbarHostState) },
        topBar = {
            TopAppBar(
                title = { Text("My Compliance") },
                navigationIcon = {
                    IconButton(onClick = onBack, modifier = Modifier.testTag("compliance_back")) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Back")
                    }
                },
                actions = {
                    TextButton(onClick = onOpenFlag, modifier = Modifier.testTag(ComplianceTestTags.REPORT)) {
                        Text("Report")
                    }
                },
            )
        },
    ) { padding ->
        Box(modifier = Modifier.padding(padding).fillMaxSize()) {
            when (state.phase) {
                ComplianceUiState.Phase.Loading ->
                    LoadingState(modifier = Modifier.testTag(ComplianceTestTags.LOADING))

                ComplianceUiState.Phase.Error ->
                    ErrorState(
                        message = state.errorMessage ?: "Could not load compliance.",
                        onRetry = onRetry,
                        modifier = Modifier.testTag(ComplianceTestTags.ERROR),
                    )

                ComplianceUiState.Phase.Empty ->
                    PullToRefreshBox(
                        isRefreshing = state.isRefreshing,
                        onRefresh = onRefresh,
                        modifier = Modifier.fillMaxSize(),
                    ) {
                        Column(modifier = Modifier.fillMaxSize().verticalScroll(rememberScrollState())) {
                            SummaryCards(state.summary)
                            StatusFilterRow(state.statusFilter, onSelectStatus)
                            EmptyState(
                                title = "No tracked content yet",
                                body = "Licensing health of your content will appear here.",
                                imageVector = Icons.Outlined.Verified,
                                modifier = Modifier
                                    .fillMaxWidth()
                                    .padding(top = 48.dp)
                                    .testTag(ComplianceTestTags.EMPTY),
                            )
                        }
                    }

                ComplianceUiState.Phase.Content ->
                    PullToRefreshBox(
                        isRefreshing = state.isRefreshing,
                        onRefresh = onRefresh,
                        modifier = Modifier.fillMaxSize(),
                    ) {
                        LazyColumn(
                            modifier = Modifier.fillMaxSize().testTag(ComplianceTestTags.LIST),
                            contentPadding = PaddingValues(bottom = 16.dp),
                        ) {
                            item { SummaryCards(state.summary) }
                            item { StatusFilterRow(state.statusFilter, onSelectStatus) }
                            items(state.items, key = { it.contentId }) { item ->
                                ComplianceRow(item, onClick = { onOpenDetail(item.contentId) })
                                HorizontalDivider()
                            }
                        }
                    }
            }
        }
    }

    val detailId = state.detailContentId
    if (detailId != null) {
        ComplianceDetailSheet(
            contentId = detailId,
            detail = state.detail,
            isLoading = state.detailLoading,
            isChecking = state.isChecking,
            onCheckNow = { onCheckNow(detailId) },
            onDismiss = onCloseDetail,
        )
    }

    if (state.flagOpen) {
        FlagContentDialog(
            isSubmitting = state.isFlagging,
            onDismiss = onCloseFlag,
            onSubmit = onSubmitFlag,
        )
    }
}

@Composable
private fun SummaryCards(summary: ComplianceSummary) {
    val cards = listOf(
        "Tracked" to summary.total,
        "Compliant" to summary.compliant,
        "Expiring" to summary.expiringSoon,
        "Issues" to summary.issues,
        "Flagged" to summary.flagged,
    )
    LazyRow(
        modifier = Modifier
            .fillMaxWidth()
            .padding(horizontal = 12.dp, vertical = 8.dp)
            .testTag(ComplianceTestTags.SUMMARY),
        horizontalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        items(cards, key = { it.first }) { (label, value) ->
            Card {
                Column(modifier = Modifier.padding(16.dp)) {
                    Text(
                        label,
                        style = MaterialTheme.typography.labelMedium,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                    Text(
                        value.toString(),
                        style = MaterialTheme.typography.headlineSmall,
                        fontWeight = FontWeight.SemiBold,
                    )
                }
            }
        }
    }
}

@Composable
private fun StatusFilterRow(selected: String, onSelect: (String) -> Unit) {
    val options = listOf("all") + COMPLIANCE_STATUSES
    LazyRow(
        modifier = Modifier.fillMaxWidth().padding(horizontal = 8.dp, vertical = 4.dp),
        horizontalArrangement = Arrangement.spacedBy(8.dp),
        contentPadding = PaddingValues(horizontal = 4.dp),
    ) {
        items(options, key = { it }) { opt ->
            val isSel = opt == selected
            AssistChip(
                onClick = { onSelect(opt) },
                label = { Text(if (opt == "all") "All" else opt.replace('_', ' ')) },
                modifier = Modifier.testTag(ComplianceTestTags.FILTER_PREFIX + opt),
                colors = if (isSel) {
                    AssistChipDefaults.assistChipColors(
                        containerColor = MaterialTheme.colorScheme.secondaryContainer,
                    )
                } else {
                    AssistChipDefaults.assistChipColors()
                },
            )
        }
    }
}

@Composable
private fun ComplianceRow(item: ComplianceItem, onClick: () -> Unit) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .testTag(ComplianceTestTags.ROW_PREFIX + item.contentId)
            .padding(horizontal = 16.dp, vertical = 14.dp),
        horizontalArrangement = Arrangement.SpaceBetween,
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Column(modifier = Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(2.dp)) {
            Text(item.contentId, style = MaterialTheme.typography.bodyLarge, fontWeight = FontWeight.SemiBold)
            val meta = listOf(item.typeLabel(), "${item.issueCount} issues", item.formattedLastChecked())
                .filter { it.isNotBlank() }
                .joinToString("  -  ")
            if (meta.isNotBlank()) {
                Text(meta, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
            }
        }
        AssistChip(onClick = onClick, label = { Text(item.statusLabel().ifBlank { "Unknown" }) })
    }
}

@Composable
private fun ComplianceDetailSheet(
    contentId: String,
    detail: ComplianceDetail?,
    isLoading: Boolean,
    isChecking: Boolean,
    onCheckNow: () -> Unit,
    onDismiss: () -> Unit,
) {
    val sheetState = rememberModalBottomSheetState(skipPartiallyExpanded = true)
    ModalBottomSheet(
        onDismissRequest = onDismiss,
        sheetState = sheetState,
        modifier = Modifier.testTag(ComplianceTestTags.DETAIL_SHEET),
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 20.dp)
                .padding(bottom = 32.dp)
                .verticalScroll(rememberScrollState()),
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            Text("Compliance Detail", style = MaterialTheme.typography.titleLarge)
            Text(contentId, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
            Row(
                modifier = Modifier.fillMaxWidth(),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                Text("Status:", style = MaterialTheme.typography.bodyMedium)
                Text(
                    detail?.statusLabel()?.ifBlank { "No record yet" } ?: "No record yet",
                    style = MaterialTheme.typography.bodyMedium,
                    fontWeight = FontWeight.SemiBold,
                    modifier = Modifier.weight(1f),
                )
                OutlinedButton(
                    onClick = onCheckNow,
                    enabled = !isChecking,
                    modifier = Modifier.testTag(ComplianceTestTags.CHECK_NOW),
                ) { Text(if (isChecking) "Checking..." else "Check Now") }
            }
            if (isLoading) {
                MutedText("Loading...")
            } else if (detail != null) {
                SectionHeader("License References")
                if (detail.refs.isEmpty()) {
                    MutedText("No license references on this content.")
                } else {
                    detail.refs.forEach { ref ->
                        Card(modifier = Modifier.fillMaxWidth()) {
                            Column(modifier = Modifier.padding(12.dp)) {
                                Text(ref.licenseId, style = MaterialTheme.typography.bodyMedium)
                                val expires = ref.formattedExpires().let { if (it.isBlank()) "" else "expires $it" }
                                val m = listOf(ref.typeLabel(), ref.statusLabel(), expires)
                                    .filter { it.isNotBlank() }
                                    .joinToString("  -  ")
                                if (m.isNotBlank()) MutedText(m)
                            }
                        }
                    }
                }
                SectionHeader("Issues")
                if (detail.issues.isEmpty()) {
                    MutedText("No issues.")
                } else {
                    detail.issues.forEach { iss ->
                        val detailText = if (iss.detail.isNotBlank()) " - ${iss.detail}" else ""
                        Text("- ${iss.type}$detailText", style = MaterialTheme.typography.bodyMedium)
                    }
                }
                SectionHeader("Flags")
                if (detail.flags.isEmpty()) {
                    MutedText("No flags.")
                } else {
                    detail.flags.forEach { f ->
                        Card(modifier = Modifier.fillMaxWidth()) {
                            Column(modifier = Modifier.padding(12.dp)) {
                                Row(
                                    modifier = Modifier.fillMaxWidth(),
                                    horizontalArrangement = Arrangement.SpaceBetween,
                                ) {
                                    Text(f.reasonLabel(), fontWeight = FontWeight.Medium)
                                    Text(f.statusLabel(), color = MaterialTheme.colorScheme.onSurfaceVariant)
                                }
                                if (f.evidence.isNotBlank()) MutedText(f.evidence)
                                if (f.resolutionNotes.isNotBlank()) {
                                    Text("Resolution: ${f.resolutionNotes}", style = MaterialTheme.typography.bodySmall)
                                }
                            }
                        }
                    }
                }
            } else {
                MutedText("Could not load details.")
            }
        }
    }
}

@Composable
private fun SectionHeader(text: String) {
    Text(text, style = MaterialTheme.typography.titleSmall, fontWeight = FontWeight.SemiBold)
}

@Composable
private fun MutedText(text: String) {
    Text(text, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
}
