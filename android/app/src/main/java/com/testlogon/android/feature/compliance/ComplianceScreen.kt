@file:OptIn(ExperimentalMaterial3Api::class)

package com.testlogon.android.feature.compliance

import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FilterChip
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Surface
import androidx.compose.material3.Tab
import androidx.compose.material3.TabRow
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
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.testlogon.android.R
import com.testlogon.android.core.ui.state.EmptyState
import com.testlogon.android.core.ui.state.ErrorState
import com.testlogon.android.core.ui.state.LoadingState
import com.testlogon.android.data.compliance.Audit
import com.testlogon.android.data.compliance.Finding
import com.testlogon.android.data.compliance.FindingSeverity
import com.testlogon.android.data.compliance.FindingStatus
import com.testlogon.android.data.compliance.FrameworkStatus

object ComplianceTestTags {
    const val SCREEN = "security_dashboard_screen"
    const val LOADING = "compliance_loading"
    const val ERROR = "compliance_error"
    const val OFFLINE = "compliance_offline"
    const val SESSION_EXPIRED = "compliance_session_expired"
    const val FINDINGS_EMPTY = "findings_empty"
    const val RUN_AUDIT = "run_audit_btn"
    const val FINDING_ROW_PREFIX = "finding_row_"
    const val AUDIT_ROW_PREFIX = "audit_row_"
    const val FRAMEWORK_PREFIX = "framework_"
    const val TRENDS_PANEL = "trends_panel"
}

/**
 * Route-level compliance/security dashboard. [titleRes] lets the same screen serve both the web
 * /agents/compliance and /agents/security entries with the right title.
 */
@Composable
fun ComplianceRoute(
    onBack: () -> Unit,
    onSessionExpired: () -> Unit,
    titleRes: Int,
    modifier: Modifier = Modifier,
    viewModel: ComplianceViewModel = hiltViewModel(),
) {
    val state by viewModel.uiState.collectAsStateWithLifecycle()
    val snackbar = remember { SnackbarHostState() }
    val context = LocalContext.current

    LaunchedEffect(viewModel) {
        viewModel.effects.collect { e ->
            if (e is ComplianceEffect.ShowMessage) snackbar.showSnackbar(context.getString(e.resId))
        }
    }
    LaunchedEffect(state.phase) {
        if (state.phase == CompliancePhase.SessionExpired) onSessionExpired()
    }

    Scaffold(
        modifier = modifier.testTag(ComplianceTestTags.SCREEN),
        snackbarHost = { SnackbarHost(snackbar) },
        topBar = {
            TopAppBar(
                title = { Text(stringResource(titleRes)) },
                navigationIcon = {
                    IconButton(onClick = onBack, modifier = Modifier.testTag("compliance_back")) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = stringResource(R.string.action_back))
                    }
                },
            )
        },
    ) { padding ->
        Box(modifier = Modifier.padding(padding).fillMaxSize()) {
            when (state.phase) {
                CompliancePhase.Loading -> LoadingState(modifier = Modifier.testTag(ComplianceTestTags.LOADING))
                CompliancePhase.Error -> ErrorState(
                    message = state.errorMessage ?: stringResource(R.string.compliance_error_generic),
                    onRetry = viewModel::onRetry,
                    modifier = Modifier.testTag(ComplianceTestTags.ERROR),
                )
                CompliancePhase.Offline -> ErrorState(
                    message = state.errorMessage ?: stringResource(R.string.compliance_error_generic),
                    onRetry = viewModel::onRetry,
                    modifier = Modifier.testTag(ComplianceTestTags.OFFLINE),
                )
                CompliancePhase.SessionExpired -> EmptyState(
                    title = stringResource(R.string.compliance_session_expired_title),
                    body = stringResource(R.string.compliance_session_expired_body),
                    modifier = Modifier.testTag(ComplianceTestTags.SESSION_EXPIRED),
                )
                CompliancePhase.Content -> Content(state, viewModel)
            }
        }
    }
}

@Composable
private fun Content(state: ComplianceUiState, viewModel: ComplianceViewModel) {
    Column(modifier = Modifier.fillMaxSize()) {
        SummaryRow(state)
        val tabs = ComplianceTab.entries
        TabRow(selectedTabIndex = tabs.indexOf(state.tab)) {
            tabs.forEach { t ->
                Tab(
                    selected = state.tab == t,
                    onClick = { viewModel.onSelectTab(t) },
                    text = { Text(stringResource(tabLabel(t))) },
                    modifier = Modifier.testTag("compliance_tab_${t.name.lowercase()}"),
                )
            }
        }
        PullToRefreshBox(
            isRefreshing = state.isRefreshing,
            onRefresh = viewModel::onRefresh,
            modifier = Modifier.fillMaxSize(),
        ) {
            when (state.tab) {
                ComplianceTab.FINDINGS -> FindingsTab(state, viewModel)
                ComplianceTab.AUDITS -> AuditsTab(state, viewModel)
                ComplianceTab.COMPLIANCE -> CompliancePanel(state)
                ComplianceTab.TRENDS -> TrendsTab(state)
            }
        }
    }
}

private fun tabLabel(t: ComplianceTab): Int = when (t) {
    ComplianceTab.FINDINGS -> R.string.compliance_tab_findings
    ComplianceTab.AUDITS -> R.string.compliance_tab_audits
    ComplianceTab.COMPLIANCE -> R.string.compliance_tab_compliance
    ComplianceTab.TRENDS -> R.string.compliance_tab_trends
}

@Composable
private fun SummaryRow(state: ComplianceUiState) {
    val s = state.summary
    Row(
        modifier = Modifier.fillMaxWidth().padding(horizontal = 16.dp, vertical = 8.dp),
        horizontalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        SummaryTile(stringResource(R.string.compliance_open_critical), s?.openCritical ?: 0, Modifier.weight(1f), "summary_critical")
        SummaryTile(stringResource(R.string.compliance_open_high), s?.openHigh ?: 0, Modifier.weight(1f), "summary_high")
        SummaryTile(stringResource(R.string.compliance_total_findings), s?.openTotal ?: 0, Modifier.weight(1f), "summary_total")
        SummaryTile(stringResource(R.string.compliance_frameworks_failing), s?.frameworksFailing ?: 0, Modifier.weight(1f), "summary_frameworks")
    }
}

@Composable
private fun SummaryTile(label: String, value: Int, modifier: Modifier, tag: String) {
    Card(modifier = modifier.testTag(tag)) {
        Column(Modifier.padding(12.dp)) {
            Text(value.toString(), style = MaterialTheme.typography.titleLarge, fontWeight = FontWeight.Bold)
            Text(label, style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
        }
    }
}

@Composable
private fun SeverityBadge(severity: FindingSeverity) {
    val (container, content) = when (severity) {
        FindingSeverity.CRITICAL -> MaterialTheme.colorScheme.errorContainer to MaterialTheme.colorScheme.onErrorContainer
        FindingSeverity.HIGH -> MaterialTheme.colorScheme.tertiaryContainer to MaterialTheme.colorScheme.onTertiaryContainer
        FindingSeverity.MEDIUM -> MaterialTheme.colorScheme.secondaryContainer to MaterialTheme.colorScheme.onSecondaryContainer
        FindingSeverity.LOW, FindingSeverity.INFO, FindingSeverity.UNKNOWN ->
            MaterialTheme.colorScheme.surfaceVariant to MaterialTheme.colorScheme.onSurfaceVariant
    }
    Surface(color = container, contentColor = content, shape = MaterialTheme.shapes.small) {
        Text(
            severity.serverValue,
            style = MaterialTheme.typography.labelSmall,
            fontWeight = FontWeight.SemiBold,
            modifier = Modifier.padding(horizontal = 8.dp, vertical = 2.dp),
        )
    }
}

@Composable
private fun FindingsTab(state: ComplianceUiState, viewModel: ComplianceViewModel) {
    LazyColumn(
        modifier = Modifier.fillMaxSize().testTag("findings_list"),
        contentPadding = PaddingValues(16.dp),
        verticalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        item {
            Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
                Text(stringResource(R.string.compliance_filter_severity), style = MaterialTheme.typography.labelMedium)
                Row(Modifier.fillMaxWidth().horizontalScroll(rememberScrollState()), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    listOf("all", "critical", "high", "medium", "low", "info").forEach { sev ->
                        FilterChip(selected = state.severityFilter == sev, onClick = { viewModel.onSeverityFilter(sev) }, label = { Text(sev) })
                    }
                }
                Text(stringResource(R.string.compliance_filter_status), style = MaterialTheme.typography.labelMedium)
                Row(Modifier.fillMaxWidth().horizontalScroll(rememberScrollState()), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    listOf("all", "open", "acknowledged", "remediated", "false_positive", "accepted_risk").forEach { st ->
                        FilterChip(selected = state.statusFilter == st, onClick = { viewModel.onStatusFilter(st) }, label = { Text(st) })
                    }
                }
            }
        }
        if (state.findings.isEmpty()) {
            item {
                Text(
                    stringResource(R.string.compliance_findings_empty),
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    modifier = Modifier.testTag(ComplianceTestTags.FINDINGS_EMPTY).padding(vertical = 16.dp),
                )
            }
        } else {
            items(state.findings, key = { it.id }) { f ->
                FindingCard(
                    finding = f,
                    expanded = state.expandedFindingId == f.id,
                    onToggle = { viewModel.onToggleExpanded(f.id) },
                    onTransition = { s -> viewModel.onTransitionFinding(f.id, s) },
                )
            }
        }
    }
}

@Composable
private fun FindingCard(finding: Finding, expanded: Boolean, onToggle: () -> Unit, onTransition: (FindingStatus) -> Unit) {
    Card(
        modifier = Modifier.fillMaxWidth().testTag(ComplianceTestTags.FINDING_ROW_PREFIX + finding.id),
        onClick = onToggle,
    ) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                SeverityBadge(finding.severity)
                Text(finding.category, style = MaterialTheme.typography.labelMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
            }
            Text(finding.title, style = MaterialTheme.typography.titleSmall, fontWeight = FontWeight.SemiBold)
            Text(
                stringResource(R.string.compliance_finding_meta, finding.sourceRef.ifBlank { "-" }, finding.status.serverValue),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            if (expanded) {
                if (finding.description.isNotBlank()) {
                    Text(finding.description, style = MaterialTheme.typography.bodyMedium)
                }
                finding.filePath?.let {
                    Text(it + (finding.lineRange?.let { r -> ":$r" } ?: ""), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                }
                finding.codeSnippet?.let {
                    Surface(color = MaterialTheme.colorScheme.surfaceVariant, shape = MaterialTheme.shapes.small) {
                        Text(it, style = MaterialTheme.typography.bodySmall, modifier = Modifier.padding(8.dp))
                    }
                }
                finding.remediation?.let {
                    Text(stringResource(R.string.compliance_remediation, it), style = MaterialTheme.typography.bodySmall)
                }
                finding.remediationTicketId?.let {
                    Text(stringResource(R.string.compliance_ticket, it), style = MaterialTheme.typography.bodySmall)
                }
            }
            if (finding.canTransition) {
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    OutlinedButton(onClick = { onTransition(FindingStatus.ACKNOWLEDGED) }, modifier = Modifier.testTag("ack_${finding.id}")) {
                        Text(stringResource(R.string.compliance_acknowledge))
                    }
                    TextButton(onClick = { onTransition(FindingStatus.FALSE_POSITIVE) }, modifier = Modifier.testTag("fp_${finding.id}")) {
                        Text(stringResource(R.string.compliance_false_positive))
                    }
                }
            }
        }
    }
}

@Composable
private fun AuditsTab(state: ComplianceUiState, viewModel: ComplianceViewModel) {
    val audits = state.audits
    LazyColumn(
        modifier = Modifier.fillMaxSize().testTag("audit_history"),
        contentPadding = PaddingValues(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        item {
            OutlinedButton(
                onClick = viewModel::onTriggerAudit,
                enabled = !state.isTriggeringAudit,
                modifier = Modifier.testTag(ComplianceTestTags.RUN_AUDIT),
            ) {
                Text(stringResource(R.string.compliance_run_audit))
            }
        }
        when {
            audits == null -> item { LoadingState(fullScreen = false) }
            audits.isEmpty() -> item {
                Text(stringResource(R.string.compliance_audits_empty), style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
            }
            else -> items(audits, key = { it.id }) { a -> AuditCard(a) }
        }
    }
}

@Composable
private fun AuditCard(audit: Audit) {
    Card(modifier = Modifier.fillMaxWidth().testTag(ComplianceTestTags.AUDIT_ROW_PREFIX + audit.id)) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
            Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
                Text(audit.id.take(12), style = MaterialTheme.typography.titleSmall, fontWeight = FontWeight.SemiBold)
                Text(audit.status, style = MaterialTheme.typography.labelMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
            }
            Text(stringResource(R.string.compliance_files_scanned, audit.filesScanned), style = MaterialTheme.typography.bodySmall)
            if (audit.totalFindings == 0) {
                Text(stringResource(R.string.compliance_all_clear), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.primary)
            } else {
                Text(
                    audit.findingCounts.joinToString("  ") { "${it.first}:${it.second}" },
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
        }
    }
}

@Composable
private fun CompliancePanel(state: ComplianceUiState) {
    val frameworks = state.frameworks
    LazyColumn(
        modifier = Modifier.fillMaxSize().testTag("compliance_panel"),
        contentPadding = PaddingValues(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        when {
            frameworks == null -> item { LoadingState(fullScreen = false) }
            frameworks.isEmpty() -> item {
                Text(stringResource(R.string.compliance_no_data), style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
            }
            else -> items(frameworks, key = { it.key }) { fw -> FrameworkCard(fw) }
        }
    }
}

@Composable
private fun FrameworkCard(fw: FrameworkStatus) {
    Card(
        modifier = Modifier.fillMaxWidth().testTag(ComplianceTestTags.FRAMEWORK_PREFIX + fw.key),
        colors = CardDefaults.cardColors(
            containerColor = if (fw.passing) MaterialTheme.colorScheme.surface else MaterialTheme.colorScheme.errorContainer,
        ),
    ) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
            Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween, verticalAlignment = Alignment.CenterVertically) {
                Text(fw.name, style = MaterialTheme.typography.titleSmall, fontWeight = FontWeight.SemiBold)
                Text(fw.statusLabel, style = MaterialTheme.typography.labelMedium)
            }
            Text(stringResource(R.string.compliance_open_findings_n, fw.openFindings), style = MaterialTheme.typography.bodySmall)
        }
    }
}

@Composable
private fun TrendsTab(state: ComplianceUiState) {
    val trends = state.trends
    Column(modifier = Modifier.fillMaxSize().padding(16.dp).testTag(ComplianceTestTags.TRENDS_PANEL), verticalArrangement = Arrangement.spacedBy(12.dp)) {
        when {
            trends == null -> LoadingState(fullScreen = false)
            else -> {
                Text(
                    stringResource(R.string.compliance_trends_summary, trends.total, trends.days),
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                if (trends.weeks.isEmpty()) {
                    Text(stringResource(R.string.compliance_no_trend_data), style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
                } else {
                    trends.weeks.forEach { w ->
                        Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
                            Text(java.text.SimpleDateFormat("MMM d", java.util.Locale.getDefault()).format(java.util.Date(w.weekStartSeconds * 1000L)), style = MaterialTheme.typography.bodySmall)
                            Text(w.total.toString(), style = MaterialTheme.typography.bodySmall, fontWeight = FontWeight.Medium)
                        }
                    }
                }
            }
        }
    }
}
