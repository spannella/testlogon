@file:OptIn(androidx.compose.material3.ExperimentalMaterial3Api::class, androidx.compose.foundation.layout.ExperimentalLayoutApi::class)

package com.testlogon.android.feature.adminops

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.FilterChip
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateListOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.Lock
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.testlogon.android.data.adminops.AUDIT_EXPORT_CATEGORIES
import com.testlogon.android.data.adminops.AUDIT_EXPORT_FORMATS
import com.testlogon.android.data.adminops.AuditExportDto

object AuditExportsTestTags {
    const val SCREEN = "adminops_audit_screen"
    const val CONTENT = "adminops_audit_content"
    const val FORBIDDEN = "adminops_audit_forbidden"
    const val RETRY = "adminops_audit_retry"
    const val CREATE = "adminops_audit_create"
    fun category(c: String) = "adminops_audit_cat_$c"
    fun format(f: String) = "adminops_audit_fmt_$f"
}

@Composable
fun AuditExportsRoute(
    onBack: () -> Unit,
    viewModel: AuditExportsViewModel = hiltViewModel(),
) {
    val state by viewModel.state.collectAsStateWithLifecycle()
    val snackbar = remember { SnackbarHostState() }
    val content = state as? AuditExportsUiState.Content
    LaunchedEffect(content?.actionMessage) {
        content?.actionMessage?.let {
            snackbar.showSnackbar(it)
            viewModel.clearActionMessage()
        }
    }
    val branch = when (state) {
        is AuditExportsUiState.Loading -> AdminOpsBranch.Loading
        is AuditExportsUiState.Forbidden -> AdminOpsBranch.Forbidden
        is AuditExportsUiState.Error -> AdminOpsBranch.Error((state as AuditExportsUiState.Error).type)
        is AuditExportsUiState.Content -> AdminOpsBranch.Content((state as AuditExportsUiState.Content).isRefreshing)
    }
    androidx.compose.material3.Scaffold(
        modifier = Modifier.testTag(AuditExportsTestTags.SCREEN),
        snackbarHost = { SnackbarHost(snackbar) },
        topBar = {
            androidx.compose.material3.TopAppBar(
                title = { Text("Audit exports") },
                navigationIcon = { AdminOpsBackIcon(onBack) },
            )
        },
    ) { padding ->
        androidx.compose.foundation.layout.Box(modifier = Modifier.fillMaxSize().padding(padding)) {
            androidx.compose.material3.pulltorefresh.PullToRefreshBox(
                isRefreshing = branch.isRefreshing,
                onRefresh = viewModel::refresh,
                modifier = Modifier.fillMaxSize(),
            ) {
                when (state) {
                    is AuditExportsUiState.Loading -> com.testlogon.android.core.ui.state.LoadingState()
                    is AuditExportsUiState.Forbidden -> com.testlogon.android.core.ui.state.EmptyState(
                        modifier = Modifier.testTag(AuditExportsTestTags.FORBIDDEN),
                        title = "Not authorised",
                        body = "Audit exports are restricted to root operators.",
                        imageVector = Icons.Outlined.Lock,
                        actionLabel = "Back",
                        onAction = onBack,
                    )
                    is AuditExportsUiState.Error -> com.testlogon.android.core.ui.state.ErrorState(
                        modifier = Modifier.testTag(AuditExportsTestTags.RETRY),
                        message = adminOpsErrorMessage((state as AuditExportsUiState.Error).type),
                        onRetry = viewModel::retry,
                    )
                    is AuditExportsUiState.Content -> AuditExportsContent(
                        content = state as AuditExportsUiState.Content,
                        onCreate = viewModel::create,
                    )
                }
            }
        }
    }
}

@Composable
private fun AuditExportsContent(
    content: AuditExportsUiState.Content,
    onCreate: (List<String>, String, Long) -> Unit,
) {
    val selectedCats = remember { mutableStateListOf("auth") }
    var selectedFormat by remember { mutableStateOf("ndjson") }
    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(16.dp)
            .testTag(AuditExportsTestTags.CONTENT),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        CardSection("New export (last 30 days)") {
            Text("Categories", style = MaterialTheme.typography.labelMedium)
            FlowRow(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                AUDIT_EXPORT_CATEGORIES.forEach { c ->
                    FilterChip(
                        selected = c in selectedCats,
                        onClick = { if (c in selectedCats) selectedCats.remove(c) else selectedCats.add(c) },
                        label = { Text(c) },
                        modifier = Modifier.testTag(AuditExportsTestTags.category(c)),
                    )
                }
            }
            Text("Format", style = MaterialTheme.typography.labelMedium, modifier = Modifier.padding(top = 8.dp))
            FlowRow(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                AUDIT_EXPORT_FORMATS.forEach { f ->
                    FilterChip(
                        selected = selectedFormat == f,
                        onClick = { selectedFormat = f },
                        label = { Text(f) },
                        modifier = Modifier.testTag(AuditExportsTestTags.format(f)),
                    )
                }
            }
            Button(
                onClick = { onCreate(selectedCats.toList(), selectedFormat, 30) },
                enabled = !content.creating && selectedCats.isNotEmpty(),
                modifier = Modifier.padding(top = 12.dp).testTag(AuditExportsTestTags.CREATE),
            ) { Text(if (content.creating) "Creating…" else "Create export") }
        }

        SectionHeader("Recent exports")
        if (content.exports.isEmpty()) {
            Text("No exports yet.", style = MaterialTheme.typography.bodyMedium)
        }
        content.exports.forEach { e -> ExportCard(e) }
    }
}

@Composable
private fun ExportCard(e: AuditExportDto) {
    CardSection("${e.format.uppercase()} · ${e.status}") {
        StatRow("Categories", e.categories.joinToString(", ").ifBlank { "-" })
        e.eventCount?.let { StatRow("Events", it.toString()) }
        e.fileSizeBytes?.let { StatRow("Size", "${it / 1024} KB") }
        if (e.createdAt > 0) StatRow("Created", relativeSeconds(e.createdAt))
        e.completedAt?.let { if (it > 0) StatRow("Completed", relativeSeconds(it)) }
        e.errorMessage?.takeIf { it.isNotBlank() }?.let { StatRow("Error", it) }
    }
}
