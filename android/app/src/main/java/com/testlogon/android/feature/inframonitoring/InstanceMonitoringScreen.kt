@file:OptIn(androidx.compose.material3.ExperimentalMaterial3Api::class)

package com.testlogon.android.feature.inframonitoring

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.outlined.Lock
import androidx.compose.material.icons.outlined.Monitor
import androidx.compose.material3.Card
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
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
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.testlogon.android.core.ui.state.EmptyState
import com.testlogon.android.core.ui.state.ErrorState
import com.testlogon.android.core.ui.state.LoadingState
import com.testlogon.android.data.infraec2.Ec2InstanceDto
import com.testlogon.android.data.inframonitoring.InstanceHealthDto
import com.testlogon.android.feature.charts.ChartGeometryCore
import com.testlogon.android.feature.charts.SeriesChartType
import com.testlogon.android.feature.charts.TestLogonSeriesChart
import com.testlogon.android.feature.infracommon.infraErrorMessage
import com.testlogon.android.feature.infracommon.statusColor

object InstanceMonitoringTestTags {
    const val SCREEN = "monitoring_screen"
    const val PICKER = "monitoring_picker"
    const val EMPTY = "monitoring_empty"
    const val FORBIDDEN = "monitoring_forbidden"
    const val ERROR_RETRY = "monitoring_error_retry"
    const val DETAIL = "monitoring_detail"
    const val CPU_CHART = "monitoring_cpu_chart"
    const val MEM_CHART = "monitoring_mem_chart"
    fun pick(id: String) = "monitoring_pick_$id"
}

@Composable
fun InstanceMonitoringRoute(
    onBack: () -> Unit,
    viewModel: InstanceMonitoringViewModel = hiltViewModel(),
) {
    val state by viewModel.state.collectAsStateWithLifecycle()
    InstanceMonitoringScreen(
        state = state,
        onBack = onBack,
        onRetry = viewModel::retry,
        onSelect = viewModel::select,
        onClearSelection = viewModel::clearSelection,
        onRefreshDetail = viewModel::refreshDetail,
    )
}

@Composable
fun InstanceMonitoringScreen(
    state: MonitoringUiState,
    onBack: () -> Unit,
    onRetry: () -> Unit,
    onSelect: (String) -> Unit,
    onClearSelection: () -> Unit,
    onRefreshDetail: () -> Unit,
    modifier: Modifier = Modifier,
) {
    val showingDetail = state.selectedInstanceId != null
    Scaffold(
        modifier = modifier.testTag(InstanceMonitoringTestTags.SCREEN),
        topBar = {
            TopAppBar(
                title = { Text(if (showingDetail) "Instance metrics" else "Monitoring") },
                navigationIcon = {
                    IconButton(onClick = { if (showingDetail) onClearSelection() else onBack() }) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Back")
                    }
                },
            )
        },
    ) { padding ->
        if (showingDetail) {
            DetailContent(
                state = state,
                onRetry = onRetry,
                onRefresh = onRefreshDetail,
                modifier = Modifier.fillMaxSize().padding(padding),
            )
        } else {
            PickerContent(
                state = state,
                onRetry = onRetry,
                onBack = onBack,
                onSelect = onSelect,
                modifier = Modifier.fillMaxSize().padding(padding),
            )
        }
    }
}

@Composable
private fun PickerContent(
    state: MonitoringUiState,
    onRetry: () -> Unit,
    onBack: () -> Unit,
    onSelect: (String) -> Unit,
    modifier: Modifier = Modifier,
) {
    when (val p = state.picker) {
        is MonitoringPickerState.Loading -> LoadingState(modifier = modifier)
        is MonitoringPickerState.Empty -> EmptyState(
            modifier = modifier.testTag(InstanceMonitoringTestTags.EMPTY),
            title = "No instances",
            body = "Launch an instance to monitor its metrics.",
            imageVector = Icons.Outlined.Monitor,
        )
        is MonitoringPickerState.Forbidden -> EmptyState(
            modifier = modifier.testTag(InstanceMonitoringTestTags.FORBIDDEN),
            title = "Not authorised",
            body = "You do not have access to monitoring.",
            imageVector = Icons.Outlined.Lock,
            actionLabel = "Back",
            onAction = onBack,
        )
        is MonitoringPickerState.Error -> ErrorState(
            modifier = modifier.testTag(InstanceMonitoringTestTags.ERROR_RETRY),
            message = infraErrorMessage(p.type),
            onRetry = onRetry,
        )
        is MonitoringPickerState.Ready -> LazyColumn(
            modifier = modifier.testTag(InstanceMonitoringTestTags.PICKER),
            contentPadding = PaddingValues(16.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            items(items = p.instances, key = { it.instanceId }) { inst ->
                InstancePickRow(inst, onClick = { onSelect(inst.instanceId) })
            }
        }
    }
}

@Composable
private fun InstancePickRow(instance: Ec2InstanceDto, onClick: () -> Unit) {
    Card(
        onClick = onClick,
        modifier = Modifier.fillMaxWidth().testTag(InstanceMonitoringTestTags.pick(instance.instanceId)),
    ) {
        Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
            Text(instance.label.ifBlank { instance.instanceId }, style = MaterialTheme.typography.titleSmall, maxLines = 1, overflow = TextOverflow.Ellipsis)
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                Text(instance.instanceType, style = MaterialTheme.typography.labelMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
                Text(instance.status, style = MaterialTheme.typography.labelMedium, color = statusColor(instance.status))
            }
        }
    }
}

@Composable
private fun DetailContent(
    state: MonitoringUiState,
    onRetry: () -> Unit,
    onRefresh: () -> Unit,
    modifier: Modifier = Modifier,
) {
    when (val d = state.detail) {
        is MonitoringDetailState.Idle, is MonitoringDetailState.Loading -> LoadingState(modifier = modifier)
        is MonitoringDetailState.Error -> ErrorState(
            modifier = modifier.testTag(InstanceMonitoringTestTags.ERROR_RETRY),
            message = infraErrorMessage(d.type),
            onRetry = onRetry,
        )
        is MonitoringDetailState.Loaded -> PullToRefreshBox(
            isRefreshing = false,
            onRefresh = onRefresh,
            modifier = modifier,
        ) {
            Column(
                modifier = Modifier
                    .fillMaxSize()
                    .verticalScroll(rememberScrollState())
                    .padding(16.dp)
                    .testTag(InstanceMonitoringTestTags.DETAIL),
                verticalArrangement = Arrangement.spacedBy(16.dp),
            ) {
                HealthCard(d.snapshot.health)
                if (d.snapshot.series.isEmpty()) {
                    Text("No metric datapoints yet.", color = MaterialTheme.colorScheme.onSurfaceVariant)
                } else {
                    MetricChartCard("CPU %", d.snapshot.series.map { it.cpuPct.toLong() }, InstanceMonitoringTestTags.CPU_CHART)
                    MetricChartCard("Memory %", d.snapshot.series.map { it.memPct.toLong() }, InstanceMonitoringTestTags.MEM_CHART)
                    MetricChartCard("Disk %", d.snapshot.series.map { it.diskPct.toLong() }, "monitoring_disk_chart")
                }
            }
        }
    }
}

@Composable
private fun HealthCard(health: InstanceHealthDto) {
    Card(modifier = Modifier.fillMaxWidth()) {
        Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                Text("Health", style = MaterialTheme.typography.titleMedium)
                Text(
                    health.healthStatus.replaceFirstChar { it.uppercase() },
                    style = MaterialTheme.typography.titleSmall,
                    color = statusColor(health.healthStatus),
                )
            }
            Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
                Metric("CPU", "${health.cpuPct}%")
                Metric("Mem", "${health.memPct}%")
                Metric("Disk", "${health.diskPct}%")
                Metric("Points", "${health.datapoints}")
            }
            if (health.instanceType.isNotBlank() || health.instanceStatus.isNotBlank()) {
                Text(
                    "${health.instanceType} · ${health.instanceStatus}",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
            health.reasons.forEach { reason ->
                Text("• $reason", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.error)
            }
        }
    }
}

@Composable
private fun Metric(label: String, value: String) {
    Column(horizontalAlignment = Alignment.CenterHorizontally) {
        Text(value, style = MaterialTheme.typography.titleMedium)
        Text(label, style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
    }
}

@Composable
private fun MetricChartCard(title: String, values: List<Long>, testTag: String) {
    var selectedIndex by remember { mutableStateOf<Int?>(null) }
    Card(modifier = Modifier.fillMaxWidth()) {
        Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            val selectedValue = selectedIndex?.let { values.getOrNull(it) }
            Text(
                if (selectedValue != null) "$title — $selectedValue" else title,
                style = MaterialTheme.typography.labelLarge,
            )
            TestLogonSeriesChart(
                geometry = ChartGeometryCore.compute(values),
                chartType = SeriesChartType.LINE,
                lineColor = MaterialTheme.colorScheme.primary,
                gridColor = MaterialTheme.colorScheme.outlineVariant,
                fillColor = MaterialTheme.colorScheme.primaryContainer,
                selectedColor = MaterialTheme.colorScheme.tertiary,
                selectedIndex = selectedIndex,
                onPointSelected = { selectedIndex = it },
                modifier = Modifier.testTag(testTag),
            )
        }
    }
}
