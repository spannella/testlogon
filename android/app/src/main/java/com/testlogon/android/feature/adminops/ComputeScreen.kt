@file:OptIn(androidx.compose.material3.ExperimentalMaterial3Api::class)

package com.testlogon.android.feature.adminops

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.testlogon.android.data.adminops.ComputeDashboardData

object ComputeTestTags {
    const val SCREEN = "adminops_compute_screen"
    const val CONTENT = "adminops_compute_content"
    const val FORBIDDEN = "adminops_compute_forbidden"
    const val RETRY = "adminops_compute_retry"
}

@Composable
fun ComputeRoute(
    onBack: () -> Unit,
    viewModel: ComputeViewModel = hiltViewModel(),
) {
    val state by viewModel.state.collectAsStateWithLifecycle()
    val branch = when (state) {
        is ComputeUiState.Loading -> AdminOpsBranch.Loading
        is ComputeUiState.Forbidden -> AdminOpsBranch.Forbidden
        is ComputeUiState.Error -> AdminOpsBranch.Error((state as ComputeUiState.Error).type)
        is ComputeUiState.Content -> AdminOpsBranch.Content((state as ComputeUiState.Content).isRefreshing)
    }
    AdminOpsDashboardScaffold(
        title = "Compute dashboard",
        branch = branch,
        onBack = onBack,
        onRefresh = viewModel::refresh,
        onRetry = viewModel::retry,
        screenTag = ComputeTestTags.SCREEN,
        forbiddenTag = ComputeTestTags.FORBIDDEN,
        retryTag = ComputeTestTags.RETRY,
        forbiddenBody = "You need platform-admin access to view compute.",
    ) {
        (state as? ComputeUiState.Content)?.let { ComputeContent(it.data) }
    }
}

@Composable
private fun ComputeContent(data: ComputeDashboardData) {
    val s = data.spending
    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(16.dp)
            .testTag(ComputeTestTags.CONTENT),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        if (s.month.isNotBlank()) {
            Text(
                text = "Month ${s.month}",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
        KpiGrid(
            tiles = listOf(
                "Total spend" to cents(s.totalCents),
                "EC2 spend" to cents(s.ec2TotalCents),
                "K8s spend" to cents(s.k8sTotalCents),
                "Active users" to s.activeUserCount.toString(),
                "Instances" to s.activeInstanceCount.toString(),
                "Pods" to s.activePodCount.toString(),
            ),
        )

        if (data.instanceTypes.isNotEmpty()) {
            CardSection("Instance types") {
                data.instanceTypes.forEach { t ->
                    StatRow(t.instanceType, "${t.runningCount} running · ${t.totalLaunched} launched")
                }
            }
        }

        if (data.perUser.isNotEmpty()) {
            CardSection("Top spenders") {
                data.perUser.forEach { u ->
                    StatRow(
                        label = "${u.userSub} · ${u.instanceCount}i/${u.podCount}p",
                        value = cents(u.totalCents),
                    )
                }
            }
        }

        SectionHeader("Running instances (${data.instanceCount})")
        if (data.instances.isEmpty()) {
            Text("No instances running.", style = MaterialTheme.typography.bodyMedium)
        }
        data.instances.forEach { i ->
            CardSection("${i.label.ifBlank { i.instanceId }} · ${i.status}") {
                StatRow("User", i.userSub)
                StatRow("Type", i.instanceType)
                if (i.publicIp.isNotBlank()) StatRow("Public IP", i.publicIp)
                if (i.createdAt > 0) StatRow("Created", relativeSeconds(i.createdAt))
            }
        }

        SectionHeader("Running pods (${data.podCount})")
        if (data.pods.isEmpty()) {
            Text("No pods running.", style = MaterialTheme.typography.bodyMedium)
        }
        data.pods.forEach { p ->
            CardSection("${p.label.ifBlank { p.podId }} · ${p.status}") {
                StatRow("User", p.userSub)
                StatRow("Preset", p.preset)
                if (p.createdAt > 0) StatRow("Created", relativeSeconds(p.createdAt))
            }
        }
    }
}
