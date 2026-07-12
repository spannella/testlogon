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
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.testlogon.android.data.adminops.PaymentHealthData
import com.testlogon.android.data.adminops.PaymentHealthProviderDto

object PaymentHealthTestTags {
    const val SCREEN = "adminops_payhealth_screen"
    const val CONTENT = "adminops_payhealth_content"
    const val FORBIDDEN = "adminops_payhealth_forbidden"
    const val RETRY = "adminops_payhealth_retry"
}

@Composable
fun PaymentHealthRoute(
    onBack: () -> Unit,
    viewModel: PaymentHealthViewModel = hiltViewModel(),
) {
    val state by viewModel.state.collectAsStateWithLifecycle()
    val branch = when (state) {
        is PaymentHealthUiState.Loading -> AdminOpsBranch.Loading
        is PaymentHealthUiState.Forbidden -> AdminOpsBranch.Forbidden
        is PaymentHealthUiState.Error -> AdminOpsBranch.Error((state as PaymentHealthUiState.Error).type)
        is PaymentHealthUiState.Content -> AdminOpsBranch.Content((state as PaymentHealthUiState.Content).isRefreshing)
    }
    AdminOpsDashboardScaffold(
        title = "Payment health",
        branch = branch,
        onBack = onBack,
        onRefresh = viewModel::refresh,
        onRetry = viewModel::retry,
        screenTag = PaymentHealthTestTags.SCREEN,
        forbiddenTag = PaymentHealthTestTags.FORBIDDEN,
        retryTag = PaymentHealthTestTags.RETRY,
        forbiddenBody = "You need platform-admin access to view payment provider health.",
    ) {
        (state as? PaymentHealthUiState.Content)?.let { PaymentHealthContent(it.data) }
    }
}

@Composable
private fun PaymentHealthContent(data: PaymentHealthData) {
    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(16.dp)
            .testTag(PaymentHealthTestTags.CONTENT),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        SectionHeader("Providers")
        if (data.providers.isEmpty()) {
            Text("No providers reported.", style = MaterialTheme.typography.bodyMedium)
        }
        data.providers.forEach { p -> ProviderCard(p) }

        SectionHeader("Recent incidents")
        if (data.incidents.isEmpty()) {
            Text("No incidents in range.", style = MaterialTheme.typography.bodyMedium)
        }
        data.incidents.forEach { inc ->
            CardSection("${inc.provider} · ${inc.status}") {
                StatRow("Started", if (inc.startedAt > 0) relativeSeconds(inc.startedAt) else "-")
                StatRow("Ended", inc.endedAt?.let { relativeSeconds(it) } ?: "ongoing")
                StatRow("Peak error rate", bpsPct(inc.peakErrorRate))
                StatRow("Affected webhooks", inc.affectedWebhooks.toString())
            }
        }
    }
}

@Composable
private fun ProviderCard(p: PaymentHealthProviderDto) {
    val statusColor = when (p.status.lowercase()) {
        "healthy" -> Color(0xFF2E7D32)
        "degraded" -> Color(0xFFEF6C00)
        "down" -> MaterialTheme.colorScheme.error
        else -> MaterialTheme.colorScheme.onSurfaceVariant
    }
    CardSection("${p.provider.ifBlank { "unknown" }}${if (!p.enabled) " (disabled)" else ""}") {
        Text(
            text = p.status.ifBlank { "unknown" }.uppercase(),
            style = MaterialTheme.typography.labelLarge,
            color = statusColor,
            modifier = Modifier.padding(bottom = 4.dp),
        )
        StatRow("Success rate", pct(p.successRate))
        StatRow("Error rate", bpsPct(p.errorRateBps))
        StatRow("Avg latency", "${p.avgLatencyMs} ms")
        StatRow("p95 / p99", "${p.p95LatencyMs} / ${p.p99LatencyMs} ms")
        StatRow("Success / failure", "${p.totalSuccess} / ${p.totalFailure}")
        if (p.lastCheckAt > 0) StatRow("Last check", relativeSeconds(p.lastCheckAt))
    }
}
