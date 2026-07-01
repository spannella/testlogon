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
import com.testlogon.android.data.adminops.RiskDashboardData

object RiskTestTags {
    const val SCREEN = "adminops_risk_screen"
    const val CONTENT = "adminops_risk_content"
    const val FORBIDDEN = "adminops_risk_forbidden"
    const val RETRY = "adminops_risk_retry"
}

@Composable
fun RiskRoute(
    onBack: () -> Unit,
    viewModel: RiskViewModel = hiltViewModel(),
) {
    val state by viewModel.state.collectAsStateWithLifecycle()
    val branch = when (state) {
        is RiskUiState.Loading -> AdminOpsBranch.Loading
        is RiskUiState.Forbidden -> AdminOpsBranch.Forbidden
        is RiskUiState.Error -> AdminOpsBranch.Error((state as RiskUiState.Error).type)
        is RiskUiState.Content -> AdminOpsBranch.Content((state as RiskUiState.Content).isRefreshing)
    }
    AdminOpsDashboardScaffold(
        title = "Risk dashboard",
        branch = branch,
        onBack = onBack,
        onRefresh = viewModel::refresh,
        onRetry = viewModel::retry,
        screenTag = RiskTestTags.SCREEN,
        forbiddenTag = RiskTestTags.FORBIDDEN,
        retryTag = RiskTestTags.RETRY,
        forbiddenBody = "You need platform-admin access to view risk scoring.",
    ) {
        (state as? RiskUiState.Content)?.let { RiskContent(it.data) }
    }
}

@Composable
private fun RiskContent(data: RiskDashboardData) {
    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(16.dp)
            .testTag(RiskTestTags.CONTENT),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        KpiGrid(
            tiles = listOf(
                "Total scored" to data.distribution.totalScored.toString(),
                "Auto approve" to pct(data.distribution.autoApproveRate),
                "Auto escalate" to pct(data.distribution.autoEscalateRate),
            ),
        )

        if (data.distribution.distribution.isNotEmpty()) {
            CardSection("Tier distribution") {
                listOf("low", "medium", "high", "critical").forEach { tier ->
                    val n = data.distribution.distribution[tier]
                    if (n != null) StatRow(tier.replaceFirstChar { it.uppercase() }, n.toString())
                }
                data.distribution.distribution
                    .filterKeys { it !in setOf("low", "medium", "high", "critical") }
                    .forEach { (k, v) -> StatRow(k.replaceFirstChar { it.uppercase() }, v.toString()) }
            }
        }

        SectionHeader("High-risk users")
        if (data.highRisk.isEmpty()) {
            Text("No high-risk users.", style = MaterialTheme.typography.bodyMedium)
        }
        data.highRisk.forEach { u ->
            CardSection(u.userSub.ifBlank { "unknown" }) {
                StatRow("Score", u.totalScore.toString())
                StatRow("Tier", u.riskTier.ifBlank { "-" })
                if (u.modelVersion.isNotBlank()) StatRow("Model", u.modelVersion)
                if (u.createdAt > 0) StatRow("Scored", relativeSeconds(u.createdAt))
            }
        }
    }
}
