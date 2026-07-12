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
import com.testlogon.android.data.adminops.RateLimitsDashboardData

object RateLimitsTestTags {
    const val SCREEN = "adminops_ratelimits_screen"
    const val CONTENT = "adminops_ratelimits_content"
    const val FORBIDDEN = "adminops_ratelimits_forbidden"
    const val RETRY = "adminops_ratelimits_retry"
}

@Composable
fun RateLimitsRoute(
    onBack: () -> Unit,
    viewModel: RateLimitsViewModel = hiltViewModel(),
) {
    val state by viewModel.state.collectAsStateWithLifecycle()
    val branch = when (state) {
        is RateLimitsUiState.Loading -> AdminOpsBranch.Loading
        is RateLimitsUiState.Forbidden -> AdminOpsBranch.Forbidden
        is RateLimitsUiState.Error -> AdminOpsBranch.Error((state as RateLimitsUiState.Error).type)
        is RateLimitsUiState.Content -> AdminOpsBranch.Content((state as RateLimitsUiState.Content).isRefreshing)
    }
    AdminOpsDashboardScaffold(
        title = "Rate limits",
        branch = branch,
        onBack = onBack,
        onRefresh = viewModel::refresh,
        onRetry = viewModel::retry,
        screenTag = RateLimitsTestTags.SCREEN,
        forbiddenTag = RateLimitsTestTags.FORBIDDEN,
        retryTag = RateLimitsTestTags.RETRY,
        forbiddenBody = "Rate-limit administration is restricted to root operators.",
    ) {
        (state as? RateLimitsUiState.Content)?.let { RateLimitsContent(it.data) }
    }
}

@Composable
private fun RateLimitsContent(data: RateLimitsDashboardData) {
    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(16.dp)
            .testTag(RateLimitsTestTags.CONTENT),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        KpiGrid(
            tiles = listOf(
                "Hits (${data.liveSummary.windowHours}h)" to data.liveSummary.totalHits.toString(),
                "Groups" to data.config.groups.size.toString(),
            ),
        )

        CardSection("Global IP limit") {
            StatRow("Enabled", if (data.config.globalIp.enabled) "yes" else "no")
            StatRow("Window", "${data.config.globalIp.windowSeconds}s")
            StatRow("Max requests", data.config.globalIp.maxRequests.toString())
        }

        if (data.liveSummary.byGroup.isNotEmpty()) {
            CardSection("Hits by group") {
                data.liveSummary.byGroup.entries.sortedByDescending { it.value }.forEach { (g, c) ->
                    StatRow(g, c.toString())
                }
            }
        }

        SectionHeader("Endpoint groups")
        data.config.groups.entries.sortedBy { it.key }.forEach { (name, g) ->
            CardSection("$name${if (g.isOverride) " (override)" else ""}") {
                if (g.description.isNotBlank()) StatRow("Description", g.description)
                StatRow("Window", "${g.windowSeconds}s")
                StatRow("Per user", g.maxRequestsPerUser.toString())
                StatRow("Per IP", g.maxRequestsPerIp.toString())
            }
        }

        SectionHeader("Top offenders")
        if (data.offenders.topIps.isEmpty() && data.offenders.topUsers.isEmpty()) {
            Text("No offenders in range.", style = MaterialTheme.typography.bodyMedium)
        }
        if (data.offenders.topIps.isNotEmpty()) {
            CardSection("By IP") {
                data.offenders.topIps.forEach { o -> StatRow(o.ip, "${o.rejectedCount} rejected") }
            }
        }
        if (data.offenders.topUsers.isNotEmpty()) {
            CardSection("By user") {
                data.offenders.topUsers.forEach { o -> StatRow(o.userSub, "${o.rejectedCount} rejected") }
            }
        }
    }
}
