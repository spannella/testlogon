@file:OptIn(androidx.compose.material3.ExperimentalMaterial3Api::class)

package com.testlogon.android.feature.kycadmin

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
import androidx.lifecycle.ViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.kycadmin.KycAnalyticsAdminRepository
import com.testlogon.android.data.kycadmin.KycAnalyticsData
import com.testlogon.android.feature.adminops.AdminOpsBranch
import com.testlogon.android.feature.adminops.AdminOpsDashboardScaffold
import com.testlogon.android.feature.adminops.AdminOpsErrorType
import com.testlogon.android.feature.adminops.CardSection
import com.testlogon.android.feature.adminops.KpiGrid
import com.testlogon.android.feature.adminops.SectionHeader
import com.testlogon.android.feature.adminops.StatRow
import com.testlogon.android.feature.adminops.adminOpsErrorFor
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import java.util.Locale
import javax.inject.Inject

sealed interface KycAnalyticsUiState {
    data object Loading : KycAnalyticsUiState
    data class Content(val data: KycAnalyticsData, val isRefreshing: Boolean = false) : KycAnalyticsUiState
    data object Forbidden : KycAnalyticsUiState
    data class Error(val type: AdminOpsErrorType) : KycAnalyticsUiState
}

@HiltViewModel
class KycAnalyticsAdminViewModel @Inject constructor(
    private val repo: KycAnalyticsAdminRepository,
) : ViewModel() {

    private val _state = MutableStateFlow<KycAnalyticsUiState>(KycAnalyticsUiState.Loading)
    val state: StateFlow<KycAnalyticsUiState> = _state.asStateFlow()

    init { load(reset = true) }
    fun retry() = load(reset = true)
    fun refresh() {
        (_state.value as? KycAnalyticsUiState.Content)?.let { _state.value = it.copy(isRefreshing = true) }
        load(reset = false)
    }

    private fun load(reset: Boolean) {
        if (reset) _state.value = KycAnalyticsUiState.Loading
        viewModelScope.launch {
            when (val r = repo.load()) {
                is ApiResult.Success -> _state.value = KycAnalyticsUiState.Content(r.data)
                is ApiResult.Failure ->
                    _state.value = if (r.error.status == 403) KycAnalyticsUiState.Forbidden
                    else KycAnalyticsUiState.Error(adminOpsErrorFor(r.error.status))
                is ApiResult.NetworkError -> _state.value = KycAnalyticsUiState.Error(AdminOpsErrorType.NETWORK)
            }
        }
    }
}

object KycAnalyticsTestTags {
    const val SCREEN = "kyc_analytics_screen"
    const val CONTENT = "kyc_analytics_content"
    const val FORBIDDEN = "kyc_analytics_forbidden"
    const val RETRY = "kyc_analytics_retry"
}

private fun pct1(v: Double): String = String.format(Locale.US, "%.1f%%", v)

@Composable
fun KycAnalyticsAdminRoute(
    onBack: () -> Unit,
    viewModel: KycAnalyticsAdminViewModel = hiltViewModel(),
) {
    val state by viewModel.state.collectAsStateWithLifecycle()
    val branch = when (state) {
        is KycAnalyticsUiState.Loading -> AdminOpsBranch.Loading
        is KycAnalyticsUiState.Forbidden -> AdminOpsBranch.Forbidden
        is KycAnalyticsUiState.Error -> AdminOpsBranch.Error((state as KycAnalyticsUiState.Error).type)
        is KycAnalyticsUiState.Content -> AdminOpsBranch.Content((state as KycAnalyticsUiState.Content).isRefreshing)
    }
    AdminOpsDashboardScaffold(
        title = "KYC analytics",
        branch = branch,
        onBack = onBack,
        onRefresh = viewModel::refresh,
        onRetry = viewModel::retry,
        screenTag = KycAnalyticsTestTags.SCREEN,
        forbiddenTag = KycAnalyticsTestTags.FORBIDDEN,
        retryTag = KycAnalyticsTestTags.RETRY,
        forbiddenBody = "You need admin access to view KYC analytics.",
    ) {
        (state as? KycAnalyticsUiState.Content)?.let { KycAnalyticsContent(it.data) }
    }
}

@Composable
private fun KycAnalyticsContent(d: KycAnalyticsData) {
    val s = d.snapshot
    Column(
        modifier = Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(16.dp)
            .testTag(KycAnalyticsTestTags.CONTENT),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        Text("Last 30 days", style = MaterialTheme.typography.labelMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
        KpiGrid(
            tiles = listOf(
                "Applications" to s.totalApplications.toString(),
                "Approved" to s.approvedCount.toString(),
                "Rejected" to s.rejectedCount.toString(),
                "Pending" to s.pendingCount.toString(),
                "Conversion" to pct1(s.conversionRate),
                "Avg hours" to String.format(Locale.US, "%.1f", s.avgProcessingHours),
            ),
        )

        if (s.funnel.isNotEmpty()) {
            CardSection("Funnel") {
                s.funnel.forEach { step ->
                    StatRow(step.step.replace('_', ' ').replaceFirstChar { it.uppercase() }, "${step.count}  (${pct1(step.percentage)})")
                }
            }
        }

        if (d.trends.isNotEmpty()) {
            CardSection("Recent trend (per day)") {
                d.trends.takeLast(7).forEach { t ->
                    StatRow(t.period, "start ${t.started} / sub ${t.submitted} / app ${t.approved} / rej ${t.rejected}")
                }
            }
        }

        if (d.rejectionReasons.isNotEmpty()) {
            SectionHeader("Rejection reasons")
            CardSection("By reason") {
                d.rejectionReasons.entries.sortedByDescending { it.value }.forEach { (k, v) ->
                    StatRow(k.replace('_', ' '), v.toString())
                }
            }
        }

        if (d.geographic.isNotEmpty()) {
            CardSection("Top countries") {
                d.geographic.sortedByDescending { it.count }.take(10).forEach { c ->
                    StatRow(c.country.ifBlank { "-" }, "${c.count}  (${pct1(c.approvalRate)} appr.)")
                }
            }
        }

        if (d.dropOff.isNotEmpty()) {
            CardSection("Drop-off between steps") {
                d.dropOff.forEach { st ->
                    StatRow("${st.fromStep} -> ${st.toStep}", "${pct1(st.dropRate)} dropped")
                }
            }
        }
    }
}
