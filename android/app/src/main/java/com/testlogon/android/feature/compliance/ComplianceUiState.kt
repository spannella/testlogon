package com.testlogon.android.feature.compliance

import androidx.annotation.StringRes
import com.testlogon.android.data.compliance.Audit
import com.testlogon.android.data.compliance.ComplianceSummary
import com.testlogon.android.data.compliance.Finding
import com.testlogon.android.data.compliance.FrameworkStatus
import com.testlogon.android.data.compliance.Trends

enum class CompliancePhase { Loading, Content, SessionExpired, Error, Offline }

/** The four tabs (mirrors the web ComplianceAgentConfigPage). */
enum class ComplianceTab { FINDINGS, AUDITS, COMPLIANCE, TRENDS }

sealed interface ComplianceEffect {
    data class ShowMessage(@StringRes val resId: Int) : ComplianceEffect
}

/**
 * Single render-ready state for the compliance/security dashboard. [phase] gates the top-level surface
 * (the summary + findings load drives it); the other tabs load lazily and hold their own lists. Mirrors
 * the web page which reuses one component for /agents/compliance and /agents/security.
 */
data class ComplianceUiState(
    val phase: CompliancePhase = CompliancePhase.Loading,
    val tab: ComplianceTab = ComplianceTab.FINDINGS,
    val summary: ComplianceSummary? = null,
    val findings: List<Finding> = emptyList(),
    val severityFilter: String = "all",
    val statusFilter: String = "all",
    val expandedFindingId: String? = null,
    val audits: List<Audit>? = null,
    val frameworks: List<FrameworkStatus>? = null,
    val trends: Trends? = null,
    val isRefreshing: Boolean = false,
    val isTriggeringAudit: Boolean = false,
    val errorMessage: String? = null,
)
