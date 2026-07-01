package com.testlogon.android.data.compliance

import java.util.Locale

/**
 * Framework-free compliance/security domain models + total DTO -> domain mappers.
 *
 * Mirrors the web ComplianceAgentConfigPage (Findings / Audits / Compliance / Trends tabs). Enum folds
 * keep the UI resilient to unknown server values. Findings expose [canTransition] to gate the
 * acknowledge / false-positive actions exactly like the web (only `open` findings show actions).
 */
enum class FindingSeverity {
    CRITICAL, HIGH, MEDIUM, LOW, INFO, UNKNOWN;

    val serverValue: String get() = name.lowercase(Locale.US)

    companion object {
        fun from(raw: String?): FindingSeverity = when (raw?.lowercase(Locale.US)) {
            "critical" -> CRITICAL
            "high" -> HIGH
            "medium" -> MEDIUM
            "low" -> LOW
            "info" -> INFO
            else -> UNKNOWN
        }
    }
}

enum class FindingStatus {
    OPEN, ACKNOWLEDGED, REMEDIATED, FALSE_POSITIVE, ACCEPTED_RISK, UNKNOWN;

    val serverValue: String get() = name.lowercase(Locale.US)

    companion object {
        fun from(raw: String?): FindingStatus = when (raw?.lowercase(Locale.US)) {
            "open" -> OPEN
            "acknowledged" -> ACKNOWLEDGED
            "remediated" -> REMEDIATED
            "false_positive" -> FALSE_POSITIVE
            "accepted_risk" -> ACCEPTED_RISK
            else -> UNKNOWN
        }
    }
}

data class Finding(
    val id: String,
    val source: String,
    val sourceRef: String,
    val severity: FindingSeverity,
    val category: String,
    val title: String,
    val description: String,
    val filePath: String?,
    val lineRange: String?,
    val codeSnippet: String?,
    val remediation: String?,
    val status: FindingStatus,
    val remediationTicketId: String?,
) {
    val canTransition: Boolean get() = status == FindingStatus.OPEN
}

data class FindingsResult(
    val findings: List<Finding>,
    val count: Int,
) {
    val isEmpty: Boolean get() = findings.isEmpty()
}

data class Audit(
    val id: String,
    val status: String,
    val filesScanned: Int,
    val findingCounts: List<Pair<String, Int>>,
) {
    val totalFindings: Int get() = findingCounts.sumOf { it.second }
}

data class TrendWeek(
    val weekStartSeconds: Long,
    val total: Int,
)

data class Trends(
    val weeks: List<TrendWeek>,
    val days: Int,
    val total: Int,
)

data class FrameworkStatus(
    val key: String,
    val name: String,
    val openFindings: Int,
    val passing: Boolean,
    val statusLabel: String,
)

// ---- Summary (mirrors the web SummaryCards) ----
data class ComplianceSummary(
    val openCritical: Int,
    val openHigh: Int,
    val openTotal: Int,
    val frameworksFailing: Int,
)

// ---- Mappers (DTO -> domain) ----

internal fun SecurityFindingDto.toDomain(): Finding = Finding(
    id = findingId,
    source = source,
    sourceRef = sourceRef,
    severity = FindingSeverity.from(severity),
    category = category,
    title = title,
    description = description,
    filePath = filePath?.takeIf { it.isNotBlank() },
    lineRange = lineRange?.takeIf { it.isNotBlank() },
    codeSnippet = codeSnippet?.takeIf { it.isNotBlank() },
    remediation = remediation?.takeIf { it.isNotBlank() },
    status = FindingStatus.from(status),
    remediationTicketId = remediationTicketId?.takeIf { it.isNotBlank() },
)

internal fun SecurityFindingsListDto.toDomain(): FindingsResult = FindingsResult(
    findings = findings.map { it.toDomain() },
    count = count,
)

internal fun SecurityAuditDto.toDomain(): Audit = Audit(
    id = auditId,
    status = status,
    filesScanned = filesScanned,
    findingCounts = findingCounts.entries.filter { it.value > 0 }.map { it.key to it.value },
)

internal fun SecurityTrendsDto.toDomain(): Trends = Trends(
    weeks = weeks.map { TrendWeek(it.weekStart, it.total) },
    days = days,
    total = total,
)

internal fun ComplianceStatusDto.toDomain(): List<FrameworkStatus> =
    frameworks.entries.map { (key, fw) ->
        FrameworkStatus(
            key = key,
            name = fw.name.ifBlank { key },
            openFindings = fw.openFindings,
            passing = fw.status.equals("passing", ignoreCase = true),
            statusLabel = fw.status,
        )
    }
