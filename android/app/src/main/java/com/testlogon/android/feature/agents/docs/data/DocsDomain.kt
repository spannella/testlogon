package com.testlogon.android.feature.agents.docs.data

/**
 * AGENTS-BASICS (web-parity) - framework-free domain models for the DOC-COVERAGE surface (web /agents/docs +
 * /agents/docs/templates). Kept in feature/data. Times are EPOCH SECONDS (0 -> null via the mapper).
 */

/** The coverage summary (overall % + per-type breakdown). */
data class DocCoverageSummary(
    val overallCoverage: Double,
    val totalDocs: Int,
    val staleDocs: Int,
    /** doc-type -> (avgCoverage 0..1, count). */
    val byType: List<DocTypeCoverage>,
)

data class DocTypeCoverage(
    val docType: String,
    val avgCoverage: Double,
    val count: Int,
)

/** One doc-coverage record. */
data class DocCoverage(
    val docPath: String,
    val docType: String,
    val sourceRefs: List<String>,
    val coverageScore: Double,
    val isStale: Boolean,
    val staleSince: Long?,
    val lastUpdated: Long?,
)

/** Result of a freshness check. */
data class FreshnessCheck(
    val total: Int,
    val stale: Int,
    val fresh: Int,
)

/** One doc template. */
data class DocTemplate(
    val templateId: String,
    val name: String,
    val docType: String,
    val templateBody: String,
    val requiredSections: List<String>,
    val createdAt: Long?,
)
