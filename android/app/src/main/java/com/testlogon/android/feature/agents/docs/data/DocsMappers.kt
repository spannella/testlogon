package com.testlogon.android.feature.agents.docs.data

import com.testlogon.android.core.network.agents.DocCoverageDto
import com.testlogon.android.core.network.agents.DocCoverageSummaryDto
import com.testlogon.android.core.network.agents.DocTemplateDto
import com.testlogon.android.core.network.agents.FreshnessCheckDto

/** AGENTS-BASICS (web-parity) - DTO -> domain mappers for the DOC-COVERAGE surface. Epoch-0 sentinels map to null. */

fun DocCoverageSummaryDto.toDomain(): DocCoverageSummary = DocCoverageSummary(
    overallCoverage = overallCoverage,
    totalDocs = totalDocs,
    staleDocs = staleDocs,
    byType = byType.map { (type, info) ->
        DocTypeCoverage(
            docType = type,
            // The web reads by_type[t].avg_coverage; count is best-effort (opaque server map).
            avgCoverage = info["avg_coverage"] ?: 0.0,
            count = (info["count"] ?: 0.0).toInt(),
        )
    }.sortedBy { it.docType },
)

fun DocCoverageDto.toDomain(): DocCoverage = DocCoverage(
    docPath = docPath,
    docType = docType,
    sourceRefs = sourceRefs,
    coverageScore = coverageScore,
    isStale = isStale,
    staleSince = staleSince.takeIf { it > 0 },
    lastUpdated = lastUpdated.takeIf { it > 0 },
)

fun FreshnessCheckDto.toDomain(): FreshnessCheck = FreshnessCheck(total = total, stale = stale, fresh = fresh)

fun DocTemplateDto.toDomain(): DocTemplate = DocTemplate(
    templateId = templateId,
    name = name,
    docType = docType,
    templateBody = templateBody,
    requiredSections = requiredSections,
    createdAt = createdAt.takeIf { it > 0 },
)
