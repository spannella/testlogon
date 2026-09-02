package com.testlogon.android.data.admin.email

/**
 * Framework-free domain models + total DTO -> domain mappers for the ADMIN-EMAIL surface.
 * Timestamps are epoch-seconds.
 */

data class EmailStats(
    val sent: Int,
    val delivered: Int,
    val bounced: Int,
    val complained: Int,
    val failed: Int,
    val suppressed: Int,
    val total: Int,
    val deliveryRatePercent: Double,
    val bounceRatePercent: Double,
    val complaintRatePercent: Double,
    val periodDays: Int,
) {
    val summaryLabel: String get() = AdminEmailMath.summaryLine(sent, deliveryRatePercent)
    val deliveryRateLabel: String get() = AdminEmailMath.formatRate(deliveryRatePercent)
    val bounceRateLabel: String get() = AdminEmailMath.formatRate(bounceRatePercent)
    val complaintRateLabel: String get() = AdminEmailMath.formatRate(complaintRatePercent)
}

data class SuppressedEmail(
    val email: String,
    val reason: String?,
    val status: String?,
    val suppressedAtSeconds: Long?,
) {
    val reasonLabel: String get() = reason?.takeIf { it.isNotBlank() } ?: "—"
}

data class CampaignTemplate(
    val id: String,
    val name: String,
    val subject: String?,
    val body: String,
    val active: Boolean,
    val campaignId: String?,
    val mergeFields: List<String>,
    val updatedAtSeconds: Long?,
) {
    val subjectLabel: String get() = subject?.takeIf { it.isNotBlank() } ?: "(no subject)"
    val mergeFieldsLabel: String
        get() = if (mergeFields.isEmpty()) "No merge fields" else mergeFields.joinToString(", ")
}

// ---- Mappers (DTO -> domain) ----

internal fun EmailStatsRawDto.toDomain(): EmailStats = EmailStats(
    sent = sent,
    delivered = delivered,
    bounced = bounced,
    complained = complained,
    failed = failed,
    suppressed = suppressed,
    total = total,
    deliveryRatePercent = deliveryRate,
    bounceRatePercent = bounceRate,
    complaintRatePercent = complaintRate,
    periodDays = periodDays,
)

internal fun SuppressionItemDto.toDomain(): SuppressedEmail? {
    val addr = email?.takeIf { it.isNotBlank() } ?: return null
    return SuppressedEmail(
        email = addr,
        reason = reason?.takeIf { it.isNotBlank() },
        status = status?.takeIf { it.isNotBlank() },
        suppressedAtSeconds = suppressedAt ?: createdAt,
    )
}

internal fun CampaignTemplateDto.toDomain(): CampaignTemplate = CampaignTemplate(
    id = templateId,
    name = name.ifBlank { templateId },
    subject = subject?.takeIf { it.isNotBlank() },
    body = body,
    active = active,
    campaignId = campaignId?.takeIf { it.isNotBlank() },
    mergeFields = mergeFields.orEmpty(),
    updatedAtSeconds = updatedAt,
)
