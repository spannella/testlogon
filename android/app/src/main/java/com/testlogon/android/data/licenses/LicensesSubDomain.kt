package com.testlogon.android.data.licenses

/**
 * Framework-free domain models + total DTO -> domain mappers for the compliance / full-requests /
 * revenue sub-screens. Reuses the shared [formatEpochSeconds]/[humanize] helpers from LicensesDomain.kt.
 * Money is integer cents; timestamps are epoch seconds.
 */

// ============================== Compliance ==============================

data class ComplianceSummary(
    val total: Int,
    val compliant: Int,
    val expiringSoon: Int,
    val issues: Int,
    val flagged: Int,
)

data class ComplianceItem(
    val contentId: String,
    val contentType: String,
    val status: String,
    val issueCount: Int,
    val lastCheckedAtSeconds: Long?,
) {
    fun statusLabel(): String = humanize(status)
    fun typeLabel(): String = contentType.ifBlank { "" }
    fun formattedLastChecked(): String =
        lastCheckedAtSeconds?.let { formatEpochSeconds(it) } ?: ""
}

data class CompliancePage(
    val items: List<ComplianceItem>,
    val summary: ComplianceSummary,
    val nextCursor: String?,
) {
    val isEmpty: Boolean get() = items.isEmpty()
}

data class ComplianceIssue(val type: String, val detail: String)

data class LicenseRef(
    val licenseId: String,
    val licenseType: String,
    val licenseStatus: String,
    val expiresAtSeconds: Long?,
) {
    fun statusLabel(): String = humanize(licenseStatus)
    fun typeLabel(): String = humanize(licenseType)
    fun formattedExpires(): String = expiresAtSeconds?.let { formatEpochSeconds(it) } ?: ""
}

data class ComplianceFlag(
    val flagId: String,
    val reason: String,
    val evidence: String,
    val status: String,
    val resolutionNotes: String,
) {
    fun reasonLabel(): String = humanize(reason)
    fun statusLabel(): String = humanize(status)
}

data class ComplianceDetail(
    val contentId: String,
    val status: String,
    val hasRecord: Boolean,
    val issues: List<ComplianceIssue>,
    val refs: List<LicenseRef>,
    val flags: List<ComplianceFlag>,
) {
    fun statusLabel(): String = humanize(status)
}

internal fun ComplianceSummaryDto?.toDomain(): ComplianceSummary = ComplianceSummary(
    total = this?.total ?: 0,
    compliant = this?.compliant ?: 0,
    expiringSoon = this?.expiringSoon ?: 0,
    issues = this?.issues ?: 0,
    flagged = this?.flagged ?: 0,
)

internal fun CreatorComplianceItemDto.toDomain(): ComplianceItem = ComplianceItem(
    contentId = contentId,
    contentType = contentType,
    status = complianceStatus,
    issueCount = issueCount,
    lastCheckedAtSeconds = lastCheckedAt,
)

internal fun CreatorComplianceListDto.toDomain(): CompliancePage = CompliancePage(
    items = items.map { it.toDomain() },
    summary = summary.toDomain(),
    nextCursor = nextCursor,
)

internal fun ComplianceIssueDto.toDomain(): ComplianceIssue =
    ComplianceIssue(type = type.ifBlank { "issue" }, detail = detail)

internal fun LicenseRefDto.toDomain(): LicenseRef = LicenseRef(
    licenseId = licenseId,
    licenseType = licenseType,
    licenseStatus = licenseStatus,
    expiresAtSeconds = expiresAt,
)

internal fun ComplianceFlagDto.toDomain(): ComplianceFlag = ComplianceFlag(
    flagId = flagId,
    reason = reason,
    evidence = evidence,
    status = status,
    resolutionNotes = resolutionNotes,
)

// ============================== Full requests ==============================

data class FullLicenseRequest(
    val requestId: String,
    val contentId: String,
    val contentType: String,
    val requesterId: String,
    val ownerId: String,
    val status: String,
    val proposedTerms: LicenseTerms?,
    val counterTerms: LicenseTerms?,
    val denialReason: String,
    val message: String,
    val createdAtSeconds: Long,
) {
    fun statusLabel(): String = humanize(status)
    fun formattedCreated(): String = formatEpochSeconds(createdAtSeconds)

    /** True when the owner can approve/counter/deny (inbox). */
    val isActionableByOwner: Boolean get() = status == "pending" || status == "negotiating"

    /** True when the requester can withdraw an as-yet-undecided request (sent). */
    val isWithdrawableBySender: Boolean get() = status == "pending"

    /** True when the requester can accept/reject a counter-offer (sent). */
    val isCounterPendingForSender: Boolean get() = status == "negotiating"
}

data class FullLicenseRequestsPage(
    val items: List<FullLicenseRequest>,
    val nextCursor: String?,
) {
    val isEmpty: Boolean get() = items.isEmpty()
}

internal fun FullLicenseRequestDto.toDomain(): FullLicenseRequest = FullLicenseRequest(
    requestId = requestId,
    contentId = contentId,
    contentType = contentType,
    requesterId = requesterId,
    ownerId = ownerId,
    status = status,
    proposedTerms = proposedTerms?.toDomain(),
    counterTerms = counterTerms?.toDomain(),
    denialReason = denialReason,
    message = message,
    createdAtSeconds = createdAt,
)

internal fun FullLicenseRequestListDto.toDomain(): FullLicenseRequestsPage = FullLicenseRequestsPage(
    items = items.map { it.toDomain() },
    nextCursor = nextCursor,
)

// ============================== Revenue (earned/paid/calc) ==============================

data class FullRevenueTransaction(
    val id: String,
    val contentId: String,
    val counterpartyId: String,
    val sourceType: String,
    val sourceAmountCents: Long,
    val splitAmountCents: Long,
    val splitType: String,
    val currency: String,
    val createdAtSeconds: Long,
) {
    fun sourceLabel(): String = humanize(sourceType)
    fun splitTypeLabel(): String = humanize(splitType)
    fun formattedCreated(): String = formatEpochSeconds(createdAtSeconds)
}

data class FullRevenuePage(
    val summary: RevenueSummary,
    val transactions: List<FullRevenueTransaction>,
    val nextCursor: String?,
)

data class RevenueSplitPreview(
    val sourceAmountCents: Long,
    val platformFeeCents: Long,
    val revenueShareCents: Long,
    val profitShareCents: Long,
    val totalLicensorShareCents: Long,
    val licenseeNetCents: Long,
)

internal fun FullRevenueTxnDto.toDomain(): FullRevenueTransaction = FullRevenueTransaction(
    id = txnId,
    contentId = contentId,
    counterpartyId = counterpartyId,
    sourceType = sourceType,
    sourceAmountCents = sourceAmountCents,
    splitAmountCents = splitAmountCents,
    splitType = splitType,
    currency = currency.ifBlank { "USD" },
    createdAtSeconds = createdAt,
)

internal fun FullRevenueListDto.toDomain(): FullRevenuePage = FullRevenuePage(
    summary = summary?.toDomain() ?: RevenueSummary(
        totalCents = 0,
        totalTransactions = 0,
        lastTransactionAtSeconds = null,
        currency = "USD",
    ),
    transactions = transactions.map { it.toDomain() },
    nextCursor = nextCursor,
)

internal fun RevenueSplitPreviewDto.toDomain(): RevenueSplitPreview = RevenueSplitPreview(
    sourceAmountCents = sourceAmountCents,
    platformFeeCents = platformFeeCents,
    revenueShareCents = revenueShareCents,
    profitShareCents = profitShareCents,
    totalLicensorShareCents = totalLicensorShareCents,
    licenseeNetCents = licenseeNetCents,
)
