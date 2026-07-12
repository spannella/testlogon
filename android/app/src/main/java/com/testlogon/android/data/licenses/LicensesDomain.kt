package com.testlogon.android.data.licenses

import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/**
 * Framework-free licensing domain models + total DTO -> domain mappers.
 *
 * Money is integer cents (the backend's `*_cents`); the UI formats it via the shared
 * com.testlogon.android.feature.earnings.formatEarningsMoney helper. Timestamps are epoch seconds and are
 * formatted with SimpleDateFormat/Date (core-library desugaring is off, so java.time is unavailable).
 * Mapping is total: absent optionals default per the schema, so the screen never sees a null DTO field.
 */

// ---- Issued licenses ----

data class IssuedLicense(
    val id: String,
    val contentId: String,
    val licenseeId: String?,
    val licenseMode: String,
    val status: String,
    val createdAtSeconds: Long,
) {
    /** "per_user" -> "Per user"; "blanket" -> "Blanket"; blank stays blank. */
    fun modeLabel(): String = humanize(licenseMode)

    fun statusLabel(): String = humanize(status)

    fun formattedCreated(): String = formatEpochSeconds(createdAtSeconds)
}

data class IssuedLicensesPage(
    val items: List<IssuedLicense>,
    val nextCursor: String?,
) {
    val isEmpty: Boolean get() = items.isEmpty()
}

// ---- License requests ----

data class LicenseTerms(
    val profitSharePct: Double,
    val fixedCostCents: Long,
    val revenueSharePct: Double,
)

data class LicenseRequest(
    val id: String,
    val contentId: String,
    val contentType: String,
    val ownerDisplayName: String,
    val status: String,
    val terms: LicenseTerms?,
    val denialReason: String,
    val message: String,
    val createdAtSeconds: Long,
) {
    fun statusLabel(): String = humanize(status)

    fun formattedCreated(): String = formatEpochSeconds(createdAtSeconds)
}

data class LicenseRequestsPage(
    val items: List<LicenseRequest>,
    val nextCursor: String?,
) {
    val isEmpty: Boolean get() = items.isEmpty()
}

// ---- Revenue ----

data class RevenueSummary(
    val totalCents: Long,
    val totalTransactions: Int,
    val lastTransactionAtSeconds: Long?,
    val currency: String,
) {
    fun formattedLastTransaction(): String =
        lastTransactionAtSeconds?.let { formatEpochSeconds(it) } ?: ""
}

data class RevenueTransaction(
    val id: String,
    val contentId: String,
    val sourceType: String,
    val splitAmountCents: Long,
    val splitType: String,
    val currency: String,
    val createdAtSeconds: Long,
) {
    fun sourceLabel(): String = humanize(sourceType)

    fun formattedCreated(): String = formatEpochSeconds(createdAtSeconds)
}

data class RevenuePage(
    val summary: RevenueSummary,
    val transactions: List<RevenueTransaction>,
    val nextCursor: String?,
) {
    /** Empty when there are no transactions and nothing was ever earned. */
    val isEmpty: Boolean get() = transactions.isEmpty() && summary.totalTransactions == 0
}

// ---- Shared helpers ----

private val DATE_FORMAT = SimpleDateFormat("MMM d, yyyy", Locale.getDefault())

/** Epoch-seconds -> "Jun 17, 2026"; <= 0 (unknown) -> blank. */
internal fun formatEpochSeconds(seconds: Long): String =
    if (seconds <= 0L) "" else DATE_FORMAT.format(Date(seconds * 1000L))

/** "license_expired" / "per_user" -> "License expired" / "Per user". Blank stays blank. */
internal fun humanize(raw: String): String {
    if (raw.isBlank()) return ""
    return raw.split('_', ' ')
        .filter { it.isNotBlank() }
        .joinToString(" ") { word ->
            word.replaceFirstChar { c -> c.titlecase(Locale.US) }
        }
}

// ---- Mappers (DTO -> domain) ----

internal fun IssuedLicenseItemDto.toDomain(): IssuedLicense = IssuedLicense(
    id = issuedLicenseId,
    contentId = contentId,
    licenseeId = licenseeId,
    licenseMode = licenseMode,
    status = status,
    createdAtSeconds = createdAt,
)

internal fun IssuedLicenseListDto.toDomain(): IssuedLicensesPage = IssuedLicensesPage(
    items = items.map { it.toDomain() },
    nextCursor = nextCursor,
)

internal fun LicenseTermsDto.toDomain(): LicenseTerms = LicenseTerms(
    profitSharePct = profitSharePct,
    fixedCostCents = fixedCostCents,
    revenueSharePct = revenueSharePct,
)

internal fun LicenseRequestDto.toDomain(): LicenseRequest = LicenseRequest(
    id = requestId,
    contentId = contentId,
    contentType = contentType,
    ownerDisplayName = ownerDisplayName,
    status = status,
    terms = proposedTerms?.toDomain(),
    denialReason = denialReason,
    message = message,
    createdAtSeconds = createdAt,
)

internal fun LicenseRequestListDto.toDomain(): LicenseRequestsPage = LicenseRequestsPage(
    items = items.map { it.toDomain() },
    nextCursor = nextCursor,
)

internal fun RevenueSummaryDto.toDomain(): RevenueSummary = RevenueSummary(
    totalCents = totalCents,
    totalTransactions = totalTransactions,
    lastTransactionAtSeconds = lastTransactionAt,
    currency = currency.ifBlank { "USD" },
)

internal fun RevenueTransactionDto.toDomain(): RevenueTransaction = RevenueTransaction(
    id = txnId,
    contentId = contentId,
    sourceType = sourceType,
    splitAmountCents = splitAmountCents,
    splitType = splitType,
    currency = currency.ifBlank { "USD" },
    createdAtSeconds = createdAt,
)

internal fun RevenueListDto.toDomain(): RevenuePage = RevenuePage(
    summary = summary?.toDomain() ?: RevenueSummary(
        totalCents = 0,
        totalTransactions = 0,
        lastTransactionAtSeconds = null,
        currency = "USD",
    ),
    transactions = transactions.map { it.toDomain() },
    nextCursor = nextCursor,
)
