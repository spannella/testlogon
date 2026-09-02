package com.testlogon.android.feature.maintenance

import com.testlogon.android.core.network.maintenance.VendorDto
import com.testlogon.android.core.network.maintenance.WoBoardColumnDto
import java.time.Instant

/**
 * WOV-004/005 — feature domain + DTO mappers for the Maintenance Vendor directory + the work-order
 * board columns. Android-free + JVM-testable. Enums carry the wire token + a lenient UNKNOWN fallback
 * (mirrors [WoStatus] / [WoPriority]) so an unrecognized server value never throws. Timestamps are
 * Unix-second Longs; 0/null degrade to null [Instant].
 */

/** Vendor lifecycle status (mirrors VendorStatus "active" | "inactive"). */
enum class VendorStatus(val token: String) {
    ACTIVE("active"),
    INACTIVE("inactive"),
    UNKNOWN("unknown"),
    ;

    /** The status a status-toggle should move an [ACTIVE] vendor to, and vice-versa. */
    val toggleTarget: VendorStatus
        get() = when (this) {
            ACTIVE -> INACTIVE
            INACTIVE -> ACTIVE
            UNKNOWN -> ACTIVE
        }

    companion object {
        fun fromToken(t: String?): VendorStatus = entries.firstOrNull { it.token == t } ?: UNKNOWN
    }
}

/** One maintenance vendor (mapped from [VendorDto]). */
data class Vendor(
    val vendorId: String,
    val name: String,
    val status: VendorStatus = VendorStatus.ACTIVE,
    val tradeCategory: String = "general",
    val source: String? = null,
    val email: String? = null,
    val phone: String? = null,
    val defaultCurrency: String = "USD",
    val paymentTermsDays: Int = 30,
    val userSub: String? = null,
    val createdBy: String? = null,
    val createdAt: Instant? = null,
    val updatedAt: Instant? = null,
)

/** One work-order board column (mapped from [WoBoardColumnDto]). */
data class WoBoardColumn(
    val columnId: String,
    val title: String,
    val statusKey: WoStatus,
    val order: Int,
)

private fun epochOrNull(sec: Long?): Instant? =
    sec?.takeIf { it > 0 }?.let { Instant.ofEpochSecond(it) }

/** Maps a transport vendor to the feature domain. */
fun VendorDto.toDomain(): Vendor = Vendor(
    vendorId = vendorId,
    name = name,
    status = VendorStatus.fromToken(status),
    tradeCategory = tradeCategory,
    source = source,
    email = email,
    phone = phone,
    defaultCurrency = defaultCurrency,
    paymentTermsDays = paymentTermsDays,
    userSub = userSub,
    createdBy = createdBy,
    createdAt = epochOrNull(createdAt),
    updatedAt = epochOrNull(updatedAt),
)

/** Maps a transport board column to the feature domain (status token -> lenient [WoStatus]). */
fun WoBoardColumnDto.toDomain(): WoBoardColumn = WoBoardColumn(
    columnId = columnId,
    title = title,
    statusKey = WoStatus.fromToken(statusKey),
    order = order,
)
