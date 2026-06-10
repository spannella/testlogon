package com.testlogon.android.data.vod.purchase

/**
 * AND-193 — pure, JVM-unit-testable purchase domain model + mappers.
 *
 * Framework-free (no Android, no java.time): timestamps are epoch SECONDS (Long); entitlement status is
 * derived client-side from expiresAt / viewsRemaining via pure Long math so gating is JVM-tested.
 */

/** The fixed purchase-type options (the "tiers" the user chooses among). */
enum class PurchaseTypeOption(val wire: String) {
    VIEW_ONCE("view_once"),
    RENTAL("rental"),
    PERMANENT("permanent"),
    DOWNLOAD("download"),
    UNKNOWN("");

    companion object {
        fun fromWire(value: String?): PurchaseTypeOption =
            entries.firstOrNull { it.wire == value } ?: UNKNOWN
    }
}

/** A purchase-type *option* the client builds from the access offer (server returns no tier list). */
data class PurchaseTier(
    val type: PurchaseTypeOption,
    val priceCents: Long?,
)

/** The offer / access state for a VOD (from VodAccessOut). */
data class VodOffer(
    val entitled: Boolean,
    val purchaseAvailable: Boolean,
    val priceCents: Long?,
    val defaultType: PurchaseTypeOption,
    val viewsRemaining: Int,
    val expiresAt: Long?,
    val downloadAllowed: Boolean,
    val adsEnabled: Boolean,
    val reason: String,
) {
    /**
     * The selectable tiers. The backend exposes one offer (single price); the client surfaces the
     * default purchase-type plus the always-available permanent/view_once options at the same price.
     */
    fun tiers(): List<PurchaseTier> {
        val types = linkedSetOf(defaultType, PurchaseTypeOption.PERMANENT, PurchaseTypeOption.VIEW_ONCE)
            .filter { it != PurchaseTypeOption.UNKNOWN }
        return types.map { PurchaseTier(it, priceCents) }
    }
}

/** EntitlementStatus derived client-side (no server `status` enum). */
enum class EntitlementStatus { ACTIVE, EXPIRED, CONSUMED, UNKNOWN }

/** The flat entitlement granted by a purchase (from VodPurchaseOut). */
data class Entitlement(
    val videoId: String,
    val purchaseType: PurchaseTypeOption,
    val alreadyOwned: Boolean,
    val grantType: String,
    val amountCents: Long,
    val purchaseId: String,
    val viewsRemaining: Int,        // -1 = unlimited
    val grantedAtSeconds: Long,
    val expiresAtSeconds: Long?,    // null = no expiry
    val downloadAllowed: Boolean,
) {
    /** Pure: derive status at [nowSeconds] (no Instant.now() / java.time). */
    fun statusAt(nowSeconds: Long): EntitlementStatus = when {
        viewsRemaining == 0 -> EntitlementStatus.CONSUMED
        expiresAtSeconds != null && nowSeconds >= expiresAtSeconds -> EntitlementStatus.EXPIRED
        else -> EntitlementStatus.ACTIVE
    }

    /** Whether the entitlement currently unlocks the content at [nowSeconds]. */
    fun isUnlockedAt(nowSeconds: Long): Boolean = statusAt(nowSeconds) == EntitlementStatus.ACTIVE
}

// ---- Mappers ----

fun VodAccessOutDto.toOffer(): VodOffer = VodOffer(
    entitled = entitled,
    purchaseAvailable = purchaseAvailable,
    priceCents = priceCents,
    defaultType = PurchaseTypeOption.fromWire(purchaseType),
    viewsRemaining = viewsRemaining,
    expiresAt = expiresAt,
    downloadAllowed = downloadAllowed,
    adsEnabled = adsEnabled,
    reason = reason,
)

fun VodPurchaseOutDto.toEntitlement(): Entitlement = Entitlement(
    videoId = videoId,
    purchaseType = PurchaseTypeOption.fromWire(purchaseType),
    alreadyOwned = alreadyOwned,
    grantType = grantType,
    amountCents = amountCents,
    purchaseId = purchaseId,
    viewsRemaining = viewsRemaining,
    grantedAtSeconds = grantedAt,
    expiresAtSeconds = expiresAt,
    downloadAllowed = downloadAllowed,
)
