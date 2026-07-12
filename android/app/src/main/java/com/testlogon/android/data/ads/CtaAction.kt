package com.testlogon.android.data.ads

import com.squareup.moshi.Json
import com.squareup.moshi.JsonClass

/**
 * ADV2-207 (F2) — the app-side twin of the backend `CtaActionIn`/`CtaActionOut` structured
 * click-through CTA target carried on a served ad (VOD ad break, broadcast pre/mid-roll, newsfeed
 * sponsored unit). [ctaType] routes the in-app destination (see [AdCtaRouter]); [targetId] names the
 * product / creator / account the destination needs; [label] is the button text.
 *
 * Framework-free (pure Kotlin) so it can be mapped in the JVM-unit-testable data layer and reused by
 * the feed (SponsoredInfo), VOD (AdBreak) and broadcast (BroadcastPreRoll) domain models alike.
 */
enum class CtaType(val wire: String) {
    BUY_PRODUCT("buy_product"),
    VIEW_PRODUCT("view_product"),
    TIP("tip"),
    SUBSCRIBE("subscribe"),
    SUBSCRIBE_OTHER("subscribe_other"),
    ;

    companion object {
        /** Parse a wire cta_type; unknown/blank values are dropped (return null) so an unrecognized
         *  server type never renders a dead button. */
        fun fromWire(v: String?): CtaType? =
            entries.firstOrNull { it.wire.equals(v?.trim(), ignoreCase = true) }
    }
}

/** One structured CTA target as consumed by the UI + [AdCtaRouter]. */
data class CtaAction(
    val ctaType: CtaType,
    val label: String,
    val targetId: String,
) {
    /** tip taps NEVER charge the advertiser (E2 locked default): the viewer tips the creator as
     *  normal creator-earnings, no advertiser CPC/CPA fires. */
    val isTip: Boolean get() = ctaType == CtaType.TIP
}

/**
 * ADV2-207 — Moshi wire DTO for a served CTA (`{cta_type, target_id, label}`). Shared by every serve
 * surface (VodAdBreak.ctas, PreRollOut.ctas / MidRollOut.ctas, the newsfeed sponsored post ctas).
 * All fields defaulted so a partial / older-server unit parses cleanly.
 */
@JsonClass(generateAdapter = true)
data class CtaActionDto(
    @Json(name = "cta_type") val ctaType: String = "",
    @Json(name = "target_id") val targetId: String? = null,
    @Json(name = "label") val label: String? = null,
) {
    /** Map to the domain model, or null when the type is unknown (dropped from the rendered bar). */
    fun toDomain(): CtaAction? {
        val type = CtaType.fromWire(ctaType) ?: return null
        return CtaAction(
            ctaType = type,
            label = label?.takeIf { it.isNotBlank() } ?: defaultLabel(type),
            targetId = targetId?.trim().orEmpty(),
        )
    }

    private fun defaultLabel(type: CtaType): String = when (type) {
        CtaType.BUY_PRODUCT -> "Buy now"
        CtaType.VIEW_PRODUCT -> "View product"
        CtaType.TIP -> "Send a tip"
        CtaType.SUBSCRIBE -> "Subscribe"
        CtaType.SUBSCRIBE_OTHER -> "Subscribe"
    }
}

/** Map a served CTA list to domain, dropping unknown types + capping at the backend max (8). */
fun List<CtaActionDto>?.toCtaActions(): List<CtaAction> =
    this?.mapNotNull { it.toDomain() }?.take(8) ?: emptyList()
