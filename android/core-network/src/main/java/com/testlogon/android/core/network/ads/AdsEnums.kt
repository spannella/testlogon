package com.testlogon.android.core.network.ads

import com.squareup.moshi.FromJson
import com.squareup.moshi.Json
import com.squareup.moshi.ToJson

/**
 * AND-363 - transport enums for the platform ads accounts control plane (ui/ads/accounts).
 *
 * RECONCILIATION (enum UNKNOWN fallback): the lenient EnumJsonAdapter.withUnknownFallback helper lives
 * in the com.squareup.moshi:moshi-adapters artifact, which is NOT a declared dependency of this project
 * and this ticket forbids adding any new dependency. So we reproduce the SAME lenient semantics the
 * established way in core-network (mirroring SigningEnums / KycEnumAdapters): each enum carries the wire
 * token, an UNKNOWN member, and a custom Moshi adapter object whose fromJson maps an unrecognized token
 * to UNKNOWN (never throws) and whose toJson writes the token back. The adapter objects are registered on
 * the shared Moshi in NetworkModule.provideMoshi (BEFORE KotlinJsonAdapterFactory) and rebuilt
 * identically in the DTO round-trip test.
 *
 * WIRE VALUES (ASSUMPTION): no frontend ads.ts / OpenAPI reference was present in this environment, so the
 * token sets below are a minimal, best-effort guess for a platform ads surface. The UNKNOWN fallback makes
 * them forward-safe - any unrecognized server token decodes to UNKNOWN rather than throwing. Reconcile the
 * exact token list against the server spec when available.
 */

/** Lifecycle status of an ad account (wire token decoded via [AdAccountStatusAdapter]). */
enum class AdAccountStatus(val token: String) {
    @Json(name = "active") ACTIVE("active"),
    @Json(name = "suspended") SUSPENDED("suspended"),
    @Json(name = "closed") CLOSED("closed"),
    @Json(name = "pending") PENDING("pending"),
    UNKNOWN("unknown"),
    ;

    companion object {
        /** Lenient: an unrecognized token maps to [UNKNOWN] rather than throwing. */
        fun fromToken(t: String?): AdAccountStatus = entries.firstOrNull { it.token == t } ?: UNKNOWN
    }
}

/** Lifecycle status of an ad campaign (wire token decoded via [AdCampaignStatusAdapter]). */
enum class AdCampaignStatus(val token: String) {
    @Json(name = "draft") DRAFT("draft"),
    @Json(name = "active") ACTIVE("active"),
    @Json(name = "paused") PAUSED("paused"),
    @Json(name = "completed") COMPLETED("completed"),
    @Json(name = "archived") ARCHIVED("archived"),
    UNKNOWN("unknown"),
    ;

    companion object {
        /** Lenient: an unrecognized token maps to [UNKNOWN] rather than throwing. */
        fun fromToken(t: String?): AdCampaignStatus = entries.firstOrNull { it.token == t } ?: UNKNOWN
    }
}

/**
 * AND-363 - Moshi adapter for [AdAccountStatus]. Wire value is the lowercase token; an unrecognized token
 * decodes to [AdAccountStatus.UNKNOWN] (never throws) and serializes back to its token. Dependency-free
 * stand-in for EnumJsonAdapter.withUnknownFallback. Registered on the production Moshi in
 * NetworkModule.provideMoshi.
 */
object AdAccountStatusAdapter {
    @FromJson fun fromJson(token: String?): AdAccountStatus = AdAccountStatus.fromToken(token)
    @ToJson fun toJson(value: AdAccountStatus): String = value.token
}

/** AND-363 - Moshi adapter for [AdCampaignStatus] (token in/out, unknown token -> UNKNOWN). */
object AdCampaignStatusAdapter {
    @FromJson fun fromJson(token: String?): AdCampaignStatus = AdCampaignStatus.fromToken(token)
    @ToJson fun toJson(value: AdCampaignStatus): String = value.token
}
