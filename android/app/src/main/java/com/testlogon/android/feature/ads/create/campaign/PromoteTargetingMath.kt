package com.testlogon.android.feature.ads.create.campaign

import com.testlogon.android.core.network.ads.AdTargetingCreateIn

/**
 * FE-162 (EPIC G, <- BE-161/BE-162/BE-163) - PURE helpers for the promote-entity picker + behavioral
 * targeting UI. Mirrors the web `promoteTargeting.ts` 1:1 so the two clients build identical create-campaign
 * / create-targeting request bodies.
 *
 * No Android / network / coroutine deps - deterministic + unit-testable (see PromoteTargetingMathTest). The
 * presentation layer (CreateCampaignViewModel / CreateCampaignScreen) consumes these to build the request
 * bodies and to render summaries + the audience estimate.
 *
 * OPT-IN INVARIANT: behavioral targeting only applies to users who opted into personalization; everyone else
 * falls into the untargeted pool. This is a product invariant surfaced in the UI ([RESPECTS_OPT_IN_NOTE]).
 */
object PromoteTargetingMath {

    /** What a campaign can promote. Wire values mirror the web PromoteEntityKind. */
    enum class PromoteEntityKind(val wire: String, val label: String) {
        MARKET("market", "Market"),
        CREATOR_TOKEN("creator_token", "Creator token"),
        PRODUCT("product", "Product");

        companion object {
            fun fromWire(value: String?): PromoteEntityKind? =
                entries.firstOrNull { it.wire == value }
        }
    }

    /** Ordered list of the three promote-entity kinds (web PROMOTE_ENTITY_KINDS parity). */
    val PROMOTE_ENTITY_KINDS: List<PromoteEntityKind> = PromoteEntityKind.entries.toList()

    /** The promote-entity descriptor persisted onto the campaign. */
    data class PromotePayload(val promoteKind: String, val promoteEntityId: String)

    /**
     * UI-side selected targeting segments. Every field is optional and defaults to "no constraint". Flat +
     * serialisable so it maps 1:1 onto [AdTargetingCreateIn]. Mirrors the web SelectedSegments.
     */
    data class SelectedSegments(
        val name: String? = null,
        val ageRanges: List<String> = emptyList(),
        val genders: List<String> = emptyList(),
        val countryCodes: List<String> = emptyList(),
        val deviceTypes: List<String> = emptyList(),
        val contentCategories: List<String> = emptyList(),
        val newUserOnly: Boolean = false,
    )

    /** A country preset: ISO [code] + human [label]. */
    data class CountryOption(val code: String, val label: String)

    /** Preset option lists for the segment multi-selects (web SEGMENT_OPTIONS parity). */
    val SEGMENT_AGE_RANGES: List<String> = listOf("18-24", "25-34", "35-44", "45-54", "55+")
    val SEGMENT_GENDERS: List<String> = listOf("male", "female", "other")
    val SEGMENT_DEVICE_TYPES: List<String> = listOf("mobile", "desktop", "tablet")
    val SEGMENT_CONTENT_CATEGORIES: List<String> = listOf(
        "gaming", "finance", "sports", "music", "tech", "lifestyle", "news", "education",
    )
    val SEGMENT_COUNTRIES: List<CountryOption> = listOf(
        CountryOption("US", "United States"),
        CountryOption("CA", "Canada"),
        CountryOption("GB", "United Kingdom"),
        CountryOption("DE", "Germany"),
        CountryOption("FR", "France"),
        CountryOption("AU", "Australia"),
        CountryOption("JP", "Japan"),
        CountryOption("BR", "Brazil"),
        CountryOption("IN", "India"),
        CountryOption("MX", "Mexico"),
    )

    /** Constant disclosure copy: targeting respects the user's opt-in choice. */
    const val RESPECTS_OPT_IN_NOTE: String =
        "Targeting only applies to users who opted into personalization. " +
            "Everyone else is reached without behavioral segments."

    /** Default targeting-set name (matches the server/web default). */
    const val DEFAULT_TARGETING_NAME: String = "Default"

    /** Minimum campaign budget in cents ($1.00). */
    const val MIN_BUDGET_CENTS: Long = 100L

    /**
     * Map the selected UI [segments] onto an [AdTargetingCreateIn] body, DROPPING empty arrays / unset
     * fields so the server never receives noise. [SelectedSegments.newUserOnly] is only carried when true.
     * Always carries a name (defaults to [DEFAULT_TARGETING_NAME]). Web buildTargetingPayload parity.
     */
    fun buildTargetingPayload(segments: SelectedSegments): AdTargetingCreateIn = AdTargetingCreateIn(
        name = segments.name?.trim().takeUnless { it.isNullOrEmpty() } ?: DEFAULT_TARGETING_NAME,
        ageRanges = segments.ageRanges.takeIf { it.isNotEmpty() },
        genders = segments.genders.takeIf { it.isNotEmpty() },
        countryCodes = segments.countryCodes.takeIf { it.isNotEmpty() },
        contentCategories = segments.contentCategories.takeIf { it.isNotEmpty() },
        deviceTypes = segments.deviceTypes.takeIf { it.isNotEmpty() },
        newUserOnly = segments.newUserOnly,
    )

    /**
     * Attach the promote-entity ids to a targeting body onto the matching additive list
     * (market_ids / token_ids / product_ids) so entity-scoped targeting rides along the segment body.
     * A null/blank id leaves the body unchanged.
     */
    fun withPromoteEntity(
        body: AdTargetingCreateIn,
        kind: PromoteEntityKind?,
        entityId: String?,
    ): AdTargetingCreateIn {
        val id = entityId?.trim().orEmpty()
        if (kind == null || id.isEmpty()) return body
        return when (kind) {
            PromoteEntityKind.MARKET -> body.copy(marketIds = listOf(id))
            PromoteEntityKind.CREATOR_TOKEN -> body.copy(tokenIds = listOf(id))
            PromoteEntityKind.PRODUCT -> body.copy(productIds = listOf(id))
        }
    }

    /** Build the promote-entity descriptor for a campaign (web buildPromotePayload parity). */
    fun buildPromotePayload(kind: PromoteEntityKind, entityId: String): PromotePayload =
        PromotePayload(promoteKind = kind.wire, promoteEntityId = entityId.trim())

    /** A promote-campaign draft to validate before submit. */
    data class PromoteCampaignDraft(
        val name: String,
        val budgetCents: Long,
        val kind: PromoteEntityKind?,
        val entityId: String?,
    )

    /**
     * Validate a promote-campaign [draft]; returns a (possibly empty) list of human error strings. Web
     * validatePromoteCampaign parity: name required, budget >= $1.00, a kind chosen, an entity selected.
     */
    fun validatePromoteCampaign(draft: PromoteCampaignDraft): List<String> {
        val errors = mutableListOf<String>()
        if (draft.name.isBlank()) {
            errors.add("Campaign name is required.")
        }
        if (draft.budgetCents < MIN_BUDGET_CENTS) {
            errors.add("Minimum budget is \$1.00.")
        }
        if (draft.kind == null) {
            errors.add("Choose what to promote (a market, creator token, or product).")
        }
        if (draft.entityId.isNullOrBlank()) {
            errors.add("Select an item to promote.")
        }
        return errors
    }

    /**
     * A compact human summary of a targeting body, e.g. "US, 18-24, 25-34, mobile - opt-in only". Segments
     * are joined with ", "; the opt-in suffix is ALWAYS appended (the invariant). "Everyone" when no
     * segments set. Web summarizeTargeting parity.
     */
    fun summarizeTargeting(targeting: AdTargetingCreateIn?): String {
        val parts = mutableListOf<String>()
        if (targeting != null) {
            targeting.countryCodes?.takeIf { it.isNotEmpty() }?.let { parts.add(it.joinToString("/")) }
            targeting.ageRanges?.takeIf { it.isNotEmpty() }?.let { parts.add(it.joinToString(", ")) }
            targeting.genders?.takeIf { it.isNotEmpty() }?.let { parts.add(it.joinToString("/")) }
            targeting.deviceTypes?.takeIf { it.isNotEmpty() }?.let { parts.add(it.joinToString("/")) }
            targeting.contentCategories?.takeIf { it.isNotEmpty() }?.let { parts.add(it.joinToString("/")) }
            if (targeting.newUserOnly) parts.add("new users")
        }
        val lead = if (parts.isNotEmpty()) parts.joinToString(", ") else "Everyone"
        return "$lead - opt-in only"
    }

    /** Compact reach formatter: 1234 -> "1.2K", 2_500_000 -> "2.5M". Web formatEstimatedReach parity. */
    fun formatEstimatedReach(n: Long): String {
        if (n < 0) return "0"
        if (n < 1_000) return n.toString()
        if (n < 1_000_000) {
            val k = n / 1000.0
            val rounded = if (k >= 100) Math.round(k).toDouble() else Math.round(k * 10) / 10.0
            return trimTrailingZero(rounded) + "K"
        }
        val m = n / 1_000_000.0
        val rounded = if (m >= 100) Math.round(m).toDouble() else Math.round(m * 10) / 10.0
        return trimTrailingZero(rounded) + "M"
    }

    /** "1.0" -> "1", "1.2" -> "1.2" (drops a trailing .0 so "1K" not "1.0K"). */
    private fun trimTrailingZero(v: Double): String {
        val asLong = v.toLong()
        return if (v == asLong.toDouble()) asLong.toString() else v.toString()
    }
}
