package com.testlogon.android.feature.kyc.data

import com.squareup.moshi.JsonClass
import com.testlogon.android.feature.kyc.model.MAX_TIER
import com.testlogon.android.feature.kyc.model.Requirement
import com.testlogon.android.feature.kyc.model.Tier
import com.testlogon.android.feature.kyc.model.TierHistory
import com.testlogon.android.feature.kyc.model.TierStatus
import java.time.Instant

// AND-320 — feature-local DTOs for the three KYC tier endpoints (AND-319 returns okhttp3.ResponseBody
// for these undocumented-body endpoints, so THIS feature owns parsing). The :app module HAS Moshi KSP
// codegen, so these use @JsonClass(generateAdapter = true) — the property names already match the
// snake_case wire keys verbatim, so no @Json overrides are needed and the generated adapters work with a
// plain Moshi (no reflective KotlinJsonAdapterFactory / moshi-kotlin on the test classpath). Epoch-second
// Longs (updated_at / changed_at) become Instant via Instant.ofEpochSecond in the DTO->domain mappers.

/**
 * AND-320 — wire shape of GET v1/kyc/tiers/me and POST v1/kyc/tiers/me/evaluate (same shape).
 * [updated_at] is an OPTIONAL epoch-second Long; [history] defaults to empty when absent.
 */
@JsonClass(generateAdapter = true)
data class TierDetailsDto(
    val current_tier: Int,
    val updated_at: Long? = null,
    val history: List<TierHistoryEntryDto> = emptyList(),
)

/** AND-320 — one entry in [TierDetailsDto.history]. [changed_at] is epoch seconds; [case_id] is optional. */
@JsonClass(generateAdapter = true)
data class TierHistoryEntryDto(
    val from_tier: Int,
    val to_tier: Int,
    val changed_at: Long,
    val reason: String,
    val case_id: String? = null,
)

/**
 * AND-320 — wire shape of GET v1/kyc/tiers/me/requirements/{target_tier}. Requirements are opaque string
 * KEYS (no per-requirement status/help/case); [met]/[unmet] partition them. [eligible] gates promotion.
 */
@JsonClass(generateAdapter = true)
data class TierRequirementsDto(
    val current_tier: Int,
    val met: List<String> = emptyList(),
    val unmet: List<String> = emptyList(),
    val eligible: Boolean = false,
)

// ---- DTO -> domain mappers ----

/** Maps a history entry; the epoch-second [TierHistoryEntryDto.changed_at] becomes an [Instant]. */
internal fun TierHistoryEntryDto.toDomain(): TierHistory = TierHistory(
    fromTier = from_tier,
    toTier = to_tier,
    changedAt = Instant.ofEpochSecond(changed_at),
    reason = reason,
    caseId = case_id,
)

/**
 * Builds the domain [TierStatus] from the parsed tier details + (optional) requirements.
 *
 * The target tier is min(current + 1, [MAX_TIER]); at the max tier there is no target (null) and the
 * requirements list is empty. Requirements are ordered met-first (met = true) then unmet (met = false);
 * the human label is left null here and resolved at the UI via a key -> @StringRes map (falling back to
 * the key for unknown requirements). [asOf] stamps when this snapshot was assembled.
 */
internal fun TierDetailsDto.toTierStatus(
    requirements: TierRequirementsDto?,
    asOf: Instant,
): TierStatus {
    val current = Tier(level = current_tier)
    val target = if (current_tier < MAX_TIER) Tier(level = current_tier + 1) else null
    val reqs: List<Requirement> = if (target != null && requirements != null) {
        requirements.met.map { Requirement(key = it, met = true) } +
            requirements.unmet.map { Requirement(key = it, met = false) }
    } else {
        emptyList()
    }
    return TierStatus(
        current = current,
        updatedAt = updated_at?.let(Instant::ofEpochSecond),
        history = history.map { it.toDomain() },
        target = target,
        requirements = reqs,
        eligibleForTarget = requirements?.eligible ?: false,
        asOf = asOf,
    )
}
