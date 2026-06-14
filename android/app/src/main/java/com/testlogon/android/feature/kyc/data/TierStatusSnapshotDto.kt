package com.testlogon.android.feature.kyc.data

import com.squareup.moshi.JsonClass
import com.testlogon.android.feature.kyc.model.Requirement
import com.testlogon.android.feature.kyc.model.Tier
import com.testlogon.android.feature.kyc.model.TierHistory
import com.testlogon.android.feature.kyc.model.TierStatus
import java.time.Instant

// AND-320 — persistence DTO for the DataStore cache (KycTierStore). The domain TierStatus carries
// java.time.Instant fields, which Moshi cannot serialize (no Instant adapter), so this mirror stores
// epoch-second Longs and rebuilds Instants on read. Uses @JsonClass(generateAdapter = true) codegen (the
// :app module has Moshi KSP) so a plain Moshi can (de)serialize it without moshi-kotlin reflection.

/** Flat, Moshi-serializable mirror of [TierStatus] (Instants as epoch-second Longs). */
@JsonClass(generateAdapter = true)
data class TierStatusSnapshotDto(
    val currentLevel: Int,
    val updatedAtEpoch: Long?,
    val targetLevel: Int?,
    val requirements: List<RequirementSnapshotDto>,
    val history: List<HistorySnapshotDto>,
    val eligibleForTarget: Boolean,
    val asOfEpoch: Long,
) {
    fun toDomain(): TierStatus = TierStatus(
        current = Tier(level = currentLevel),
        updatedAt = updatedAtEpoch?.let(Instant::ofEpochSecond),
        history = history.map { it.toDomain() },
        target = targetLevel?.let { Tier(level = it) },
        requirements = requirements.map { it.toDomain() },
        eligibleForTarget = eligibleForTarget,
        asOf = Instant.ofEpochSecond(asOfEpoch),
    )

    companion object {
        fun from(status: TierStatus): TierStatusSnapshotDto = TierStatusSnapshotDto(
            currentLevel = status.current.level,
            updatedAtEpoch = status.updatedAt?.epochSecond,
            targetLevel = status.target?.level,
            requirements = status.requirements.map { RequirementSnapshotDto(it.key, it.met) },
            history = status.history.map {
                HistorySnapshotDto(it.fromTier, it.toTier, it.changedAt.epochSecond, it.reason, it.caseId)
            },
            eligibleForTarget = status.eligibleForTarget,
            asOfEpoch = status.asOf.epochSecond,
        )
    }
}

/** Persisted requirement (label is UI-resolved, never stored). */
@JsonClass(generateAdapter = true)
data class RequirementSnapshotDto(val key: String, val met: Boolean) {
    fun toDomain(): Requirement = Requirement(key = key, met = met)
}

/** Persisted history entry (epoch-second timestamp). */
@JsonClass(generateAdapter = true)
data class HistorySnapshotDto(
    val fromTier: Int,
    val toTier: Int,
    val changedAtEpoch: Long,
    val reason: String,
    val caseId: String?,
) {
    fun toDomain(): TierHistory = TierHistory(
        fromTier = fromTier,
        toTier = toTier,
        changedAt = Instant.ofEpochSecond(changedAtEpoch),
        reason = reason,
        caseId = caseId,
    )
}
