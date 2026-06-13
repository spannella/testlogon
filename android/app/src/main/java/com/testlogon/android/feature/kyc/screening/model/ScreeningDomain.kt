package com.testlogon.android.feature.kyc.screening.model

import com.testlogon.android.core.model.kyc.KycScreeningResultOut
import java.time.Instant

/**
 * AND-328 - feature domain model + DTO mappers + the pure aggregation function for the READ-ONLY KYC
 * screening surface (sanctions / PEP / adverse-media per-screen results aggregated into ONE status).
 *
 * The wire `result` / `screen_type` tokens are mapped to lenient enums here (unknown token -> UNKNOWN, never
 * throws). The epoch-second wire `screened_at` becomes a [java.time.Instant]. All DTO -> domain mapping
 * happens BEFORE the typed ApiResult in the repository (mirrors AND-326 / AND-327).
 *
 * READ-ONLY: nothing here writes; the only entry point is the per-screen results read + the pure
 * [aggregate] reducer.
 */

/** Lenient per-screen screening outcome (unknown token -> [UNKNOWN]). */
enum class KycScreenResult {
    CLEAR,
    POTENTIAL_MATCH,
    CONFIRMED_MATCH,
    UNKNOWN,
    ;

    companion object {
        fun fromToken(token: String?): KycScreenResult = when (token?.lowercase()) {
            "clear" -> CLEAR
            "potential_match" -> POTENTIAL_MATCH
            "confirmed_match" -> CONFIRMED_MATCH
            else -> UNKNOWN
        }
    }
}

/** Lenient type of an individual screen (unknown / unlisted token -> [UNKNOWN]). */
enum class KycScreenType {
    SANCTIONS_OFAC,
    SANCTIONS_EU,
    SANCTIONS_UN,
    PEP_CHECK,
    ADVERSE_MEDIA,
    UNKNOWN,
    ;

    companion object {
        fun fromToken(token: String?): KycScreenType = when (token?.lowercase()) {
            "sanctions_ofac" -> SANCTIONS_OFAC
            "sanctions_eu" -> SANCTIONS_EU
            "sanctions_un" -> SANCTIONS_UN
            "pep_check" -> PEP_CHECK
            "adverse_media" -> ADVERSE_MEDIA
            else -> UNKNOWN
        }
    }
}

/**
 * Aggregated screening status surfaced to the user. [NOT_STARTED] means there is no case yet or the case has
 * no screening results; [UNKNOWN] means every result is an unrecognized token.
 */
enum class ScreeningStatus {
    NOT_STARTED,
    CLEAR,
    REVIEW,
    HIT,
    UNKNOWN,
}

/** Domain model of one per-screen screening result. */
data class KycScreeningResult(
    val result: KycScreenResult,
    val screenType: KycScreenType,
    val screenedAt: Instant?,
    val matchCount: Int?,
)

// ---- DTO -> domain mappers (never throw; unknown tokens -> UNKNOWN; epoch -> Instant) ----

fun KycScreeningResultOut.toDomain(): KycScreeningResult = KycScreeningResult(
    result = KycScreenResult.fromToken(result),
    screenType = KycScreenType.fromToken(screen_type),
    screenedAt = screened_at?.let { Instant.ofEpochSecond(it) },
    matchCount = match_count,
)

/**
 * Pure aggregation of per-screen [results] into a single [ScreeningStatus]:
 *   - empty results              -> NOT_STARTED (no case / no screening run yet),
 *   - any CONFIRMED_MATCH        -> HIT,
 *   - else any POTENTIAL_MATCH   -> REVIEW,
 *   - else any CLEAR (non-empty) -> CLEAR,
 *   - else (all UNKNOWN tokens)  -> UNKNOWN.
 *
 * No I/O, no side effects: directly unit-testable.
 */
fun aggregate(results: List<KycScreeningResult>): ScreeningStatus = when {
    results.isEmpty() -> ScreeningStatus.NOT_STARTED
    results.any { it.result == KycScreenResult.CONFIRMED_MATCH } -> ScreeningStatus.HIT
    results.any { it.result == KycScreenResult.POTENTIAL_MATCH } -> ScreeningStatus.REVIEW
    results.any { it.result == KycScreenResult.CLEAR } -> ScreeningStatus.CLEAR
    else -> ScreeningStatus.UNKNOWN
}
