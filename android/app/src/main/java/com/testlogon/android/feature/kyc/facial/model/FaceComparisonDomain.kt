package com.testlogon.android.feature.kyc.facial.model

import com.testlogon.android.core.model.kyc.FaceComparisonResultDto
import java.time.Instant

/**
 * AND-323 - feature domain model + DTO mapper for the KYC facial-comparison flow.
 *
 * The wire `result` token is mapped to a lenient [FaceResult] enum here (unknown token -> [FaceResult.UNKNOWN],
 * never throws). The epoch-second wire timestamp becomes a [java.time.Instant]. All DTO -> domain mapping
 * happens BEFORE the typed ApiResult in the repository (mirrors AND-320 / AND-321 / AND-322).
 */

/** Lenient comparison verdict (unknown token -> [UNKNOWN]). */
enum class FaceResult {
    PASS,
    REVIEW,
    FAIL,
    UNKNOWN,
    ;

    companion object {
        fun fromToken(token: String?): FaceResult = when (token?.lowercase()) {
            "pass" -> PASS
            "review" -> REVIEW
            "fail" -> FAIL
            else -> UNKNOWN
        }
    }
}

/**
 * Domain result of ONE server-side face comparison. The anti-spoof aggregate is flattened to the
 * passed flag + passed/total check counts the result panel renders; the per-check breakdown is not
 * surfaced in the UI this wave.
 */
data class FaceComparison(
    val comparisonId: String,
    val confidenceScore: Int,
    val result: FaceResult,
    val antiSpoofPassed: Boolean,
    val antiSpoofPassedChecks: Int,
    val antiSpoofTotalChecks: Int,
    val attemptNumber: Int,
    val maxAttempts: Int,
    val remainingAttempts: Int,
    val createdAt: Instant,
)

/** Maps the comparison DTO to the domain [FaceComparison]. Never throws; unknown result -> [FaceResult.UNKNOWN]. */
fun FaceComparisonResultDto.toDomain(): FaceComparison = FaceComparison(
    comparisonId = comparison_id,
    confidenceScore = confidence_score,
    result = FaceResult.fromToken(result),
    antiSpoofPassed = anti_spoof.passed,
    antiSpoofPassedChecks = anti_spoof.passed_checks,
    antiSpoofTotalChecks = anti_spoof.total_checks,
    attemptNumber = attempt_number,
    maxAttempts = max_attempts,
    remainingAttempts = remaining_attempts,
    createdAt = Instant.ofEpochSecond(created_at),
)
