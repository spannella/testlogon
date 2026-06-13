package com.testlogon.android.feature.kyc.eidv.model

import com.testlogon.android.core.model.kyc.EidDiscrepancyOutDto
import com.testlogon.android.core.model.kyc.EidSchemeOutDto
import com.testlogon.android.core.model.kyc.EidStatusOutDto
import com.testlogon.android.core.model.kyc.EidVerificationOutDto
import com.testlogon.android.core.model.kyc.StartEidVerificationOutDto
import java.time.Instant

/**
 * AND-325 - feature domain model + DTO mappers for KYC electronic ID verification (eIDV).
 *
 * The wire `scheme` / `assurance_level` / `auth_flow` / `severity` tokens are mapped to lenient enums here
 * (unknown token -> UNKNOWN, never throws). The epoch-second wire `expires_at` / `verified_at` become
 * [java.time.Instant]. All DTO -> domain mapping happens BEFORE the typed ApiResult in the repository
 * (mirrors AND-320 / AND-321 / AND-322 / AND-323 / AND-324).
 *
 * This is a REAL REST redirect-based eIDV feature: [StartEidSession.redirectUrl] is opened EXTERNALLY by the
 * screen (ACTION_VIEW), NOT an in-app vendor / ML / CameraX flow.
 */

/** Lenient government eID scheme (unknown token -> [UNKNOWN]). [wire] is the start-request token. */
enum class EidScheme(val wire: String) {
    EIDAS("eidas"),
    DIGID("digid"),
    BANKID("bankid"),
    AADHAAR("aadhaar"),
    UNKNOWN("unknown"),
    ;

    companion object {
        fun fromToken(token: String?): EidScheme =
            entries.firstOrNull { it.wire == token?.lowercase() } ?: UNKNOWN
    }
}

/** Lenient eID authentication flow style (unknown token -> [UNKNOWN]). */
enum class EidAuthFlow {
    BROWSER_REDIRECT,
    MOBILE_APP_QR,
    OTP_BIOMETRIC,
    UNKNOWN,
    ;

    companion object {
        fun fromToken(token: String?): EidAuthFlow = when (token?.lowercase()) {
            "browser_redirect" -> BROWSER_REDIRECT
            "mobile_app_qr" -> MOBILE_APP_QR
            "otp_biometric" -> OTP_BIOMETRIC
            else -> UNKNOWN
        }
    }
}

/** Lenient assurance level (unknown token -> [UNKNOWN]). */
enum class EidAssuranceLevel {
    LOW,
    SUBSTANTIAL,
    HIGH,
    UNKNOWN,
    ;

    companion object {
        fun fromToken(token: String?): EidAssuranceLevel = when (token?.lowercase()) {
            "low" -> LOW
            "substantial" -> SUBSTANTIAL
            "high" -> HIGH
            else -> UNKNOWN
        }
    }
}

/** Lenient discrepancy severity (unknown token -> [UNKNOWN]). */
enum class EidDiscrepancySeverity {
    MATCH,
    WARNING,
    CRITICAL,
    UNKNOWN,
    ;

    companion object {
        fun fromToken(token: String?): EidDiscrepancySeverity = when (token?.lowercase()) {
            "match" -> MATCH
            "warning" -> WARNING
            "critical" -> CRITICAL
            else -> UNKNOWN
        }
    }
}

/** Domain model of one available eID scheme row. */
data class SchemeInfo(
    val scheme: EidScheme,
    val name: String,
    val assuranceLevel: EidAssuranceLevel,
    val authFlow: EidAuthFlow,
    val countries: List<String>,
    val description: String?,
)

/** Domain model of a started eID session: the provider redirect URL and its expiry. */
data class StartEidSession(
    val sessionId: String,
    val redirectUrl: String,
    val expiresAt: Instant,
)

/** Domain model of one profile-vs-eID field discrepancy. */
data class EidDiscrepancy(
    val field: String,
    val profileValue: String?,
    val eidValue: String?,
    val severity: EidDiscrepancySeverity,
)

/**
 * Domain model of a completed eID verification assertion. [hasCriticalDiscrepancy] is derived: true when
 * any discrepancy is [EidDiscrepancySeverity.CRITICAL].
 */
data class EidVerification(
    val assertionId: String,
    val assuranceLevel: EidAssuranceLevel,
    val verifiedAt: Instant?,
    val discrepancies: List<EidDiscrepancy>,
) {
    val hasCriticalDiscrepancy: Boolean
        get() = discrepancies.any { it.severity == EidDiscrepancySeverity.CRITICAL }
}

/** The mapped status result: the verification (null until the redirect flow completes) plus the tier flag. */
data class EidStatusResult(
    val verification: EidVerification?,
    val autoTierUpgrade: Boolean,
)

// ---- DTO -> domain mappers (never throw; unknown tokens -> UNKNOWN; epoch -> Instant) ----

fun EidSchemeOutDto.toDomain(): SchemeInfo = SchemeInfo(
    scheme = EidScheme.fromToken(scheme),
    name = name,
    assuranceLevel = EidAssuranceLevel.fromToken(assurance_level),
    authFlow = EidAuthFlow.fromToken(auth_flow),
    countries = countries,
    description = description,
)

fun StartEidVerificationOutDto.toDomain(): StartEidSession = StartEidSession(
    sessionId = session_id,
    redirectUrl = redirect_url,
    expiresAt = Instant.ofEpochSecond(expires_at),
)

fun EidDiscrepancyOutDto.toDomain(): EidDiscrepancy = EidDiscrepancy(
    field = field,
    profileValue = profile_value,
    eidValue = eid_value,
    severity = EidDiscrepancySeverity.fromToken(severity),
)

fun EidVerificationOutDto.toDomain(): EidVerification = EidVerification(
    assertionId = assertion_id,
    assuranceLevel = EidAssuranceLevel.fromToken(assurance_level),
    verifiedAt = verified_at?.let { Instant.ofEpochSecond(it) },
    discrepancies = discrepancies.map { it.toDomain() },
)

fun EidStatusOutDto.toDomain(): EidStatusResult = EidStatusResult(
    verification = eid_verification?.toDomain(),
    autoTierUpgrade = auto_tier_upgrade ?: false,
)
