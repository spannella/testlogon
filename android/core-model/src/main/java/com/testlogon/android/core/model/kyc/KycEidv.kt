package com.testlogon.android.core.model.kyc

/**
 * AND-325 - transport DTOs for the `v1/kyc/.../eid` electronic ID verification (eIDV) endpoints.
 *
 * RECONCILIATION NOTE (identical to AND-319's Kyc.kt / AND-321 / AND-322 / AND-323 / AND-324): core-model
 * has NO Moshi dependency and NO Moshi codegen, so these DTOs carry NO annotations. The production Moshi
 * (core-network NetworkModule.provideMoshi) decodes them via the reflective KotlinJsonAdapterFactory, which
 * maps Kotlin property names to JSON keys VERBATIM. Every property below is therefore named EXACTLY as the
 * snake_case wire key (scheme, assurance_level, auth_flow, session_id, redirect_url, expires_at,
 * eid_verification, auto_tier_upgrade, assertion_id, verified_at, verified_fields, profile_value, ...).
 * Zero annotations, zero new dependencies. Required wire fields have NO default so the reflective adapter
 * throws JsonDataException when absent; optional wire fields are nullable (or empty-collection) with a
 * default. Extra/unknown wire fields are tolerated leniently.
 *
 * FEATURE NATURE: this is a FULLY REAL REST eIDV feature using a REDIRECT-based government eID scheme flow.
 * NO PII is submitted by the app (only the chosen {scheme}); the backend returns a [StartEidVerificationOutDto.redirect_url]
 * which the screen opens EXTERNALLY (an ACTION_VIEW intent) so the user authenticates with their national
 * eID provider; the app then POLLS the status endpoint until an eid_verification assertion appears or the
 * session expires. There is NO vendor / ML / CameraX SDK and NO flagged seam.
 *
 * Wire contract (verified; cookie + CSRF + Bearer attached globally):
 *   GET  v1/kyc/eid/schemes  optional ?country  -> EidSchemesListOutDto { schemes[] }
 *   POST v1/kyc/cases  (REUSE AND-319 KycApi.createCase)  -> KycCaseEnvelope (draft case_id)
 *   POST v1/kyc/cases/{case_id}/eid/start  body StartEidVerificationInDto { scheme } -> StartEidVerificationOutDto
 *   GET  v1/kyc/cases/{case_id}/eid/status -> EidStatusOutDto { eid_verification?, auto_tier_upgrade? }
 *
 * expires_at / verified_at are epoch-SECOND Longs (NOT Instant/ISO) so JVM unit tests need no java.time;
 * the feature mapper converts them to Instant. scheme / assurance_level / auth_flow / severity are plain
 * Strings on the wire (the typed enums + UNKNOWN fallback live in the feature domain mapper).
 */

/** One available government eID scheme. The scheme-id field is `scheme` (e.g. "eidas", "digid"). */
data class EidSchemeOutDto(
    val scheme: String,
    val name: String,
    val assurance_level: String,
    val auth_flow: String,
    val countries: List<String> = emptyList(),
    val description: String? = null,
)

/** GET v1/kyc/eid/schemes envelope: the available schemes (absent key -> empty list). */
data class EidSchemesListOutDto(
    val schemes: List<EidSchemeOutDto> = emptyList(),
)

/** Body for POST v1/kyc/cases/{case_id}/eid/start. Carries ONLY the chosen scheme - NO PII. */
data class StartEidVerificationInDto(
    val scheme: String,
)

/** Response of POST .../eid/start: an opaque session plus the provider redirect URL and its expiry. */
data class StartEidVerificationOutDto(
    val session_id: String,
    val redirect_url: String,
    val expires_at: Long,
)

/** One profile-vs-eID field discrepancy detected during verification. */
data class EidDiscrepancyOutDto(
    val field: String,
    val profile_value: String? = null,
    val eid_value: String? = null,
    val severity: String,
)

/**
 * A completed eID verification assertion. `verified_fields` is a loosely-typed map; the production Moshi
 * resolves Map<String, Any?> via its built-in support. `@JvmSuppressWildcards` keeps the reflective adapter
 * from generating a wildcard-typed value adapter it cannot resolve.
 */
data class EidVerificationOutDto(
    val assertion_id: String,
    val assurance_level: String,
    val verified_at: Long? = null,
    val verified_fields: Map<String, @JvmSuppressWildcards Any?> = emptyMap(),
    val discrepancies: List<EidDiscrepancyOutDto> = emptyList(),
)

/**
 * GET .../eid/status envelope. `eid_verification` is NULL until the redirect flow completes; there is NO
 * top-level status enum. `auto_tier_upgrade` signals the backend auto-bumped the KYC tier on completion.
 */
data class EidStatusOutDto(
    val eid_verification: EidVerificationOutDto? = null,
    val auto_tier_upgrade: Boolean? = null,
)
