package com.testlogon.android.core.model.kyc

/**
 * AND-328 - transport DTOs for the READ-ONLY KYC screening results surface
 * (sanctions / PEP / adverse-media results aggregated into one status).
 *
 * RECONCILIATION NOTE (identical to AND-319's Kyc.kt / AND-321..327): core-model has NO Moshi dependency and
 * NO Moshi codegen, so these DTOs carry NO annotations. The production Moshi (core-network
 * NetworkModule.provideMoshi) decodes them via the reflective KotlinJsonAdapterFactory, which maps Kotlin
 * property names to JSON keys VERBATIM. Every property below is therefore named EXACTLY as the snake_case wire
 * key (result, screen_type, screened_at, match_count, details). Zero annotations, zero new dependencies.
 * Required wire fields have NO default so the reflective adapter throws JsonDataException when absent; optional
 * wire fields are nullable (or empty-collection) with a default. Extra/unknown wire fields are tolerated
 * leniently.
 *
 * Wire contract (verified; cookie + CSRF + Bearer attached globally):
 *   GET ui/kyc/screening/cases/{case_id} -> 200 KycScreeningResultsListResponseDto { results[] }
 *
 * screened_at is an epoch-SECOND Long (NOT Instant/ISO) so JVM unit tests need no java.time; the feature
 * mapper converts it to Instant. result / screen_type are plain Strings on the wire (the typed enums +
 * UNKNOWN fallback live in the feature domain mapper). The endpoint is a GET and is idempotent (READ-ONLY).
 */

/** GET ui/kyc/screening/cases/{case_id} envelope: the per-screen results (absent key -> empty list). */
data class KycScreeningResultsListResponseDto(
    val results: List<KycScreeningResultOut> = emptyList(),
)

/**
 * A single per-screen screening result as returned by the backend. Only [result] is REQUIRED (no default) so
 * a body missing it fails fast with a JsonDataException at decode time; everything else is optional. [details]
 * is a loosely-typed map (the production Moshi resolves Map and Any? via its built-in support;
 * `@JvmSuppressWildcards` keeps the reflective adapter from generating a wildcard-typed value adapter it
 * cannot resolve).
 */
data class KycScreeningResultOut(
    val result: String,
    val screen_type: String? = null,
    val screened_at: Long? = null,
    val match_count: Int? = null,
    val details: Map<String, @JvmSuppressWildcards Any?>? = null,
)
