package com.testlogon.android.core.network.msgprivacy

import com.squareup.moshi.Json

/**
 * TIP-B4 (TIP-401) — MessagePrivacy (pay-to-message gate + tip-free allowlist) transport DTOs.
 *
 * CODEGEN NOTE: core-network has NO Moshi KSP codegen; these decode via the reflective
 * KotlinJsonAdapterFactory on the shared Moshi. Every wire key is pinned with @Json(name = ...);
 * @JsonClass is intentionally OMITTED (mirrors CallRateDtos).
 *
 * WIRE CONTRACT (verified against app/routers/messaging.py TIP-B4; relative paths, NO leading slash):
 *   GET    messaging/privacy/message                         -> MessagePrivacyDto
 *   PUT    messaging/privacy/message  <- MessagePrivacyUpdateDto (partial) -> MessagePrivacyDto
 *   POST   messaging/privacy/message/allowlist  <- MessagePrivacyAllowlistEntryDto -> MessagePrivacyDto
 *   DELETE messaging/privacy/message/allowlist/{allow_user_id} -> MessagePrivacyDto
 */

/** MessagePrivacyOut — the recipient's pay-to-message configuration. */
data class MessagePrivacyDto(
    @Json(name = "require_tip_to_message") val requireTipToMessage: Boolean = false,
    @Json(name = "min_tip_cents") val minTipCents: Int = 0,
    @Json(name = "tip_free_allowlist") val tipFreeAllowlist: List<String> = emptyList(),
)

/** MessagePrivacyUpdateIn — partial update; any null field is left unchanged server-side. */
data class MessagePrivacyUpdateDto(
    @Json(name = "require_tip_to_message") val requireTipToMessage: Boolean? = null,
    @Json(name = "min_tip_cents") val minTipCents: Int? = null,
    @Json(name = "tip_free_allowlist") val tipFreeAllowlist: List<String>? = null,
)

/** MessagePrivacyAllowlistEntryIn — add one user_sub to the tip-free allowlist. */
data class MessagePrivacyAllowlistEntryDto(
    @Json(name = "user_id") val userId: String,
)
