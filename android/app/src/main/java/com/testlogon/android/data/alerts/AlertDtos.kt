package com.testlogon.android.data.alerts

import com.squareup.moshi.Json
import com.squareup.moshi.JsonClass

/**
 * AND-086 / AND-087 — wire DTOs for email + SMS alert-target management.
 *
 * Verified against reference/src/api/types.ts (AlertPreferences) and
 * reference/src/api/endpoints/alerts.ts:
 *  - email/sms prefs (and confirm/remove responses) return AlertPreferences: a flat
 *    emails / sms_numbers string[] of already-verified targets (NO per-target id, NO verified flag),
 *    plus *_event_types arrays (the alert categories, owned by the AND-080 type-preferences surface).
 *  - begin returns { challenge_id, sent_to }.
 *  - confirm body is { challenge_id, code }; remove body is { email } / { phone }.
 *
 * OpenAPI leaves the 200 bodies untyped (only 422 HTTPValidationError is documented), so the
 * frontend contract is authoritative. Unknown keys are tolerated by the shared converter.
 */
@JsonClass(generateAdapter = true)
data class AlertPrefsDto(
    val emails: List<String> = emptyList(),
    @Json(name = "email_event_types") val emailEventTypes: List<String> = emptyList(),
    @Json(name = "sms_numbers") val smsNumbers: List<String> = emptyList(),
    @Json(name = "sms_event_types") val smsEventTypes: List<String> = emptyList(),
)

@JsonClass(generateAdapter = true)
data class AlertBeginResponseDto(
    @Json(name = "challenge_id") val challengeId: String = "",
    @Json(name = "sent_to") val sentTo: String = "",
)

// ── Email ────────────────────────────────────────────────────────

@JsonClass(generateAdapter = true)
data class EmailBeginRequest(val email: String)

@JsonClass(generateAdapter = true)
data class EmailConfirmRequest(
    @Json(name = "challenge_id") val challengeId: String,
    val code: String,
)

@JsonClass(generateAdapter = true)
data class EmailRemoveRequest(val email: String)

// ── SMS ──────────────────────────────────────────────────────────

@JsonClass(generateAdapter = true)
data class SmsBeginRequest(val phone: String)

@JsonClass(generateAdapter = true)
data class SmsConfirmRequest(
    @Json(name = "challenge_id") val challengeId: String,
    val code: String,
)

@JsonClass(generateAdapter = true)
data class SmsRemoveRequest(val phone: String)
