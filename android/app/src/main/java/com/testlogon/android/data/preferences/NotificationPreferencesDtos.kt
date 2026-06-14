package com.testlogon.android.data.preferences

import com.squareup.moshi.Json
import com.squareup.moshi.JsonClass
import com.testlogon.android.core.model.NotificationTypePreference

/**
 * AND-080 — Moshi DTOs for `/ui/alerts/type-preferences`.
 *
 * The POST body is the verified `AlertTypePreferenceUpdate` (one alert type per call; flat,
 * nullable channel booleans). The GET response is untyped server-side (`200: {}`); the Android port
 * tolerantly decodes a list of the same shape under a `type_preferences` key (falling back to an
 * empty list), and reconciles authoritative state by re-reading after each POST.
 */
@JsonClass(generateAdapter = true)
data class AlertTypePreferenceDto(
    @Json(name = "alert_type") val alertType: String? = null,
    @Json(name = "enabled") val enabled: Boolean? = null,
    @Json(name = "push") val push: Boolean? = null,
    @Json(name = "email") val email: Boolean? = null,
    @Json(name = "sms") val sms: Boolean? = null,
    @Json(name = "in_app") val inApp: Boolean? = null,
)

/** Tolerant GET envelope: accepts `{"type_preferences":[...]}` or `{"preferences":[...]}`. */
@JsonClass(generateAdapter = true)
data class AlertTypePreferencesEnvelopeDto(
    @Json(name = "type_preferences") val typePreferences: List<AlertTypePreferenceDto>? = null,
    @Json(name = "preferences") val preferences: List<AlertTypePreferenceDto>? = null,
) {
    fun entries(): List<AlertTypePreferenceDto> = typePreferences ?: preferences ?: emptyList()
}

/** POST body — `AlertTypePreferenceUpdate`. `alert_type` is required; channels are nullable. */
@JsonClass(generateAdapter = true)
data class AlertTypePreferenceUpdateDto(
    @Json(name = "alert_type") val alertType: String,
    @Json(name = "enabled") val enabled: Boolean? = null,
    @Json(name = "push") val push: Boolean? = null,
    @Json(name = "email") val email: Boolean? = null,
    @Json(name = "sms") val sms: Boolean? = null,
    @Json(name = "in_app") val inApp: Boolean? = null,
)

internal fun AlertTypePreferenceDto.toDomainOrNull(): NotificationTypePreference? {
    val type = alertType?.takeIf { it.isNotBlank() } ?: return null
    return NotificationTypePreference(
        alertType = type,
        enabled = enabled ?: true,
        push = push ?: false,
        email = email ?: false,
        sms = sms ?: false,
        inApp = inApp ?: false,
    )
}

internal fun NotificationTypePreference.toUpdateDto(): AlertTypePreferenceUpdateDto =
    AlertTypePreferenceUpdateDto(
        alertType = alertType,
        enabled = enabled,
        push = push,
        email = email,
        sms = sms,
        inApp = inApp,
    )
