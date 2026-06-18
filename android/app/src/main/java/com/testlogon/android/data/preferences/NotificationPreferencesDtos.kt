package com.testlogon.android.data.preferences

import com.squareup.moshi.Json
import com.squareup.moshi.JsonClass
import com.testlogon.android.core.model.NotificationTypePreference

/**
 * AND-080 — Moshi DTOs for `/ui/alerts/type-preferences`.
 *
 * The POST body is the verified `AlertTypePreferenceUpdate` (one alert type per call; flat, nullable
 * channel booleans). The GET response carries `type_preferences` as an OBJECT keyed by alert_type
 * (each value = the channel flags), e.g. `{"login_success":{"enabled":true,"email":true,...}}`. We
 * decode that map (and tolerate a legacy `preferences` list of the flat shape), flattening to the flat
 * [AlertTypePreferenceDto] the repository maps to domain. Authoritative state is re-read after each POST.
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

/** The per-alert-type channel flags carried as the VALUE of the `type_preferences` map. */
@JsonClass(generateAdapter = true)
data class AlertTypeChannelsDto(
    @Json(name = "enabled") val enabled: Boolean? = null,
    @Json(name = "push") val push: Boolean? = null,
    @Json(name = "email") val email: Boolean? = null,
    @Json(name = "sms") val sms: Boolean? = null,
    @Json(name = "in_app") val inApp: Boolean? = null,
)

/**
 * GET envelope. `type_preferences` is an OBJECT keyed by alert_type (the real server shape); a legacy
 * `preferences` list of flat rows is tolerated as a fallback.
 */
@JsonClass(generateAdapter = true)
data class AlertTypePreferencesEnvelopeDto(
    @Json(name = "type_preferences") val typePreferences: Map<String, AlertTypeChannelsDto>? = null,
    @Json(name = "preferences") val preferences: List<AlertTypePreferenceDto>? = null,
) {
    /** Flatten to the flat row shape (injecting the map key as alert_type). */
    fun entries(): List<AlertTypePreferenceDto> {
        typePreferences?.let { map ->
            return map.map { (type, ch) ->
                AlertTypePreferenceDto(
                    alertType = type,
                    enabled = ch.enabled,
                    push = ch.push,
                    email = ch.email,
                    sms = ch.sms,
                    inApp = ch.inApp,
                )
            }
        }
        return preferences ?: emptyList()
    }
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
