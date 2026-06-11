package com.testlogon.android.data.gcal

import com.squareup.moshi.Json
import com.squareup.moshi.JsonClass

/**
 * AND-273 — Moshi DTOs for the Google Calendar integration contract, verified against
 * openapi.pretty.json schemas + src/api/endpoints/calendar.ts google helpers.
 *
 * Mappers tolerate absent optionals via Kotlin/Moshi defaults and never throw. The `provider` constant
 * is always "google".
 */

// POST ui/calendar/integrations/google/connect/start -> GoogleCalendarConnectStartOut
@JsonClass(generateAdapter = true)
data class ConnectStartDto(
    @Json(name = "authorization_url") val authorizationUrl: String,
    val state: String,
    val nonce: String,
    @Json(name = "expires_at_utc") val expiresAtUtc: String,
    val provider: String = "google",
)

// GET ui/calendar/integrations/google/connect/callback?code=&state=&error= -> GoogleCalendarConnectCallbackOut
@JsonClass(generateAdapter = true)
data class ConnectCallbackDto(
    @Json(name = "connection_id") val connectionId: String,
    @Json(name = "account_email") val accountEmail: String,
    val linked: Boolean,
    @Json(name = "updated_at_utc") val updatedAtUtc: String,
    val provider: String = "google",
)

// GET ui/calendar/integrations/google/status -> GoogleCalendarIntegrationStatusOut
@JsonClass(generateAdapter = true)
data class IntegrationStatusDto(
    @Json(name = "connection_active") val connectionActive: Boolean = false,
    @Json(name = "sync_enabled") val syncEnabled: Boolean = false,
    @Json(name = "writeback_enabled") val writebackEnabled: Boolean = false,
    @Json(name = "reauth_required") val reauthRequired: Boolean = false,
    @Json(name = "sync_health") val syncHealth: String = "unknown",
    @Json(name = "last_sync_status") val lastSyncStatus: String = "never_synced",
    @Json(name = "last_sync_at_utc") val lastSyncAtUtc: String = "",
    @Json(name = "rollout_mode") val rolloutMode: String = "off",
    @Json(name = "rollout_percent") val rolloutPercent: Int = 0,
    @Json(name = "in_rollout_cohort") val inRolloutCohort: Boolean = false,
    val provider: String = "google",
)

// GET ui/calendar/integrations/google/calendars -> GoogleCalendarProviderCalendarsOut
@JsonClass(generateAdapter = true)
data class ProviderCalendarDto(
    @Json(name = "google_calendar_id") val googleCalendarId: String,
    val summary: String = "",
    @Json(name = "access_role") val accessRole: String? = null,
    val primary: Boolean = false,
    @Json(name = "mapped_internal_calendar_id") val mappedInternalCalendarId: String? = null,
)

@JsonClass(generateAdapter = true)
data class ProviderCalendarsDto(
    val calendars: List<ProviderCalendarDto> = emptyList(),
)

// POST ui/calendar/integrations/google/mappings body=GoogleCalendarMappingCreateIn
@JsonClass(generateAdapter = true)
data class MappingCreateDto(
    @Json(name = "internal_calendar_id") val internalCalendarId: String,
    @Json(name = "google_calendar_id") val googleCalendarId: String,
)

// -> GoogleCalendarMappingOut
@JsonClass(generateAdapter = true)
data class MappingDto(
    @Json(name = "mapping_id") val mappingId: String = "",
    @Json(name = "user_sub") val userSub: String = "",
    @Json(name = "internal_calendar_id") val internalCalendarId: String = "",
    @Json(name = "google_calendar_id") val googleCalendarId: String = "",
    val active: Boolean = false,
    @Json(name = "created_at_utc") val createdAtUtc: String = "",
    @Json(name = "updated_at_utc") val updatedAtUtc: String = "",
    @Json(name = "unmapped_at_utc") val unmappedAtUtc: String = "",
    val provider: String = "google",
)

// POST ui/calendar/integrations/google/disconnect?connection_id= -> GoogleCalendarDisconnectOut
@JsonClass(generateAdapter = true)
data class DisconnectDto(
    @Json(name = "connection_id") val connectionId: String = "",
    @Json(name = "account_email") val accountEmail: String = "",
    val active: Boolean = false,
    val revoked: Boolean = false,
    @Json(name = "revoke_status") val revokeStatus: String = "",
    @Json(name = "disconnected_at_utc") val disconnectedAtUtc: String = "",
    val provider: String = "google",
)

// POST ui/calendar/integrations/google/sync/run?mode= -> GoogleCalendarSyncRunOut
@JsonClass(generateAdapter = true)
data class SyncRunDto(
    val accepted: Boolean = false,
    val mode: String = "incremental",
    @Json(name = "rate_limited") val rateLimited: Boolean = false,
    val metrics: Map<String, Any?> = emptyMap(),
)
