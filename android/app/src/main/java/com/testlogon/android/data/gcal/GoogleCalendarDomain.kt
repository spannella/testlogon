package com.testlogon.android.data.gcal

/**
 * AND-273 — Google Calendar integration domain models (DTO-free).
 *
 * This integration is BACKEND-MEDIATED OAuth (verified): the backend returns an `authorization_url`
 * which the client opens in a Custom Tab; the backend handles the token exchange off the provider
 * redirect. The client never talks to Google's APIs and never holds Google tokens — so NO Google /
 * GMS SDK dependency is added. (See spec AND-273 §2/§5; this is the redirect path, not an SDK seam.)
 *
 * Mirrors the verified OpenAPI schemas: GoogleCalendarConnectStartOut / GoogleCalendarConnectCallbackOut
 * / GoogleCalendarIntegrationStatusOut / GoogleCalendarProviderCalendarOut / GoogleCalendarMappingOut /
 * GoogleCalendarDisconnectOut (openapi.pretty.json) + src/api/endpoints/calendar.ts google helpers.
 */

/** Derived client-side connection phase (the backend status is booleans, not a single enum). */
enum class ConnectPhase { DISCONNECTED, CONNECTING, CONNECTED, REAUTH_REQUIRED }

/** Result of connect/start: the opaque authorization URL + the OAuth state/nonce to persist. */
data class ConnectStart(
    val authorizationUrl: String,
    val state: String,
    val nonce: String,
    val expiresAtUtc: String,
)

/** Mirrors GoogleCalendarIntegrationStatusOut. account email is cached from the callback (status omits it). */
data class GoogleCalendarStatus(
    val connectionActive: Boolean,
    val syncEnabled: Boolean,
    val writebackEnabled: Boolean,
    val reauthRequired: Boolean,
    val syncHealth: String,
    val lastSyncStatus: String,
    val lastSyncAtUtc: String,
    val rolloutMode: String,
    val rolloutPercent: Int,
    val inRolloutCohort: Boolean,
    val accountEmail: String?,
) {
    val phase: ConnectPhase
        get() = when {
            reauthRequired -> ConnectPhase.REAUTH_REQUIRED
            connectionActive -> ConnectPhase.CONNECTED
            else -> ConnectPhase.DISCONNECTED
        }
}

/** Mirrors GoogleCalendarProviderCalendarOut — flat, NOT the AND-270 Calendar type. */
data class ProviderCalendar(
    val googleCalendarId: String,
    val summary: String,
    val accessRole: String?,
    val primary: Boolean,
    val mappedInternalCalendarId: String?,
)
