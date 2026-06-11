package com.testlogon.android.data.gcal

/**
 * AND-273 — pure DTO->domain mappers. Tolerate absent optionals (Kotlin/Moshi defaults); never throw.
 * There is no string status enum to parse — the connection phase is derived from booleans on the domain.
 */
fun IntegrationStatusDto.toDomain(cachedAccountEmail: String? = null): GoogleCalendarStatus =
    GoogleCalendarStatus(
        connectionActive = connectionActive,
        syncEnabled = syncEnabled,
        writebackEnabled = writebackEnabled,
        reauthRequired = reauthRequired,
        syncHealth = syncHealth,
        lastSyncStatus = lastSyncStatus,
        lastSyncAtUtc = lastSyncAtUtc,
        rolloutMode = rolloutMode,
        rolloutPercent = rolloutPercent,
        inRolloutCohort = inRolloutCohort,
        accountEmail = cachedAccountEmail,
    )

fun ConnectStartDto.toDomain(): ConnectStart = ConnectStart(
    authorizationUrl = authorizationUrl,
    state = state,
    nonce = nonce,
    expiresAtUtc = expiresAtUtc,
)

fun ProviderCalendarDto.toDomain(): ProviderCalendar = ProviderCalendar(
    googleCalendarId = googleCalendarId,
    summary = summary,
    accessRole = accessRole,
    primary = primary,
    mappedInternalCalendarId = mappedInternalCalendarId,
)

fun MappingDto.toProviderCalendar(): ProviderCalendar = ProviderCalendar(
    googleCalendarId = googleCalendarId,
    summary = "",
    accessRole = null,
    primary = false,
    mappedInternalCalendarId = internalCalendarId.takeIf { active && it.isNotBlank() },
)
