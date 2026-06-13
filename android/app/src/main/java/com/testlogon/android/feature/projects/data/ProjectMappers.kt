package com.testlogon.android.feature.projects.data

import com.testlogon.android.core.model.projects.DriveConnection
import com.testlogon.android.core.model.projects.Project
import com.testlogon.android.core.model.projects.ProviderStart
import com.testlogon.android.core.network.projects.ProjectOut
import com.testlogon.android.core.network.projects.ProviderCredentialOut
import com.testlogon.android.core.network.projects.ProviderOAuthStartOut

/**
 * AND-374 - DTO -> domain mappers for the PROJECTS surface.
 *
 * PLACEMENT: core-model has NO dependency on core-network's DTOs (and core-network has no domain dep), so the
 * bridging mapper lives here in the :app feature, which depends on BOTH (mirrors AND-372 TicketMappers /
 * AND-358 CollaborationMappers).
 *
 * Key transforms:
 *  - timestamps pass through as RAW ISO-8601 Strings (the UI parses / relative-formats them).
 *  - tags / settings pass through; description stays nullable.
 *  - a successful credential read maps to DriveConnection(connected = true) carrying the scopes; the "not
 *    connected" case (404 / error) is synthesized by the repository, not here.
 */
fun ProjectOut.toDomain(): Project = Project(
    id = id,
    owner = owner,
    name = name,
    description = description,
    tags = tags,
    settings = settings,
    createdAt = createdAt,
    updatedAt = updatedAt,
)

fun ProviderOAuthStartOut.toDomain(): ProviderStart = ProviderStart(
    provider = provider,
    authorizationUrl = authorizationUrl,
    state = state,
    expiresAt = expiresAt,
)

fun ProviderCredentialOut.toDriveConnection(): DriveConnection = DriveConnection(
    connected = true,
    scopes = scopes,
)
