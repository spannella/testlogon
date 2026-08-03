package com.testlogon.android.feature.webhooks.data

import com.testlogon.android.core.model.webhooks.Webhook
import com.testlogon.android.core.model.webhooks.WebhookTestResult
import com.testlogon.android.core.model.webhooks.WebhookEventType
import com.testlogon.android.core.network.webhooks.WebhookEndpointDto
import com.testlogon.android.core.network.webhooks.WebhookTestResultDto
import com.testlogon.android.core.network.webhooks.WebhookEventTypeDto

/**
 * AND-398 - DTO -> domain mappers for the webhooks (light) surface. They live in :app (NOT core-model) because
 * core-model cannot depend on core-network. Mirrors the AND-372 TicketMappers pattern.
 *
 * FIELD CORRECTIONS baked in (see the AND-398 CORRECTED contract): domain.id <- dto.endpoint_id,
 * domain.events <- dto.event_types, domain.enabled <- dto.enabled (NOT `active`), domain.secretSet is DERIVED
 * (dto.secret != null), and domain.createdAt is the epoch-SECONDS Long passed through verbatim (formatted at
 * the UI).
 */

/** Maps a wire [WebhookEndpointDto] to the domain [Webhook] (secretSet derived; the one-time secret passed on). */
fun WebhookEndpointDto.toDomain(): Webhook = Webhook(
    id = endpointId,
    url = url,
    description = description.orEmpty(),
    events = eventTypes,
    enabled = enabled,
    secretSet = secret != null,
    secret = secret,
    createdAt = createdAt,
)

/** Maps a wire [WebhookEventTypeDto] to the domain [WebhookEventType] (description defaulted to ""). */
fun WebhookEventTypeDto.toDomain(): WebhookEventType = WebhookEventType(
    type = type,
    description = description.orEmpty(),
)

/** PAR-26 - maps a wire [WebhookTestResultDto] to the domain [WebhookTestResult] (succeeded is derived). */
fun WebhookTestResultDto.toDomain(): WebhookTestResult = WebhookTestResult(
    deliveryId = deliveryId,
    status = status,
    responseCode = responseCode,
    error = error,
    durationMs = durationMs,
)
