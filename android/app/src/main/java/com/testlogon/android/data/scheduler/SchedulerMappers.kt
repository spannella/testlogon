package com.testlogon.android.data.scheduler

import java.time.Instant

/**
 * AND-275 — pure DTO->domain mapper. Epoch-SECONDS integers convert via [Instant.ofEpochSecond];
 * nullable timestamps stay null. Never throws.
 */
fun ScheduledActionOutDto.toDomain(): ScheduledAction = ScheduledAction(
    actionId = actionId,
    actionType = actionType,
    status = status,
    scheduledAt = Instant.ofEpochSecond(scheduledAt),
    createdAt = Instant.ofEpochSecond(createdAt),
    updatedAt = updatedAt?.let(Instant::ofEpochSecond),
    completedAt = completedAt?.let(Instant::ofEpochSecond),
    title = title,
    description = description,
    payload = payload,
    error = error,
    retryCount = retryCount,
    maxRetries = maxRetries,
    notifyBeforeSeconds = notifyBeforeSeconds,
    reminderSent = reminderSent,
)
