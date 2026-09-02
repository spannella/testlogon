package com.testlogon.android.feature.agents.feedback.data

import com.testlogon.android.core.network.agents.FeedbackRequestDto

/**
 * AGENTS-BASICS (web-parity) - DTO -> domain mappers for the FEEDBACK surface (in :app; core-model cannot depend
 * on core-network). Epoch-0 sentinels map to null.
 */
fun FeedbackRequestDto.toDomain(): FeedbackRequest = FeedbackRequest(
    requestId = requestId,
    workerId = workerId,
    ticketId = ticketId,
    status = FeedbackStatus.from(feedbackStatus),
    statusWire = feedbackStatus,
    question = question,
    terminalContext = terminalContext,
    detectedPattern = detectedPattern,
    responseText = responseText,
    respondedAt = respondedAt.takeIf { it > 0 },
    timeoutAt = timeoutAt.takeIf { it > 0 },
    timeoutAction = timeoutAction,
    createdAt = createdAt.takeIf { it > 0 },
)

fun com.testlogon.android.core.network.agents.TerminalOutputDto.toDomain(): TerminalOutput = TerminalOutput(
    workerId = workerId,
    output = output,
    charCount = charCount,
)
