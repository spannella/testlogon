package com.testlogon.android.data.messaging.report

/**
 * AND-163 — domain models for message reporting. JVM-pure (no android.* / java.time API-26).
 *
 * `reason_code` is a backend free string (2..64); the selectable set mirrors the web client's
 * MODERATION_TOPICS (reference/src/components/shared/ReportContentModal.tsx) verbatim. The previously
 * proposed uppercase enum (SPAM/HARASSMENT/...) is NOT what the backend/web use.
 */
enum class ReportReason(val code: String) {
    // MOD-C1 — the six live moderation categories (backend `topics`): spam, harassment, hate, sexual,
    // violence_threats, other. Old codes (extortion/criminal/racist) are retired here; the backend keeps
    // back-compat acceptance of the retired codes, but the app only ever offers this current six.
    SPAM("spam"),
    HARASSMENT("harassment"),
    HATE("hate"),
    SEXUAL("sexual"),
    VIOLENCE_THREATS("violence_threats"),
    OTHER("other"),
    ;

    companion object {
        /** The selectable reason set, in display order (matches the web client). */
        val SELECTABLE: List<ReportReason> = entries.toList()
    }
}

/**
 * AND-163 — client-side report status for a target message. There is NO server report-status GET
 * endpoint (the only status endpoint is moderator-facing), so this is a client-only affordance:
 *  - NONE — never reported on this device,
 *  - PENDING — optimistic, in-flight,
 *  - SUBMITTED — the POST returned 200 (status const "submitted").
 *
 * `ALREADY_REPORTED` is intentionally absent: the verified contract has no 409 / already_reported.
 */
enum class ReportStatus { NONE, PENDING, SUBMITTED }

/** AND-163 — the parsed result of a successful message report. `createdAt` is epoch SECONDS. */
data class Report(
    val reportId: String,
    val conversationId: String,
    val messageId: String,
    val reasonCode: String,
    val status: ReportStatus,
    val createdAtEpochSeconds: Long,
)

/** AND-163 — map the wire response to the domain Report. The const status "submitted" -> SUBMITTED. */
internal fun ReportMessageResponseDto.toDomain(): Report = Report(
    reportId = reportId,
    conversationId = conversationId,
    messageId = messageId,
    reasonCode = reasonCode,
    status = if (status.equals("submitted", ignoreCase = true)) ReportStatus.SUBMITTED else ReportStatus.NONE,
    createdAtEpochSeconds = createdAt,
)
