package com.testlogon.android.notifications

import javax.inject.Inject

/**
 * AND-107 — parsed, validated FCM data payload consumed by the notification presenter (AND-107) and
 * the deep-link router (AND-108).
 *
 * `entityId` drives both the deterministic notification id (dedupe/replace) and the deep-link target.
 * `deepLink` is optional and passed through verbatim.
 */
data class PushPayload(
    val kind: NotificationKind,
    val entityId: String,
    val title: String,
    val body: String,
    val deepLink: String?,
)

/**
 * AND-107 — FCM `data` map -> [PushPayload]. Pure/framework-free (no android.util.*) so the full
 * matrix is JVM-unit-testable.
 *
 * The Android-proposed keys (`kind`, `entity_id`, `title`, `body`, `deep_link`) are tolerated
 * alongside the real backend names (`notification_type`, `notification_id`) per AND-107/AND-108 §5,
 * since the backend notification model uses `notification_type` + `notification_id` + a free-form
 * `data` map (verified: reference/src/api/types.ts NotificationOut). Parsing rules:
 *  - kind is lowercased and matched; unmatched -> UNKNOWN (routed to broadcasts, FR-4).
 *  - entityId/title/body are required; a payload missing any is dropped (returns null).
 *  - deepLink is optional, verbatim. All values are strings (FCM data is Map<String,String>).
 */
class PushPayloadParser @Inject constructor() {

    fun parse(data: Map<String, String>): PushPayload? {
        val kindToken = data["kind"] ?: data["notification_type"]
        val entityId = (data["entity_id"] ?: data["notification_id"])?.takeIf { it.isNotBlank() }
            ?: return null
        val title = data["title"]?.takeIf { it.isNotBlank() } ?: return null
        val body = data["body"]?.takeIf { it.isNotBlank() } ?: return null
        val deepLink = data["deep_link"]?.takeIf { it.isNotBlank() }
        return PushPayload(
            kind = kindFrom(kindToken),
            entityId = entityId,
            title = title,
            body = body,
            deepLink = deepLink,
        )
    }

    private fun kindFrom(token: String?): NotificationKind = when (token?.lowercase()) {
        "message" -> NotificationKind.MESSAGE
        "broadcast" -> NotificationKind.BROADCAST
        "alert" -> NotificationKind.ALERT
        else -> NotificationKind.UNKNOWN
    }
}
