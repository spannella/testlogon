package com.testlogon.android.core.model

/**
 * AND-080 — per-alert-type notification channel preferences, mirroring the backend
 * `AlertTypePreferenceUpdate` contract: each update targets one `alert_type` with flat,
 * nullable channel booleans (web has no typed GET response; the Android port models a
 * fixed catalog of alert types and reads back via re-GET — see repository).
 */
enum class NotificationChannel { PUSH, EMAIL, SMS, IN_APP }

/**
 * The toggle state for a single alert type across the supported channels.
 * `enabled` is the per-type master flag (`AlertTypePreferenceUpdate.enabled`).
 */
data class NotificationTypePreference(
    val alertType: String,
    val enabled: Boolean = true,
    val push: Boolean = false,
    val email: Boolean = false,
    val sms: Boolean = false,
    val inApp: Boolean = false,
) {
    fun channelEnabled(channel: NotificationChannel): Boolean = when (channel) {
        NotificationChannel.PUSH -> push
        NotificationChannel.EMAIL -> email
        NotificationChannel.SMS -> sms
        NotificationChannel.IN_APP -> inApp
    }

    fun withChannel(channel: NotificationChannel, value: Boolean): NotificationTypePreference =
        when (channel) {
            NotificationChannel.PUSH -> copy(push = value)
            NotificationChannel.EMAIL -> copy(email = value)
            NotificationChannel.SMS -> copy(sms = value)
            NotificationChannel.IN_APP -> copy(inApp = value)
        }
}

/** Snapshot of all known alert-type preferences. */
data class NotificationPreferences(
    val types: List<NotificationTypePreference> = emptyList(),
)
