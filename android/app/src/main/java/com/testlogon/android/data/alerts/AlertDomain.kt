package com.testlogon.android.data.alerts

/**
 * AND-086 / AND-087 — framework-free domain types for alert targets.
 *
 * The backend exposes no per-target id or verified flag — presence in AlertPreferences.emails /
 * .sms_numbers means the target is verified. The pending add is challenge-scoped, never a list row.
 */

/** Outcome of a begin (or resend = re-begin) dispatch: {challenge_id, sent_to}. */
data class AlertBeginResult(
    val challengeId: String,
    val sentTo: String,
)
