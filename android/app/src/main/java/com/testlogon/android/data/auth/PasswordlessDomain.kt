package com.testlogon.android.data.auth

/**
 * Domain types for the passwordless / magic-link flow (AND-060/061).
 *
 * These translate the wire DTOs into typed outcomes the feature layer branches on, so the
 * passwordless ViewModels never touch raw HTTP/Moshi shapes. The flow is unauthenticated; a
 * successful verify establishes the session on the shared cookie jar.
 */

/** Outcome of [PasswordlessRepository.start] (AND-060). */
data class PasswordlessStarted(
    /** Required server status string (e.g. "sent"). */
    val status: String,
    /**
     * Server-returned destinations (`sent_to`), opaque and not guaranteed masked. Optional
     * enrichment only — the confirmation screen primarily echoes the user's typed identifier.
     */
    val sentTo: List<String> = emptyList(),
)

/**
 * Outcome of [PasswordlessRepository.verify] (AND-061), discriminated exactly as the web client does.
 *
 * - [Authenticated]: full session granted (`status == "ok"` AND `session_id` present).
 * - [MfaRequired]: first factor passed but a second is required (`auth_required` AND `challenge_id`).
 * - [Invalid]: any other 200 body (neither full-session nor MFA) — treated as an invalid/expired link.
 */
sealed interface PasswordlessVerified {
    data object Authenticated : PasswordlessVerified

    data class MfaRequired(
        val challengeId: String,
        val requiredFactors: List<String>,
    ) : PasswordlessVerified

    data object Invalid : PasswordlessVerified
}
