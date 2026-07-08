package com.testlogon.android.feature.settings.msgprivacy

/**
 * TIP-B4 (TIP-404) — framework-free domain model for the caller's pay-to-message settings.
 *
 * When [requireTipToMessage] is on, a NEW sender (no existing conversation, not mutual-follow, not
 * on the allowlist) must attach a tip >= [minTipCents] on their first message; that tip is credited
 * to the caller as non-refundable creator earnings. Users on [tipFreeAllowlist] bypass the gate.
 */
data class MessagePrivacy(
    val requireTipToMessage: Boolean,
    val minTipCents: Int,
    val tipFreeAllowlist: List<String>,
)
