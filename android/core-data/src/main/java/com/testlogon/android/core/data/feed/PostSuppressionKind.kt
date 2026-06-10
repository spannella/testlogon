package com.testlogon.android.core.data.feed

/**
 * AND-175 — the kind of suppression recorded for a post. Stored as [name] in
 * [PostSuppressionEntity.kind]. HIDDEN = an explicit "hide this post"; NOT_INTERESTED = a "show fewer
 * like this" signal (implemented via the same /feed/hide endpoint; the kind is local UX/telemetry
 * metadata only — there is no dedicated negative-preference endpoint).
 */
enum class PostSuppressionKind { HIDDEN, NOT_INTERESTED }
