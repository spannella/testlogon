package com.testlogon.android.data.call

import java.util.UUID

/**
 * AND-295 (FR-9) — small helpers for the idempotent-bodied call operations.
 *
 * [newKey] mints a UUIDv4 string for `idempotency_key`; [deriveEnd] derives a stable, distinct key for
 * the `end` POST from a base key so a retried end is server-side deduped (matching AND-296 §6). Kept
 * java.util-only (no android.*) so it is JVM-unit-testable.
 */
object IdempotencyKey {
    fun newKey(): String = UUID.randomUUID().toString()

    fun deriveEnd(baseKey: String): String = "$baseKey-end"
}

/** AND-296 (FR-2) — mints a client call id (UUIDv4) for a new outgoing call. */
object CallId {
    fun new(): String = UUID.randomUUID().toString()
}

/** AND-290/295 — mints a per-signal nonce (UUIDv4; satisfies the server minLength=8 constraint). */
object SignalNonce {
    fun new(): String = UUID.randomUUID().toString()
}
