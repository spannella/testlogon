package com.testlogon.android.core.data.db

/**
 * AND-115 — common columns every cache row carries.
 *
 * Implemented by all Room cache entities. The on-device cache is **not** the source of truth (the
 * FastAPI backend is); rows here are last-known content rendered while the network is slow, flaky,
 * or offline.
 *
 * Contract for downstream AND-116 (SWR) / AND-118 (TTL + eviction):
 * - [id] is the logical cache key (primary key).
 * - [updatedAt] MUST be set to `System.currentTimeMillis()` on every upsert. It is the basis for
 *   AND-118 TTL expiry and is read by the freshness policy. Callers stamp it; the DAO does not.
 *
 * NOTE: never store auth cookies, the bearer access token, or the `ui_csrf` token in a cache row —
 * those live in the OkHttp cookie jar / DataStore (see AND-115 section 8).
 */
interface CacheEntity {
    /** Logical cache key / primary key. */
    val id: String

    /** Epoch millis the row was last written; basis for AND-118 TTL. */
    val updatedAt: Long
}
