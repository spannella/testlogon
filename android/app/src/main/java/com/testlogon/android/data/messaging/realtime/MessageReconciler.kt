package com.testlogon.android.data.messaging.realtime

/**
 * AND-148 — pure, JVM-testable live-reconciliation core for a single conversation thread.
 *
 * Merges the cold REST snapshot (paged history) with the hot SSE tail into ONE ordered, de-duplicated
 * list, and answers the "did we miss anything across a reconnect?" question. It owns NO transport and
 * NO Room — the repository writes the merged result through the cache (single source of truth). This
 * formalises + hardens (does not duplicate) the existing per-event reconcile already wired through
 * ThreadViewModel/MessagingRepository.applyInboundMessage / applyMessageMutation.
 *
 * Ordering key (verified against the web client + the Message payload — there is NO wire `seq`):
 * ascending `(createdAtEpochSeconds, id)` in-thread. De-duplication is by the stable string `id`;
 * last-writer-wins on the same id (FR-2/FR-8). The resume cursor is the NEWEST known id, sent as the
 * `after` query param on reconnect (verified: GET /messaging/events/stream `params=after,...`), NOT a
 * Last-Event-ID header (the backend has no such resume contract — AND-148 §5.2 / AND-150 FR-5).
 */
object MessageReconciler {

    /** A reconciler row: a stable id + its sort key. Generic so it works over entities or domain. */
    data class Row(val id: String, val createdAtEpochSeconds: Long)

    private val comparator: Comparator<Row> =
        compareBy<Row> { it.createdAtEpochSeconds }.thenBy { it.id }

    /**
     * Merge [incoming] rows into [existing], de-duplicating by id (incoming wins — it is the fresher
     * write) and returning the union in strict ascending `(createdAt, id)` order. Idempotent: merging
     * the same rows N times yields the same list as merging once (AC-3 / FR-8).
     */
    fun merge(existing: List<Row>, incoming: List<Row>): List<Row> {
        if (incoming.isEmpty()) return existing.sortedWith(comparator)
        val byId = LinkedHashMap<String, Row>(existing.size + incoming.size)
        existing.forEach { byId[it.id] = it }
        incoming.forEach { byId[it.id] = it } // last-writer-wins on duplicate id
        return byId.values.sortedWith(comparator)
    }

    /** The resume cursor to send as `after=` on (re)connect: the NEWEST known id, or null if empty. */
    fun resumeCursor(rows: List<Row>): String? =
        rows.maxWithOrNull(comparator)?.id

    /**
     * Decide whether a reconnect needs a REST backfill. Because the backend has no monotonic `seq`,
     * we treat a reconnect as potentially lossy and key recovery on the resume cursor: if the first
     * live event after reconnect is NOT contiguous with what we hold (its predecessor id is unknown
     * AND it is strictly newer than our head by more than the live tail we received), a backfill of
     * the head page closes any gap idempotently. Conservatively: backfill whenever the reconnect
     * delivered no overlap with our known ids.
     *
     * @param knownIds the ids currently cached for the thread.
     * @param resumedIds the ids delivered by the stream immediately after reconnect.
     * @return true when a head-page REST backfill should run to guarantee no gap (FR-2/FR-6).
     */
    fun needsBackfill(knownIds: Set<String>, resumedIds: List<String>): Boolean {
        if (knownIds.isEmpty()) return false // cold start: the snapshot mediator already covers it
        if (resumedIds.isEmpty()) return false // nothing arrived; a later event/list refresh reconciles
        // Lossless overlap: at least one resumed id was already known => the tail is contiguous.
        val hasOverlap = resumedIds.any { it in knownIds }
        return !hasOverlap
    }
}
