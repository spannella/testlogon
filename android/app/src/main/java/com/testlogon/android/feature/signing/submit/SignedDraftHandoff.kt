package com.testlogon.android.feature.signing.submit

import com.testlogon.android.feature.signing.capture.model.SignedPacketDraft
import java.util.concurrent.ConcurrentHashMap
import javax.inject.Inject
import javax.inject.Singleton

/**
 * AND-343 - a process-scoped handoff for the AND-342 [SignedPacketDraft].
 *
 * DRAFT-HANDOFF CHOICE: a [SignedPacketDraft] (asset paths + placements) is not a primitive, so it can
 * NOT be a navigation argument. Rather than serialize it through SavedStateHandle, the AND-342
 * SigningRoute deposits the validated draft here keyed by packet id immediately before navigating, and
 * the AND-343 SubmitSignViewModel reads (and clears) it on load by the same packet id from its
 * SavedStateHandle. This singleton lives for the app process only (NO Room / disk persistence, NO
 * migration); if the process dies mid-flow the submit screen simply has no draft and flushes nothing,
 * which is the safe terminal behaviour (mark-done is then a pure terminal acknowledgement).
 */
@Singleton
class SignedDraftHandoff @Inject constructor() {

    private val drafts = ConcurrentHashMap<String, SignedPacketDraft>()

    /** Deposits [draft] for later pickup, keyed by its packet id. */
    fun put(draft: SignedPacketDraft) {
        if (draft.packetId.isNotBlank()) {
            drafts[draft.packetId] = draft
        }
    }

    /** Returns the draft for [packetId] without removing it (NULL when none was deposited). */
    fun peek(packetId: String): SignedPacketDraft? = drafts[packetId]

    /** Returns and removes the draft for [packetId] (a one-shot consume). */
    fun take(packetId: String): SignedPacketDraft? = drafts.remove(packetId)
}
