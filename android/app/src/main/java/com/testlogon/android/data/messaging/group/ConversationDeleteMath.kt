package com.testlogon.android.data.messaging.group

/**
 * AND-160 — pure decision logic for the "Delete conversation" action (DELETE
 * /messaging/conversations/{id}). Kept as a tiny pure object so the degrade-on-404 rule is
 * unit-testable without a network or Room, and reused by [GroupRepositoryImpl.deleteConversation].
 *
 * Rule: a successful DELETE removes the conversation. A 404 (already gone) and a 410 (gone) are
 * BENIGN — the end state is identical to a success (the conversation no longer exists), so we treat
 * them as success and still evict the local cache / pop the thread. Every other status is a real
 * failure surfaced to the caller.
 */
object ConversationDeleteMath {

    const val HTTP_NOT_FOUND = 404
    const val HTTP_GONE = 410

    /**
     * True when a non-2xx [status] should still be COALESCED to success (the conversation is already
     * absent, so the user's intent — "make it gone" — is satisfied). Null (no HTTP status, e.g. a
     * transport error) is NOT benign.
     */
    fun isBenignDeleteFailure(status: Int?): Boolean =
        status == HTTP_NOT_FOUND || status == HTTP_GONE
}
