package com.testlogon.android.core.network.delegates

import okhttp3.Interceptor
import okhttp3.Response
import javax.inject.Inject
import javax.inject.Singleton

/**
 * Delegate full-parity messaging: re-targets the SHARED messaging requests onto their delegate
 * (creator-attributed) equivalents while [DelegateRoutingStore.activeCreatorId] is set.
 *
 * DESIGN - reuse, don't duplicate: the whole normal messaging stack (ThreadViewModel / MessagingRepository
 * / MessagingApi + the media presign/upload transport) is reused verbatim. This interceptor is the single
 * "flag that swaps the send targets": while managing a creator it rewrites ONLY the exact paths that have a
 * verified delegate backend route (see ops/prod-hotfixes/delegate_fullparity_messaging.patch) so the
 * backend re-runs the identical normal send handlers with user_id=creator and stamps [via @delegate].
 *
 * The rewrite is a WHITELIST - any messaging path WITHOUT a delegate route (read receipts, tips, unlock,
 * pins, voice/voicemail, polls, calendar/find-datetime, delete/revoke, hide, schedule mgmt, attachment
 * grants, search, single-conversation GET, the conversation LIST) is left untouched and simply acts as the
 * delegate's own identity server-side (harmless / gated). Query params and body are preserved.
 *
 * Supported rewrites (normal -> delegate), method-scoped:
 *  - POST   messaging/conversations/{cid}/messages             -> .../delegate/{c}/conversations/{cid}/messages/text
 *  - GET    messaging/conversations/{cid}/messages             -> .../delegate/{c}/conversations/{cid}/messages
 *  - POST   messaging/conversations/{cid}/images/presign       -> delegate (covers image/gallery/video/lottery media)
 *  - POST   messaging/conversations/{cid}/messages/image       -> delegate
 *  - POST   messaging/conversations/{cid}/messages/gallery     -> delegate
 *  - POST   messaging/conversations/{cid}/messages/video-share -> delegate
 *  - POST   messaging/conversations/{cid}/messages/file        -> delegate
 *  - POST   messaging/conversations/{cid}/messages/countdown   -> delegate
 *  - POST   messaging/conversations/{cid}/messages/{mid}/reactions -> delegate
 *  - PATCH  messaging/conversations/{cid}/messages/{mid}       -> delegate (edit)
 *  - POST   messaging/messages/lottery                         -> .../delegate/{c}/messages/lottery
 */
@Singleton
class DelegateRoutingInterceptor @Inject constructor(
    private val store: DelegateRoutingStore,
) : Interceptor {

    override fun intercept(chain: Interceptor.Chain): Response {
        val request = chain.request()
        val creator = store.activeCreatorId ?: return chain.proceed(request)

        val segments = request.url.encodedPathSegments
        val rewritten = rewrite(segments, request.method, creator)
            ?: return chain.proceed(request)

        val newUrl = request.url.newBuilder()
            .encodedPath("/" + rewritten.joinToString("/"))
            .build()
        return chain.proceed(request.newBuilder().url(newUrl).build())
    }

    /**
     * Returns the rewritten path segments (WITHOUT a leading slash), or null when the request must be left
     * unchanged. Pure + side-effect free so it is unit-testable in isolation.
     */
    internal fun rewrite(segments: List<String>, method: String, creator: String): List<String>? {
        // messaging/messages/lottery  (conversation is in the BODY, not the path)
        if (method == "POST" &&
            segments.size == 3 &&
            segments[0] == "messaging" && segments[1] == "messages" && segments[2] == "lottery"
        ) {
            return listOf("messaging", "delegate", creator, "messages", "lottery")
        }

        // messaging/events/poll  (DELEGATE REALTIME: inbound arrives live projected for the creator)
        if (method == "GET" &&
            segments.size == 3 &&
            segments[0] == "messaging" && segments[1] == "events" && segments[2] == "poll"
        ) {
            return listOf("messaging", "delegate", creator, "events", "poll")
        }

        // messaging/messages/find-datetime/{poll_id}/{availability|close}  (poll_id-scoped)
        if (method == "POST" &&
            segments.size == 5 &&
            segments[0] == "messaging" && segments[1] == "messages" && segments[2] == "find-datetime" &&
            (segments[4] == "availability" || segments[4] == "close")
        ) {
            return listOf("messaging", "delegate", creator) + segments.drop(1)
        }

        // messaging/conversations/{cid}/<tail...>
        if (segments.size < 4 || segments[0] != "messaging" || segments[1] != "conversations") return null
        val tail = segments.drop(3) // everything after {cid}

        val supported = when {
            tail == listOf("images", "presign") && method == "POST" -> true
            tail == listOf("messages") && (method == "POST" || method == "GET") -> true
            tail == listOf("messages", "image") && method == "POST" -> true
            tail == listOf("messages", "gallery") && method == "POST" -> true
            tail == listOf("messages", "video-share") && method == "POST" -> true
            tail == listOf("messages", "file") && method == "POST" -> true
            tail == listOf("messages", "countdown") && method == "POST" -> true
            // remaining kinds (DELEGATE-REST): voice / voicemail / gif / sticker / poll /
            // calendar-event / calendar-share / find-datetime.
            tail == listOf("messages", "gif") && method == "POST" -> true
            tail == listOf("messages", "sticker") && method == "POST" -> true
            tail == listOf("messages", "poll") && method == "POST" -> true
            tail == listOf("messages", "calendar-event") && method == "POST" -> true
            tail == listOf("messages", "calendar-share") && method == "POST" -> true
            tail == listOf("messages", "find-datetime") && method == "POST" -> true
            tail == listOf("voice-message") && method == "POST" -> true
            tail == listOf("voice-message", "presign") && method == "POST" -> true
            tail == listOf("voicemail") && method == "POST" -> true
            tail == listOf("voicemail", "presign") && method == "POST" -> true
            // message ACTIONS: mark-read (receipts) / typing.
            tail == listOf("read") && method == "POST" -> true
            tail == listOf("typing") && method == "POST" -> true
            // messages/{mid}/reactions
            tail.size == 3 && tail[0] == "messages" && tail[2] == "reactions" && method == "POST" -> true
            // messages/{mid}/{pin|hide}  (POST set, DELETE unset)
            tail.size == 3 && tail[0] == "messages" && (tail[2] == "pin" || tail[2] == "hide") &&
                (method == "POST" || method == "DELETE") -> true
            // messages/{mid}: PATCH = edit, DELETE = delete-for-me (NOT .../revoke, which has no route).
            tail.size == 2 && tail[0] == "messages" && (method == "PATCH" || method == "DELETE") -> true
            else -> false
        }
        if (!supported) return null

        // messaging/delegate/{creator}/conversations/{cid}/<tail...>
        val base = listOf("messaging", "delegate", creator) + segments.drop(1)
        // The bare text send has a distinct delegate sub-path (.../messages/text).
        return if (tail == listOf("messages") && method == "POST") base + "text" else base
    }
}
