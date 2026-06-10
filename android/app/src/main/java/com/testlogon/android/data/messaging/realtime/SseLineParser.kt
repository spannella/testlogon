package com.testlogon.android.data.messaging.realtime

import okio.BufferedSource

/**
 * AND-143 (SSE client core) — pure, transport-decoupled Server-Sent-Events line/frame parser.
 *
 * This is the hardened, reusable core of the SSE wire protocol that previously lived inline inside
 * [SseMessagingEventStream.readFrames]. It is kept free of OkHttp/Android types (it only depends on
 * okio's [BufferedSource], which is itself JVM-friendly and feedable from a plain byte buffer) so the
 * frame state machine — including comment/heartbeat handling and `id:`/`retry:`/`event:`/`data:`
 * field accumulation per the WHATWG SSE grammar — is fully unit-testable on the JVM without a socket.
 *
 * Per the SSE spec a frame is a run of `field: value` lines terminated by a blank line. We accumulate:
 *  - `event:` -> the event name (defaults to "message" when unnamed),
 *  - `data:`  -> data payload lines, joined with '\n',
 *  - `id:`    -> the last-event-id (retained across frames for resume — AND-143 FR-3),
 *  - `retry:` -> the server-suggested reconnect time in ms (a floor for backoff — AND-143 FR-6),
 *  - lines beginning with ':' are comments/heartbeats and keep the socket alive (not a frame).
 *
 * The parser tracks the most-recent non-blank `id:` as [lastEventId] so a reconnect can replay it via
 * the `Last-Event-ID` header. It never logs payloads.
 */
class SseLineParser {

    /** Most recently observed SSE `id:` value; retained for `Last-Event-ID` resume. Null until seen. */
    var lastEventId: String? = null
        private set

    /** Most recent server `retry:` hint in milliseconds, or null if the server has not sent one. */
    var retryMillis: Long? = null
        private set

    /** Restore a resume id (e.g. one carried over from a previous connection) before reading. */
    fun seedLastEventId(id: String?) {
        if (id != null) lastEventId = id
    }

    /**
     * Reads SSE frames from [source], invoking [onFrame] with the accumulated event name + data per
     * blank-line-delimited frame. The frame's `id` (the retained [lastEventId] at frame boundary) is
     * passed too. Returns when [onFrame] returns false or the source is exhausted.
     *
     * A frame with no `data:` and no `event:` is suppressed (pure-comment/heartbeat groups).
     */
    fun readFrames(source: BufferedSource, onFrame: (frame: SseFrame) -> Boolean) {
        var eventType = ""
        val data = StringBuilder()
        while (!source.exhausted()) {
            val line = source.readUtf8Line() ?: break
            if (line.isEmpty()) {
                if (data.isNotEmpty() || eventType.isNotEmpty()) {
                    val keepGoing = onFrame(
                        SseFrame(
                            id = lastEventId,
                            event = eventType.ifEmpty { DEFAULT_EVENT },
                            data = data.toString(),
                        ),
                    )
                    if (!keepGoing) return
                }
                eventType = ""
                data.setLength(0)
            } else {
                consumeField(line) { field, value ->
                    when (field) {
                        "event" -> eventType = value
                        "data" -> {
                            if (data.isNotEmpty()) data.append('\n')
                            data.append(value)
                        }
                        "id" -> if (value.isNotEmpty()) lastEventId = value
                        "retry" -> value.toLongOrNull()?.let { retryMillis = it }
                        else -> Unit // unknown field — ignore per spec
                    }
                }
            }
        }
    }

    /**
     * Splits a single SSE line into (field, value), honoring the spec rules: a leading ':' is a
     * comment (ignored), the field is the text before the first ':', and a single leading space in the
     * value is stripped. Lines with no ':' are a field with an empty value.
     */
    private inline fun consumeField(line: String, body: (field: String, value: String) -> Unit) {
        if (line.startsWith(":")) return // comment / heartbeat
        val colon = line.indexOf(':')
        if (colon < 0) {
            body(line, "")
            return
        }
        val field = line.substring(0, colon)
        var value = line.substring(colon + 1)
        if (value.startsWith(" ")) value = value.substring(1)
        body(field, value)
    }

    companion object {
        const val DEFAULT_EVENT = "message"
    }
}

/** A single decoded SSE frame: the event name, the joined data payload, and the retained id. */
data class SseFrame(
    val id: String?,
    val event: String,
    val data: String,
)
