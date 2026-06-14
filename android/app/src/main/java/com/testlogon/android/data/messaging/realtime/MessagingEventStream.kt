package com.testlogon.android.data.messaging.realtime

import kotlinx.coroutines.flow.Flow

/**
 * AND-123 (realtime) — testable seam over the messaging realtime transport.
 *
 * [events] is a cold [Flow]: collecting it opens the stream (connect + auth), and cancelling the
 * collection (e.g. when the screen leaves the foreground) disconnects it — making consumption
 * lifecycle-aware via `repeatOnLifecycle`/`collectAsStateWithLifecycle` at the call site. The
 * implementation reconnects with exponential backoff on transport drops; the flow only completes
 * when the collector cancels.
 *
 * A fake implementation ([FakeMessagingEventStream]) lets ViewModel unit tests drive inbound events
 * without a live socket.
 */
interface MessagingEventStream {
    /** Emits connection-state transitions interleaved with parsed events for collectors. */
    fun events(): Flow<MessagingStreamEvent>
}

/** A stream emission: either a lifecycle [State] change or a parsed inbound [Event]. */
sealed interface MessagingStreamEvent {
    data class State(val state: StreamConnectionState) : MessagingStreamEvent
    data class Event(val event: MessagingEvent) : MessagingStreamEvent
}
