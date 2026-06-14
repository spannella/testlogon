package com.testlogon.android.feature.call.telecom

import java.util.concurrent.ConcurrentHashMap
import javax.inject.Inject
import javax.inject.Singleton

/**
 * AND-304 — thread-safe correlation map from callId -> the live [TestLogonConnection] (FR-9: exactly one OS
 * Connection per call id; remove on disconnect to avoid phantom calls lingering in the system call screen).
 *
 * Backed by a [ConcurrentHashMap] because OS Telecom callbacks and the app's own placement path can touch it
 * from different threads. [put] is last-write-wins; the connection removes ITSELF on destroy so a torn-down
 * call never leaks a reference.
 */
@Singleton
class ConnectionRegistry @Inject constructor() {

    private val connections = ConcurrentHashMap<String, TestLogonConnection>()

    /** Registers (or replaces) the connection for [callId]. */
    fun put(callId: String, connection: TestLogonConnection) {
        connections[callId] = connection
    }

    /** The connection for [callId], or null if none is registered. */
    fun get(callId: String): TestLogonConnection? = connections[callId]

    /** Removes the connection for [callId] (idempotent). */
    fun remove(callId: String) {
        connections.remove(callId)
    }

    /** Clears all connections (e.g. on a hard reset). */
    fun clear() {
        connections.clear()
    }
}
