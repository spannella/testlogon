package com.testlogon.android.data.messaging.presence

import com.testlogon.android.data.auth.AppScope
import com.testlogon.android.data.auth.AuthStateStore
import com.testlogon.android.data.messaging.realtime.MessagingEvent
import com.testlogon.android.data.messaging.realtime.MessagingEventStream
import com.testlogon.android.data.messaging.realtime.MessagingStreamEvent
import com.testlogon.android.data.messaging.realtime.StreamConnectionState
import dagger.Binds
import dagger.Module
import dagger.hilt.InstallIn
import dagger.hilt.components.SingletonComponent
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.distinctUntilChanged
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import javax.inject.Inject
import javax.inject.Singleton

/**
 * AND-145 — read side of presence: a single observable cache reconciled from the SSE
 * `presence:update` stream and seed reads (GET messaging/presence). The write side (heartbeat) is
 * the [HeartbeatScheduler].
 *
 * Behaviour:
 *  - [track] reference-counts peer ids; the first tracker of a fresh id triggers a seed read.
 *  - SSE `presence:update` events merge into the cache (most-recent last_seen wins).
 *  - on SSE reconnect, currently-tracked entries are marked `stale=true`, re-seeded, then cleared.
 *  - the local user id is never tracked/seeded (the heartbeat is authoritative for self).
 */
interface PresenceRepository {
    val presence: StateFlow<Map<String, Presence>>

    /** Observe presence for one user (OFFLINE default when untracked). */
    fun presenceOf(userId: String): Flow<Presence>

    /** Start collecting the SSE presence stream + reconnect re-seed. Idempotent. */
    fun start()

    /** Reference-counted tracking; close the returned handle to untrack. */
    fun track(userIds: Set<String>): PresenceSubscription

    /** Seed presence for [userIds] from the network, merging into the cache. */
    suspend fun seed(userIds: Set<String>)
}

/** Closeable tracking handle; closing decrements the per-id reference count. */
fun interface PresenceSubscription {
    fun close()
}

@Singleton
class DefaultPresenceRepository @Inject constructor(
    private val api: PresenceApi,
    private val eventStream: MessagingEventStream,
    private val authStateStore: AuthStateStore,
    @AppScope private val scope: CoroutineScope,
) : PresenceRepository {

    private val cache = MutableStateFlow<Map<String, Presence>>(emptyMap())
    override val presence: StateFlow<Map<String, Presence>> = cache.asStateFlow()

    /** Per-user reference counts; an id with count 0 is eligible for eviction. */
    private val refCounts = mutableMapOf<String, Int>()
    private val refLock = Any()
    private var started = false

    override fun presenceOf(userId: String): Flow<Presence> =
        presence.map { it[userId] ?: Presence.offline(userId) }.distinctUntilChanged()

    @Synchronized
    override fun start() {
        if (started) return
        started = true
        scope.launch {
            eventStream.events().collect { streamEvent ->
                when (streamEvent) {
                    is MessagingStreamEvent.Event ->
                        (streamEvent.event as? MessagingEvent.PresenceUpdate)?.let(::mergePresence)
                    is MessagingStreamEvent.State ->
                        if (streamEvent.state == StreamConnectionState.DISCONNECTED) {
                            markAllStale()
                        } else if (streamEvent.state == StreamConnectionState.CONNECTED) {
                            reseedTracked()
                        }
                }
            }
        }
    }

    override fun track(userIds: Set<String>): PresenceSubscription {
        val self = authStateStore.userSub.value
        val peers = userIds.filter { it.isNotBlank() && it != self }.toSet()
        val firstSeen = mutableSetOf<String>()
        synchronized(refLock) {
            peers.forEach { id ->
                val prev = refCounts[id] ?: 0
                if (prev == 0) firstSeen += id
                refCounts[id] = prev + 1
            }
        }
        if (firstSeen.isNotEmpty()) scope.launch { seed(firstSeen) }
        return PresenceSubscription {
            val evictable = mutableSetOf<String>()
            synchronized(refLock) {
                peers.forEach { id ->
                    val next = (refCounts[id] ?: 1) - 1
                    if (next <= 0) {
                        refCounts.remove(id)
                        evictable += id
                    } else {
                        refCounts[id] = next
                    }
                }
            }
            if (evictable.isNotEmpty()) {
                cache.update { current -> current - evictable }
            }
        }
    }

    override suspend fun seed(userIds: Set<String>) {
        val self = authStateStore.userSub.value
        val peers = userIds.filter { it.isNotBlank() && it != self }.toSet()
        if (peers.isEmpty()) return
        val dtos = runCatching { api.getPresence(peers.sorted().joinToString(",")) }.getOrNull() ?: return
        val seeded = dtos.associate { it.userId to it.toPresence() }
        cache.update { current ->
            current + seeded
        }
    }

    private fun mergePresence(event: MessagingEvent.PresenceUpdate) {
        val self = authStateStore.userSub.value
        if (event.userId == self) return
        cache.update { current ->
            val prior = current[event.userId]
            // Most-recent last_seen wins on conflict; an unknown incoming last_seen never regresses.
            val incomingLastSeen = event.lastSeenAtEpochSeconds
            val priorLastSeen = prior?.lastSeenAtEpochSeconds
            if (prior != null && incomingLastSeen != null && priorLastSeen != null &&
                incomingLastSeen < priorLastSeen
            ) {
                // Older snapshot than what we have; only update the online flag, keep newer last_seen.
                current + (event.userId to prior.copy(
                    status = if (event.online) PresenceStatus.ONLINE else PresenceStatus.OFFLINE,
                    stale = false,
                ))
            } else {
                current + (event.userId to Presence(
                    userId = event.userId,
                    status = if (event.online) PresenceStatus.ONLINE else PresenceStatus.OFFLINE,
                    lastSeenAtEpochSeconds = incomingLastSeen ?: priorLastSeen,
                    stale = false,
                ))
            }
        }
    }

    private fun markAllStale() {
        cache.update { current -> current.mapValues { (_, p) -> p.copy(stale = true) } }
    }

    private fun reseedTracked() {
        val tracked = synchronized(refLock) { refCounts.keys.toSet() }
        if (tracked.isEmpty()) return
        scope.launch { seed(tracked) }
    }
}

/** AND-145 — binds the presence repository implementation. */
@Module
@InstallIn(SingletonComponent::class)
abstract class PresenceRepositoryModule {
    @Binds
    @Singleton
    abstract fun bindPresenceRepository(impl: DefaultPresenceRepository): PresenceRepository
}
