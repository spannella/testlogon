package com.testlogon.android.feature.call.fsm

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * AND-305 — snapshot (de)serialization + rehydrate is tested PURELY (no DataStore). The codec round-trips a
 * non-terminal call; rehydration restores [CallState.Active] with the correct startedAtMs (so duration
 * continues), and terminal/Idle states are never persisted (clear-on-Ended semantics).
 */
class CallSnapshotTest {

    private val peer = PeerRef("u1", "c1", "Alex Smith")

    @Test
    fun activeSnapshot_roundTrips_andRestoresWithStartedAt() {
        val active = CallState.Active("call-1", peer, isVideo = true, startedAtMs = 12_345L)
        val snapshot = CallSnapshot.from(active)!!
        val encoded = CallSnapshotCodec.encode(snapshot)
        val decoded = CallSnapshotCodec.decode(encoded)!!
        assertEquals(snapshot, decoded)

        val restored = decoded.toState()
        assertEquals(active, restored)
        // Duration with a clock 2s later continues from the restored startedAtMs.
        val ui = CallUiState.project(restored, nowMs = 14_345L)
        assertEquals("00:02", ui.formattedDuration)
    }

    @Test
    fun displayNameWithSeparator_roundTrips() {
        val tricky = PeerRef("u9", "c9", "A|B|C name")
        val snapshot = CallSnapshot.from(CallState.Dialing("call-7", tricky, isVideo = false))!!
        val decoded = CallSnapshotCodec.decode(CallSnapshotCodec.encode(snapshot))!!
        assertEquals("A|B|C name", decoded.peerDisplayName)
        assertEquals(snapshot, decoded)
    }

    @Test
    fun nullDisplayName_roundTrips() {
        val noName = PeerRef("u9", "c9", null)
        val snapshot = CallSnapshot.from(CallState.Connecting("call-7", noName, isVideo = false))!!
        val decoded = CallSnapshotCodec.decode(CallSnapshotCodec.encode(snapshot))!!
        assertNull(decoded.peerDisplayName)
    }

    @Test
    fun reconnectingSnapshot_rehydratesAsActive() {
        val reconnecting =
            CallState.Reconnecting("call-1", peer, isVideo = false, startedAtMs = 100L, since = 900L)
        val snapshot = CallSnapshot.from(reconnecting)!!
        val restored = CallSnapshotCodec.decode(CallSnapshotCodec.encode(snapshot))!!.toState()
        assertEquals(CallState.Active("call-1", peer, isVideo = false, startedAtMs = 100L), restored)
    }

    @Test
    fun terminalAndIdleStates_areNotPersistable() {
        assertNull(CallSnapshot.from(CallState.Idle))
        assertNull(CallSnapshot.from(CallState.Ending("c", EndReason.LOCAL_HANGUP)))
        assertNull(CallSnapshot.from(CallState.Ended("c", EndReason.REMOTE_HANGUP, 1_000L)))
    }

    @Test
    fun decode_handlesNullEmptyAndCorruptInput() {
        assertNull(CallSnapshotCodec.decode(null))
        assertNull(CallSnapshotCodec.decode(""))
        assertNull(CallSnapshotCodec.decode("garbage"))
        assertNull(CallSnapshotCodec.decode("v2|wrong|version|..."))
    }

    @Test
    fun inMemoryStore_saveLoadClear() {
        val store = InMemoryCallSnapshotStore()
        val snapshot = CallSnapshot.from(CallState.Active("c", peer, isVideo = false, startedAtMs = 5L))!!
        kotlinx.coroutines.runBlocking {
            store.save(snapshot)
            assertEquals(snapshot, store.load())
            store.clear()
            assertNull(store.load())
        }
    }

    @Test
    fun newHostFromSnapshot_restoresActiveDuration() {
        // A new host built over a store pre-seeded with an Active snapshot rehydrates to Active.
        val store = InMemoryCallSnapshotStore()
        val active = CallState.Active("call-1", peer, isVideo = false, startedAtMs = 1_000L)
        kotlinx.coroutines.runBlocking {
            store.save(CallSnapshot.from(active)!!)
            val loaded = store.load()!!.toState()
            assertTrue(loaded is CallState.Active)
            assertEquals(1_000L, (loaded as CallState.Active).startedAtMs)
        }
    }
}

/** Minimal in-memory [CallSnapshotStore] for JVM tests (DataStore needs an Android context). */
class InMemoryCallSnapshotStore : CallSnapshotStore {
    private var current: CallSnapshot? = null
    override suspend fun save(snapshot: CallSnapshot) { current = snapshot }
    override suspend fun load(): CallSnapshot? = current
    override suspend fun clear() { current = null }
}
