package com.testlogon.android.feature.broadcast.viewer

import com.testlogon.android.data.broadcast.BroadcastSessionStatus
import org.junit.Assert.assertEquals
import org.junit.Test

/** AND-280 — pure status -> playback-state mapping (TC-AND-280-01/03/04, the JVM-safe part). */
class ViewerModelsTest {

    @Test
    fun liveStatus_mapsToLive() {
        assertEquals(SessionPlaybackState.LIVE, BroadcastSessionStatus.LIVE.toPlaybackState())
    }

    @Test
    fun preGoLive_mapsToScheduled() {
        assertEquals(SessionPlaybackState.SCHEDULED, BroadcastSessionStatus.SCHEDULED.toPlaybackState())
        assertEquals(SessionPlaybackState.SCHEDULED, BroadcastSessionStatus.PROVISIONING.toPlaybackState())
        assertEquals(SessionPlaybackState.SCHEDULED, BroadcastSessionStatus.READY.toPlaybackState())
        assertEquals(SessionPlaybackState.SCHEDULED, BroadcastSessionStatus.DRAFT.toPlaybackState())
    }

    @Test
    fun terminal_mapsToEnded() {
        assertEquals(SessionPlaybackState.ENDED, BroadcastSessionStatus.STOPPED.toPlaybackState())
        assertEquals(SessionPlaybackState.ENDED, BroadcastSessionStatus.STOPPING.toPlaybackState())
        assertEquals(SessionPlaybackState.ENDED, BroadcastSessionStatus.CANCELLED.toPlaybackState())
        assertEquals(SessionPlaybackState.ENDED, BroadcastSessionStatus.ERROR.toPlaybackState())
        assertEquals(SessionPlaybackState.ENDED, BroadcastSessionStatus.UNKNOWN.toPlaybackState())
    }
}
