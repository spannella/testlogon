package com.testlogon.android.feature.player

import com.testlogon.android.data.preferences.PlaybackQualityPreferences
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.cancel
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.test.UnconfinedTestDispatcher
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * AND-169 / AND-172 — verifies the provider re-emits the resolved [EffectiveQuality] on prefs change
 * and on network change. Uses fakes + an [UnconfinedTestDispatcher]-backed collector scope (per the
 * AND-172 injected-scope convention) instead of Turbine (not on the classpath).
 */
class EffectiveQualityProviderTest {

    private class FakePrefs(initial: QualityPolicy) : PlaybackQualityPreferences {
        val flow = MutableStateFlow(initial)
        override fun qualityPolicy(): Flow<QualityPolicy> = flow
        override fun currentPolicy(): QualityPolicy = flow.value
        override fun autoplayEnabled(): Boolean = true
        override fun setPreferredQuality(quality: VideoQuality) {
            flow.value = flow.value.copy(userSelection = quality)
        }
        override fun setCapOnMetered(enabled: Boolean) {
            flow.value = flow.value.copy(capOnMetered = enabled)
        }
        override fun setAutoplayEnabled(enabled: Boolean) = Unit
    }

    private class FakeConnectivity(initial: NetworkStatus) : MeteredNetworkObserver {
        val flow = MutableStateFlow(initial)
        override fun observe(): Flow<NetworkStatus> = flow
        override fun current(): NetworkStatus = flow.value
    }

    @Test
    fun reEmits_onPrefsAndNetworkChange() = runTest {
        val prefs = FakePrefs(QualityPolicy(VideoQuality.AUTO, capOnMetered = true))
        val net = FakeConnectivity(NetworkStatus(isMetered = false))
        val scope = CoroutineScope(UnconfinedTestDispatcher(testScheduler))
        val provider = EffectiveQualityProvider(prefs, net, scope)

        // Keep the WhileSubscribed StateFlow hot so it tracks upstream changes.
        scope.launch { provider.effective.collect { } }

        // Initial: AUTO unmetered -> unbounded.
        assertNull(provider.effective.value.maxHeightPx)
        assertFalse(provider.effective.value.capped)

        // Flip to metered -> capped at 480.
        net.flow.value = NetworkStatus(isMetered = true)
        assertEquals(480, provider.effective.value.maxHeightPx)
        assertTrue(provider.effective.value.capped)

        // Lower the user choice -> 360 wins.
        prefs.setPreferredQuality(VideoQuality.P360)
        assertEquals(360, provider.effective.value.maxHeightPx)

        scope.cancel()
    }

    @Test
    fun dataSaverSelection_forcesLowest() = runTest {
        val prefs = FakePrefs(QualityPolicy(VideoQuality.DATA_SAVER))
        val net = FakeConnectivity(NetworkStatus(isMetered = false))
        val scope = CoroutineScope(UnconfinedTestDispatcher(testScheduler))
        val provider = EffectiveQualityProvider(prefs, net, scope)
        scope.launch { provider.effective.collect { } }
        assertTrue(provider.effective.value.forceLowest)
        scope.cancel()
    }
}
