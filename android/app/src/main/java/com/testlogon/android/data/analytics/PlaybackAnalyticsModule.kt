package com.testlogon.android.data.analytics

import com.testlogon.android.core.network.health.ConnectivityMonitor
import com.testlogon.android.data.auth.AppScope
import dagger.Binds
import dagger.Module
import dagger.Provides
import dagger.hilt.InstallIn
import dagger.hilt.components.SingletonComponent
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.flow.launchIn
import kotlinx.coroutines.flow.onEach
import retrofit2.Retrofit
import javax.inject.Inject
import javax.inject.Singleton

/**
 * AND-171 — wires the playback-analytics layer: the verified Retrofit API on the shared client, the
 * config store, the offline gate (bridged from core-network's [ConnectivityMonitor]), the sink, and
 * the lifecycle-scoped reporter.
 */
@Module
@InstallIn(SingletonComponent::class)
object PlaybackAnalyticsProvidesModule {

    @Provides
    @Singleton
    fun providePlaybackAnalyticsApi(retrofit: Retrofit): PlaybackAnalyticsApi =
        retrofit.create(PlaybackAnalyticsApi::class.java)
}

@Module
@InstallIn(SingletonComponent::class)
abstract class PlaybackAnalyticsBindsModule {

    @Binds
    @Singleton
    abstract fun bindHeartbeatSink(impl: CoroutineHeartbeatSink): HeartbeatSink

    @Binds
    @Singleton
    abstract fun bindHeartbeatConfigStore(impl: DefaultHeartbeatConfigStore): HeartbeatConfigStore

    @Binds
    @Singleton
    abstract fun bindPlaybackReporter(impl: DefaultPlaybackReporter): PlaybackReporter

    @Binds
    @Singleton
    abstract fun bindOfflineGate(impl: ConnectivityOfflineGate): OfflineGate
}

/**
 * AND-171 §7 — best-effort offline gate. Collects core-network's online/offline flow into a volatile
 * flag so the sink can short-circuit HEARTBEATs without suspending. Fails open (treated as online)
 * until the first emission.
 */
@Singleton
class ConnectivityOfflineGate @Inject constructor(
    connectivityMonitor: ConnectivityMonitor,
    @AppScope scope: CoroutineScope,
) : OfflineGate {

    @Volatile
    private var online: Boolean = true

    init {
        connectivityMonitor.isOnline
            .onEach { online = it }
            .launchIn(scope)
    }

    override fun isOffline(): Boolean = !online
}
