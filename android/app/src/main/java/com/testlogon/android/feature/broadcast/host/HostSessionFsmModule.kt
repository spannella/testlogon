package com.testlogon.android.feature.broadcast.host

import dagger.Binds
import dagger.Module
import dagger.Provides
import dagger.hilt.InstallIn
import dagger.hilt.components.SingletonComponent
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.Dispatchers
import javax.inject.Singleton

/**
 * AND-317 — Hilt wiring for the host-broadcast FSM presentation layer.
 *
 * Binds the thin SEAM interfaces ([BroadcastHostRepository] / [WebRtcIngestController] / [HostSessionPrefs] /
 * [HostAnalytics]) to their default impls. The impls delegate to the EXISTING AND-307/308/309 data pieces;
 * NO new endpoint, migration, or dependency is added here. Provides the [DefaultDispatcher] binding (a bare
 * CoroutineDispatcher cannot be injected unqualified) used by [BroadcastHostViewModel].
 */
@Module
@InstallIn(SingletonComponent::class)
abstract class HostSessionFsmModule {

    @Binds
    @Singleton
    abstract fun bindBroadcastHostRepository(impl: DefaultBroadcastHostRepository): BroadcastHostRepository

    @Binds
    @Singleton
    abstract fun bindWebRtcIngestController(impl: DefaultWebRtcIngestController): WebRtcIngestController

    @Binds
    @Singleton
    abstract fun bindHostSessionPrefs(impl: DataStoreHostSessionPrefs): HostSessionPrefs

    @Binds
    @Singleton
    abstract fun bindHostAnalytics(impl: LoggingHostAnalytics): HostAnalytics

    companion object {
        @Provides
        @DefaultDispatcher
        fun provideDefaultDispatcher(): CoroutineDispatcher = Dispatchers.Default
    }
}
