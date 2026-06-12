package com.testlogon.android.feature.call.fsm

import dagger.Binds
import dagger.Module
import dagger.hilt.InstallIn
import dagger.hilt.components.SingletonComponent
import javax.inject.Singleton

/**
 * AND-305 — Hilt wiring for the canonical call FSM host.
 *
 * Binds the [CallTimerScheduler] and [CallSnapshotStore] interfaces to their default implementations. The
 * [CallStateMachine] itself is @Singleton @Inject (auto-provided); its other deps (CallRepository, the
 * FLAGGED SignalingTransport, the app CoroutineScope, Clock) are already bound by AND-295's CallDataModule /
 * AND-290's WebRtcDataModule / the core-data Clock module — nothing new is provided for them here (so the
 * FLAGGED media seams stay the single source of truth).
 */
@Module
@InstallIn(SingletonComponent::class)
abstract class CallFsmModule {

    @Binds
    @Singleton
    abstract fun bindCallTimerScheduler(impl: CoroutineCallTimerScheduler): CallTimerScheduler

    @Binds
    @Singleton
    abstract fun bindCallSnapshotStore(impl: DataStoreCallSnapshotStore): CallSnapshotStore
}
