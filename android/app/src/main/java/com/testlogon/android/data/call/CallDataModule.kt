package com.testlogon.android.data.call

import com.testlogon.android.feature.call.domain.CallTiming
import dagger.Binds
import dagger.Module
import dagger.Provides
import dagger.hilt.InstallIn
import dagger.hilt.components.SingletonComponent
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import retrofit2.Retrofit
import javax.inject.Singleton

/**
 * AND-295/296/297 — Hilt wiring for the 1:1 call CONTROL PLANE + the call orchestrators.
 *
 * Provides [CallApi] on the shared (authenticated) Retrofit, binds [CallRepository], and supplies the
 * app-scoped [CoroutineScope] + [CallTiming] the singleton orchestrators ([CallManager] /
 * [IncomingCallController]) own their lifecycle on. The signaling + TURN seams are NOT provided here — the
 * call feature reuses AND-290/291's already-bound SignalingTransport / IceServersProvider /
 * PeerConnectionController stubs (WebRtcDataModule), so the FLAGGED media seams stay the single source of
 * truth and the call media is "unavailable" until the native WebRTC SDK is wired.
 */
@Module
@InstallIn(SingletonComponent::class)
object CallProvidesModule {

    @Provides
    @Singleton
    fun provideCallApi(retrofit: Retrofit): CallApi = retrofit.create(CallApi::class.java)

    @Provides
    @Singleton
    fun provideCallTiming(): CallTiming = CallTiming()

    /**
     * App-scoped supervised scope for the call orchestrators. A SupervisorJob so one failed call job never
     * cancels the others; Default dispatcher (the orchestrators delegate IO to the repository).
     */
    @Provides
    @Singleton
    fun provideCallScope(): CoroutineScope = CoroutineScope(SupervisorJob() + Dispatchers.Default)
}

@Module
@InstallIn(SingletonComponent::class)
abstract class CallBindsModule {

    @Binds
    @Singleton
    abstract fun bindCallRepository(impl: CallRepositoryImpl): CallRepository

    @Binds
    @Singleton
    abstract fun bindRinger(
        impl: com.testlogon.android.feature.call.incoming.SystemRinger,
    ): com.testlogon.android.feature.call.incoming.Ringer

    @Binds
    @Singleton
    abstract fun bindIncomingCallNotifier(
        impl: com.testlogon.android.feature.call.incoming.SystemIncomingCallNotifier,
    ): com.testlogon.android.feature.call.incoming.IncomingCallNotifier
}
