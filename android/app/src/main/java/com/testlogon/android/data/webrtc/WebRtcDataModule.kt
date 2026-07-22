package com.testlogon.android.data.webrtc

import dagger.Binds
import dagger.Module
import dagger.Provides
import dagger.hilt.InstallIn
import dagger.hilt.components.SingletonComponent
import retrofit2.Retrofit
import javax.inject.Singleton

/**
 * AND-288..291 — provides the dedicated signaling + ICE-credentials APIs on the shared (authenticated)
 * Retrofit, binds the implementable repositories/provider, and binds the FOUR FLAGGED engine seams to
 * their NotConfigured stubs.
 *
 * What is REAL (plain network reads with verified backend endpoints): [SignalingApi]/[SignalingRepository]
 * (broadcast publish SDP exchange + 1:1 call signaling send) and [IceServersApi]/[IceServersRepository]/
 * [IceServersProvider] (TURN/STUN credential fetch -> domain). What is FLAGGED (no WebRTC Gradle
 * dependency; never starts capture/peer/media): [BroadcastPublisher] -> [StubBroadcastPublisher],
 * [PeerConnectionController] -> [StubPeerConnectionController], [SignalingTransport] ->
 * [StubSignalingTransport].
 */
@Module
@InstallIn(SingletonComponent::class)
object WebRtcApiModule {

    @Provides
    @Singleton
    fun provideSignalingApi(retrofit: Retrofit): SignalingApi =
        retrofit.create(SignalingApi::class.java)

    @Provides
    @Singleton
    fun provideIceServersApi(retrofit: Retrofit): IceServersApi =
        retrofit.create(IceServersApi::class.java)

    @Provides
    @Singleton
    fun provideTurnFetchConfig(): TurnFetchConfig = TurnFetchConfig()

    /**
     * AND-293 — video-renderer seam. Provides the FLAGGED [PlaceholderVideoRenderer] (paints a placeholder,
     * never hosts a SurfaceViewRenderer / opens a camera) until the native WebRTC SDK decision is made.
     * Provided (not @Binds) because [PlaceholderVideoRenderer] is a Kotlin object.
     */
    @Provides
    @Singleton
    fun provideVideoRenderer(
        impl: com.testlogon.android.core.webrtc.ui.RealVideoRenderer,
    ): com.testlogon.android.core.webrtc.ui.VideoRenderer = impl
}

@Module
@InstallIn(SingletonComponent::class)
abstract class WebRtcDataModule {

    /** CALL-PiP — the live-call PiP source factory is the real [CallPipRenderer]. */
    @Binds
    abstract fun bindCallPipSourceFactory(
        impl: com.testlogon.android.core.webrtc.ui.CallPipRenderer,
    ): com.testlogon.android.core.webrtc.ui.CallPipSourceFactory


    // ── Implementable (real backend endpoints) ──────────────────────────────────────────────────

    @Binds
    @Singleton
    abstract fun bindSignalingRepository(impl: SignalingRepositoryImpl): SignalingRepository

    @Binds
    @Singleton
    abstract fun bindIceServersRepository(impl: DefaultIceServersRepository): IceServersRepository

    @Binds
    @Singleton
    abstract fun bindIceServersProvider(impl: DefaultIceServersProvider): IceServersProvider

    // ── Device enumeration (AND-292) ────────────────────────────────────────────────────────────

    /**
     * AND-292 — device-enumeration seam. Defaults to [StubMediaDeviceProvider] (EMPTY inventory — never
     * touches Camera2/AudioManager / opens hardware) until the native WebRTC SDK decision is made. Even a
     * real provider only *enumerates*; capture START stays behind the FLAGGED [BroadcastPublisher].
     */
    @Binds
    @Singleton
    abstract fun bindMediaDeviceProvider(impl: RealMediaDeviceProvider): MediaDeviceProvider

    // ── FLAGGED engine seams (native WebRTC SDK not configured; never start capture/peer/media) ──

    /**
     * AND-288 — go-live engine. Defaults to [StubBroadcastPublisher] (NotConfigured, never opens
     * camera/mic / creates a peer) until the native WebRTC SDK decision is made; swap this @Binds to the
     * real engine then. The WebRTC Gradle dependency is intentionally NOT added.
     */
    @Binds
    @Singleton
    abstract fun bindBroadcastPublisher(impl: RealBroadcastPublisher): BroadcastPublisher

    /** AND-289 — PeerConnection wrapper. Defaults to the no-op [StubPeerConnectionController]. */
    @Binds
    @Singleton
    abstract fun bindPeerConnectionController(impl: RealPeerConnectionController): PeerConnectionController

    /** AND-290 — signaling transport. Defaults to the never-connect [StubSignalingTransport]. */
    @Binds
    @Singleton
    abstract fun bindSignalingTransport(impl: StubSignalingTransport): SignalingTransport

    /**
     * AND-299 — group-call full-mesh manager. Defaults to the no-op [StubMeshConnectionManager]
     * (NotConfigured, never creates a peer / opens media, events never emit) until the native WebRTC SDK
     * decision is made; swap this @Binds to the real mesh then.
     */
    @Binds
    @Singleton
    abstract fun bindMeshConnectionManager(impl: StubMeshConnectionManager): MeshConnectionManager
}
