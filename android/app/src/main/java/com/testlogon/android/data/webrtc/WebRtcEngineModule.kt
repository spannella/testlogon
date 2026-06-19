package com.testlogon.android.data.webrtc

import android.content.Context
import dagger.Module
import dagger.Provides
import dagger.hilt.InstallIn
import dagger.hilt.android.qualifiers.ApplicationContext
import dagger.hilt.components.SingletonComponent
import org.webrtc.DefaultVideoDecoderFactory
import org.webrtc.DefaultVideoEncoderFactory
import org.webrtc.EglBase
import org.webrtc.PeerConnectionFactory
import org.webrtc.audio.JavaAudioDeviceModule
import javax.inject.Singleton

/**
 * Process-singleton WebRTC engine primitives (real native engine — replaces the FLAGGED stub seams).
 *
 * Provides a shared [EglBase] (the GL context shared by the video source, the remote sink, and the
 * Compose [SurfaceViewRenderer]s) and the [PeerConnectionFactory]. `PeerConnectionFactory.initialize`
 * runs exactly once (this @Singleton @Provides). The factory uses the hardware-accelerated default
 * video encoder/decoder factories bound to the shared EGL context, and a [JavaAudioDeviceModule] for
 * mic capture + speaker playback (with HW AEC/NS where available).
 */
@Module
@InstallIn(SingletonComponent::class)
object WebRtcEngineModule {

    @Provides
    @Singleton
    fun provideEglBase(): EglBase = EglBase.create()

    @Provides
    @Singleton
    fun providePeerConnectionFactory(
        @ApplicationContext context: Context,
        eglBase: EglBase,
    ): PeerConnectionFactory {
        PeerConnectionFactory.initialize(
            PeerConnectionFactory.InitializationOptions.builder(context)
                .createInitializationOptions(),
        )
        val audioModule = JavaAudioDeviceModule.builder(context)
            .setUseHardwareAcousticEchoCanceler(true)
            .setUseHardwareNoiseSuppressor(true)
            .createAudioDeviceModule()
        return PeerConnectionFactory.builder()
            .setVideoEncoderFactory(
                DefaultVideoEncoderFactory(eglBase.eglBaseContext, true, true),
            )
            .setVideoDecoderFactory(DefaultVideoDecoderFactory(eglBase.eglBaseContext))
            .setAudioDeviceModule(audioModule)
            .createPeerConnectionFactory()
    }
}
