package com.testlogon.android.feature.player

import android.content.Context
import androidx.media3.common.util.UnstableApi
import androidx.media3.exoplayer.ExoPlayer
import dagger.Module
import dagger.Provides
import dagger.hilt.InstallIn
import dagger.hilt.android.qualifiers.ApplicationContext
import dagger.hilt.components.SingletonComponent
import javax.inject.Inject
import javax.inject.Singleton

/**
 * AND-166 — factory so a screen/ViewModel creates a [VideoPlayerController] PER-SCREEN
 * (lifecycle-scoped) instead of injecting an eager singleton player. The factory itself is a cheap
 * [Singleton] holding only the app [Context] + the [MediaSourceFactoryProvider]; it does NOT eagerly
 * construct an ExoPlayer (built on demand in [create], released on screen disposal) — mirroring the
 * AND-133 VoicePlayerFactory contract so there is no competing/eager player.
 */
@OptIn(UnstableApi::class)
class VideoPlayerFactory @Inject constructor(
    @ApplicationContext private val appContext: Context,
    private val sourceFactory: MediaSourceFactoryProvider,
) {
    /**
     * Builds a fresh lifecycle-scoped controller. The ExoPlayer is configured with the ABR track
     * selector (AND-167) and audio-becoming-noisy handling; the caller MUST [VideoPlayerController.release]
     * it on disposal (e.g. ViewModel.onCleared / DisposableEffect.onDispose).
     */
    fun create(): VideoPlayerController {
        val exo = ExoPlayer.Builder(appContext)
            .setTrackSelector(ExoVideoPlayerController.abrTrackSelector(appContext))
            .setHandleAudioBecomingNoisy(true)
            .build()
        return ExoVideoPlayerController(exo, sourceFactory)
    }
}

@Module
@InstallIn(SingletonComponent::class)
object VideoPlayerModule {

    @Provides
    @Singleton
    @OptIn(UnstableApi::class)
    fun provideVideoPlayerFactory(
        @ApplicationContext context: Context,
        sourceFactory: MediaSourceFactoryProvider,
    ): VideoPlayerFactory = VideoPlayerFactory(context, sourceFactory)
}
