package com.testlogon.android.feature.videos.detail

import com.testlogon.android.feature.player.VideoPlayerController
import com.testlogon.android.feature.player.VideoPlayerFactory
import dagger.Binds
import dagger.Module
import dagger.hilt.InstallIn
import dagger.hilt.components.SingletonComponent
import javax.inject.Inject
import javax.inject.Singleton

/**
 * AND-190 — a thin seam over [VideoPlayerFactory.create] so [VideoDetailViewModel] can be unit-tested
 * on the JVM without constructing the real (Context-bound, ExoPlayer-building) factory. The production
 * binding [DefaultVideoControllerProvider] just delegates to the existing AND-166
 * [VideoPlayerFactory] — there is no second player and no eager ExoPlayer (the controller, and thus the
 * ExoPlayer, is still created lazily per-screen and released by the ViewModel).
 */
fun interface VideoControllerProvider {
    /** Builds a fresh lifecycle-scoped controller; the caller owns releasing it. */
    fun create(): VideoPlayerController
}

@Singleton
class DefaultVideoControllerProvider @Inject constructor(
    private val factory: VideoPlayerFactory,
) : VideoControllerProvider {
    override fun create(): VideoPlayerController = factory.create()
}

@Module
@InstallIn(SingletonComponent::class)
abstract class VideoControllerProviderModule {
    @Binds
    @Singleton
    abstract fun bindVideoControllerProvider(impl: DefaultVideoControllerProvider): VideoControllerProvider
}
