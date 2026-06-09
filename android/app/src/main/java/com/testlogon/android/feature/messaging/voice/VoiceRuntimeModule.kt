package com.testlogon.android.feature.messaging.voice

import android.content.Context
import dagger.Module
import dagger.Provides
import dagger.hilt.InstallIn
import dagger.hilt.android.qualifiers.ApplicationContext
import dagger.hilt.components.SingletonComponent
import javax.inject.Inject
import javax.inject.Singleton

/**
 * AND-133 — factories so the composer creates a [VoiceRecorder] / [VoicePlayerController] PER-SCREEN
 * (lifecycle-scoped) instead of injecting an eager singleton instance. The factory itself is a cheap
 * singleton that holds only the application [Context]; it does NOT eagerly construct a MediaRecorder
 * or ExoPlayer (those are created on demand and released on screen disposal).
 */
class VoiceRecorderFactory @Inject constructor(
    @ApplicationContext private val appContext: Context,
) {
    fun create(): VoiceRecorder = MediaRecorderVoiceRecorder(appContext)
}

class VoicePlayerFactory @Inject constructor(
    @ApplicationContext private val appContext: Context,
) {
    fun create(): VoicePlayerController = ExoVoicePlayerController(appContext)
}

@Module
@InstallIn(SingletonComponent::class)
object VoiceRuntimeModule {

    @Provides
    @Singleton
    fun provideVoiceRecorderFactory(@ApplicationContext context: Context): VoiceRecorderFactory =
        VoiceRecorderFactory(context)

    @Provides
    @Singleton
    fun provideVoicePlayerFactory(@ApplicationContext context: Context): VoicePlayerFactory =
        VoicePlayerFactory(context)
}
