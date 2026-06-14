package com.testlogon.android.feature.call.telecom

import android.content.Context
import android.media.AudioManager
import android.telecom.TelecomManager
import dagger.Binds
import dagger.Module
import dagger.Provides
import dagger.hilt.InstallIn
import dagger.hilt.android.qualifiers.ApplicationContext
import dagger.hilt.components.SingletonComponent
import javax.inject.Singleton

/**
 * AND-304 — Hilt wiring for the self-managed Telecom integration.
 *
 * Provides the two system services the integration wraps. [TelecomManager] is provided as NULLABLE on
 * purpose: some OEM/region SKUs return null from getSystemService(TELECOM_SERVICE), and the whole graceful-
 * degradation design ([TelecomCapabilities] / [TelecomCallController]) keys off that nullability rather than
 * crashing. AudioManager is also nullable-tolerant downstream ([CallAudioRouter] guards a null). Binds the
 * [CallSignaling] implementation to the repository-backed sink.
 */
@Module
@InstallIn(SingletonComponent::class)
object TelecomProvidesModule {

    @Provides
    @Singleton
    fun provideTelecomManager(@ApplicationContext context: Context): TelecomManager? =
        context.getSystemService(Context.TELECOM_SERVICE) as? TelecomManager

    @Provides
    @Singleton
    fun provideAudioManager(@ApplicationContext context: Context): AudioManager? =
        context.getSystemService(Context.AUDIO_SERVICE) as? AudioManager
}

@Module
@InstallIn(SingletonComponent::class)
abstract class TelecomBindsModule {

    @Binds
    @Singleton
    abstract fun bindCallSignaling(impl: RepositoryCallSignaling): CallSignaling
}
