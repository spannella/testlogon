package com.testlogon.android.core.network.kb

import dagger.Module
import dagger.Provides
import dagger.hilt.InstallIn
import dagger.hilt.components.SingletonComponent
import retrofit2.Retrofit
import javax.inject.Singleton

/**
 * KB-AND-1 - Hilt wiring for the Knowledge Base transport layer.
 *
 * Provides [KbApi] from the shared singleton [Retrofit] (reusing the production OkHttp / Moshi / converter
 * config; no new Retrofit, OkHttp or Moshi is built, and NO new dependency is introduced). The KB DTOs decode
 * with the reflective KotlinJsonAdapterFactory already on the shared Moshi (status is a plain String on the
 * wire - no enum adapter is needed). Mirrors the AND-371 TicketsNetworkModule pattern.
 */
@Module
@InstallIn(SingletonComponent::class)
object KbNetworkModule {

    @Provides
    @Singleton
    fun provideKbApi(retrofit: Retrofit): KbApi =
        retrofit.create(KbApi::class.java)
}
