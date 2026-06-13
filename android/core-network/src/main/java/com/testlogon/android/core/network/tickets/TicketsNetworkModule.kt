package com.testlogon.android.core.network.tickets

import dagger.Module
import dagger.Provides
import dagger.hilt.InstallIn
import dagger.hilt.components.SingletonComponent
import retrofit2.Retrofit
import javax.inject.Singleton

/**
 * AND-371 - Hilt wiring for the ticket spaces transport layer.
 *
 * Provides [TicketsApi] from the shared singleton [Retrofit] (reusing the production OkHttp / Moshi /
 * converter config; no new Retrofit, OkHttp or Moshi is built, and no new dependency is introduced). The
 * ticket DTOs decode with the reflective KotlinJsonAdapterFactory already on the shared Moshi (status / role
 * / visibility / sender_role are plain Strings on the wire - no enum adapter is needed). Mirrors the AND-353
 * OrgsNetworkModule / AND-365 SponsorshipNetworkModule pattern.
 */
@Module
@InstallIn(SingletonComponent::class)
object TicketsNetworkModule {

    @Provides
    @Singleton
    fun provideTicketsApi(retrofit: Retrofit): TicketsApi =
        retrofit.create(TicketsApi::class.java)
}
