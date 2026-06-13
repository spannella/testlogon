package com.testlogon.android.core.network.sponsorship

import dagger.Module
import dagger.Provides
import dagger.hilt.InstallIn
import dagger.hilt.components.SingletonComponent
import retrofit2.Retrofit
import javax.inject.Singleton

/**
 * AND-365 - Hilt wiring for the sponsorship inbox transport layer.
 *
 * Provides [SponsorshipApi] from the shared singleton [Retrofit] (reusing the production OkHttp / Moshi /
 * converter config; no new Retrofit, OkHttp or Moshi is built, and no new dependency is introduced). The
 * deal DTO decodes reflectively (status is a raw String, not an enum), so NO provideMoshi adapter change is
 * required. Mirrors the AND-363 AdsNetworkModule pattern.
 */
@Module
@InstallIn(SingletonComponent::class)
object SponsorshipNetworkModule {

    @Provides
    @Singleton
    fun provideSponsorshipApi(retrofit: Retrofit): SponsorshipApi =
        retrofit.create(SponsorshipApi::class.java)
}
