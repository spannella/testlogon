package com.testlogon.android.core.network.sponsoredpost

import dagger.Module
import dagger.Provides
import dagger.hilt.InstallIn
import dagger.hilt.components.SingletonComponent
import retrofit2.Retrofit
import javax.inject.Singleton

/**
 * ADV2-E4 (F4) — Hilt wiring for the sponsored-as-creator transport. Provides [SponsoredPostApi] from the
 * shared singleton [Retrofit] (reusing the production OkHttp / Moshi / converter config; no new Retrofit,
 * OkHttp or Moshi is built). The DTOs decode reflectively (status is a raw String), so NO provideMoshi
 * change is required. Mirrors the AND-365 SponsorshipNetworkModule pattern.
 */
@Module
@InstallIn(SingletonComponent::class)
object SponsoredPostNetworkModule {

    @Provides
    @Singleton
    fun provideSponsoredPostApi(retrofit: Retrofit): SponsoredPostApi =
        retrofit.create(SponsoredPostApi::class.java)
}
