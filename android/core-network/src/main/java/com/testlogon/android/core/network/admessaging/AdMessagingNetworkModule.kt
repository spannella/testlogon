package com.testlogon.android.core.network.admessaging

import dagger.Module
import dagger.Provides
import dagger.hilt.InstallIn
import dagger.hilt.components.SingletonComponent
import retrofit2.Retrofit
import javax.inject.Singleton

/**
 * ADV2-E5 (F5+F6) — Hilt wiring for the ad-messaging transport. Provides [AdMessagingApi] from the shared
 * singleton [Retrofit] (reusing the production OkHttp / Moshi / converter config; no new Retrofit, OkHttp
 * or Moshi is built). The DTOs decode reflectively (status/product raw Strings), so NO provideMoshi change
 * is required. Mirrors the E4 SponsoredPostNetworkModule pattern.
 */
@Module
@InstallIn(SingletonComponent::class)
object AdMessagingNetworkModule {

    @Provides
    @Singleton
    fun provideAdMessagingApi(retrofit: Retrofit): AdMessagingApi =
        retrofit.create(AdMessagingApi::class.java)
}
