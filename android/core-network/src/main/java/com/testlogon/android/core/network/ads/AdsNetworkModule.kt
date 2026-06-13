package com.testlogon.android.core.network.ads

import dagger.Module
import dagger.Provides
import dagger.hilt.InstallIn
import dagger.hilt.components.SingletonComponent
import retrofit2.Retrofit
import javax.inject.Singleton

/**
 * AND-363 - Hilt wiring for the ads accounts transport layer.
 *
 * Provides [AdsAccountsApi] from the shared singleton [Retrofit] (reusing the production OkHttp / Moshi /
 * converter config; no new Retrofit, OkHttp or Moshi is built, and no new dependency is introduced). The
 * two ads enum adapters (AdAccountStatusAdapter / AdCampaignStatusAdapter) are registered on the shared
 * Moshi in NetworkModule.provideMoshi so these DTOs decode with the UNKNOWN fallback. Mirrors the AND-353
 * OrgsNetworkModule / AND-339 SigningNetworkModule pattern.
 */
@Module
@InstallIn(SingletonComponent::class)
object AdsNetworkModule {

    @Provides
    @Singleton
    fun provideAdsAccountsApi(retrofit: Retrofit): AdsAccountsApi =
        retrofit.create(AdsAccountsApi::class.java)
}
