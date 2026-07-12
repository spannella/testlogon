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

    /**
     * AND-364 - the CONTENT BOOST transport ([ContentBoostApi]) from the shared singleton [Retrofit]. The
     * boost DTOs decode reflectively (no new Moshi adapter needed - status is a raw String, not an enum),
     * so no provideMoshi change is required. Folded here rather than a separate module (same ads surface).
     */
    @Provides
    @Singleton
    fun provideContentBoostApi(retrofit: Retrofit): ContentBoostApi =
        retrofit.create(ContentBoostApi::class.java)

    /**
     * Web-parity ads STUDIO control planes (targeting / scheduling / optimization), from the shared singleton
     * [Retrofit]. All three sets of DTOs decode reflectively (raw String / Map fields, no custom enum), so no
     * provideMoshi change is needed. Folded here (same ads surface) rather than a separate module.
     */
    @Provides
    @Singleton
    fun provideAdTargetingApi(retrofit: Retrofit): AdTargetingApi =
        retrofit.create(AdTargetingApi::class.java)

    @Provides
    @Singleton
    fun provideAdSchedulingApi(retrofit: Retrofit): AdSchedulingApi =
        retrofit.create(AdSchedulingApi::class.java)

    @Provides
    @Singleton
    fun provideAdOptimizationApi(retrofit: Retrofit): AdOptimizationApi =
        retrofit.create(AdOptimizationApi::class.java)
    /**
     * The CONTENT AD-CONTROLS transport ([ContentAdControlsApi]) from the shared singleton [Retrofit].
     * The DTOs decode reflectively (no custom enum / adapter), so no provideMoshi change is needed.
     * Folded here (same ads surface) rather than a separate module.
     */
    @Provides
    @Singleton
    fun provideContentAdControlsApi(retrofit: Retrofit): ContentAdControlsApi =
        retrofit.create(ContentAdControlsApi::class.java)

    /**
     * ADV2-709/710/711 (F7) — the SYNDICATE-owned advertiser transport ([SyndicateAdsApi]) from the shared
     * singleton [Retrofit]. Its DTOs decode reflectively (raw String status, no custom enum), so no
     * provideMoshi change is needed. Folded here (same ads surface) rather than a separate module.
     */
    @Provides
    @Singleton
    fun provideSyndicateAdsApi(retrofit: Retrofit): SyndicateAdsApi =
        retrofit.create(SyndicateAdsApi::class.java)
}

