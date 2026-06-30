package com.testlogon.android.core.network.syndicates

import dagger.Module
import dagger.Provides
import dagger.hilt.InstallIn
import dagger.hilt.components.SingletonComponent
import retrofit2.Retrofit
import javax.inject.Singleton

/**
 * Hilt wiring for the "My Bundles" + syndicate-advertising transport. Provides [SyndicateBundleApi] and
 * [SyndicateCampaignApi] from the shared singleton [Retrofit] (no new Retrofit/OkHttp/Moshi, no new
 * dependency). Mirrors SyndicateNetworkModule.
 */
@Module
@InstallIn(SingletonComponent::class)
object SyndicateBundleNetworkModule {

    @Provides
    @Singleton
    fun provideSyndicateBundleApi(retrofit: Retrofit): SyndicateBundleApi =
        retrofit.create(SyndicateBundleApi::class.java)

    @Provides
    @Singleton
    fun provideSyndicateCampaignApi(retrofit: Retrofit): SyndicateCampaignApi =
        retrofit.create(SyndicateCampaignApi::class.java)
}
