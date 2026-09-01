package com.testlogon.android.data.marketing.campaigns

import dagger.Binds
import dagger.Module
import dagger.Provides
import dagger.hilt.InstallIn
import dagger.hilt.components.SingletonComponent
import retrofit2.Retrofit
import javax.inject.Singleton

/** Provides [MarketingCampaignsApi] on the shared (authenticated) Retrofit. */
@Module
@InstallIn(SingletonComponent::class)
object MarketingCampaignsApiModule {

    @Provides
    @Singleton
    fun provideMarketingCampaignsApi(retrofit: Retrofit): MarketingCampaignsApi =
        retrofit.create(MarketingCampaignsApi::class.java)
}

/** Binds the Marketing-campaigns data-layer implementation. */
@Module
@InstallIn(SingletonComponent::class)
abstract class MarketingCampaignsDataModule {

    @Binds
    @Singleton
    abstract fun bindMarketingCampaignsRepository(
        impl: MarketingCampaignsRepositoryImpl,
    ): MarketingCampaignsRepository
}
