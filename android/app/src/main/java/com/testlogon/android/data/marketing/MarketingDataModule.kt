package com.testlogon.android.data.marketing

import dagger.Binds
import dagger.Module
import dagger.Provides
import dagger.hilt.InstallIn
import dagger.hilt.components.SingletonComponent
import retrofit2.Retrofit
import javax.inject.Singleton

/** Provides [MarketingApi] on the shared (authenticated) Retrofit. */
@Module
@InstallIn(SingletonComponent::class)
object MarketingApiModule {

    @Provides
    @Singleton
    fun provideMarketingApi(retrofit: Retrofit): MarketingApi =
        retrofit.create(MarketingApi::class.java)
}

/** Binds the Marketing data-layer implementation. */
@Module
@InstallIn(SingletonComponent::class)
abstract class MarketingDataModule {

    @Binds
    @Singleton
    abstract fun bindMarketingRepository(impl: MarketingRepositoryImpl): MarketingRepository
}
