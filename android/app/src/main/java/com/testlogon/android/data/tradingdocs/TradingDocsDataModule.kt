package com.testlogon.android.data.tradingdocs

import dagger.Binds
import dagger.Module
import dagger.Provides
import dagger.hilt.InstallIn
import dagger.hilt.components.SingletonComponent
import retrofit2.Retrofit
import javax.inject.Singleton

/** FE-170 — provides the [TradingDocsApi] on the shared (authenticated) Retrofit. */
@Module
@InstallIn(SingletonComponent::class)
object TradingDocsApiModule {

    @Provides
    @Singleton
    fun provideTradingDocsApi(retrofit: Retrofit): TradingDocsApi =
        retrofit.create(TradingDocsApi::class.java)
}

/** FE-170 — binds the trading-documents repository over [TradingDocsApi]. */
@Module
@InstallIn(SingletonComponent::class)
abstract class TradingDocsDataModule {

    @Binds
    @Singleton
    abstract fun bindTradingDocsRepository(impl: TradingDocsRepositoryImpl): TradingDocsRepository
}
