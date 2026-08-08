package com.testlogon.android.data.exchange

import dagger.Binds
import dagger.Module
import dagger.Provides
import dagger.hilt.InstallIn
import dagger.hilt.components.SingletonComponent
import retrofit2.Retrofit
import javax.inject.Singleton

/** Provides the [ExchangeApi] + [TradingApi] and binds the exchange repositories to their impls. */
@Module
@InstallIn(SingletonComponent::class)
abstract class ExchangeDataModule {

    @Binds
    @Singleton
    abstract fun bindExchangeRepository(impl: ExchangeRepositoryImpl): ExchangeRepository

    @Binds
    @Singleton
    abstract fun bindTradingRepository(impl: TradingRepositoryImpl): TradingRepository

    companion object {
        /**
         * The cpp HTTP/2 edge refuses concurrent streams (REFUSED_STREAM) under the markets screen's
         * REST + SSE load, so the exchange REST calls fail intermittently over h2. Pin them to
         * HTTP/1.1 on their own connection pool, isolated from the app's shared (busy) h2 connection.
         */
        private fun http1(baseClient: okhttp3.OkHttpClient): okhttp3.OkHttpClient =
            baseClient.newBuilder()
                .protocols(listOf(okhttp3.Protocol.HTTP_1_1))
                .connectionPool(okhttp3.ConnectionPool())
                .build()

        @Provides
        @Singleton
        fun provideExchangeApi(retrofit: Retrofit, baseClient: okhttp3.OkHttpClient): ExchangeApi =
            retrofit.newBuilder().client(http1(baseClient)).build().create(ExchangeApi::class.java)

        @Provides
        @Singleton
        fun provideTradingApi(retrofit: Retrofit, baseClient: okhttp3.OkHttpClient): TradingApi =
            retrofit.newBuilder().client(http1(baseClient)).build().create(TradingApi::class.java)
    }
}
