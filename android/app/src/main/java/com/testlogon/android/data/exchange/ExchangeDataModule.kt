package com.testlogon.android.data.exchange

import dagger.Binds
import dagger.Module
import dagger.Provides
import dagger.hilt.InstallIn
import dagger.hilt.components.SingletonComponent
import retrofit2.Retrofit
import javax.inject.Singleton

/** Provides the [ExchangeApi] and binds the Markets repository to its implementation. */
@Module
@InstallIn(SingletonComponent::class)
abstract class ExchangeDataModule {

    @Binds
    @Singleton
    abstract fun bindExchangeRepository(impl: ExchangeRepositoryImpl): ExchangeRepository

    companion object {
        @Provides
        @Singleton
        fun provideExchangeApi(retrofit: Retrofit, baseClient: okhttp3.OkHttpClient): ExchangeApi {
            // The cpp HTTP/2 edge refuses concurrent streams (REFUSED_STREAM) under the markets
            // screen's REST + SSE load, so /md/candles|book|trades fail intermittently. Pin the
            // exchange REST client to HTTP/1.1 on its own connection pool, isolated from the app's
            // shared (busy) h2 connection.
            val h1Client = baseClient.newBuilder()
                .protocols(listOf(okhttp3.Protocol.HTTP_1_1))
                .connectionPool(okhttp3.ConnectionPool())
                .build()
            return retrofit.newBuilder().client(h1Client).build().create(ExchangeApi::class.java)
        }
    }
}
