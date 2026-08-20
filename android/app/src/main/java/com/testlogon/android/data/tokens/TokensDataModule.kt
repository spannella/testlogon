package com.testlogon.android.data.tokens

import dagger.Binds
import dagger.Module
import dagger.Provides
import dagger.hilt.InstallIn
import dagger.hilt.components.SingletonComponent
import retrofit2.Retrofit
import javax.inject.Singleton

/**
 * Provides the [TokensApi] and binds [TokensRepository] to its impl for the CREATOR REVENUE-SHARE
 * TOKEN surface. Mirrors the exchange data module: the API is built off the shared Retrofit but pinned
 * to HTTP/1.1 on its own pool (the cpp h2 edge refuses concurrent streams under polling load).
 */
@Module
@InstallIn(SingletonComponent::class)
abstract class TokensDataModule {

    @Binds
    @Singleton
    abstract fun bindTokensRepository(impl: TokensRepositoryImpl): TokensRepository

    companion object {
        private fun http1(baseClient: okhttp3.OkHttpClient): okhttp3.OkHttpClient =
            baseClient.newBuilder()
                .protocols(listOf(okhttp3.Protocol.HTTP_1_1))
                .connectionPool(okhttp3.ConnectionPool())
                .build()

        @Provides
        @Singleton
        fun provideTokensApi(retrofit: Retrofit, baseClient: okhttp3.OkHttpClient): TokensApi =
            retrofit.newBuilder().client(http1(baseClient)).build().create(TokensApi::class.java)
    }
}
