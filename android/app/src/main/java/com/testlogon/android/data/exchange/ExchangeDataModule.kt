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
        fun provideExchangeApi(retrofit: Retrofit): ExchangeApi =
            retrofit.create(ExchangeApi::class.java)
    }
}
