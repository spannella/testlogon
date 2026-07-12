package com.testlogon.android.data.bots

import dagger.Binds
import dagger.Module
import dagger.Provides
import dagger.hilt.InstallIn
import dagger.hilt.components.SingletonComponent
import retrofit2.Retrofit
import javax.inject.Singleton

/** Provides [BotsApi] on the shared (authenticated) Retrofit. */
@Module
@InstallIn(SingletonComponent::class)
object BotsApiModule {

    @Provides
    @Singleton
    fun provideBotsApi(retrofit: Retrofit): BotsApi =
        retrofit.create(BotsApi::class.java)
}

/** Binds the bots data-layer implementation. */
@Module
@InstallIn(SingletonComponent::class)
abstract class BotsDataModule {

    @Binds
    @Singleton
    abstract fun bindBotsRepository(impl: BotsRepositoryImpl): BotsRepository
}
