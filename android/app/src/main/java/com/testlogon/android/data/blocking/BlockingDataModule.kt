package com.testlogon.android.data.blocking

import dagger.Binds
import dagger.Module
import dagger.Provides
import dagger.hilt.InstallIn
import dagger.hilt.components.SingletonComponent
import retrofit2.Retrofit
import javax.inject.Singleton

/** AND-382 - provides [BlockApi] on the shared (AND-027 authenticated) Retrofit. */
@Module
@InstallIn(SingletonComponent::class)
object BlockApiModule {

    @Provides
    @Singleton
    fun provideBlockApi(retrofit: Retrofit): BlockApi =
        retrofit.create(BlockApi::class.java)
}

/** AND-382 - binds the blocking repository to its implementation. */
@Module
@InstallIn(SingletonComponent::class)
abstract class BlockingDataModule {

    @Binds
    @Singleton
    abstract fun bindBlockingRepository(impl: BlockingRepositoryImpl): BlockingRepository
}
