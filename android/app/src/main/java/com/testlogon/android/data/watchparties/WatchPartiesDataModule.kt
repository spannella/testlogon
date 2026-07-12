package com.testlogon.android.data.watchparties

import dagger.Binds
import dagger.Module
import dagger.Provides
import dagger.hilt.InstallIn
import dagger.hilt.components.SingletonComponent
import retrofit2.Retrofit
import javax.inject.Singleton

/** Provides [WatchPartiesApi] on the shared (authenticated) Retrofit. */
@Module
@InstallIn(SingletonComponent::class)
object WatchPartiesApiModule {

    @Provides
    @Singleton
    fun provideWatchPartiesApi(retrofit: Retrofit): WatchPartiesApi =
        retrofit.create(WatchPartiesApi::class.java)
}

/** Binds the watch-parties data-layer implementation. */
@Module
@InstallIn(SingletonComponent::class)
abstract class WatchPartiesDataModule {

    @Binds
    @Singleton
    abstract fun bindWatchPartiesRepository(impl: WatchPartiesRepositoryImpl): WatchPartiesRepository
}
