package com.testlogon.android.data.stylist

import dagger.Binds
import dagger.Module
import dagger.Provides
import dagger.hilt.InstallIn
import dagger.hilt.components.SingletonComponent
import retrofit2.Retrofit
import javax.inject.Singleton

/** Provides [StylistApi] on the shared (authenticated) Retrofit. */
@Module
@InstallIn(SingletonComponent::class)
object StylistApiModule {

    @Provides
    @Singleton
    fun provideStylistApi(retrofit: Retrofit): StylistApi =
        retrofit.create(StylistApi::class.java)
}

/** Binds the Stylist data-layer implementation. */
@Module
@InstallIn(SingletonComponent::class)
abstract class StylistDataModule {

    @Binds
    @Singleton
    abstract fun bindStylistRepository(impl: StylistRepositoryImpl): StylistRepository
}
