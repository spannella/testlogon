package com.testlogon.android.data.ideas

import dagger.Binds
import dagger.Module
import dagger.Provides
import dagger.hilt.InstallIn
import dagger.hilt.components.SingletonComponent
import retrofit2.Retrofit
import javax.inject.Singleton

/** Provides [IdeasApi] on the shared (authenticated) Retrofit. */
@Module
@InstallIn(SingletonComponent::class)
object IdeasApiModule {

    @Provides
    @Singleton
    fun provideIdeasApi(retrofit: Retrofit): IdeasApi =
        retrofit.create(IdeasApi::class.java)
}

/** Binds the product-ideas data-layer implementation. */
@Module
@InstallIn(SingletonComponent::class)
abstract class IdeasDataModule {

    @Binds
    @Singleton
    abstract fun bindIdeasRepository(impl: IdeasRepositoryImpl): IdeasRepository
}
