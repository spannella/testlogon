package com.testlogon.android.data.pmideas

import dagger.Binds
import dagger.Module
import dagger.Provides
import dagger.hilt.InstallIn
import dagger.hilt.components.SingletonComponent
import retrofit2.Retrofit
import javax.inject.Singleton

/** Provides [PmIdeasApi] on the shared (authenticated) Retrofit. */
@Module
@InstallIn(SingletonComponent::class)
object PmIdeasApiModule {

    @Provides
    @Singleton
    fun providePmIdeasApi(retrofit: Retrofit): PmIdeasApi =
        retrofit.create(PmIdeasApi::class.java)
}

/** Binds the PM-idea triage data-layer implementation. */
@Module
@InstallIn(SingletonComponent::class)
abstract class PmIdeasDataModule {

    @Binds
    @Singleton
    abstract fun bindPmIdeasRepository(impl: PmIdeasRepositoryImpl): PmIdeasRepository
}
