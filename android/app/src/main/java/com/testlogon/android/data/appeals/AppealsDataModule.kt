package com.testlogon.android.data.appeals

import dagger.Binds
import dagger.Module
import dagger.Provides
import dagger.hilt.InstallIn
import dagger.hilt.components.SingletonComponent
import retrofit2.Retrofit
import javax.inject.Singleton

/** Provides [AppealsApi] on the shared (authenticated) Retrofit. */
@Module
@InstallIn(SingletonComponent::class)
object AppealsApiModule {

    @Provides
    @Singleton
    fun provideAppealsApi(retrofit: Retrofit): AppealsApi =
        retrofit.create(AppealsApi::class.java)
}

/** Binds the appeals data-layer implementation. */
@Module
@InstallIn(SingletonComponent::class)
abstract class AppealsDataModule {

    @Binds
    @Singleton
    abstract fun bindAppealsRepository(impl: AppealsRepositoryImpl): AppealsRepository
}
