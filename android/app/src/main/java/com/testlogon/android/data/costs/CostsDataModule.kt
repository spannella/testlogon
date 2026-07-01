package com.testlogon.android.data.costs

import dagger.Binds
import dagger.Module
import dagger.Provides
import dagger.hilt.InstallIn
import dagger.hilt.components.SingletonComponent
import retrofit2.Retrofit
import javax.inject.Singleton

/** Provides [CostsApi] on the shared (authenticated) Retrofit. */
@Module
@InstallIn(SingletonComponent::class)
object CostsApiModule {

    @Provides
    @Singleton
    fun provideCostsApi(retrofit: Retrofit): CostsApi =
        retrofit.create(CostsApi::class.java)
}

/** Binds the cost-tracking data-layer implementation. */
@Module
@InstallIn(SingletonComponent::class)
abstract class CostsDataModule {

    @Binds
    @Singleton
    abstract fun bindCostsRepository(impl: CostsRepositoryImpl): CostsRepository
}
