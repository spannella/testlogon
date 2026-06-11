package com.testlogon.android.data.disputes

import dagger.Binds
import dagger.Module
import dagger.Provides
import dagger.hilt.InstallIn
import dagger.hilt.components.SingletonComponent
import retrofit2.Retrofit
import javax.inject.Singleton

/** AND-245 — provides the [DisputesApi] on the shared (authenticated) Retrofit. */
@Module
@InstallIn(SingletonComponent::class)
object DisputesApiModule {

    @Provides
    @Singleton
    fun provideDisputesApi(retrofit: Retrofit): DisputesApi =
        retrofit.create(DisputesApi::class.java)
}

/** AND-245 — binds the disputes repository over [DisputesApi]. */
@Module
@InstallIn(SingletonComponent::class)
abstract class DisputesDataModule {

    @Binds
    @Singleton
    abstract fun bindDisputesRepository(impl: DisputesRepositoryImpl): DisputesRepository
}
