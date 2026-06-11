package com.testlogon.android.data.analytics

import dagger.Binds
import dagger.Module
import dagger.Provides
import dagger.hilt.InstallIn
import dagger.hilt.components.SingletonComponent
import retrofit2.Retrofit
import javax.inject.Singleton

/** AND-254 — provides the engagement API on the shared (authenticated) Retrofit. */
@Module
@InstallIn(SingletonComponent::class)
object EngagementApiModule {

    @Provides
    @Singleton
    fun provideEngagementApi(retrofit: Retrofit): EngagementApi =
        retrofit.create(EngagementApi::class.java)
}

/** AND-254 — binds the engagement repository implementation. */
@Module
@InstallIn(SingletonComponent::class)
abstract class EngagementDataModule {

    @Binds
    @Singleton
    abstract fun bindEngagementRepository(impl: EngagementRepositoryImpl): EngagementRepository
}
