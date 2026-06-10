package com.testlogon.android.data.tracking

import dagger.Binds
import dagger.Module
import dagger.Provides
import dagger.hilt.InstallIn
import dagger.hilt.components.SingletonComponent
import retrofit2.Retrofit
import javax.inject.Singleton

/**
 * AND-215 — provides the [TrackingApi] on the shared Retrofit and binds the tracking repository.
 */
@Module
@InstallIn(SingletonComponent::class)
object TrackingApiModule {

    @Provides
    @Singleton
    fun provideTrackingApi(retrofit: Retrofit): TrackingApi =
        retrofit.create(TrackingApi::class.java)
}

@Module
@InstallIn(SingletonComponent::class)
abstract class TrackingDataModule {

    @Binds
    @Singleton
    abstract fun bindTrackingRepository(impl: TrackingRepositoryImpl): TrackingRepository
}
