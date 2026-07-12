package com.testlogon.android.data.ads

import dagger.Binds
import dagger.Module
import dagger.Provides
import dagger.hilt.InstallIn
import dagger.hilt.components.SingletonComponent
import retrofit2.Retrofit
import javax.inject.Singleton

/** ADV-106 — provides the [AdTrackApi] on the shared Retrofit. */
@Module
@InstallIn(SingletonComponent::class)
object AdTrackApiModule {

    @Provides
    @Singleton
    fun provideAdTrackApi(retrofit: Retrofit): AdTrackApi =
        retrofit.create(AdTrackApi::class.java)
}

/** ADV-106 — binds the ad-event tracking repository. */
@Module
@InstallIn(SingletonComponent::class)
abstract class AdsDataModule {

    @Binds
    @Singleton
    abstract fun bindAdTrackRepository(impl: AdTrackRepositoryImpl): AdTrackRepository
}
