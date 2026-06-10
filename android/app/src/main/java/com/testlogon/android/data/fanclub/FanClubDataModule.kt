package com.testlogon.android.data.fanclub

import dagger.Binds
import dagger.Module
import dagger.Provides
import dagger.hilt.InstallIn
import dagger.hilt.components.SingletonComponent
import retrofit2.Retrofit
import javax.inject.Singleton

/** AND-238/239/240 — provides the [FanClubApi] on the shared (authenticated) Retrofit. */
@Module
@InstallIn(SingletonComponent::class)
object FanClubApiModule {

    @Provides
    @Singleton
    fun provideFanClubApi(retrofit: Retrofit): FanClubApi =
        retrofit.create(FanClubApi::class.java)
}

/** AND-238/239/240 — binds the fan-club repository over [FanClubApi]. */
@Module
@InstallIn(SingletonComponent::class)
abstract class FanClubDataModule {

    @Binds
    @Singleton
    abstract fun bindFanClubRepository(impl: FanClubRepositoryImpl): FanClubRepository
}
