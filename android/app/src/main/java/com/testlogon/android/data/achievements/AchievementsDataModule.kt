package com.testlogon.android.data.achievements

import dagger.Binds
import dagger.Module
import dagger.Provides
import dagger.hilt.InstallIn
import dagger.hilt.components.SingletonComponent
import retrofit2.Retrofit
import javax.inject.Singleton

/** AND-093 / AND-094 — provides the [AchievementsApi] on the shared Retrofit. */
@Module
@InstallIn(SingletonComponent::class)
object AchievementsApiModule {

    @Provides
    @Singleton
    fun provideAchievementsApi(retrofit: Retrofit): AchievementsApi =
        retrofit.create(AchievementsApi::class.java)
}

/** AND-093 / AND-094 — binds the achievements repository to its implementation. */
@Module
@InstallIn(SingletonComponent::class)
abstract class AchievementsDataModule {

    @Binds
    @Singleton
    abstract fun bindAchievementsRepository(impl: AchievementsRepositoryImpl): AchievementsRepository
}
