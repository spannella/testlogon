package com.testlogon.android.data.activity

import dagger.Binds
import dagger.Module
import dagger.Provides
import dagger.hilt.InstallIn
import dagger.hilt.components.SingletonComponent
import retrofit2.Retrofit
import javax.inject.Singleton

/** AND-091 — provides the [ActivityApi] on the shared Retrofit. */
@Module
@InstallIn(SingletonComponent::class)
object ActivityApiModule {

    @Provides
    @Singleton
    fun provideActivityApi(retrofit: Retrofit): ActivityApi =
        retrofit.create(ActivityApi::class.java)
}

/** AND-091 — binds the activity repository to its implementation. */
@Module
@InstallIn(SingletonComponent::class)
abstract class ActivityDataModule {

    @Binds
    @Singleton
    abstract fun bindActivityRepository(impl: ActivityRepositoryImpl): ActivityRepository
}
