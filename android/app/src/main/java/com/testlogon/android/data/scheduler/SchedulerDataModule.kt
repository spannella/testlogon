package com.testlogon.android.data.scheduler

import dagger.Binds
import dagger.Module
import dagger.Provides
import dagger.hilt.InstallIn
import dagger.hilt.components.SingletonComponent
import retrofit2.Retrofit
import javax.inject.Singleton

/**
 * AND-275 — provides [SchedulerApi] on the shared Retrofit (no new OkHttp/Retrofit) and binds
 * [SchedulerRepository].
 */
@Module
@InstallIn(SingletonComponent::class)
object SchedulerApiModule {

    @Provides
    @Singleton
    fun provideSchedulerApi(retrofit: Retrofit): SchedulerApi =
        retrofit.create(SchedulerApi::class.java)
}

@Module
@InstallIn(SingletonComponent::class)
abstract class SchedulerDataModule {

    @Binds
    @Singleton
    abstract fun bindSchedulerRepository(impl: SchedulerRepositoryImpl): SchedulerRepository
}
