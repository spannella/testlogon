package com.testlogon.android.data.dashboard

import dagger.Binds
import dagger.Module
import dagger.Provides
import dagger.hilt.InstallIn
import dagger.hilt.components.SingletonComponent
import retrofit2.Retrofit
import javax.inject.Singleton

/** AND-065 — provides the [DashboardApi] on the shared Retrofit. */
@Module
@InstallIn(SingletonComponent::class)
object DashboardApiModule {

    @Provides
    @Singleton
    fun provideDashboardApi(retrofit: Retrofit): DashboardApi =
        retrofit.create(DashboardApi::class.java)
}

/** AND-065 — binds the dashboard repository to its implementation. */
@Module
@InstallIn(SingletonComponent::class)
abstract class DashboardDataModule {

    @Binds
    @Singleton
    abstract fun bindDashboardRepository(impl: DashboardRepositoryImpl): DashboardRepository
}
