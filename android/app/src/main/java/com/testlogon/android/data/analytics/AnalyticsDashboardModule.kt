package com.testlogon.android.data.analytics

import dagger.Binds
import dagger.Module
import dagger.Provides
import dagger.hilt.InstallIn
import dagger.hilt.components.SingletonComponent
import retrofit2.Retrofit
import javax.inject.Singleton

/** AND-399 - provides the analytics-dashboard API on the shared (authenticated) Retrofit. */
@Module
@InstallIn(SingletonComponent::class)
object AnalyticsDashboardApiModule {

    @Provides
    @Singleton
    fun provideAnalyticsDashboardApi(retrofit: Retrofit): AnalyticsDashboardApi =
        retrofit.create(AnalyticsDashboardApi::class.java)
}

/** AND-399 - binds the analytics-dashboard repository + range prefs implementations. */
@Module
@InstallIn(SingletonComponent::class)
abstract class AnalyticsDashboardDataModule {

    @Binds
    @Singleton
    abstract fun bindAnalyticsDashboardRepository(
        impl: AnalyticsDashboardRepositoryImpl,
    ): AnalyticsDashboardRepository

    @Binds
    @Singleton
    abstract fun bindAnalyticsRangePrefs(impl: DataStoreAnalyticsRangePrefs): AnalyticsRangePrefs
}
