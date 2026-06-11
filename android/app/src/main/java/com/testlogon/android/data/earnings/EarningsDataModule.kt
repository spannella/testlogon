package com.testlogon.android.data.earnings

import dagger.Binds
import dagger.Module
import dagger.Provides
import dagger.hilt.InstallIn
import dagger.hilt.components.SingletonComponent
import retrofit2.Retrofit
import javax.inject.Singleton

/** AND-251/253 — provides the earnings + content-revenue APIs on the shared (authenticated) Retrofit. */
@Module
@InstallIn(SingletonComponent::class)
object EarningsApiModule {

    @Provides
    @Singleton
    fun provideEarningsApi(retrofit: Retrofit): EarningsApi =
        retrofit.create(EarningsApi::class.java)

    @Provides
    @Singleton
    fun provideContentRevenueApi(retrofit: Retrofit): ContentRevenueApi =
        retrofit.create(ContentRevenueApi::class.java)
}

/** AND-251/252/253 — binds the earnings data-layer implementations. */
@Module
@InstallIn(SingletonComponent::class)
abstract class EarningsDataModule {

    @Binds
    @Singleton
    abstract fun bindEarningsRepository(impl: EarningsRepositoryImpl): EarningsRepository

    @Binds
    @Singleton
    abstract fun bindContentRevenueRepository(impl: ContentRevenueRepositoryImpl): ContentRevenueRepository

    @Binds
    @Singleton
    abstract fun bindEarningsPrefs(impl: DataStoreEarningsPrefs): EarningsPrefs

    @Binds
    @Singleton
    abstract fun bindEarningsClock(impl: SystemEarningsClock): EarningsClock
}
