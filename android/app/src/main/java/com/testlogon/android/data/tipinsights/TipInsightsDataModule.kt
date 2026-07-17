package com.testlogon.android.data.tipinsights

import dagger.Binds
import dagger.Module
import dagger.Provides
import dagger.hilt.InstallIn
import dagger.hilt.components.SingletonComponent
import retrofit2.Retrofit
import javax.inject.Singleton

/** TIPX-D3/D4 — provides the [TipInsightsApi] on the shared Retrofit. */
@Module
@InstallIn(SingletonComponent::class)
object TipInsightsApiModule {

    @Provides
    @Singleton
    fun provideTipInsightsApi(retrofit: Retrofit): TipInsightsApi =
        retrofit.create(TipInsightsApi::class.java)
}

/** TIPX-D3/D4 — binds the tip-insights repository to its implementation. */
@Module
@InstallIn(SingletonComponent::class)
abstract class TipInsightsDataModule {

    @Binds
    @Singleton
    abstract fun bindTipInsightsRepository(impl: TipInsightsRepositoryImpl): TipInsightsRepository
}
