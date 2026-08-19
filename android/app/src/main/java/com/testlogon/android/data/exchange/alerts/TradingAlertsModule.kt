package com.testlogon.android.data.exchange.alerts

import dagger.Binds
import dagger.Module
import dagger.Provides
import dagger.hilt.InstallIn
import dagger.hilt.components.SingletonComponent
import javax.inject.Singleton

/** Binds the derived-trading-alerts store + provides the wall-clock used by the poller/detector. */
@Module
@InstallIn(SingletonComponent::class)
abstract class TradingAlertsModule {

    @Binds
    @Singleton
    abstract fun bindTradingAlertsStore(impl: DataStoreTradingAlertsStore): TradingAlertsStore

    companion object {
        @Provides
        @Singleton
        fun provideAlertClock(): AlertClock = AlertClock { System.currentTimeMillis() }
    }
}
