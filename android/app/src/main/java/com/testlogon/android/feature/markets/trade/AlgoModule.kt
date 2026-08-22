package com.testlogon.android.feature.markets.trade

import dagger.Binds
import dagger.Module
import dagger.hilt.InstallIn
import dagger.hilt.components.SingletonComponent
import javax.inject.Singleton

/** Binds the durable client-side algo-order store (DataStore + Moshi) for injection into [AlgoManager]. */
@Module
@InstallIn(SingletonComponent::class)
abstract class AlgoModule {

    @Binds
    @Singleton
    abstract fun bindAlgoOrderStore(impl: DataStoreAlgoOrderStore): AlgoOrderStore
}
