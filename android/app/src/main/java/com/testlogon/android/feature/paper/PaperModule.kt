package com.testlogon.android.feature.paper

import dagger.Binds
import dagger.Module
import dagger.hilt.InstallIn
import dagger.hilt.components.SingletonComponent
import javax.inject.Singleton

/** Binds the durable paper-trading account store (DataStore + Moshi) for injection into the ViewModel. */
@Module
@InstallIn(SingletonComponent::class)
abstract class PaperModule {

    @Binds
    @Singleton
    abstract fun bindPaperAccountStore(impl: DataStorePaperAccountStore): PaperAccountStore
}
