package com.testlogon.android.feature.settings.callrate

import dagger.Binds
import dagger.Module
import dagger.hilt.InstallIn
import dagger.hilt.components.SingletonComponent
import javax.inject.Singleton

/** Hilt wiring for the call-rate settings feature. Binds the repository seam to its default impl. */
@Module
@InstallIn(SingletonComponent::class)
abstract class CallRateDataModule {

    @Binds
    @Singleton
    abstract fun bindCallRateRepository(impl: DefaultCallRateRepository): CallRateRepository
}
