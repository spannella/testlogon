package com.testlogon.android.feature.agents.fleet.data

import dagger.Binds
import dagger.Module
import dagger.hilt.InstallIn
import dagger.hilt.components.SingletonComponent
import javax.inject.Singleton

/** AGENTS-BASICS (web-parity) - Hilt wiring for the FLEET feature. */
@Module
@InstallIn(SingletonComponent::class)
abstract class FleetDataModule {

    @Binds
    @Singleton
    abstract fun bindFleetRepository(impl: DefaultFleetRepository): FleetRepository
}
