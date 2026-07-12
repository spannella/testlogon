package com.testlogon.android.feature.agents.workers.data

import dagger.Binds
import dagger.Module
import dagger.hilt.InstallIn
import dagger.hilt.components.SingletonComponent
import javax.inject.Singleton

/** AGENTS-BASICS (web-parity) - Hilt wiring for the WORKERS feature. Binds the repository seam to its impl. */
@Module
@InstallIn(SingletonComponent::class)
abstract class WorkersDataModule {

    @Binds
    @Singleton
    abstract fun bindWorkersRepository(impl: DefaultWorkersRepository): WorkersRepository
}
