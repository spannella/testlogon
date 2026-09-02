package com.testlogon.android.feature.agents.orchestrator.data

import dagger.Binds
import dagger.Module
import dagger.hilt.InstallIn
import dagger.hilt.components.SingletonComponent
import javax.inject.Singleton

/**
 * AGENT-ORCHESTRATOR (web-parity) - Hilt wiring for the ORCHESTRATOR feature. Binds the repository seam to its
 * impl (the transport [com.testlogon.android.core.network.agents.OrchestratorApi] is provided by
 * AgentsNetworkModule alongside the other agents APIs).
 */
@Module
@InstallIn(SingletonComponent::class)
abstract class OrchestratorDataModule {

    @Binds
    @Singleton
    abstract fun bindOrchestratorRepository(impl: DefaultOrchestratorRepository): OrchestratorRepository
}
