package com.testlogon.android.data.agentconfig

import dagger.Binds
import dagger.Module
import dagger.hilt.InstallIn
import dagger.hilt.components.SingletonComponent
import javax.inject.Singleton

/** B4 web-parity - binds the agent-type config data-layer implementation. */
@Module
@InstallIn(SingletonComponent::class)
abstract class AgentConfigDataModule {

    @Binds
    @Singleton
    abstract fun bindAgentConfigRepository(impl: AgentConfigRepositoryImpl): AgentConfigRepository
}
