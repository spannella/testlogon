package com.testlogon.android.data.agentrun

import dagger.Binds
import dagger.Module
import dagger.hilt.InstallIn
import dagger.hilt.components.SingletonComponent
import javax.inject.Singleton

/** AGENT-RUN (web-parity) - binds the agent-run console data-layer implementation. */
@Module
@InstallIn(SingletonComponent::class)
abstract class AgentRunDataModule {

    @Binds
    @Singleton
    abstract fun bindAgentRunRepository(impl: AgentRunRepositoryImpl): AgentRunRepository
}
