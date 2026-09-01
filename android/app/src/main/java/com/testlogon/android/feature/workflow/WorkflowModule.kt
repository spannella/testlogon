package com.testlogon.android.feature.workflow

import dagger.Binds
import dagger.Module
import dagger.hilt.InstallIn
import dagger.hilt.components.SingletonComponent
import javax.inject.Singleton

/**
 * WFL — Hilt wiring for the SuiteCRM Workflow feature repository seam. The impl consumes the core-network
 * [com.testlogon.android.core.network.workflow.WorkflowRulesApi] + shared ApiErrorParser; NO new endpoint
 * module, migration, or dependency is added here.
 */
@Module
@InstallIn(SingletonComponent::class)
abstract class WorkflowModule {

    @Binds
    @Singleton
    abstract fun bindWorkflowRulesRepository(impl: WorkflowRulesRepositoryImpl): WorkflowRulesRepository
}
