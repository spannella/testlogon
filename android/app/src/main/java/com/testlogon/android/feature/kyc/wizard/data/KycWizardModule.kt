package com.testlogon.android.feature.kyc.wizard.data

import dagger.Binds
import dagger.Module
import dagger.hilt.InstallIn
import dagger.hilt.components.SingletonComponent
import javax.inject.Singleton

/**
 * Batch-9 (#18) - Hilt wiring for the guided KYC verification wizard. Binds the repository seam to its impl.
 * [KycWizardRepositoryImpl] consumes the new KycVerifyApi + the existing KycApi (both provided by core-network's
 * KycNetworkModule) + the shared ApiErrorParser. No new endpoint/migration/dependency is added here.
 */
@Module
@InstallIn(SingletonComponent::class)
abstract class KycWizardModule {

    @Binds
    @Singleton
    abstract fun bindKycWizardRepository(impl: KycWizardRepositoryImpl): KycWizardRepository
}
