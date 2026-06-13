package com.testlogon.android.feature.kyc.data

import dagger.Binds
import dagger.Module
import dagger.hilt.InstallIn
import dagger.hilt.components.SingletonComponent
import javax.inject.Singleton

/**
 * AND-320 — Hilt wiring for the KYC Tier Status feature. Binds the thin seam interfaces to their default
 * impls. The impls consume AND-319's [com.testlogon.android.core.network.kyc.KycApi] + the shared Moshi
 * (NetworkModule.provideMoshi) + DataStore; NO new endpoint, migration, or dependency is added here.
 */
@Module
@InstallIn(SingletonComponent::class)
abstract class KycTierModule {

    @Binds
    @Singleton
    abstract fun bindKycTierRepository(impl: KycTierRepositoryImpl): KycTierRepository

    @Binds
    @Singleton
    abstract fun bindKycTierStore(impl: DataStoreKycTierStore): KycTierStore
}
