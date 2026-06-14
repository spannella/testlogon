package com.testlogon.android.feature.donation.data

import dagger.Binds
import dagger.Module
import dagger.hilt.InstallIn
import dagger.hilt.components.SingletonComponent
import javax.inject.Singleton

/**
 * AND-393 - binds the public-donation repository.
 *
 * [com.testlogon.android.core.network.donation.DonationApi] (public, cookieless Retrofit) is provided by
 * the core-network DonationNetworkModule; [com.testlogon.android.core.network.error.ApiErrorParser] is an
 * already-available singleton. No new dependency, no Room, no DataStore (donor PII stays in memory +
 * SavedStateHandle only, §8).
 */
@Module
@InstallIn(SingletonComponent::class)
abstract class DonationDataModule {

    @Binds
    @Singleton
    abstract fun bindDonationRepository(impl: DonationRepositoryImpl): DonationRepository
}
