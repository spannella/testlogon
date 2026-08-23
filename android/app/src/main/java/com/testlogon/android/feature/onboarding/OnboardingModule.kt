package com.testlogon.android.feature.onboarding

import dagger.Binds
import dagger.Module
import dagger.hilt.InstallIn
import dagger.hilt.components.SingletonComponent
import javax.inject.Singleton

/** Binds the durable onboarding seen-set store (DataStore) for injection into the tour ViewModels. */
@Module
@InstallIn(SingletonComponent::class)
abstract class OnboardingModule {

    @Binds
    @Singleton
    abstract fun bindOnboardingStore(impl: DataStoreOnboardingStore): OnboardingStore
}
