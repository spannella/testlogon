package com.testlogon.android.feature.payments

import dagger.Binds
import dagger.Module
import dagger.hilt.InstallIn
import dagger.hilt.components.SingletonComponent
import javax.inject.Singleton

/** AND-228/229 — binds the Custom Tab launcher used by the redirect payment screens. */
@Module
@InstallIn(SingletonComponent::class)
abstract class PaymentsFeatureModule {

    @Binds
    @Singleton
    abstract fun bindPaymentTabLauncher(impl: CustomTabsPaymentTabLauncher): PaymentTabLauncher
}
