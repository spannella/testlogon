package com.testlogon.android.data.payouts

import dagger.Binds
import dagger.Module
import dagger.Provides
import dagger.hilt.InstallIn
import dagger.hilt.components.SingletonComponent
import retrofit2.Retrofit
import javax.inject.Singleton

/** AND-258/259 — provides the payouts + KYC tier APIs on the shared (authenticated) Retrofit. */
@Module
@InstallIn(SingletonComponent::class)
object PayoutsApiModule {

    @Provides
    @Singleton
    fun providePayoutsApi(retrofit: Retrofit): PayoutsApi =
        retrofit.create(PayoutsApi::class.java)

    @Provides
    @Singleton
    fun provideKycApi(retrofit: Retrofit): KycApi =
        retrofit.create(KycApi::class.java)
}

/**
 * AND-258/259 — binds the payout data-layer implementations + the FLAGGED [KycVerifier] stub.
 *
 * STOP-AND-FLAG: [bindKycVerifier] binds [StubKycVerifier] (NotConfigured, never launches a real flow).
 * The payout-request authorizer is bound elsewhere as the [com.testlogon.android.data.messaging.
 * BillingAuthorizer] stub (StubBillingAuthorizer) — request-payout routes through it and never executes
 * a real payout. Replace these @Binds when the respective vendor SDK decisions are made.
 */
@Module
@InstallIn(SingletonComponent::class)
abstract class PayoutsDataModule {

    @Binds
    @Singleton
    abstract fun bindPayoutsRepository(impl: PayoutsRepositoryImpl): PayoutsRepository

    @Binds
    @Singleton
    abstract fun bindKycRepository(impl: KycRepositoryImpl): KycRepository

    @Binds
    @Singleton
    abstract fun bindPayoutSetupRepository(impl: PayoutSetupRepositoryImpl): PayoutSetupRepository

    @Binds
    @Singleton
    abstract fun bindKycVerifier(impl: StubKycVerifier): KycVerifier
}
