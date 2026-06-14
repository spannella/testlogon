package com.testlogon.android.data.billing

import dagger.Binds
import dagger.Module
import dagger.Provides
import dagger.hilt.InstallIn
import dagger.hilt.components.SingletonComponent
import retrofit2.Retrofit
import javax.inject.Singleton

/** AND-223 — provides the [BillingApi] on the shared (authenticated) Retrofit. */
@Module
@InstallIn(SingletonComponent::class)
object BillingApiModule {

    @Provides
    @Singleton
    fun provideBillingApi(retrofit: Retrofit): BillingApi =
        retrofit.create(BillingApi::class.java)
}

/** AND-223..226 — binds the billing repository and the FLAGGED card-entry seam. */
@Module
@InstallIn(SingletonComponent::class)
abstract class BillingDataModule {

    /** AND-223/224 — billing repository over [BillingApi]. */
    @Binds
    @Singleton
    abstract fun bindBillingRepository(impl: BillingRepositoryImpl): BillingRepository

    /**
     * AND-225/226 — card-entry seam. Defaults to [StubCardTokenizer] (NotConfigured, never tokenizes /
     * charges) until the Stripe Android SDK decision is made; swap this @Binds to the real
     * Stripe-backed implementation then. The Stripe Gradle dependency is intentionally NOT added.
     */
    @Binds
    @Singleton
    abstract fun bindCardTokenizer(impl: StubCardTokenizer): CardTokenizer
}
