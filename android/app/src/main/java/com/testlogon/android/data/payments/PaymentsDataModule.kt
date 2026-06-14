package com.testlogon.android.data.payments

import dagger.Binds
import dagger.Module
import dagger.Provides
import dagger.hilt.InstallIn
import dagger.hilt.components.SingletonComponent
import dagger.multibindings.ElementsIntoSet
import javax.inject.Singleton

/**
 * AND-231 — binds the redirect/return infrastructure and the data-driven provider registry.
 *
 * Adding a provider (AND-228/229) is supplying a [PaymentProvider] into the multibound set (FR-9) — no
 * parser edits. The PayPal/CCBill descriptors are contributed here since both ride the same handler.
 */
@Module
@InstallIn(SingletonComponent::class)
abstract class PaymentsDataModule {

    @Binds
    @Singleton
    abstract fun bindPaymentIntentStore(impl: DataStorePaymentIntentStore): PaymentIntentStore

    @Binds
    @Singleton
    abstract fun bindPaymentClock(impl: SystemPaymentClock): PaymentClock

    companion object {
        /** Provider ids match the `provider` token providers return with (AND-228/229). */
        const val PROVIDER_PAYPAL = "paypal"
        const val PROVIDER_CCBILL = "ccbill"

        /**
         * AND-228/AND-229 — registers the PayPal + CCBill redirect providers. Each maps its `provider`
         * token to the path segment it returns under. Adding a future provider is one more entry here.
         */
        @Provides
        @ElementsIntoSet
        @Singleton
        fun providePaymentProviders(): Set<PaymentProvider> = setOf(
            PaymentProvider(id = PROVIDER_PAYPAL, returnPathSegment = PROVIDER_PAYPAL),
            PaymentProvider(id = PROVIDER_CCBILL, returnPathSegment = PROVIDER_CCBILL),
        )
    }
}
