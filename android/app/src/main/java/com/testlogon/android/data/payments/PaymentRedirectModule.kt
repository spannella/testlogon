package com.testlogon.android.data.payments

import dagger.Binds
import dagger.Module
import dagger.Provides
import dagger.hilt.InstallIn
import dagger.hilt.components.SingletonComponent
import retrofit2.Retrofit
import javax.inject.Singleton

/** AND-228/229/230 — provides the [PaymentRedirectApi] on the shared (authenticated) Retrofit. */
@Module
@InstallIn(SingletonComponent::class)
object PaymentRedirectApiModule {

    @Provides
    @Singleton
    fun providePaymentRedirectApi(retrofit: Retrofit): PaymentRedirectApi =
        retrofit.create(PaymentRedirectApi::class.java)
}

/** AND-227..230 — binds the redirect repository (session creation gated by the BillingAuthorizer stub). */
@Module
@InstallIn(SingletonComponent::class)
abstract class PaymentRedirectBindModule {

    @Binds
    @Singleton
    abstract fun bindPaymentRedirectRepository(
        impl: PaymentRedirectRepositoryImpl,
    ): PaymentRedirectRepository
}
