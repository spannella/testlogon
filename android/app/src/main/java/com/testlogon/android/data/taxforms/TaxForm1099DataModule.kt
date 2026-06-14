package com.testlogon.android.data.taxforms

import dagger.Binds
import dagger.Module
import dagger.Provides
import dagger.hilt.InstallIn
import dagger.hilt.components.SingletonComponent
import retrofit2.Retrofit
import javax.inject.Singleton

/** AND-247 — provides the [TaxForm1099Api] on the shared (authenticated) Retrofit. */
@Module
@InstallIn(SingletonComponent::class)
object TaxForm1099ApiModule {

    @Provides
    @Singleton
    fun provideTaxForm1099Api(retrofit: Retrofit): TaxForm1099Api =
        retrofit.create(TaxForm1099Api::class.java)
}

/** AND-247 — binds the 1099-NEC repository over [TaxForm1099Api]. */
@Module
@InstallIn(SingletonComponent::class)
abstract class TaxForm1099DataModule {

    @Binds
    @Singleton
    abstract fun bindTaxForm1099Repository(impl: TaxForm1099RepositoryImpl): TaxForm1099Repository
}
