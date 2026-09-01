package com.testlogon.android.feature.signing.packetlist

import dagger.Binds
import dagger.Module
import dagger.hilt.InstallIn
import dagger.hilt.components.SingletonComponent
import javax.inject.Singleton

/**
 * SUX-008 — Hilt wiring for the signing INBOX repository seam. Kept separate from the DETAIL feature's
 * SigningDataModule so the browse-list layer stays self-contained. The impl consumes the shared
 * [com.testlogon.android.core.network.signing.SigningApi] + [ApiErrorParser] provided by core-network;
 * NO new endpoint module, migration, or dependency is added.
 */
@Module
@InstallIn(SingletonComponent::class)
abstract class SigningInboxModule {

    @Binds
    @Singleton
    abstract fun bindSigningInboxRepository(impl: SigningInboxRepositoryImpl): SigningInboxRepository
}
