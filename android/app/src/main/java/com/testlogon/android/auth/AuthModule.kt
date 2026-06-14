package com.testlogon.android.auth

import com.testlogon.android.data.auth.DataStoreAuthStateStore
import dagger.Binds
import dagger.Module
import dagger.hilt.InstallIn
import dagger.hilt.components.SingletonComponent
import javax.inject.Singleton

/**
 * Binds the auth-state seam to the real, DataStore-backed session store (AND-029).
 *
 * The router depends only on the [AuthStateProvider] interface; the binding now points at
 * [DataStoreAuthStateStore] (which implements [AuthStateProvider]) so the nav gate reflects the
 * persisted cookie session. The temporary [DefaultAuthStateProvider] is no longer wired.
 */
@Module
@InstallIn(SingletonComponent::class)
abstract class AuthModule {
    @Binds
    @Singleton
    abstract fun bindAuthStateProvider(impl: DataStoreAuthStateStore): AuthStateProvider
}
