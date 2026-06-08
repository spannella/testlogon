package com.testlogon.android.data.auth

import com.testlogon.android.core.network.auth.AuthEventSink
import com.testlogon.android.core.network.cookie.PersistentCookieJar
import dagger.Binds
import dagger.Module
import dagger.Provides
import dagger.hilt.InstallIn
import dagger.hilt.components.SingletonComponent
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.launch
import retrofit2.Retrofit
import javax.inject.Provider
import javax.inject.Singleton

/** Provides the auth data-layer collaborators (API, app scope, auth-event sink). */
@Module
@InstallIn(SingletonComponent::class)
object AuthDataProvidesModule {

    @Provides
    @Singleton
    fun provideAuthApi(retrofit: Retrofit): AuthApi = retrofit.create(AuthApi::class.java)

    @Provides
    @Singleton
    @AppScope
    fun provideAppScope(): CoroutineScope = CoroutineScope(SupervisorJob() + Dispatchers.IO)

    @Provides
    @Singleton
    fun provideSessionCookieCleaner(cookieJar: PersistentCookieJar): SessionCookieCleaner =
        SessionCookieCleaner { cookieJar.clear() }

    /**
     * Bridges the core-network 401-give-up event into a durable auth-state clear (AND-029/032).
     * The cookie jar is already cleared by the authenticator; this flips the persisted flag so the
     * nav gate routes back to login. [AuthStateStore] is taken lazily ([Provider]) to avoid a DI
     * cycle (the store does not depend on the network event sink, but keeping it lazy is safe).
     */
    @Provides
    @Singleton
    fun provideAuthEventSink(
        @AppScope scope: CoroutineScope,
        store: Provider<AuthStateStore>,
    ): AuthEventSink = AuthEventSink {
        // The authenticator only fires this on an unrecoverable 401 -> session expired (AND-044).
        scope.launch { store.get().clear(com.testlogon.android.core.model.LogoutReason.SESSION_EXPIRED) }
    }
}

/** Binds the auth data-layer interfaces to their implementations. */
@Module
@InstallIn(SingletonComponent::class)
abstract class AuthDataBindsModule {

    @Binds
    @Singleton
    abstract fun bindAuthRepository(impl: AuthRepositoryImpl): AuthRepository

    @Binds
    @Singleton
    abstract fun bindAuthStateStore(impl: DataStoreAuthStateStore): AuthStateStore

    @Binds
    @Singleton
    abstract fun bindSessionsRepository(impl: SessionsRepositoryImpl): SessionsRepository
}
