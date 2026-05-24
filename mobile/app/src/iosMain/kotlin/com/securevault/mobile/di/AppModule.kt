package com.securevault.mobile.di

import com.securevault.mobile.data.api.SecureVaultApi
import com.securevault.mobile.data.local.IosEntryEncryptor
import com.securevault.mobile.data.repository.*
import com.securevault.mobile.domain.crypto.CryptoEngine
import com.securevault.mobile.domain.repository.AuthRepository
import com.securevault.mobile.domain.repository.DeviceRepository
import com.securevault.mobile.domain.repository.TwoFactorRepository
import com.securevault.mobile.domain.repository.VaultRepository
import org.koin.dsl.module

val appModule = module {
    single<SecureVaultApi> { SecureVaultApi.create("http://localhost:8080") }

    single<IosEntryEncryptor> { IosEntryEncryptor() }
    single<EntryEncryptor> { get<IosEntryEncryptor>() }
    single<VaultKeyManager> { get<IosEntryEncryptor>() }

    single<CryptoEngine> { CryptoEngine() }

    single<AuthRepository> { AuthRepositoryImpl(get(), get(), get(), get()) }
    single<VaultRepository> { VaultRepositoryImpl(get(), get()) }
    single<DeviceRepository> { DeviceRepositoryImpl(get()) }
    single<TwoFactorRepository> { TwoFactorRepositoryImpl(get()) }
}
