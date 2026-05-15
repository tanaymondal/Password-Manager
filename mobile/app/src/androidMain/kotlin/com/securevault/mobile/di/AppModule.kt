package com.securevault.mobile.di

import android.content.Context
import com.securevault.mobile.data.api.SecureVaultApi
import com.securevault.mobile.data.local.AndroidEntryEncryptor
import com.securevault.mobile.data.repository.*
import com.securevault.mobile.domain.repository.AuthRepository
import com.securevault.mobile.domain.repository.DeviceRepository
import com.securevault.mobile.domain.repository.TwoFactorRepository
import com.securevault.mobile.domain.repository.VaultRepository
import com.securevault.mobile.domain.usecase.auth.*
import com.securevault.mobile.domain.usecase.auth.impl.*
import com.securevault.mobile.domain.usecase.device.*
import com.securevault.mobile.domain.usecase.device.impl.*
import com.securevault.mobile.domain.usecase.twofactor.*
import com.securevault.mobile.domain.usecase.twofactor.impl.*
import com.securevault.mobile.domain.usecase.vault.*
import com.securevault.mobile.domain.usecase.vault.impl.*
import com.securevault.mobile.ui.screens.auth.LoginViewModel
import com.securevault.mobile.ui.screens.auth.RegisterViewModel
import com.securevault.mobile.ui.screens.settings.ChangePasswordViewModel
import com.securevault.mobile.ui.screens.settings.SettingsViewModel
import com.securevault.mobile.ui.screens.vault.AddEditEntryViewModel
import com.securevault.mobile.ui.screens.vault.VaultViewModel
import org.koin.android.ext.koin.androidContext
import org.koin.androidx.viewmodel.dsl.viewModel
import org.koin.dsl.module

val appModule = module {
    // API
    single<SecureVaultApi> { SecureVaultApi.create("https://vault.tanay.pro") }

    // Encryptor - Android specific (single instance for both EntryEncryptor and VaultKeyManager)
    single { AndroidEntryEncryptor() }
    single<EntryEncryptor> { get<AndroidEntryEncryptor>() }
    single<VaultKeyManager> { get<AndroidEntryEncryptor>() }

    // Repositories
    single<AuthRepository> { AuthRepositoryImpl(get(), get(), get()) }
    single<VaultRepository> { CachedVaultRepository(androidContext(), VaultRepositoryImpl(get(), get())) }
    single<DeviceRepository> { DeviceRepositoryImpl(get()) }
    single<TwoFactorRepository> { TwoFactorRepositoryImpl(get()) }

    // Auth Use Cases
    factory<GetAuthStateUseCase> { GetAuthStateUseCaseImpl(get()) }
    factory<LoginUseCase> { LoginUseCaseImpl(get()) }
    factory<RegisterUseCase> { RegisterUseCaseImpl(get()) }
    factory<LogoutUseCase> { LogoutUseCaseImpl(get()) }
    factory<RefreshTokenUseCase> { RefreshTokenUseCaseImpl(get()) }
    factory<ChangePasswordUseCase> { ChangePasswordUseCaseImpl(get()) }

    // Vault Use Cases
    factory<GetVaultEntriesUseCase> { GetVaultEntriesUseCaseImpl(get()) }
    factory<GetVaultEntryUseCase> { GetVaultEntryUseCaseImpl(get()) }
    factory<CreateVaultEntryUseCase> { CreateVaultEntryUseCaseImpl(get()) }
    factory<UpdateVaultEntryUseCase> { UpdateVaultEntryUseCaseImpl(get()) }
    factory<DeleteVaultEntryUseCase> { DeleteVaultEntryUseCaseImpl(get()) }
    factory<DeleteAllVaultEntriesUseCase> { DeleteAllVaultEntriesUseCaseImpl(get()) }

    // Device Use Cases
    factory<GetDevicesUseCase> { GetDevicesUseCaseImpl(get()) }
    factory<RegisterDeviceUseCase> { RegisterDeviceUseCaseImpl(get()) }
    factory<RemoveDeviceUseCase> { RemoveDeviceUseCaseImpl(get()) }

    // Two-Factor Use Cases
    factory<SetupTwoFactorUseCase> { SetupTwoFactorUseCaseImpl(get()) }
    factory<EnableTwoFactorUseCase> { EnableTwoFactorUseCaseImpl(get()) }
    factory<DisableTwoFactorUseCase> { DisableTwoFactorUseCaseImpl(get()) }
    factory<GetTwoFactorStatusUseCase> { GetTwoFactorStatusUseCaseImpl(get()) }

    // ViewModels
    viewModel { LoginViewModel(get(), get()) }
    viewModel { RegisterViewModel(get(), get()) }
    viewModel { VaultViewModel(get(), get(), get()) }
    viewModel { AddEditEntryViewModel(get(), get(), get()) }
    viewModel { SettingsViewModel(get(), get(), get()) }
    viewModel { ChangePasswordViewModel(get()) }
}