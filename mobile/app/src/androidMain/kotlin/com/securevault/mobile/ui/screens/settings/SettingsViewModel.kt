package com.securevault.mobile.ui.screens.settings

import com.securevault.mobile.domain.entity.DeviceEntity
import com.securevault.mobile.domain.usecase.auth.LogoutUseCase
import com.securevault.mobile.domain.usecase.device.GetDevicesUseCase
import com.securevault.mobile.domain.usecase.twofactor.GetTwoFactorStatusUseCase
import com.securevault.mobile.ui.mvi.MviEffect
import com.securevault.mobile.ui.mvi.MviIntent
import com.securevault.mobile.ui.mvi.MviState
import com.securevault.mobile.ui.mvi.MviViewModel

sealed class SettingsIntent : MviIntent {
    data object LoadSettings : SettingsIntent()
    data object LogoutClicked : SettingsIntent()
    data object ConfirmLogout : SettingsIntent()
    data object DismissLogoutDialog : SettingsIntent()
}

data class SettingsState(
    val devices: List<DeviceEntity> = emptyList(),
    val twoFactorEnabled: Boolean? = null,
    val isLoading: Boolean = false,
    val showLogoutDialog: Boolean = false
) : MviState

sealed class SettingsEffect : MviEffect {
    data object NavigateToLogin : SettingsEffect()
}

class SettingsViewModel(
    private val getDevicesUseCase: GetDevicesUseCase,
    private val getTwoFactorStatusUseCase: GetTwoFactorStatusUseCase,
    private val logoutUseCase: LogoutUseCase
) : MviViewModel<SettingsIntent, SettingsState, SettingsEffect>(SettingsState()) {

    init {
        handleIntent(SettingsIntent.LoadSettings)
    }

    override fun handleIntent(intent: SettingsIntent) {
        when (intent) {
            is SettingsIntent.LoadSettings -> loadSettings()
            is SettingsIntent.LogoutClicked -> setState { copy(showLogoutDialog = true) }
            is SettingsIntent.ConfirmLogout -> logout()
            is SettingsIntent.DismissLogoutDialog -> setState { copy(showLogoutDialog = false) }
        }
    }

    private fun loadSettings() {
        setState { copy(isLoading = true) }

        runInBackground(
            block = { getDevicesUseCase() },
            onResult = { devicesResult ->
                runInBackground(
                    block = { getTwoFactorStatusUseCase() },
                    onResult = { twoFactorResult ->
                        setState {
                            copy(
                                isLoading = false,
                                devices = when (val r = devicesResult.getOrNull()) {
                                    is com.securevault.mobile.domain.usecase.device.DevicesResult.Success -> r.devices
                                    else -> emptyList()
                                },
                                twoFactorEnabled = when (val r = twoFactorResult.getOrNull()) {
                                    is com.securevault.mobile.domain.usecase.twofactor.TwoFactorStatusResult.Success -> r.enabled
                                    else -> null
                                }
                            )
                        }
                    }
                )
            }
        )
    }

    private fun logout() {
        setState { copy(showLogoutDialog = false) }

        runInBackground(
            block = { logoutUseCase() },
            onResult = {
                setEffect(SettingsEffect.NavigateToLogin)
            }
        )
    }
}