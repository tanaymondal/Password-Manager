package com.securevault.mobile

import androidx.compose.runtime.Composable
import androidx.compose.runtime.remember
import androidx.compose.ui.window.ComposeUIViewController
import com.securevault.mobile.di._koin
import com.securevault.mobile.di.appModule
import com.securevault.mobile.ui.navigation.SecureVaultNavHost
import org.koin.core.context.startKoin

fun MainViewController() = ComposeUIViewController { SecureVaultApp() }

@Composable
fun SecureVaultApp() {
    remember {
        _koin = startKoin {
            modules(appModule)
        }.koin
    }
    SecureVaultNavHost()
}
