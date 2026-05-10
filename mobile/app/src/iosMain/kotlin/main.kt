package com.securevault.mobile

import androidx.compose.ui.platform.ComposeView
import androidx.compose.ui.window.Application
import androidx.compose.ui.window.WindowManager
import platform.UIKit.UIScreen

fun main() {
    Application(
        title = "SecureVault"
    ) {
        WindowManager(UIScreen.main.bounds)
        ComposeView().apply {
            setContent {
                SecureVaultApp()
            }
        }
    }
}

@Composable
fun SecureVaultApp() {
    androidx.compose.material3.MaterialTheme {
        androidx.compose.material3.Text("SecureVault iOS")
    }
}