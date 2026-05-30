package com.securevault.mobile

import androidx.compose.runtime.Composable
import androidx.compose.ui.window.ComposeUIViewController

fun MainViewController() = ComposeUIViewController { SecureVaultApp() }

@Composable
fun SecureVaultApp() {
    androidx.compose.material3.MaterialTheme {
        androidx.compose.material3.Text("SecureVault iOS")
    }
}
