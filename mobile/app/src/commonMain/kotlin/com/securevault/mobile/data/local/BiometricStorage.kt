package com.securevault.mobile.data.local

import com.securevault.mobile.ui.PlatformContext

expect class BiometricStorage(context: PlatformContext) {
    fun isAvailable(): Boolean
    fun hasEncryptedVaultKey(): Boolean
    fun isLockedOut(): Boolean
    fun recordFailure()
    fun resetFailureCount()
    fun shouldShowBiometricPrompt(): Boolean
    fun authenticate(
        title: String,
        subtitle: String,
        onSuccess: () -> Unit,
        onError: (String) -> Unit,
        onCancel: () -> Unit = {}
    )
    fun storeVaultKey(vaultKey: String): Boolean
    fun retrieveVaultKey(): String?
    fun clear()
}
