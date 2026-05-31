@file:OptIn(kotlinx.cinterop.ExperimentalForeignApi::class)
package com.securevault.mobile.data.local

import com.securevault.mobile.data.repository.SessionManager
import com.securevault.mobile.ui.PlatformContext
import platform.LocalAuthentication.*

actual class BiometricStorage actual constructor(context: PlatformContext) {
    companion object {
        private const val KEY_BIOMETRIC_VAULT = "sv_bio_vk"
        private const val KEY_FAILURE_COUNT = "sv_bio_fail"
        private const val MAX_BIOMETRIC_FAILURES = 5
    }

    private var authorizedVaultKey: String? = null

    actual fun isAvailable(): Boolean {
        val ctx = LAContext()
        return ctx.canEvaluatePolicy(LAPolicyDeviceOwnerAuthenticationWithBiometrics, null)
    }

    actual fun hasEncryptedVaultKey(): Boolean {
        return SessionManager.getBiometricVaultKey().isNotEmpty()
    }

    actual fun isLockedOut(): Boolean {
        return SessionManager.getBiometricFailureCount() >= MAX_BIOMETRIC_FAILURES
    }

    actual fun recordFailure() {
        SessionManager.setBiometricFailureCount(SessionManager.getBiometricFailureCount() + 1)
    }

    actual fun resetFailureCount() {
        SessionManager.setBiometricFailureCount(0)
    }

    actual fun shouldShowBiometricPrompt(): Boolean {
        return isAvailable() && hasEncryptedVaultKey() && !isLockedOut()
    }

    actual fun authenticate(
        title: String,
        subtitle: String,
        onSuccess: () -> Unit,
        onError: (String) -> Unit,
        onCancel: () -> Unit
    ) {
        val ctx = LAContext()
        ctx.evaluatePolicy(LAPolicyDeviceOwnerAuthenticationWithBiometrics, title) { success, error ->
            if (success) {
                resetFailureCount()
                authorizedVaultKey = SessionManager.getBiometricVaultKey().ifEmpty { null }
                onSuccess()
            } else {
                val errorCode = error?.let { it.code.toLong() } ?: -1L
                when (errorCode) {
                    LAErrorUserCancel, LAErrorSystemCancel, LAErrorAppCancel -> onCancel()
                    LAErrorBiometryLockout, LAErrorTouchIDLockout -> {
                        recordFailure()
                        onError("Biometric locked out. Use your master password.")
                    }
                    else -> {
                        recordFailure()
                        onError(error?.localizedDescription ?: "Biometric authentication failed")
                    }
                }
            }
        }
    }

    actual fun storeVaultKey(vaultKey: String): Boolean {
        SessionManager.setBiometricVaultKey(vaultKey)
        return true
    }

    actual fun retrieveVaultKey(): String? {
        val cached = authorizedVaultKey
        if (cached != null) {
            authorizedVaultKey = null
            return cached
        }
        return SessionManager.getBiometricVaultKey().ifEmpty { null }
    }

    actual fun clear() {
        SessionManager.setBiometricVaultKey("")
        SessionManager.setBiometricFailureCount(0)
        authorizedVaultKey = null
    }
}
