@file:OptIn(kotlinx.cinterop.ExperimentalForeignApi::class)
package com.securevault.mobile.data.local

import com.securevault.mobile.ui.PlatformContext
import kotlinx.cinterop.toKString
import kotlinx.cinterop.ExperimentalForeignApi
import platform.LocalAuthentication.*

actual class BiometricStorage actual constructor(context: PlatformContext) {
    companion object {
        private const val BIO_SERVICE = "com.securevault.biometric"
        private const val BIO_KEY = "vault_key"
        private const val PREFS_KEY_FAILURES = "sv_biometric_failure_count"
        private const val MAX_BIOMETRIC_FAILURES = 5
    }

    private var authorizedVaultKey: String? = null

    actual fun isAvailable(): Boolean {
        val ctx = LAContext()
        return ctx.canEvaluatePolicy(LAPolicyDeviceOwnerAuthenticationWithBiometrics, null)
    }

    actual fun hasEncryptedVaultKey(): Boolean {
        val ptr = KeychainHelper.keychain_read(BIO_SERVICE, BIO_KEY)
        if (ptr != null) {
            KeychainHelper.keychain_free_string(ptr)
            return true
        }
        return false
    }

    actual fun isLockedOut(): Boolean {
        val ptr = KeychainHelper.keychain_read(BIO_SERVICE, "$BIO_KEY.failures")
        val count = ptr?.toKString()?.toIntOrNull() ?: 0
        if (ptr != null) KeychainHelper.keychain_free_string(ptr)
        return count >= MAX_BIOMETRIC_FAILURES
    }

    actual fun recordFailure() {
        val ptr = KeychainHelper.keychain_read(BIO_SERVICE, "$BIO_KEY.failures")
        val count = (ptr?.toKString()?.toIntOrNull() ?: 0) + 1
        if (ptr != null) KeychainHelper.keychain_free_string(ptr)
        KeychainHelper.keychain_write(BIO_SERVICE, "$BIO_KEY.failures", count.toString())
    }

    actual fun resetFailureCount() {
        KeychainHelper.keychain_delete(BIO_SERVICE, "$BIO_KEY.failures")
    }

    actual fun shouldShowBiometricPrompt(): Boolean {
        return isAvailable() && hasEncryptedVaultKey() && !isLockedOut()
    }

    @OptIn(ExperimentalForeignApi::class)
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
                // Read vault key with biometric context
                val ptr = KeychainHelper.keychain_read_biometric(BIO_SERVICE, BIO_KEY, title)
                if (ptr != null) {
                    authorizedVaultKey = ptr.toKString()
                    KeychainHelper.keychain_free_string(ptr)
                }
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
        val status = KeychainHelper.keychain_write_biometric(BIO_SERVICE, BIO_KEY, vaultKey)
        return status.toInt() == 0
    }

    actual fun retrieveVaultKey(): String? {
        val cached = authorizedVaultKey
        if (cached != null) {
            authorizedVaultKey = null
            return cached
        }
        val ptr = KeychainHelper.keychain_read_biometric(BIO_SERVICE, BIO_KEY, "Unlock SecureVault")
        if (ptr != null) {
            val result = ptr.toKString()
            KeychainHelper.keychain_free_string(ptr)
            return result
        }
        return null
    }

    actual fun clear() {
        KeychainHelper.keychain_delete(BIO_SERVICE, BIO_KEY)
        KeychainHelper.keychain_delete(BIO_SERVICE, "$BIO_KEY.failures")
        authorizedVaultKey = null
    }
}
