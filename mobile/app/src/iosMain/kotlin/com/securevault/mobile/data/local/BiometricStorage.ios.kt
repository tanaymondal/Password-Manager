@file:OptIn(kotlinx.cinterop.ExperimentalForeignApi::class)
package com.securevault.mobile.data.local

import com.securevault.mobile.data.repository.SessionManager
import com.securevault.mobile.ui.PlatformContext
import kotlinx.cinterop.toKString
import platform.LocalAuthentication.*

private const val BIO_KEYCHAIN_KEY = "vault_key"
private const val KEY_FAILURE_COUNT = "sv_bio_fail"
private const val MAX_BIOMETRIC_FAILURES = 5

actual class BiometricStorage actual constructor(context: PlatformContext) {
    private var authorizedVaultKey: String? = null

    actual fun isAvailable(): Boolean {
        val ctx = LAContext()
        return ctx.canEvaluatePolicy(LAPolicyDeviceOwnerAuthenticationWithBiometrics, null)
    }

    actual fun hasEncryptedVaultKey(): Boolean {
        return BioKeychain.bio_exists(BIO_KEYCHAIN_KEY).toInt() != 0
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
                // Read vault key from Secure Enclave-protected Keychain
                val ptr = BioKeychain.bio_read(BIO_KEYCHAIN_KEY, title)
                if (ptr != null) {
                    authorizedVaultKey = ptr.toKString()
                    BioKeychain.bio_free(ptr)
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
        val status = BioKeychain.bio_write(BIO_KEYCHAIN_KEY, vaultKey)
        return status.toInt() == 0
    }

    actual fun retrieveVaultKey(): String? {
        val cached = authorizedVaultKey
        if (cached != null) {
            authorizedVaultKey = null
            return cached
        }
        // Only readable via Secure Enclave after biometric scan in authenticate()
        return null
    }

    actual fun clear() {
        BioKeychain.bio_write(BIO_KEYCHAIN_KEY, "")
        SessionManager.setBiometricFailureCount(0)
        authorizedVaultKey = null
    }
}
