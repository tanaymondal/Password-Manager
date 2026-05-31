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
        // Use DataStore as the source of truth (written alongside Keychain in storeVaultKey)
        // Direct Keychain read would trigger biometric prompt, which we don't want here.
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
        // Store in Secure Enclave-protected Keychain
        val status = BioKeychain.bio_write(BIO_KEYCHAIN_KEY, vaultKey)
        if (status.toInt() == 0) {
            // Also store in DataStore (encrypted) as fallback for legacy migration
            SessionManager.setBiometricVaultKey(vaultKey)
            return true
        }
        return false
    }

    actual fun retrieveVaultKey(): String? {
        val cached = authorizedVaultKey
        if (cached != null) {
            authorizedVaultKey = null
            return cached
        }
        // Read from Keychain — requires biometric via LAContext in authenticate()
        // This method is called after successful authenticate(), which already
        // cached the key. Direct read without biometric context won't work
        // (Secure Enclave enforces biometric), so fall back to DataStore.
        val ds = SessionManager.getBiometricVaultKey().ifEmpty { null }
        if (ds != null) return ds
        val ptr = BioKeychain.bio_read(BIO_KEYCHAIN_KEY, "Unlock SecureVault")
        if (ptr != null) {
            val result = ptr.toKString()
            BioKeychain.bio_free(ptr)
            return result
        }
        return null
    }

    actual fun clear() {
        // Overwrite existing Keychain item with empty string (delete isn't exposed)
        BioKeychain.bio_write(BIO_KEYCHAIN_KEY, "")
        SessionManager.setBiometricVaultKey("")
        SessionManager.setBiometricFailureCount(0)
        authorizedVaultKey = null
    }
}
