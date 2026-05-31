package com.securevault.mobile.data.local

import android.content.Context
import android.util.Log
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import androidx.fragment.app.FragmentActivity
import com.securevault.mobile.ui.PlatformContext

actual class BiometricStorage actual constructor(context: PlatformContext) {
    companion object {
        private const val PREFS_NAME = "secure_vault_biometric"
        private const val KEY_VAULT_KEY = "vault_key"
        private const val KEY_FAILURE_COUNT = "biometric_failure_count"
        private const val MAX_BIOMETRIC_FAILURES = 5
    }

    private val appContext = context.androidContext
    private val prefs = appContext.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)

    actual fun isAvailable(): Boolean {
        return BiometricManager.from(appContext).canAuthenticate(
            BiometricManager.Authenticators.BIOMETRIC_STRONG
        ) == BiometricManager.BIOMETRIC_SUCCESS
    }

    actual fun hasEncryptedVaultKey(): Boolean {
        return prefs.contains(KEY_VAULT_KEY)
    }

    actual fun isLockedOut(): Boolean {
        return prefs.getInt(KEY_FAILURE_COUNT, 0) >= MAX_BIOMETRIC_FAILURES
    }

    actual fun recordFailure() {
        val count = prefs.getInt(KEY_FAILURE_COUNT, 0) + 1
        prefs.edit().putInt(KEY_FAILURE_COUNT, count).apply()
        if (count >= MAX_BIOMETRIC_FAILURES) {
            clear()
        }
    }

    actual fun resetFailureCount() {
        prefs.edit().remove(KEY_FAILURE_COUNT).apply()
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
        Log.d("BiometricStorage", "authenticate() called, appContext: ${appContext::class.simpleName}")
        val activity = appContext as? FragmentActivity ?: run {
            Log.w("BiometricStorage", "appContext is not FragmentActivity: ${appContext::class.simpleName}")
            onError("Activity not available")
            return
        }
        val executor = ContextCompat.getMainExecutor(appContext)

        val callback = object : BiometricPrompt.AuthenticationCallback() {
            override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                resetFailureCount()
                onSuccess()
            }

            override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                if (errorCode == BiometricPrompt.ERROR_USER_CANCELED ||
                    errorCode == BiometricPrompt.ERROR_NEGATIVE_BUTTON
                ) {
                    onCancel()
                } else {
                    recordFailure()
                    onError(errString.toString())
                }
            }

            override fun onAuthenticationFailed() {
                recordFailure()
                onError("Biometric authentication failed. Try again.")
            }
        }

        val prompt = BiometricPrompt(activity, executor, callback)
        val promptInfo = BiometricPrompt.PromptInfo.Builder()
            .setTitle(title)
            .setSubtitle(subtitle)
            .setAllowedAuthenticators(BiometricManager.Authenticators.BIOMETRIC_STRONG)
            .setNegativeButtonText("Cancel")
            .build()

        prompt.authenticate(promptInfo)
    }

    actual fun storeVaultKey(vaultKey: String): Boolean {
        prefs.edit().putString(KEY_VAULT_KEY, vaultKey).apply()
        return true
    }

    actual fun retrieveVaultKey(): String? {
        return prefs.getString(KEY_VAULT_KEY, null)
    }

    actual fun clear() {
        prefs.edit()
            .remove(KEY_VAULT_KEY)
            .remove(KEY_FAILURE_COUNT)
            .apply()
    }
}
