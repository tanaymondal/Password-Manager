package com.securevault.mobile

import android.os.Bundle
import android.view.WindowManager
import androidx.activity.compose.setContent
import androidx.fragment.app.FragmentActivity
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.ui.Modifier
import com.securevault.mobile.data.repository.SessionManager
import com.securevault.mobile.di.appModule
import com.securevault.mobile.ui.navigation.SecureVaultNavHost
import com.securevault.mobile.ui.theme.SecureVaultTheme
import org.koin.android.ext.koin.androidContext
import org.koin.core.context.startKoin

class MainActivity : FragmentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        window.setFlags(
            WindowManager.LayoutParams.FLAG_SECURE,
            WindowManager.LayoutParams.FLAG_SECURE
        )

        SessionManager.storage.init(this)

        if (org.koin.core.context.GlobalContext.getOrNull() == null) {
            startKoin {
                androidContext(this@MainActivity)
                modules(appModule)
            }
        }

        setContent {
            SecureVaultTheme {
                Surface(
                    modifier = Modifier.fillMaxSize(),
                    color = MaterialTheme.colorScheme.background
                ) {
                    SecureVaultNavHost()
                }
            }
        }
    }
}