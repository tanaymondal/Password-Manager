package com.securevault.mobile.di

import androidx.compose.runtime.Composable
import androidx.compose.runtime.remember

@Composable
actual inline fun <reified T : Any> koinInject(): T {
    @Suppress("UNCHECKED_CAST")
    return remember {
        (null as Any) as T
    }
}
