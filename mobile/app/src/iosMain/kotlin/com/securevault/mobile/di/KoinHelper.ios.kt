package com.securevault.mobile.di

import androidx.compose.runtime.Composable
import org.koin.core.Koin

var _koin: Koin? = null

@Composable
actual inline fun <reified T : Any> koinInject(): T {
    return _koin!!.get()
}
