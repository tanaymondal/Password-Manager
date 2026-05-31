package com.securevault.mobile.di

import androidx.compose.runtime.Composable
import androidx.compose.runtime.remember
import org.koin.core.Koin

var _koin: Koin? = null

@Composable
actual inline fun <reified T : Any> koinInject(): T {
    return remember {
        _koin!!.get<T>()
    }
}
