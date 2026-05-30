package com.securevault.mobile.di

import androidx.compose.runtime.Composable
import androidx.compose.runtime.remember
import org.koin.core.context.GlobalContext

@Composable
actual inline fun <reified T : Any> koinInject(): T {
    return remember {
        GlobalContext.get().get<T>()
    }
}
